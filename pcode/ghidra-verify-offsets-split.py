#!/usr/bin/env python3
import argparse
import enum
import collections
import json
import re
import subprocess
import sys
import math
from collections import defaultdict

from layout import Layout

class Color(enum.Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37

def write(color, member, offset, colored_sources, width):
    sources = ', '.join(f'\x1b[{source_color.value}m{source}\x1b[0m' for source, source_color in colored_sources)
    print(f'\t\x1b[{color.value};1m{member.ljust(width)}\t{offset:#x}\x1b[0m\t{sources}\x1b[0m')

def colorize(sources_by_offset, true_offset):
    colorized = [(source, Color.GREEN) for source in sources_by_offset[true_offset]]
    for offset in sources_by_offset:
        if offset != true_offset:
            colorized.extend([(source, Color.RED) for source in sources_by_offset[offset]])
    return colorized

STRUCT_NAME = re.compile("(struct|union) (.+) {")
STRUCT_WITHOUT_NAME = re.compile("\W*(?:const )?(struct|union) {")
ENUM = re.compile("\W*(?:const )?(enum) {")
STRUCT_END = re.compile("\s*}(?: (?:\*\s*)*(.+))?;\s*(?:/\*\s+(0x[0-9a-fA-F]+|0)(?:\s|:))?")
EMPTY_LINE = re.compile(r"^\W*(?:/\*.*\*/)?\W*$")

def unmangle_pahole(member):
    if match := re.match(r'([^\[:]+)', member):
        member = match.group(1) # Strip array extents and bitfields
    if match := re.match(r'\(\*([^)]+)\)', member):
        member = match.group(1) # Strip function pointer
    return member

def parse_pahole(output):
    pos = 0
    output = re.sub(br' __attribute__\(\(.*\)\);', b';', output) # Remove attributes
    lines = output.splitlines()

    type_offsets = defaultdict(list)

    def get_line():
        nonlocal pos
        pos += 1
        return lines[pos-1].decode("ascii")
    
    def skip_enum_body():
        while not (m := STRUCT_END.match(get_line())):
            pass
        return m.groups()

    def parse_struct_body(type_name):
        fields = []
        # Parse body
        while True:
            # Check for substruct/union
            l = get_line()
            m = STRUCT_WITHOUT_NAME.match(l)
            if m:
                _, fields_child, childname, maybe_offset = parse_struct_body(None)
                if childname:
                    if maybe_offset is None:
                        # Throw away stuff like this:
                        # struct dio { 
                        # ...
                        # /* Force padding: */
                        # union {
                        #	struct page *      pages[64];            /*     0 0x200 */
                        #	struct work_struct complete_work;        /*     0  0x40 */
                        # } :4096;
                        # ... }
                        continue
                    fields.append((unmangle_pahole(childname), int(maybe_offset, 0)))
                else:
                    fields.extend(fields_child)
                continue
            if (m := ENUM.match(l)):
                childname, offset= skip_enum_body()
                if offset is None:
                    # Of course the same shit that happend to unions also applies to enums... (see above)
                    continue
                fields.append((unmangle_pahole(childname), int(offset, 0)))
                continue
            
            if (e := STRUCT_END.search(l)) :
                return (type_name, fields, e.group(1), e.group(2))
            elif (e := EMPTY_LINE.match(l)):
                # Skip empty lines or lines with just a comment
                continue
            else:
                m = re.search(r'(\S+|\(\*[^()]+\)\(.*\));\s*/\*\s+(0x[0-9a-fA-F]+|0)(?:\s|:)', l)
                if not m:
                    continue
                member = m.group(1)
                offset = int(m.group(2), 0)
                member = unmangle_pahole(member)
                fields.append((member, offset))

    types = defaultdict(list)
    while pos < len(lines):
        try:
            type_kind, type_name = STRUCT_NAME.match(get_line()).groups()
            if type_kind == "union":
                # Also Unions are listed here. At toplevel all offsets are zero.
                # As there is nothing to recover here, we will drop them here
                while get_line().rstrip() != "};":
                    pass
                continue

            m = parse_struct_body(type_name)
            if m is not None:
                types[m[0]].append(m[1])
        except:
            print(lines[pos-1:pos])
            print(pos)
            raise
    return types

def get_all_type_offsets(vmlinux):
    print("Loading struct offsets . . .")
    output = subprocess.check_output(['pahole', '--hex', '--nested_anon_include', vmlinux])
    result = {}
    for typename, defs in parse_pahole(output).items():
        # If we have multiple types with the same name, choose the first one
        if len(defs) > 1:
            print(f'Multiple definitions for type {typename}!')
        result[typename] = defs[0]
    return result

def parse_structinfo(filename):
    offsets = json.load(open(filename))
    result = {}
    for typename, defs in offsets.items():
        if len(defs) > 1:
            print(f'Multiple definitions for type {typename}!')
        result[typename] = [(x['name'], x['offset']) for x in defs[0]['fields']]
    return result

analysis_sources = ['[PARAMETER]', '[GLOBAL]', '[CALL]', '[CALL_RECURSIVE]', '[INDIRECT_CALL]', '[INDIRECT_CALL_ARG]', '[CONTAINER]','[RETURN_VALUE]', '[RETURN_VALUE_ACCESS]', '[RESOLVED_FROM_DOTS]', '[STRUCTINFO]']

def translate_source(source):
    for idx, src in enumerate(analysis_sources):
        if src in source:
            return idx

class AnalysisStat:
    def __init__(self, analysis_source):
        self.analysis_source = analysis_source
        self.wrong = 0
        self.correct = 0

    def __str__(self):
        total = self.wrong + self.correct
        return f"{self.analysis_source} {(3 - math.floor((len(self.analysis_source) + 1) / 8)) * chr(9)}Wrong: \x1b[31m{self.wrong} ({self.wrong / total:5.1%})\x1b[0m\tCorrect: \x1b[32m{self.correct} ({self.correct / total:5.1%})\x1b[0m"

ALTERNATE_SETS_MARKER = '<alternate sets>'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('vmlinux', help='vmlinux image')
    parser.add_argument('--layout', help='extracted type information (JSON)')
    parser.add_argument('--structinfo', help='struct info file (JSON)', required=True)
    parser.add_argument('--overrule-debuginfo-with', help="A struct info file (JSON) to overrule faulty debug information (randstruct plugin)")
    parser.add_argument('-c', '--check', help='fields that we MUST get correct in a majority vote, in JSON ({"type": ["field1", "field2"]})')
    parser.add_argument('--check-extra', nargs=2, help='do an additional --check', action='append')
    style = parser.add_mutually_exclusive_group()
    style.add_argument('-p', '--pretty', help='dump pretty output on stdout', action='store_true')
    style.add_argument('--progress', help='write dots to stdout to indicate progress', action='store_true')
    parser.add_argument('-o', '--output', help='output file to write JSON to (otherwise, stdout)')
    args = parser.parse_args()


    if args.layout:
        layout_path = args.layout
    else:
        layout_path = args.vmlinux + '-layout'
    with open(layout_path) as jsonf:
        extracted = json.load(jsonf)['reconstructed']

    layout = Layout(extracted, args.structinfo) # Replicate majority vote accurately, instead of doing it in here...

    if args.overrule_debuginfo_with:
        all_type_offsets = parse_structinfo(args.overrule_debuginfo_with)
    else:
        all_type_offsets = get_all_type_offsets(args.vmlinux)

    dict_all_type_offsets = defaultdict(dict)
    for sname, mems in all_type_offsets.items():
        for mem, off in mems:
            dict_all_type_offsets[sname][mem] = off

    analysis_stats = [AnalysisStat(analysis_source) for analysis_source in analysis_sources]
    perfect = sometimes = wrong = not_found = not_recovered = 0
    out = {}

    all_known_types = set(all_type_offsets.keys()) | set(extracted.keys()) | set(layout.structinfo.keys()) # ground truth | extracted types that we found directly | structinfo types

    for typename in all_known_types:
        if typename == '???':
            continue

        # Reorder JSON output by member and offset
        actual = collections.defaultdict(lambda: collections.defaultdict(list))
        out[typename] = {}
        for member, offset, _, source in extracted.get(typename, []):
            if member != '???':
                actual[member][offset].append(source)
        structinfo = layout.get_structinfo_type(typename)
        for member, offset in structinfo.members.items():
            if member not in actual:
                actual[member][offset].append('[STRUCTINFO]')
        # This way, we know whether info came from structinfo or from recovery

        # Get the ground truth
        if typename not in all_type_offsets:
            continue
        truth = sorted(all_type_offsets[typename], key=lambda t: t[1])
        out[typename] = {member: {'offset': offset, 'majority': layout[typename][member], 'matches': dict(actual[member])} for member, offset in truth}

        if args.progress:
            print('.', end='', flush=True)
        #if len(actual) <= 0:
        #    continue
        # Dump
        if args.pretty:
            print(f'\n\x1b[1m{typename}\x1b[0m')
            width = max([0] + [len(member) for member, _ in truth])
            for member, offset in truth:
                if all(not any(f['name'] == member for f in info['fields']) for info in layout.structinfo.get(typename, [])):
                    # write(Color.CYAN, member, offset, [], width)
                    not_found += 1 # couldn't possibly recover this, member/type not known in reference
                elif layout[typename][member] is None:
                    write(Color.CYAN, member, offset, colorize(actual[member], offset), width)
                    not_recovered += 1
                elif offset not in actual[member] or layout[typename][member] != offset: # Also handles cases in which the voting goes wrong
                    write(Color.RED, member, offset, colorize(actual[member], offset), width)
                    wrong += 1
                elif not [wrong for wrong in actual[member] if wrong != offset]:
                    write(Color.GREEN, member, offset, colorize(actual[member], offset), width)
                    perfect += 1
                else:
                    # Mixed true-false
                    write(Color.YELLOW, member, offset, colorize(actual[member], offset), width)
                    sometimes += 1

                for found_offset in actual[member]:
                    for source in actual[member][found_offset]:
                        source_idx = translate_source(source)
                        if found_offset == offset:
                            analysis_stats[source_idx].correct += 1
                        else:
                            analysis_stats[source_idx].wrong += 1
    if args.pretty:
        found = perfect + sometimes + wrong
        total = perfect + sometimes + wrong + not_found + not_recovered
        print(f'Found {found} of {total} members\t({found / total:5.1%})')
        print(f'  - matched perfectly: {perfect}\t({perfect / total:5.1%})')
        print(f'  - not recovered : {not_recovered}\t({not_recovered / total:5.1%})')
        print(f'  - matched sometimes: {sometimes}\t({sometimes / total:5.1%})')
        print(f'  - matched never:     {wrong}\t({wrong / total:5.1%})')

        print('===Printing stats for all analyses===')
        for analysis_stat in analysis_stats:
            print(analysis_stat)
    elif args.progress:
        print()


    output_stream = sys.stdout if not args.output else open(args.output, 'w')

    checks = []
    if args.check:
        checks.append((args.check, output_stream))
    if args.check_extra:
        checks += args.check_extra

    for req_file, out_file in checks:
        print(f'Checking against requirements specified in {req_file}')
        with open(req_file) as jsonf:
            to_check = json.load(jsonf)
        result = {}
        for blockname, requirements in to_check.items():
            result[blockname] = {'types_missing_in_kernel': {}, 'members_missing_in_kernel': collections.defaultdict(list), 'not_recovered': collections.defaultdict(list), 'wrong': collections.defaultdict(list), 'correct': collections.defaultdict(list)}
            for typename in requirements:
                if typename == ALTERNATE_SETS_MARKER:
                    continue # Process sets of alternatives separately!

                if typename not in dict_all_type_offsets:
                    result[blockname]['types_missing_in_kernel'][typename] = requirements[typename]
                    print(f'\x1b[33m{blockname}: type \x1b[1m{typename}\x1b[0m\x1b[33m is missing from the kernel\x1b[0m')
                    continue
                for member in requirements[typename]:
                    if member not in dict_all_type_offsets[typename]:
                        result[blockname]['members_missing_in_kernel'][typename].append(member)
                        print(f'\x1b[33m{blockname}: \x1b[1m{typename}->{member}\x1b[0m\x1b[33m is missing from the kernel\x1b[0m')
                        continue
                    #print(out[typename])
                    #print(dict_all_type_offsets[typename])
                    if typename not in layout or member not in layout[typename]:
                        result[blockname]['not_recovered'][typename].append(member)
                        print(f'\x1b[34m{blockname}: \x1b[1m{typename}->{member}\x1b[0m\x1b[34m not recovered\x1b[0m')
                    elif layout[typename][member] == dict_all_type_offsets[typename][member]:
                        result[blockname]['correct'][typename].append(member)
                        print(f'\x1b[32m{blockname}: \x1b[1m{typename}->{member}\x1b[0m\x1b[32m correct\x1b[0m')
                    elif layout[typename][member] is None:
                        result[blockname]['not_recovered'][typename].append(member)
                        print(f'\x1b[34m{blockname}: \x1b[1m{typename}->{member}\x1b[0m\x1b[34m not recovered\x1b[0m')
                    else:
                        result[blockname]['wrong'][typename].append(member)
                        print(f'\x1b[31m{blockname}: \x1b[1m{typename}->{member}\x1b[0m\x1b[31m wrong\x1b[0m')
            if ALTERNATE_SETS_MARKER in requirements:
                for alternate_set in requirements[ALTERNATE_SETS_MARKER]:
                    resolution_reason = (None, None)
                    for index, (typename, member) in enumerate(alternate_set):
                        label = f'({index + 1}/{len(alternate_set)})'
                        if typename not in dict_all_type_offsets:
                            if resolution_reason[0] != 'not_recovered':
                                resolution_reason = ('types_missing_in_kernel', index)
                            print(f'\x1b[33m{blockname}: {label} type \x1b[1m{typename}\x1b[0m\x1b[33m is missing from the kernel\x1b[0m')
                        elif member not in dict_all_type_offsets[typename]:
                            if resolution_reason[0] != 'not_recovered':
                                resolution_reason = ('members_missing_in_kernel', index)
                            print(f'\x1b[33m{blockname}: {label} \x1b[1m{typename}->{member}\x1b[0m\x1b[33m is missing from the kernel\x1b[0m')
                        elif typename not in layout or member not in layout[typename]:
                            resolution_reason = ('not_recovered', index)
                            print(f'\x1b[34m{blockname}: {label} \x1b[1m{typename}->{member}\x1b[0m\x1b[34m not recovered\x1b[0m')
                        elif layout[typename][member] == dict_all_type_offsets[typename][member]:
                            resolution_reason = ('correct', index)
                            print(f'\x1b[32m{blockname}: {label} \x1b[1m{typename}->{member}\x1b[0m\x1b[32m correct\x1b[0m')
                            break # Stop here.
                        elif layout[typename][member] is None:
                            resolution_reason = ('not_recovered', index)
                            print(f'\x1b[34m{blockname}: {label} \x1b[1m{typename}->{member}\x1b[0m\x1b[34m not recovered\x1b[0m')
                        else:
                            resolution_reason = ('wrong', index)
                            print(f'\x1b[31m{blockname}: {label} \x1b[1m{typename}->{member}\x1b[0m\x1b[31m wrong\x1b[0m')
                            break # Stop after an offset is recovered
                    assert resolution_reason[0], f'Did not give resolution for alternate set {alternate_set} in block {blockname}'
                    problem_type, problem_member = alternate_set[resolution_reason[1]]
                    if problem_type in result[blockname][resolution_reason[0]]:
                        if problem_member not in result[blockname][resolution_reason[0]][problem_type]:
                            result[blockname][resolution_reason[0]][problem_type].append(problem_member)
                    else:
                        result[blockname][resolution_reason[0]][problem_type] = [problem_member]
        if isinstance(out_file, str):
            with open(out_file, 'w') as stream:
                json.dump(result, stream)
        else:
            json.dump(result, output_stream)
