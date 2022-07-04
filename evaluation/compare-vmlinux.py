#!/usr/bin/env python3
# Compare offsets between vmlinux files

import argparse
import enum
import collections
import json
import re
import subprocess
import sys
from collections import defaultdict

class Color(enum.Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37

class Change(enum.Enum):
    NEW = 0
    REMOVED = 1
    SAME = 2
    CHANGED = 3

def write(member, offset1, offset2, width):
    if offset1 is None:
        color = Color.CYAN # New
        rv = Change.NEW
    elif offset2 is None:
        color = Color.MAGENTA # Removed
        rv = Change.REMOVED
    elif offset1 == offset2:
        color = Color.GREEN # Same
        rv = Change.SAME
    else:
        color = Color.RED # Different
        rv = Change.CHANGED
    offset1t = '' if offset1 is None else f'{offset1:#x}'
    offset2t = '' if offset2 is None else f'{offset2:#x}'
    print(f'\t\x1b[{color.value};1m{member.ljust(width)}\t{offset1t}\t{offset2t}\x1b[0m')
    return rv

def get_all_type_offsets(vmlinux):
    print("Loading struct offsets . . .")
    output = subprocess.check_output(['pahole', '--hex', '--nested_anon_include', vmlinux])
    output = re.sub(br' __attribute__\(\(.*\)\);', b';', output) # Remove attributes
    struct_splits = output.split(b'};\n')[:-1]
    type_offsets = defaultdict(list)
    for struct in struct_splits:
        while b'typedef' in struct.splitlines()[0]:
            struct = b'\n'.join(struct.splitlines()[1:])
        header = struct.splitlines()[0]
        struct_name = header[len("struct "):header.find(b' {')].decode('ascii')
        for match in re.finditer(br'(\S+|\(\*[^()]+\)\(.*\));\s*/\*\s+(0x[0-9a-fA-F]+|0)(?:\s|:)', struct, re.MULTILINE):
            member = match.group(1)
            offset = int(match.group(2), 0)
            if match := re.match(br'([^\[:]+)', member):
                member = match.group(1) # Strip array extents and bitfields
            if match := re.match(br'\(\*([^)]+)\)', member):
                member = match.group(1) # Strip function pointer
            member = member.decode()
            if member == '}':
                continue # Skip ends of anonymous structs or unions
            type_offsets[struct_name].append((member, offset))

    return type_offsets

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('vmlinux1', help='original vmlinux image')
    parser.add_argument('vmlinux2', help='vmlinux image to compare to')
    parser.add_argument('-c', '--check', help='check these fields especially')
    parser.add_argument('-o', '--output', help='output file to write check report to (otherwise, stdout)')
    args = parser.parse_args()

    offsets1 = get_all_type_offsets(args.vmlinux1)
    offsets2 = get_all_type_offsets(args.vmlinux2)

    stats = collections.defaultdict(lambda: 0)
    for typename in sorted(set(offsets1.keys()) | set(offsets2.keys())):
        print(f'\n\x1b[1m{typename}\x1b[0m')
        # find differences
        m1 = m2 = 0
        t1 = { m: o for m, o in offsets1.get(typename, []) }
        t2 = { m: o for m, o in offsets2.get(typename, []) }
        keys = sorted(set(t1.keys()) | set(t2.keys()))
        width = max([0] + [len(k) for k in keys])
        for k in keys:
            stats[write(k, t1.get(k, None), t2.get(k, None), width)] += 1

    total = sum(stats.values())
    print(f'Found {total} members:')
    print(f'  - same offset: {stats[Change.SAME]}\t({stats[Change.SAME] / total:5.1%})')
    print(f'  - added:       {stats[Change.NEW]}\t({stats[Change.NEW] / total:5.1%})')
    print(f'  - deleted:     {stats[Change.REMOVED]}\t({stats[Change.REMOVED] / total:5.1%})')
    print(f'  - changed:     {stats[Change.CHANGED]}\t({stats[Change.CHANGED] / total:5.1%})')

    if args.check:
        # Offsets present in both versions that break by changing config
        output_stream = sys.stdout if not args.output else open(args.output, 'w')
        with open(args.check) as jsonf:
            to_check = json.load(jsonf)
        result = {}
        for blockname, requirements in to_check.items():
            result[blockname] = {'always_missing': collections.defaultdict(list), 'now_missing': collections.defaultdict(list), 'was_missing': collections.defaultdict(list), 'changed': collections.defaultdict(list), 'correct': collections.defaultdict(list)}
            for typename in requirements:
                t1 = { m: o for m, o in offsets1.get(typename, []) }
                t2 = { m: o for m, o in offsets2.get(typename, []) }
                for member in requirements[typename]:
                    if member not in t1 and member not in t2:
                        result[blockname]['always_missing'][typename].append(member)
                    elif member not in t1:
                        result[blockname]['was_missing'][typename].append(member)
                    elif member not in t2:
                        result[blockname]['now_missing'][typename].append(member)
                    elif t1[member] != t2[member]:
                        result[blockname]['changed'][typename].append(member)
                    else:
                        result[blockname]['correct'][typename].append(member)
        json.dump(result, output_stream)
