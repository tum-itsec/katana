import collections
import json
import sys
import re
import statistics

src_re = re.compile(r'0x([a-f0-9]+)L')
dots_trust_re = re.compile(r'TRUST=(\d+)')

# For now only based on one kernel - FIXME
weights = {
    '[PARAMETER]': 5,
    '[GLOBAL]': 5,
    '[CALL]': 8,
    '[CALL_RECURSIVE]': 7,
    '[INDIRECT_CALL]': 7,
    '[INDIRECT_CALL_ARG]': 9,
    '[CONTAINER]': 6,
    '[RETURN_VALUE]': 9,
    '[RETURN_VALUE_ACCESS]': 5,
    '[RESOLVED_FROM_DOTS]': 7,
    '[STRUCTINFO]': 20,
}

class Type:
    def __init__(self, layout, structname, structinfo):
        # Majority vote
        # Allow only one vote for an offset per function
        self.layout = {}
        self.trust = {}
        encounters = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))
        voters = collections.defaultdict(lambda: collections.defaultdict(set))
        for member, offset, _, source in layout:
            for key, weight in weights.items():
                if key in source:
                    trust = weight
                    break
            else:
                print("BUG - no weight found:", source)
                sys.exit(-1)
            #if '[CONTAINER]' in source:
            #    trust = 1 if offset % 4 == 0 else 0 # container_of on unaligned values is unreasonably rare, much more likely to be an error
            #else:
            #    trust = 2

            if src_addr := src_re.search(source):
                src_addr = src_addr.group(0)
            elif '[RESOLVED_FROM_DOTS]' in source:
                src_addr = 'dots'
                trust = int(dots_trust_re.search(source).group(1))
            else:
                print("Cant match:", source)
                sys.exit(-1)

            if offset >= 0:
                if src_addr not in voters[member][offset]:
                    encounters[member][offset] += trust
                    voters[member][offset].add(src_addr)

        # Include structinfo
        structinfo = StructInfoType(structname, structinfo)
        for member, offset in structinfo.members.items():
            trust = weights['[STRUCTINFO]']
            if member not in self.layout:
                encounters[member][offset] += trust

        for member in encounters:
            voted_offset = max(encounters[member], key=lambda offset: encounters[member][offset])
            trust = encounters[member][voted_offset]
            self.layout[member] = voted_offset
            self.trust[member] = trust

    def get_trust_for_member(self, name):
        return self.trust.get(name, None)

    def get_offset_for_member(self, name):
        return self.layout.get(name, None)
    def __getitem__(self, key):
        return self.get_offset_for_member(key)
    def __contains__(self, name):
        return name in self.layout

    def items(self):
        return self.layout.items()
    def __iter__(self):
        return iter(self.layout)

class StructInfoType:
    def __init__(self, struct, structinfo):
        self.members = {}
        if struct not in structinfo:
            return
        if len(structinfo[struct]) > 1:
            print("More than one struct definition, cannot use")
            return
        struct = structinfo[struct][0]

        if len(struct['attributes']) > 0:
            print("Attributes found, skipping for now")
            return

        for field in struct['fields']:
            # Throw away everything inside an ifdef for now
            if field['ifdefblk'] == 0:
                self.members[field['name']] = field['offset']

    def get_trust_for_member(self, name):
        if name in self.members:
            return weights['[STRUCTINFO]']
        else:
            return None

    def get_offset_for_member(self, name):
        print("Getting structinfo member:", name)
        return self.members.get(name, None)
    def __getitem__(self, key):
        return self.get_offset_for_member(key)

    def items(self):
        return self.members.items()
    def __iter__(self):
        return iter(self.members)

class Layout:
    def __init__(self, reconstructed_file, structinfo_file):
        self.global_variables = {}
        self.global_variables_all = {}
        if isinstance(reconstructed_file, dict):
            self.layout = reconstructed_file
        else:
            with open(reconstructed_file) as jsonf:
                data = json.load(jsonf)
                self.layout = data['reconstructed']
                for name, addrs in data.get('globals', {}).items():
                    if not addrs:
                        continue
                    try:
                        best = statistics.mode(addrs)
                    except statistics.StatisticsError: # < Python 3.8, no unique mode.
                        best = collections.Counter(addrs).most_common(1)[0]
                    if not best:
                        continue
                    self.global_variables[name] = best
                    self.global_variables_all[name] = set(addrs)

        with open(structinfo_file) as jsonf:
            self.structinfo = json.load(jsonf)

    def get_structinfo_type(self, typename):
        return StructInfoType(typename, self.structinfo)
    def get_type(self, typename):
        tmptype = self.layout.get(typename, {})
        if tmptype == {}:
            return StructInfoType(typename, self.structinfo)
        else:
            return Type(tmptype, typename, self.structinfo)
    def get_global(self, name, all=False):
        if all:
            return self.global_variables_all.get(name)
        else:
            return self.global_variables.get(name)
    def __getitem__(self, key):
        return self.get_type(key)
    def __contains__(self, key):
        return key in self.layout

    def items(self):
        return self.layout.items()
    def __iter__(self):
        return iter(self.layout)
