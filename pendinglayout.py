import collections
import json
import sys
import re

src_re = re.compile('0x([a-f0-9]+)L')

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
    def __init__(self, layout):
        # Majority vote
        # Allow only one vote for an offset per function
        self.layout = {}
        self.trust = {}
        encounters = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))
        voters = collections.defaultdict(lambda: collections.defaultdict(set))
        for key, fields, offset, source in layout:
            for weight_name, weight in weights.items():
                if weight_name in source:
                    trust = weight
                    break
            else:
                print("BUG - no weight found:", source)
                sys.exit(-1)

            if src_addr := src_re.search(source):
                src_addr = src_addr.group(0)
            elif '[RESOLVED_FROM_DOTS]' in source:
                src_addr = 'dots'
            else:
                print("Cant match:", source)
                sys.exit(-1)

            if offset >= 0:
                if src_addr not in voters[key][offset]:
                    encounters[key][offset] += trust
                    voters[key][offset].add(src_addr)

        for fields in encounters:
            voted_offset = max(encounters[fields], key=lambda offset: encounters[fields][offset])
            trust = encounters[fields][voted_offset]
            self.layout[fields] = voted_offset
            self.trust[fields] = trust


    def get_trust_for_fields(self, name):
        return self.trust.get(name, None)

    def get_offset_for_fields(self, name):
        return self.layout.get(name, None)
    def __getitem__(self, key):
        return self.get_offset_for_fields(key)

    def items(self):
        return self.layout.items()
    def __iter__(self):
        return iter(self.layout)

class Layout:
    def __init__(self, path_or_object):
        if isinstance(path_or_object, dict):
            self.layout = path_or_object
        else:
            with open(path_or_object) as jsonf:
                self.layout = json.load(jsonf)

    def get_type(self, typename):
        return Type(self.layout.get(typename, {}))
    def __getitem__(self, key):
        return self.get_type(key)

    def items(self):
        return self.layout.items()
    def __iter__(self):
        return iter(self.layout)
