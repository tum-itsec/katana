import collections
import json

class Type:
    def __init__(self, layout):
        # Majority vote
        # Allow only one vote for an offset per function
        self.layout = {}
        encounters = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))
        voters = collections.defaultdict(lambda: collections.defaultdict(set))
        for member, offset, _, source in layout:
            source = source[:source.find('[')]
            if offset >= 0:
                if source not in voters[member][offset]:
                    encounters[member][offset] += 1
                    voters[member][offset].add(source)

        self.satisfy_encounters(encounters)

    def satisfy_encounters(self, encounters):
        max_member = None
        for member in encounters:
            for offset in encounters[member]:
                trust = encounters[member][offset]
                if max_member is None or trust > max_member[2]:
                    max_member = (member, offset, trust)

        if not max_member:
            return

        self.layout[max_member[0]] = max_member[1]

        if max_member[2] <= 1:
            for member in encounters:
                for offset in encounters[member]:
                    self.layout[member] = offset

            return

        # Remove all other occurences of this offset
        new_encounters = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))
        for member in encounters:
            for offset in encounters[member]:
                if offset != max_member[1]:
                    new_encounters[member][offset] = encounters[member][offset]
                    #del encounters[member][offset]

        self.satisfy_encounters(new_encounters)
        #self.layout[member] = max(encounters[member], key=lambda offset: encounters[member][offset])

    def get_offset_for_member(self, name):
        return self.layout.get(name, None)
    def __getitem__(self, key):
        return self.get_offset_for_member(key)

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
