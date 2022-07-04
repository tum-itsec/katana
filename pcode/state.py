from collections import defaultdict, OrderedDict

from maps import VarnodeMap, MemoryMap

class State:
    def __init__(self, parameters_to_track):
        self.parameters_to_track = parameters_to_track
        self.parameter_accesses = defaultdict(list)
        self.global_accesses = OrderedDict()
        self.global_pointers = []
        self.calls = OrderedDict()
        self.indirect_calls = OrderedDict()
        self.containerofs = OrderedDict()
        self.return_values = []
        self.return_value_accesses = OrderedDict()

        self.varnode_map = VarnodeMap(parameters_to_track, self.parameter_accesses, self.global_accesses, self.return_value_accesses)
        self.memory_map = MemoryMap(parameters_to_track, self.parameter_accesses, self.global_accesses, self.return_value_accesses)
