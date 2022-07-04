import pprint
import logging

from tracknode import *

class Map:
    def __init__(self, tracking_varnodes, tracked_accesses, global_accesses, return_value_accesses):
        # TODO: defaultdict(dict) for MemoryMap
        self.addr = None
        self.map = {}
        self.tracking_varnodes = tracking_varnodes
        self.tracked_accesses = tracked_accesses
        self.global_accesses = global_accesses
        self.return_value_accesses = return_value_accesses

    def set_current_addr(self, addr):
        self.addr = addr

    def __str__(self):
        pass

    def get_tracked_accesses(self):
        return self.tracked_accesses

    def get_global_accesses(self):
        return self.global_accesses

class MemoryMap(Map):
    #def __init__(self, tracking_varnodes, tracked_accesses, global_accesses):
    #    super().__init__(tracking_varnodes, tracked_accesses, global_accesses)

    def __str__(self):
        return "MemoryMap:\n" + pprint.pformat(self.map)

    def track_varnode(self, varnode):
        self.tracking_varnodes.add(varnode)

    def get_overlapping(self, space, varnode):
        # FIXME: Not too sure if any scaling between varnode size and offset is necessary...
        for (node, node_offset) in self.map[space].keys():
            if varnode.intersects(node) and varnode.offset == node_offset:
                return (node, node_offset)

        return None

    def set(self, space, key, value):

        # Can't write to unknown location
        if isinstance(key, Garbage):
            return

        if space not in self.map:
            self.map[space] = {}

        overlapping = self.get_overlapping(space, key)
        if overlapping is not None:
            del self.map[space][overlapping]

        self.map[space][key.get_key_representation()] = value

        #(key_varnode, key_offset) = key
        for (param_idx, tracking_varnode) in self.tracking_varnodes:
            if key.intersects(tracking_varnode):
                if key.offset == 0:
                    logging.debug("[W]rite access found at: {}".format(key.offset))
                    self.tracked_accesses[param_idx].append(("[W]", key.offset))

        # Return value tracking
        if key.is_from_return():
            if value.offset == 0:
                logging.debug("Return value deref tracked with offset: %s", key.offset)
                self.return_value_accesses[self.addr] = (key.callee, key.offset)

        if key.is_address():
            addr = key.get_varnode_offset() + key.offset
            logging.debug("Global [W]rite access found at: %s", addr)
            self.global_accesses[self.addr] = ("[W]", addr)

    def get(self, space, key):
        #TODO: respect varnode size

        if space not in self.map:
            value = Garbage("TRASH", 0, key.offset)
        else:
            value = self.map[space].get(key.get_key_representation(), Garbage("TRASH", 0, key.offset))

        #(key_varnode, key_offset) = key
        for (param_idx, tracking_varnode) in self.tracking_varnodes:
            if key.intersects(tracking_varnode):
                if key.offset == 0:
                    logging.debug("[R]ead access found at: {}".format(key.offset))
                    self.tracked_accesses[param_idx].append(("[R]", key.offset))

        # Return value tracking
        if key.is_from_return():
            if value.offset == 0:
                logging.debug("Return value deref tracked with offset: %s", key.offset)
                self.return_value_accesses[self.addr] = (key.callee, key.offset)

        if key.is_address():
            addr = key.get_varnode_offset() + key.offset
            logging.debug("Global [R]ead access found at: %s", addr)
            self.global_accesses[self.addr] = ("[R]", addr)
        return value

class VarnodeMap(Map):
    def __str__(self):
        return "VarnodeMap:\n" + pprint.pformat(self.map)

    def get_overlapping(self, varnode):
        for node in self.map.keys():
            if varnode.intersects(node):
                return node

        return None

    def set(self, key, value, track=False):
        overlapping = self.get_overlapping(key)
        if overlapping is not None:
            del self.map[overlapping]

        self.map[key] = value

        if track:
            for (param_idx, tracking_varnode) in self.tracking_varnodes:
                if value.intersects(tracking_varnode):
                    if value.offset > 0:
                        self.tracked_accesses[param_idx].append(("ADD/SUB", value.offset))
            
            # Return value tracking
            if value.is_from_return():
                if value.offset > 0:
                    self.return_value_accesses[self.addr] = (value.callee, value.offset)
                    logging.debug("Return value tracked with offset: %s", value.offset)


        # From ram is direct memory access e.g. (ram, 0xfffffffoobar, 8)
        # From const is a direct offset to a member e.g. foobar(&foo->bar) -> (const, 0xfffffabcd, 8)
        if 'ram' in str(key):
            logging.debug("Global write detected: %s", key)
            self.global_accesses[self.addr] = ("[W]", key.getAddress().getOffsetAsBigInteger())

    def get(self, key):
        overlapping = self.get_overlapping(key)

        if 'ram' in str(key):
            logging.debug("Global read detected: %s", key)
            self.global_accesses[self.addr] = ("[R]", key.getAddress().getOffsetAsBigInteger())

        if overlapping is not None:
            value = self.map.get(overlapping)
        else:
            value = self.map.get(key, ActualNode(key, 0))

        return value
