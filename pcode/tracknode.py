import logging
import sys

class Tracknode:
    def __init__(self, offset = 0, latest_offset = None, deref_offset = None):
        self.offset = offset
        self.deref_offset = deref_offset
        self.latest_offset = latest_offset

class Garbage(Tracknode):
    def __init__(self, desc, offset = 0, deref_offset = None):
        Tracknode.__init__(self, offset, None, deref_offset)
        self.desc = desc

    def __str__(self):
        #if self.is_from_return():
        #    return "ReturnGarbage: (callee:{}, addr:{}, off:{}, deref:{}, latest_offset:{})".format(self.callee, self.addr, self.offset, self.deref_offset, self.latest_offset)
        #else:
        return "Garbage: (desc:{}, off:{}, deref:{}, latest_offset:{})".format(self.desc, self.offset, self.deref_offset, self.latest_offset)

    def __repr__(self):
        return self.__str__()

    def is_constant(self):
        return False

    def is_address(self):
        return False

    def intersects(self, other):
        return False

    def get_key_representation(self):
        return (self.desc, self.offset)

    def create_from_offset(self, new_offset):
        return Garbage(self.desc, new_offset, self.deref_offset)

    def is_mips_call_mask(self):
        return self.desc == "MIPS_CALL_ALIGN"

    def is_from_return(self):
        #return self.desc == "RETURN GARBAGE"
        return False

class ReturnGarbage(Garbage):
    def __init__(self, callee, addr, desc = "RETURN GARBAGE", offset = 0, deref_offset = None):
        Garbage.__init__(self, desc, offset, deref_offset)
        self.desc = desc
        self.callee = callee
        self.addr = addr

    def is_from_return(self):
        return True

    def __str__(self):
        return "ReturnGarbage: (callee:{}, addr:{}, off:{}, deref:{}, latest_offset:{})".format(self.callee, self.addr, self.offset, self.deref_offset, self.latest_offset)

    def create_from_offset(self, new_offset):
        return ReturnGarbage(self.callee, self.addr, self.desc, new_offset, self.deref_offset)

class ActualNode(Tracknode):
    def __init__(self, varnode, offset=0, deref_offset=None):
        Tracknode.__init__(self, offset, deref_offset)

        if varnode is None:
            logging.error("None varnode received")
            sys.exit(-1)
        self.varnode = varnode

    def __str__(self):
        return "Actualnode: (vnode:{}, off:{}, deref:{}, latest_offset:{})".format(self.varnode, self.offset, self.deref_offset, self.latest_offset)
    def __repr__(self):
        return self.__str__()

    def is_constant(self):
        return self.varnode.isConstant()

    def is_address(self):
        return self.varnode.isAddress()

    def get_varnode_offset(self):
        return self.varnode.getAddress().getOffsetAsBigInteger()

    def get_varnode_size(self):
        return self.varnode.getSize()

    def get_key_representation(self):
        return (self.varnode, self.offset)

    def intersects(self, other):
        return self.varnode.intersects(other)

    def create_from_offset(self, new_offset):
        return ActualNode(self.varnode, new_offset, self.deref_offset)

    def is_mips_call_mask(self):
        return False

    def is_from_return(self):
        return False
