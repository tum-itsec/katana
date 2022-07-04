from collections import defaultdict, namedtuple
import re
import sys

from ghidra.program.model.lang import PrototypeModel

FUNC_REGEX = re.compile(r"^([^(]+)\(\) (.+:[\d]+)[\s]?(.*)$")
ACCESS_REGEX = re.compile(r"^ param_access (.*) (.*?)(->|\.)(.*) (.*)$")
GLOBAL_ACCESS_REGEX = re.compile(r"^ global_access (private|public) (.*) (.*?)(->|\.)(.*) (.*)$")
CALL_REGEX = re.compile(r"^ call (?P<callee>\S+) (?P<args>(?:.* |))(?P<calls>\d+)$")
CALL_ARGS_REGEX = re.compile(r"(?:(?P<stype>\S+?)(?P<acctype>->|\.)(?P<member>\S+))|(?P<global>#\S+)|_") # Pulls the arguments from <args> in CALL_REGEX
CONTAINER_OF_REGEX = re.compile(r"^ container_of (?P<stype>\S+?)(->|\.)(?P<member>\S+) (?P<calls>\d+)$")
GLOB_REGEX = re.compile(r"^ global_var (?P<visibility>private|public) (?P<name>\S+) (?P<type>.*) (?P<calls>\d+)$")
SPECIAL_ASM_REGEX = re.compile(r"^ val_from_asm (?P<stype>\S+)(->|\.)(?P<member>\S+) (?P<calls>\d+)$")
RETVAL_FROM_CALL_REGEX = re.compile(r"^ retval_from_call (?P<callee>\S+) (?P<stype>\S+?)(->|\.)(?P<member>\S+) (?P<calls>\d+)$")
RETVAL_IN_FUNCTION_REGEX = re.compile(r"^ retval_from_access (?P<stype>\S+?)(->|\.)(?P<member>\S+)$")
INDIRECT_CALL_REGEX = re.compile(r"^ call_indirect (?P<stype>\S+?|\?)(->|\.|\?)(?P<member>\S+|\?) (?P<args>(?:.* |))(?P<calls>\d+)$") # Callee member is parsed like any access.
FIELD_ELEMENT_REGEX = re.compile(r"(?P<member>.*)\[(?P<type>.*)\]")


Symbol = namedtuple('Symbol', 'name start size')
Access = namedtuple("Access", "symbol stype fields calls direct") # If the top level is not a dereference, direct = True
UnnamedAccess = namedtuple('UnnamedAccess', 'stype fields calls direct')
Arg = namedtuple("Arg", "stype fields direct")
Call = namedtuple("Call", "callee arguments")
IndirectCall = namedtuple("IndirectCall", "callee arguments") # callee is an Arg here, with stype and field
Field = namedtuple("Field", "member type")
GlobAccessResult = namedtuple("GlobAccess", "type insn_addr insn_size glob_addr target_reg")

class Function():
    def __init__(self, name, loc, linkage, accesses=None, calls=None, indirect_calls=None, globs=None, container_of=None, special_asms=None, retval_uses_after_call=None, retvals=None):
        self.name = name
        self.linkage = linkage
        self.loc = loc
        self.accesses = accesses if accesses else []
        self.calls = calls if calls else []
        self.indirect_calls = indirect_calls if indirect_calls else []
        self.globs = globs if globs else []
        self.container_of = container_of if container_of else []
        self.special_asms = special_asms if special_asms else []
        self.retval_uses_after_call = retval_uses_after_call if retval_uses_after_call else []
        self.retvals = retvals if retvals else []

def convert_field_element(e):
    l = []
    for x in e.split("."):
        m = FIELD_ELEMENT_REGEX.match(x)
        if m:
            (member, typ) = m.groups()
            l.append(Field(member, typ))
        else:
            l.append(None)
    return l

def read_tracking_file(filename, calling_convention, program):

    """
    register_storage = []
    idx = 0
    while True:
        storage = calling_convention.getArgLocation(idx, None, None, program)
        register = storage.getRegister()
        print(register)
        if register:
            register_storage.append(idx)
        else:
            break
        idx += 1

    cur_func = None
    """

    # we should be able to track stack passed arguments aswell, so really no need to restrict amount of parameters
    TRACK_MAX = 6

    res = {}
    with open(filename) as f:
        for line in f:
            m = CALL_REGEX.match(line)
            if (m):
                callee, arg_string = m.group('callee'), m.group('args')
                if callee == '???':
                    continue
                arguments = {}
                for index, arg_m in enumerate(CALL_ARGS_REGEX.finditer(arg_string)):
                    if index >= TRACK_MAX:
                        break # Won't be able to track registers
                    if arg_m.group(0) == '_':
                        continue # Skip irrelevant arguments
                    if arg_m.group('global'):
                        #arguments[register_storage[index]] = arg_m.group('global')
                        arguments[index] = arg_m.group('global')
                    else:
                        arguments[index] = Arg(arg_m.group('stype'), convert_field_element(arg_m.group('member')), arg_m.group('acctype') == '.')

                cur_func.calls.append(Call(callee, arguments))
                continue
            m = INDIRECT_CALL_REGEX.match(line)
            if (m):
                stype, acctype, member, arg_string, calls = m.groups()
                arg_string = arg_string.rstrip() # contains last space
                arguments = {}
                for index, arg_m in enumerate(CALL_ARGS_REGEX.finditer(arg_string)):
                    if index >= TRACK_MAX:
                        break # Won't be able to track registers
                    if arg_m.group(0) == '_':
                        continue # Skip irrelevant arguments
                    if arg_m.group('global'):
                        #arguments[register_storage[index]] = arg_m.group('global')
                        arguments[index] = arg_m.group('global')
                    else:
                        arguments[index] = Arg(arg_m.group('stype'), convert_field_element(arg_m.group('member')), arg_m.group('acctype') == '.')

                cur_func.indirect_calls.append(IndirectCall(Arg(stype, convert_field_element(member), acctype == '.'), arguments))
                continue
            m = GLOB_REGEX.match(line)
            if (m):
                name, visibility = m.group('name'), m.group('visibility')
                cur_func.globs.append((name, visibility))
                continue
            m = CONTAINER_OF_REGEX.match(line)
            if (m):
                stype, acctype, field, calls = m.groups()
                cur_func.container_of.append(Arg(stype, field, acctype == ".") )
                continue
            m = ACCESS_REGEX.match(line)
            if (m):
                symbol, stype, acctype, field, calls = m.groups()
                cur_func.accesses.append(Access("$" + symbol.lstrip(), stype, convert_field_element(field), calls, acctype == "."))
                continue
            m = GLOBAL_ACCESS_REGEX.match(line)
            if (m):
                visibility, symbol, stype, acctype, field, calls = m.groups()
                if visibility == "public":
                    cur_func.accesses.append(Access(symbol.lstrip(), stype, convert_field_element(field), calls, acctype == "."))
                elif visibility == "private":
                    cur_func.accesses.append(Access("<private>" + symbol.lstrip(), stype, convert_field_element(field), calls, acctype == "."))
                else:
                    raise ValueError("Unknown visibility: " + visibility)
                continue
            m = SPECIAL_ASM_REGEX.match(line)
            if (m):
                stype, acctype, field, calls = m.groups()
                cur_func.special_asms.append(UnnamedAccess(stype, convert_field_element(field), calls, acctype == "."))
                continue
            m = RETVAL_FROM_CALL_REGEX.match(line)
            if (m):
                callee, stype, acctype, member, calls = m.groups() # If this comes from an indirect call, callee may be ???.
                cur_func.retval_uses_after_call.append(Access(callee + '()', stype, convert_field_element(member), calls, acctype == "."))
                continue
            m = RETVAL_IN_FUNCTION_REGEX.match(line)
            if (m):
                stype, acctype, member = m.groups()
                cur_func.retvals.append(Arg(stype, convert_field_element(member), acctype == "."))
                continue
            m = FUNC_REGEX.match(line)
            if (m):
                name, loc, linkage = m.groups()
                cur_func = Function(name, loc, "int" if linkage == "[static]" else "ext")
                res[name] = cur_func
                continue

    return res

def read_testing_symbols(exe_name):
    symbols = []
    with open(exe_name + '_funs', 'r') as f:
        for line in f.read().split('\n'):
            if line == '':
                continue

            line = line.split(' ')
            name = line[0]
            offset = int(line[1])
            if offset > 0x400000:
                offset -= 0x400000
            # TODO: calculate size based on sorted list
            size = int(line[2])
            symbols.append(Symbol(name, offset, size))

    return symbols

def read_katana_symbols(image, model):

    fn_symbols = set()
    # dict to allow indexing via either name or addr
    all_symbols = {}

    info = ""
    with open(image + '-symtab', 'r') as f:
        info += f.read()
    with open(image + '-kallsym', 'r') as f:
        info += f.read()

    for line in info.splitlines():
        if not line:
            continue
        (name, addr) = line.split(' ')
        addr = int(addr, 16)
        fn_symbols.add((name, addr))
        all_symbols[name] = addr
        all_symbols[addr] = name

    fn_symbols = list(fn_symbols)

    fn_symbols = sorted(fn_symbols, key=lambda x: x[1])
    fn_symbols = filter(lambda x: x[0] in model, fn_symbols)

    sized_symbols = []
    for idx, sym in enumerate(fn_symbols):
        if idx == len(fn_symbols) - 1:
            continue
            #size = 0x100
        else:
            size = fn_symbols[idx + 1][1] - sym[1]
        sized_symbol = Symbol(sym[0], sym[1], size)
        sized_symbols.append(sized_symbol)

        #self._elf = ELFFile(image)
        #for s in self._elf.iter_segments():
        #    if s.header["p_type"] == "PT_LOAD":
        #        offset = s.header["p_offset"]
        #        print(offset)
        #        break

    #for idx in range(len(sized_symbols)):
        #sized_symbols[idx].start += offset
        #print(offset)

    return (sized_symbols, all_symbols)
