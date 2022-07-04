from elfview import autoselect, NotMapped
import elfcore
from pcode.layout import Layout
import pagetable

import argparse
import functools
import struct

# Common utilities for tools

class SymbolNotFound(Exception):
    def __init__(self, symbol):
        super().__init__(self, f'Could not find required symbol "{symbol}"')

class OffsetNotFound(Exception):
    def __init__(self, type_and_member):
        super().__init__(self, f'Could not find required offset of {type_and_member}')

def require(*offsets, expr):
    offset = next((o for o in offsets if o is not None), None)
    if offset is None:
        raise OffsetNotFound(expr)
    return offset

def maybe(*offsets, expr, default): # For non-randomized structs that are constant across kernel versions, we can use a default offset if no layout information exists
    offset = next((o for o in offsets if o is not None), None)
    if offset is None:
        if default is not None:
            print(f'\x1b[33mUsing default of {default:#04x} for member {expr}\x1b[0m')
        else:
            print(f'\x1b[33mDid not find offset for optional member {expr}\x1b[0m')
    return default if offset is None else offset

pointer_struct_size = lambda view: ("Q" if view.pointer_size == 8 else "I")

u64 = lambda addr, view: struct.unpack(view.byte_order + "Q", view.get_virt(addr, 8))[0]
u32 = lambda addr, view: struct.unpack(view.byte_order + "I", view.get_virt(addr, 4))[0]
u16 = lambda addr, view: struct.unpack(view.byte_order + "H", view.get_virt(addr, 2))[0]
u8 = lambda addr, view: struct.unpack(view.byte_order + "B", view.get_virt(addr, 1))[0]
i32 = lambda addr, view: struct.unpack(view.byte_order + "i", view.get_virt(addr, 4))[0]
decode_pointer = lambda data, view: struct.unpack(view.byte_order + pointer_struct_size(view), data)[0]
pointer = lambda addr, view: decode_pointer(view.get_virt(addr, view.pointer_size), view)
align = lambda addr, to: addr if not addr % to else addr + (to - addr % to)

extract_bits = lambda value, mask_and_shift: (value >> mask_and_shift[1]) & mask_and_shift[0]
swab = lambda value, key: struct.unpack('>' + key, struct.pack('<' + key, value))[0]
swab_pointer = lambda value, view: swab(value, pointer_struct_size(view))

ntohs = lambda value, view: value if view.byte_order == '>' else swab(value, 'H')
ntohl = lambda value, view: value if view.byte_order == '>' else swab(value, 'I')

def string(addr, view):
    element = b'' # inefficient but whatever
    while True:
        char = view.get_virt(addr + len(element), 1)
        if char == b'\x00':
            return element
        element += char

def percpu_pointers(addr, view):
    # TODO: ARM64 in certain hypervisor modes and SPARC are special
    per_cpu_base = view.lookup_symbol('__per_cpu_offset')
    # This is an array of NR_CPUS, which can be very very large.
    # We assume that the first null pointer is the end
    # This isn't exactly accurate with hotswapping, but good enough for now
    # TODO: Find NR_CPUS somehow.
    while not pointer(per_cpu_base, view):
        per_cpu_base += view.pointer_size
    while True:
        offset = pointer(per_cpu_base, view)
        if not offset:
            break
        yield offset + pointer(addr, view)
        per_cpu_base += view.pointer_size


def tool_setup(custom_parser_setup = lambda parser: None, layout_optional=False):
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    if layout_optional:
        grp = parser.add_mutually_exclusive_group()
        grp.add_argument("-l", "--layout", help="reconstructed types and globals")
        grp.add_argument("-n", "--no-layout", help="don't use recovered information", action="store_true")
        parser.add_argument("-s", "--structinfo", help="struct information from the compiler plugin")
    else:
        parser.add_argument("-l", "--layout", help="reconstructed types")
        parser.add_argument("-s", "--structinfo", help="struct information from the compiler plugin", required=True)
    custom_parser_setup(parser)

    args = parser.parse_args()
    if layout_optional and args.no_layout:
        layout = None
    else:
        layout = Layout(args.layout if args.layout else "{}-layout-processed".format(args.image), args.structinfo)

    view = autoselect(args.image, need_symbols=True, debug_paging=True)
    # Supplement lookup_symbol with layout information if necessary
    if layout is not None:
        def supplement(view, layout):
            original = view.lookup_symbol
            def search(name, all=False):
                sym = original(name)
                if sym is None:
                    sym = layout.get_global(name, all=all)
                elif all:
                    sym = { sym }
                return sym
            return functools.wraps(original)(search)
    else:
        def supplement(view, layout):
            original = view.lookup_symbol
            def search(name, all=False):
                sym = original(name)
                if all and sym is not None:
                    sym = { sym }
                return sym
            return functools.wraps(original)(search)
    view.lookup_symbol = supplement(view, layout)
    return args, layout, view

