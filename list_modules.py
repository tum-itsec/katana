#!/usr/bin/env python3
from common import *

import argparse
from elfview import autoselect
from pcode.layout import Layout
import struct


if __name__ == "__main__":
    args, layout, view = tool_setup()

    next_off = layout['list_head']['next']
    ptr_off = layout['module']['list'] + next_off
    name_off = layout['module']['name']

    assert None not in [ptr_off, name_off], 'Required offsets not found'

    print(f'''
Extracted offsets:
    module->list.next: {ptr_off:#04x}
    module->name:      {name_off:#04x}
''')

    module_list_head = view.lookup_symbol('modules')
    assert module_list_head is not None, 'Head of the module list (symbol "modules") not found'
    module_list_head = module_list_head # Get address
    cur = pointer(module_list_head + next_off, view) - ptr_off

    while True:
        name = view.get_virt(cur + name_off, 56) # Length of module names has always been 64 - sizeof(unsigned long), i.e. 56 bytes
        try:
            if b"\x00" in name:
                name = name[:name.find(b"\x00")]
                name = name.decode().strip('\x00').ljust(56, " ")
            else:
                name = name.decode()[:56].ljust(56, " ")
        except UnicodeDecodeError:
            name = repr(name)[2:-1][:56].ljust(56, ' ')

        print("Module struct @ {:#x} ({})".format(cur, name))
        cur = pointer(cur + ptr_off, view) - ptr_off
        if cur + ptr_off - next_off == module_list_head:
            break
