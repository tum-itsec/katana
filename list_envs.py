#!/usr/bin/env python3
from elfview import autoselect, NotMapped
import elfcore
from pcode.layout import Layout
import pagetable

import argparse
import bisect
import json
import os
import struct

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("-l", "--layout", help="reconstructed types from match-asm.py")
    parser.add_argument("-s", "--structinfo", help="struct info from compiler plugin", required=True)

    args = parser.parse_args()
    layout = Layout(args.layout if args.layout else "{}-layout-processed".format(args.image), args.structinfo)

    view = autoselect(args.image, need_symbols=True, debug_paging=True)

    u64 = lambda x: struct.unpack(view.byte_order + "Q", x)[0]
    u32 = lambda x: struct.unpack(view.byte_order + "I", x)[0]
    i32 = lambda x: struct.unpack(view.byte_order + "i", x)[0]
    pointer = lambda x: struct.unpack(view.byte_order + ("Q" if view.pointer_size == 8 else "I"), x)[0]

    tasks_off = require(layout['task_struct']['tasks'], expr='task_struct->tasks')
    next_ptr_off = require(layout['list_head']['next'], expr='list_head->next')
    ptr_off = tasks_off + next_ptr_off

    pid_off = require(layout['task_struct']['pid'], expr='task_struct->pid')
    comm_off = require(layout['task_struct']['comm'], expr='task_struct->comm')
    mm_off = require(layout['task_struct']['mm'], layout['task_struct']['active_mm'], expr='task_struct->mm or task_struct->active_mm')
    pgd_off = require(layout['mm_struct']['pgd'], expr='mm_struct->pgd')
    env_start_off = require(layout['mm_struct']['env_start'], expr='mm_struct->env_start')
    env_end_off = layout['mm_struct']['env_end']

    mm_name = 'mm:       ' if mm_off == layout['task_struct']['mm'] else 'active_mm:'
    print(f'''
Extracted offsets:
    task_struct->tasks.next: {ptr_off:#04x}
    task_struct->pid:        {pid_off:#04x}
    task_struct->comm:       {comm_off:#04x}
    task_struct->{mm_name}  {mm_off:#04x}
    mm_struct->pgd:          {pgd_off:#04x}
    mm_struct->env_start:    {env_start_off:#04x}'''
    )
    if env_end_off is not None:
        print(f'''    mm_struct->env_end:      {env_end_off:#04x}''')
    print()


    init_task_sym = view.lookup_symbol('init_task')
    if not init_task_sym:
        raise SymbolNotFound('init_task')
    cur = init_task = init_task_sym

    index = 1
    seen = set()
    while True:
        seen.add(cur)
        mm = pointer(view.get_virt(cur + mm_off, view.pointer_size))
        comm = view.get_virt(cur + comm_off, 16)
        pid = i32(view.get_virt(cur + pid_off, 4))
        if b"\x00" in comm:
            comm = comm[:comm.find(b"\x00")]
            comm = comm.decode().strip('\x00').ljust(16, " ")
        else:
            comm = comm.decode()
        prefix = '{} ({})'.format(pid, comm)
        task_page_mapping = None
        env_start = None
        env_end = None
        cr3_val = None
        cr3_val_phys = 0
        if mm != 0:
            cr3_val = pointer(view.get_virt(mm + pgd_off, view.pointer_size))
            cr3_val_phys = view.virt_to_phys(cr3_val)
            pages = pagetable.do_4level_paging(cr3_val_phys, view.get_phys)
            task_page_mapping = pagetable.merge_pages(pages)
            env_start = pointer(view.get_virt(mm + env_start_off, view.pointer_size))
            if env_end_off is not None:
                env_end = pointer(view.get_virt(mm + env_end_off, view.pointer_size))
            else:
                env_end = env_start + 0x10000
            if env_start > env_end:
                env_start, env_end = env_end, env_start # Handle swapped offsets/pointers if necessary

        if env_start == 0 or env_end == 0:
            print(prefix, 'no environment')
        elif task_page_mapping is not None:
            entry_index = bisect.bisect(task_page_mapping, pagetable.PageEntry(env_start, 0xffffffffffffffff, 0xffffffffffffffff, True, True, True)) - 1
            try:
                at_index = task_page_mapping[entry_index]
            except IndexError:
                print(prefix, 'paging resulted in bad mapping')
            else:
                if entry_index < 0:
                    end_mark = f' - {env_end:#x}' if env_end_off is not None else ''
                    print(prefix, f'environment (at {env_start:#x}{end_mark}) is not mapped (env_start < first entry)')
                elif at_index.virt > env_start:
                    print(prefix, 'invalid mapping')
                elif at_index.virt + at_index.size <= env_start:
                    print(prefix, 'environment is not mapped')
                else:
                    env = b''
                    while env_start < env_end:
                        offset = env_start - at_index.virt
                        size = min(env_end - env_start, at_index.size - offset)
                        try:
                            env += view.get_phys(at_index.phys + offset, size)
                        except NotMapped:
                            if env_end_off is not None:
                                raise
                            else:
                                break
                        entry_index += 1
                        env_start += size
                        if env_start >= env_end:
                            break
                        try:
                            at_index = task_page_mapping[entry_index]
                        except IndexError:
                            if env_end_off is not None:
                                env = None
                                print(prefix, 'environment is not fully mapped')
                            break
                        if at_index.virt != env_start:
                            if env_end_off is not None:
                                env = None
                                print(prefix, 'environment is not contiguous')
                            break
                    if env is not None:
                        print(prefix)
                        for entry in env.split(b'\0'):
                            if b'=' in entry:
                                try:
                                    print('\t' + entry.decode())
                                except UnicodeDecodeError:
                                    if env_end_off is not None:
                                        raise
                                    else:
                                        break
        else:
            print(prefix, 'no userspace memory map')

        index += 1
        cur = pointer(view.get_virt(cur + ptr_off, view.pointer_size)) - ptr_off
        if cur == init_task or cur in seen:
            break

