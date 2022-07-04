#!/usr/bin/env python3
from elfview import autoselect, NotMapped
import elfcore
from pcode.layout import Layout
import pagetable

import argparse
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
    parser.add_argument("-o", "--outdir", help="output directory")
    parser.add_argument("-c", "--gencore", help="generate core files for running processes", action="store_true")

    args = parser.parse_args()
    outdir = args.outdir if args.outdir else "{}-procs".format(args.image)
    layout = Layout(args.layout if args.layout else "{}-layout-processed".format(args.image), args.structinfo)

    view = autoselect(args.image, need_symbols=True, debug_paging=True)

    u64 = lambda x: struct.unpack(view.byte_order + "Q", x)[0]
    u32 = lambda x: struct.unpack(view.byte_order + "I", x)[0]
    i32 = lambda x: struct.unpack(view.byte_order + "i", x)[0]
    pointer = lambda x: struct.unpack(view.byte_order + ("Q" if view.pointer_size == 8 else "I"), x)[0]

    tasks_off = require(layout['task_struct']['tasks'], expr='task_struct->tasks')
    next_ptr_off = require(layout['list_head']['next'], expr='list_head->next')
    ptr_off = tasks_off + next_ptr_off

    state_off = require(layout['task_struct']['state'], expr='task_struct->state')
    pid_off = require(layout['task_struct']['pid'], expr='task_struct->pid')
    comm_off = require(layout['task_struct']['comm'], expr='task_struct->comm')
    mm_off = require(layout['task_struct']['mm'], layout['task_struct']['active_mm'], expr='task_struct->mm or task_struct->active_mm')
    pgd_off = require(layout['mm_struct']['pgd'], expr='mm_struct->pgd')

    mm_name = 'mm:       ' if mm_off == layout['task_struct']['mm'] else 'active_mm:'
    print(f'''
Extracted offsets:
    task_struct->tasks.next: {ptr_off:#04x}
    task_struct->state:      {state_off:#04x}
    task_struct->pid:        {pid_off:#04x}
    task_struct->comm:       {comm_off:#04x}
    task_struct->{mm_name}  {mm_off:#04x}
    mm_struct->pgd:          {pgd_off:#04x}
''')

    # Only show UID if we have all the necessary offsets
    cred_off = layout['task_struct']['cred']
    cred_uid_off = layout['cred']['uid']
    if cred_off is not None and cred_uid_off is not None:
        task_uid_str = lambda task: 'UID {:#04x}'.format(u32(view.get_virt(pointer(view.get_virt(task + cred_off, view.pointer_size)) + cred_uid_off, 4)))
        print(f'''
    task_struct->cred:       {cred_off:#04x}
    cred->uid                {cred_uid_off:#04x}
''')
    else:
        task_uid_str = lambda task: ''

    init_task_sym = view.lookup_symbol('init_task')
    if not init_task_sym:
        raise SymbolNotFound('init_task')
    cur = init_task = init_task_sym

    index = 1
    seen = set()
    while True:
        print('{:#x}'.format(cur))
        seen.add(cur)
        mm = pointer(view.get_virt(cur + mm_off, view.pointer_size))
        comm = view.get_virt(cur + comm_off, 16)
        state = pointer(view.get_virt(cur + state_off, view.pointer_size))
        pid = i32(view.get_virt(cur + pid_off, 4))
        if b"\x00" in comm:
            comm = comm[:comm.find(b"\x00")]
            comm = comm.decode().strip('\x00').ljust(16, " ")
        else:
            comm = comm.decode()
        task_page_mapping = None
        cr3_val = None
        cr3_val_phys = 0
        if mm != 0:
            cr3_val = pointer(view.get_virt(mm + pgd_off, view.pointer_size))
            cr3_val_phys = view.virt_to_phys(cr3_val)
            if args.gencore:
                pages = pagetable.do_4level_paging(cr3_val_phys, view.get_phys)
                task_page_mapping = pagetable.merge_pages(pages)
        print("PID: {} ({}) State: {:#x} MM {:#x} {}".format(pid, comm, state, mm, task_uid_str(cur)))
        print("Task struct @ {:#x} CR3 ({})".format(cur, "{:#18x} {:#18x}".format(cr3_val, cr3_val_phys) if cr3_val else "\x1b[31m0x" + "0" * 16 + "\x1b[39m"))
        if args.gencore and task_page_mapping is not None:
            if not os.path.exists(outdir):
                os.mkdir(outdir)
            core = elfcore.ELFCore()
            for entry in task_page_mapping:
                if not entry.user_mode: #entry.virt > 0xff00000000000000:
                    continue
                #print(" - 0x{:016x} - 0x{:016x} [{}{}]".format(entry.virt, entry.virt + entry.size, "rw" if entry.rw else "r", "" if entry.nx else "x"))
                try:
                    data = view.get_phys(entry.phys, entry.size)
                except NotMapped:
                    continue # Pages that we don't have access to should not show up in the coredump anyways...
                perm = elfcore.PF_R
                perm |= elfcore.PF_W if entry.rw else 0
                perm |= elfcore.PF_X if not entry.nx else 0 # NB: If KPTI is enabled, it will set the NX bits in the PML4 entries, so no page will be marked as executable here.

                core.add_load_segment(entry.virt, perm, data)
            with open(os.path.join(outdir, "{:03d}-{:03d}-{}.core".format(index, pid, comm.strip().replace('/', '_'))), "wb") as t:
                core.write(t)

        index += 1
        cur = pointer(view.get_virt(cur + ptr_off, view.pointer_size)) - ptr_off
        if cur == init_task or cur in seen:
            break
