#!/usr/bin/env python3
from elfview import autoselect, NotMapped
import elfcore
from pcode.layout import Layout

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
    parser.add_argument("-26", "--linux-26", help="use the Linux 2.6 structures instead", action="store_true") # Deal with the refactor

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

    files_off = require(layout['task_struct']['files'], expr='task_struct->files')
    fs_off = require(layout['task_struct']['fs'], expr='task_struct->fs')
    fdt_off = require(layout['files_struct']['fdt'], expr='files_struct->fdt')
    max_fds_off = require(layout['fdtable']['max_fds'], expr='fdtable->max_fds')
    fds_off = require(layout['fdtable']['fd'], expr='fdtable->fd')
    # We could try to walk the open_fds bitmap, but it's easier to just check all max_fds fds
    path_off = require(layout['file']['f_path'], expr='file->f_path')
    mnt_off = require(layout['path']['mnt'], expr='path->mnt')
    dentry_off = require(layout['path']['dentry'], expr='path->dentry')
    parent_off = require(layout['dentry']['d_parent'], expr='dentry->d_parent')
    name_off = require(layout['dentry']['d_name'], expr='dentry->d_name')
    qstr_name_off = require(layout['qstr']['name'], expr='qstr->name')
    if args.linux_26:
        mount_container_off = 0 # No container_of necessary on the old source
        mountpoint_off = require(layout['vfsmount']['mnt_mountpoint'], expr='vfsmount->mnt_mountpoint')
    else:
        mount_container_off = require(layout['mount']['mnt'], expr='mount->mnt')
        mountpoint_off = require(layout['mount']['mnt_mountpoint'], expr='mount->mnt_mountpoint')
    root_off = require(layout['fs_struct']['root'], expr='fs_struct->root')

    get_fdtab = lambda i: pointer(view.get_virt(i + fdt_off, view.pointer_size))
    #fdtab_log = f'files_struct->fdtab:     {fdtab_off:#04x}' if fdtab_off == layout['files_struct']['fdtab'] else f'files_struct->fdt:       {fdtab_off:#04x}'

    print(f'''
Extracted offsets:
    task_struct->tasks.next: {ptr_off:#04x}
    task_struct->pid:        {pid_off:#04x}
    task_struct->comm:       {comm_off:#04x}
    task_struct->fs:         {fs_off:#04x}
    task_struct->files:      {files_off:#04x}
    fs_struct->root:         {root_off:#04x}
    files_struct->fdt:       {fdt_off:#04x}
    fdtable->max_fds:        {max_fds_off:#04x}
    file->f_path:            {path_off:#04x}
    path->mnt:               {mnt_off:#04x}
    path->dentry:            {dentry_off:#04x}
    mount->mnt:              {mount_container_off:#04x}
    mount->mnt_mountpoint:   {mountpoint_off:#04x}
    dentry->d_parent:        {parent_off:#04x}
    dentry->d_name:          {name_off:#04x}
    qstr->name               {qstr_name_off:#04x}
''')

    init_task_sym = view.lookup_symbol('init_task')
    if not init_task_sym:
        raise SymbolNotFound('init_task')
    cur = init_task = init_task_sym

    seen_tasks = set()
    while True:
        seen_tasks.add(cur)
        comm = view.get_virt(cur + comm_off, 16)
        pid = i32(view.get_virt(cur + pid_off, 4))
        if b"\x00" in comm:
            comm = comm[:comm.find(b"\x00")]
            comm = comm.decode().strip('\x00').ljust(16, " ")
        else:
            comm = comm.decode()
        prefix = '{} ({})'.format(pid, comm)

        try:
            files = pointer(view.get_virt(cur + files_off, view.pointer_size))
            fs = pointer(view.get_virt(cur + fs_off, view.pointer_size))
            if not fs:
                print(prefix, 'no fs_struct for this process')
                raise StopIteration
            root_dentry = pointer(view.get_virt(fs + root_off + dentry_off, view.pointer_size))
            fdtab = get_fdtab(files)
            fd_array = pointer(view.get_virt(fdtab + fds_off, view.pointer_size))
            max_fds = u32(view.get_virt(fdtab + max_fds_off, 4))
            bit_words = ((max_fds + view.pointer_size * 8 - 1) // (view.pointer_size * 8))
            actual_count = 0
            for index in range(max_fds):
                file_obj = pointer(view.get_virt(fd_array + view.pointer_size * index, view.pointer_size))
                if file_obj < 0x1000: # Needs to be a valid pointer...
                    continue
                actual_count += 1
                dentry = pointer(view.get_virt(file_obj + path_off + dentry_off, view.pointer_size))
                if not dentry:
                    print(prefix, '[{}] (no dentry!)'.format(index))
                    continue
                path = b''
                # Linux has some extended magic here where some dentry objects have
                # a d_op->d_dname function that dynamically generates names
                # We don't use that here because it would require emulating all sorts of stuff
                # (and it may just as well be manipulated). Instead we just show the placeholder name.
                seen = set()
                while dentry and dentry not in seen:
                    seen.add(dentry)
                    next_dentry = pointer(view.get_virt(dentry + parent_off, view.pointer_size))
                    if next_dentry == dentry:
                        # Hit the mount point
                        vfsmount = pointer(view.get_virt(file_obj + path_off + mnt_off, view.pointer_size))
                        mount = vfsmount - mount_container_off
                        next_dentry = pointer(view.get_virt(mount + mountpoint_off, view.pointer_size))
                    if next_dentry == dentry:
                        # Non-mounted FS dentry
                        break
                    element_ptr = pointer(view.get_virt(dentry + name_off + qstr_name_off, view.pointer_size))
                    element = b''
                    while True:
                        char = view.get_virt(element_ptr + len(element), 1)
                        if char == b'\x00':
                            break
                        element += char
                    path = element + (b'/' if path and not path.startswith(b'/') and not element.endswith(b'/') else b'') + path
                    if dentry == root_dentry:
                        break # Hit the root
                    dentry = next_dentry

                print(prefix, '[{}]:'.format(index), path.decode())
            if not actual_count:
                print(prefix, 'no file descriptors')
        except NotMapped:
            print(prefix, 'invalid memory access')
        except StopIteration:
            pass
        cur = pointer(view.get_virt(cur + ptr_off, view.pointer_size)) - ptr_off
        if cur == init_task or cur in seen_tasks:
            break

