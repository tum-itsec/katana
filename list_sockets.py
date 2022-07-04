#!/usr/bin/env python3
from common import *

import json
import os
import struct
import ipaddress

protos = {
    0 : 'ip',
    6 : 'tcp',
    17 : 'udp'
}

tcp_states = ("",
              "ESTABLISHED",
              "SYN_SENT",
              "SYN_RECV",
              "FIN_WAIT1",
              "FIN_WAIT2",
              "TIME_WAIT",
              "CLOSE",
              "CLOSE_WAIT",
              "LAST_ACK",
              "LISTEN",
              "CLOSING")

UNIX_PATH_MAX = 108
AF_UNIX = 1
AF_INET6 = 10

def proto_to_string(protocol):
    return protos.get(protocol, 'unknown')

def state_to_string(state):
    if 0 <= state < len(tcp_states):
        ret = tcp_states[state]
    else:
        ret = ""

    return ret

if __name__ == "__main__":
    args, layout, view = tool_setup()

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
    fop_off = require(layout['file']['f_op'], expr='file->f_op')
    # We could try to walk the open_fds bitmap, but it's easier to just check all max_fds fds
    path_off = require(layout['file']['f_path'], expr='file->f_path')
    dentry_off = require(layout['path']['dentry'], expr='path->dentry')
    inode_off = require(layout['dentry']['d_inode'], expr='dentry->d_inode')
    sk_off = require(layout['socket']['sk'], expr='socket->sk')

    vfs_inode_off = require(layout['socket_alloc']['vfs_inode'], expr='socket_alloc->vfs_inode')
    #vfs_inode_off = sk_off + view.pointer_size + view.pointer_size

    __sk_common_off = maybe(layout['sock']['__sk_common'], expr='sock->__sk_common', default=0) # Kernel asks for this field to be the first one + no randomization => static 0 offset
    __sk_common_family_off = require(layout['sock_common']['skc_family'], expr='sock_common->skc_family')
    sk_family_off = __sk_common_off + __sk_common_family_off
    sk_state = __sk_common_off + require(layout['sock_common']['skc_state'], expr='sock_common->skc_state')
    unix_address = require(layout['unix_sock']['addr'], expr='unix_sock->addr')
    unix_name = require(layout['unix_address']['name'], expr='unix_address->name')
    sun_path = require(layout['sockaddr_un']['sun_path'], expr='sockaddr_un->sun_path')
    sk_type = require(layout['sock']['sk_type'], expr='sock->sk_type')
    sk_protocol = require(layout['sock']['sk_protocol'], expr='sock->sk_protocol')

    inet_sport = require(layout['inet_sock']['inet_sport'], layout['inet_sock']['sport'], expr='inet_sock->inet_sport')
    try:
        inet_dport = require(layout['inet_sock']['inet_dport'], layout['inet_sock']['dport'], expr='inet_sock->inet_dport')
    # Moved into __sk_common.skc_dport
    except OffsetNotFound:
        inet_dport = __sk_common_off + require(layout['sock_common']['skc_dport'], expr='inet_sock->__sk_common.skc_dport')
        # Hacky...
        #if inet_dport == sk_family_off:
        #    inet_dport = sk_family_off - 2
    try:
        inet_rcv_saddr = require(layout['inet_sock']['inet_rcv_saddr'], layout['inet_sock']['rcv_saddr'], expr='inet_sock->inet_rcv_saddr')
    # Moved into __sk_common.skc_rcv_saddr
    except OffsetNotFound:
        inet_rcv_saddr = __sk_common_off + require(layout['sock_common']['skc_rcv_saddr'], expr='inet_sock->__sk_common.skc_rcv_saddr')
    try:
        inet_daddr = require(layout['inet_sock']['inet_daddr'], layout['inet_sock']['daddr'], expr='inet_sock->inet_daddr')
    # Moved into __sk_common.skc_daddr
    except OffsetNotFound:
        inet_daddr = __sk_common_off + require(layout['sock_common']['skc_daddr'], expr='inet_sock->__sk_common.skc_daddr')

    if inet_rcv_saddr - 4 != inet_daddr:
        inet_daddr = min(inet_rcv_saddr - 4, inet_daddr)
        inet_rcv_saddr = inet_daddr + 4
        print('Overriding inet_daddr and inet_rcv_saddr via __addrpair')

    try:
        inet6_rcv_saddr = require(layout['inet_sock']['pinet6'], expr='inet_sock->pinet6') + \
                          require(layout['ipv6_pinfo']['saddr'], expr='ipv6_pinfo->saddr')
    except OffsetNotFound:
        inet6_rcv_saddr = __sk_common_off + require(layout['sock_common']['skc_v6_rcv_saddr'], expr='sock_common->skc_v6_rcv_saddr')

    try:
        inet6_daddr = require(layout['inet_sock']['pinet6'], expr='inet_sock->pinet6') + \
                      require(layout['ipv6_pinfp']['daddr'], expr='ipv6_pinfo->daddr')
    # Moved into __sk_common.skc_v6_daddr
    except OffsetNotFound:
        try:
            inet6_daddr = __sk_common_off + require(layout['sock_common']['skc_v6_daddr'], expr='sock_common->skc_v6_daddr')
        except OffsetNotFound:
            inet6_daddr = 0x10000 # insane enough to be fixed by alignment below

    if inet6_rcv_saddr - 16 != inet6_daddr:
        inet6_daddr = min(inet6_rcv_saddr - 16, inet6_daddr)
        inet6_rcv_saddr = inet6_daddr + 16
        print('Overriding inet6_daddr and inet6_rcv_saddr via neighboring alignment')

    get_fdtab = lambda i: pointer(i + fdt_off, view)

    print(f'''
Extracted offsets:
    task_struct->tasks.next:   {ptr_off:#04x}
    task_struct->pid:          {pid_off:#04x}
    task_struct->comm:         {comm_off:#04x}
    task_struct->fs:           {fs_off:#04x}
    task_struct->files:        {files_off:#04x}
    files_struct->fdt:         {fdt_off:#04x}
    fdtable->max_fds:          {max_fds_off:#04x}
    file->f_op:                {fop_off:#04x}
    socket_alloc->vfs_inode:   {vfs_inode_off:#04x}
    socket->sk:                {sk_off:#04x}
    sock->sk_family:           {sk_family_off:#04x}
    sock->sk_type:             {sk_type:#04x}
    sock->sk_protocol          {sk_protocol:#04x}
    unix_sock->addr            {unix_address:#04x}
    unix_address->name         {unix_name:#04x}
    sockaddr_un->sun_path      {sun_path:#04x}
    inet_sock->inet_sport      {inet_sport:#04x}
    inet_sock->inet_dport      {inet_dport:#04x}
    inet_sock->inet_rcv_saddr  {inet_rcv_saddr:#04x}
    inet_sock->inet_daddr      {inet_daddr:#04x}
    inet_sock->inet6_rcv_saddr {inet6_rcv_saddr:#04x}
    inet_sock->inet6_daddr     {inet6_daddr:#04x}
''')

    socket_file_ops_sym = view.lookup_symbol('socket_file_ops')
    if not socket_file_ops_sym:
        raise SymbolNotFound('socket_file_ops')

    init_task_sym = view.lookup_symbol('init_task')
    if not init_task_sym:
        raise SymbolNotFound('init_task')
    cur = init_task = init_task_sym

    seen = set()
    while True:
        seen.add(cur)
        comm = view.get_virt(cur + comm_off, 16)
        pid = i32(cur + pid_off, view)
        if b"\x00" in comm:
            comm = comm[:comm.find(b"\x00")]
            comm = comm.decode().strip('\x00').ljust(16, " ")
        else:
            comm = comm.decode()
        prefix = '{} ({})'.format(pid, comm)

        try:
            files = pointer(cur + files_off, view)
            fs = pointer(cur + fs_off, view)
            if not fs:
                print(prefix, 'no fs_struct for this process')
                raise StopIteration
            fdtab = get_fdtab(files)
            fd_array = pointer(fdtab + fds_off, view)
            max_fds = u32(fdtab + max_fds_off, view)
            bit_words = ((max_fds + view.pointer_size * 8 - 1) // (view.pointer_size * 8))
            for index in range(max_fds):
                file_obj = pointer(fd_array + view.pointer_size * index, view)
                if file_obj < 0x1000: # Needs to be a valid pointer...
                    continue

                file_operations = pointer(file_obj + fop_off, view)
                if file_operations != socket_file_ops_sym:
                    continue

                dentry = pointer(file_obj + path_off + dentry_off, view)
                if not dentry:
                    print(prefix, '[{}] (no dentry!)'.format(index))
                    continue

                inode = pointer(dentry + inode_off, view)
                if inode < 0x1000: # Needs to be a valid pointer...
                    print(prefix, '[{}] (no inode!)'.format(index))
                    continue

                # Emulate container_of to obtain socket struct - SOCKET_I()
                socket = inode - vfs_inode_off
                # This socket is representation agnostic
                sk = pointer(socket + sk_off, view)

                # Change introduced in v5.6: sk_protocol now after sk_type and a u16 instead of an 8-bit field
                if sk_protocol < sk_type:
                    protocol = u8(sk + sk_protocol, view)
                else:
                    protocol = u16(sk + sk_protocol, view)

                family = u16(sk + sk_family_off, view)
                #type = u16(sk + sk_type, view)
                protocol = proto_to_string(protocol)

                unix_path = ''
                if family == AF_UNIX:
                    cur_unix_address = pointer(sk + unix_address, view)
                    if cur_unix_address != 0:
                        cur_unix_address_name = cur_unix_address + unix_name
                        cur_sun_path = cur_unix_address_name + sun_path
                        unix_path = view.get_virt(cur_sun_path, UNIX_PATH_MAX)
                        unix_path = unix_path[:unix_path[1:].find(b'\x00') + 1].lstrip(b'\x00') # Beware of anonymous sockets!
                        try:
                            unix_path = unix_path.decode()
                        except UnicodeDecodeError:
                            unix_path = repr(unix_path)[2:-1]

                if family == AF_INET6:
                    protocol += '6'

                if unix_path:
                    if 'tcp' in protocol:
                        state = u8(sk + sk_state, view)
                        state = state_to_string(state)
                    else:
                        state = ""
                    if protocol == 'ip':
                        protocol = 'unix'
                    state = state.ljust(max(len(state) for state in tcp_states))
                    print(f"{prefix}\t{protocol}\t{state} {unix_path}")
                elif protocol in ['tcp', 'udp', 'tcp6', 'udp6']:
                    if 'tcp' in protocol:
                        state = u8(sk + sk_state, view)
                        state = state_to_string(state)
                    else:
                        state = ""

                    sport = ntohs(u16(sk + inet_sport, view), view)
                    dport = ntohs(u16(sk + inet_dport, view), view)
                    if family == AF_INET6:
                        saddr = ipaddress.IPv6Address(view.get_virt(sk + inet6_rcv_saddr, 16))
                        daddr = ipaddress.IPv6Address(view.get_virt(sk + inet6_daddr, 16))
                    else:
                        saddr = ipaddress.IPv4Address(view.get_virt(sk + inet_rcv_saddr, 4))
                        daddr = ipaddress.IPv4Address(view.get_virt(sk + inet_daddr, 4))

                    if state == "LISTEN" or ('udp' in protocol and daddr.packed.strip(b'\0') == b'' and dport == 0):
                        to = "" # no target (listening, or stateless with empty destination)
                    else:
                        to = f"--> {daddr}:{dport}"
                    state = state.ljust(max(len(state) for state in tcp_states))
                    print(f"{prefix}\t{protocol}\t{state} {saddr}:{sport} {to}")

        except NotMapped:
            print(prefix, 'invalid memory access')
        except StopIteration:
            pass
        cur = pointer(cur + ptr_off, view) - ptr_off
        if cur == init_task or cur in seen:
            break

