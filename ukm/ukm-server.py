#!/usr/bin/python3

import argparse
import bisect
import collections
import pathlib
import struct
import socketserver
import sys
import time

from elfcore import ELFCore, PF_R, PF_W, PF_X

client_data = {}
class ukm_client:
    def __init__(self):
        self.expected_sequence_number = 0
        self.memory = []
        self.registers = None
        self.architecture = None
        self.paging = []

architecture_names = ['x64', 'i386', 'mips32', 'arm64', 'mips32el']

class ukm_handler(socketserver.BaseRequestHandler):
    def handle(self):
        global client_data

        if self.client_address not in client_data:
            client_data[self.client_address] = ukm_client()

        data = self.request[0]

        if data[:2] != b'\xbaI':
            # Invalid magic, drop
            print('Dropping packet with invalid magic', file=sys.stderr)
            return

        packet_type, arch, sequence_number, length = struct.unpack_from('>BBIH', data, 2)
        payload = data[10:]

        if len(payload) != length:
            # Invalid length, drop
            print('Dropping packet with invalid length', file=sys.stderr)
            return

        if sequence_number != client_data[self.client_address].expected_sequence_number:
            if sequence_number == 0 and packet_type == 0:
                print('Connection reset', file=sys.stderr)
                client_data[self.client_address] = ukm_client()
            else:
                print('Dropping packet with unexpected sequence number', sequence_number, file=sys.stderr)
                return
        client_data[self.client_address].expected_sequence_number = sequence_number + 1

        if client_data[self.client_address].architecture not in [None, arch]:
            print(f'Dropping packet with incorrect architecture {arch:#02x} (expected {client_data[self.client_address].architecture:#02x})', file=sys.stderr)
            return
        else:
            client_data[self.client_address].architecture = arch

        if packet_type == 0: # Status message
            if len(payload) == 0:
                print('Received setup packet from', self.client_address[0], f'({architecture_names[arch]})', file=sys.stderr)
            elif len(payload) == 1:
                errno = payload[0]
                if not errno:
                    print('Transfer completed', file=sys.stderr)
                    min_paddr = min(physaddr for physaddr, _ in client_data[self.client_address].memory)
                    max_paddr = max(physaddr + len(chunk) for physaddr, chunk in client_data[self.client_address].memory)

                    core = ELFCore() # We pretend this is x86-64 (it is probably not, but that makes it easier on the Katana parser later)
                    if client_data[self.client_address].registers:
                        core.add_note(b'UKM_REG\x00', len(client_data[self.client_address].registers), 0, client_data[self.client_address].registers)

                    core.add_note(b'UKM_ARCH\x00', 1, 0xff, client_data[self.client_address].architecture.to_bytes(length=1, byteorder='little'))

                    if not client_data[self.client_address].paging:
                        coretype = 'p'
                        # No paging information, dump the full physical dump
                        space_required = max_paddr - min_paddr
                        # TODO: This is probably too big on actual systems
                        memory = bytearray(space_required)
                        for physaddr, chunk in client_data[self.client_address].memory:
                            memory[physaddr - min_paddr : physaddr - min_paddr + len(chunk)] = chunk
                        core.add_load_segment(min_paddr, PF_R | PF_W | PF_X, memory) # Physical memory dump
                    else:
                        print(f'Received {len(client_data[self.client_address].paging)} page table entries', file=sys.stderr)
                        # Consolidate pages if enabled
                        if self.server.args.consolidate:
                            index = 0
                            while index < len(client_data[self.client_address].paging) - 1:
                                a, b = client_data[self.client_address].paging[index:index+2]
                                a_virt, a_phys, a_size, a_data = a
                                b_virt, b_phys, b_size, b_data = b
                                if a_virt + a_size == b_virt and a_phys + a_size == b_phys:
                                    client_data[self.client_address].paging[index] = (a_virt, a_phys, a_size + b_size, b'')
                                    del client_data[self.client_address].paging[index + 1]
                                else:
                                    index += 1
                            print(f'Consolidated page table entries, {len(client_data[self.client_address].paging)} remaining')
                        coretype = 'v'
                        def get_pram(paddr, size, memory, chunks_fully_used):
                            block = bytearray(size)
                            target_end = paddr + size
                            first_ge_page = bisect.bisect_left(memory, (paddr, b'')) # e >= x
                            if first_ge_page >= len(memory):
                                first_ge_page = len(memory) - 1
                            while memory[first_ge_page][0] + len(memory[first_ge_page][1]) > paddr and first_ge_page > 0:
                                first_ge_page -= 1 # Go backwards to find overlapping chunks
                            for index in range(first_ge_page, len(memory)):
                                cpaddr, chunk = memory[index]
                                if cpaddr >= target_end:
                                    break
                                source_end = cpaddr + len(chunk)
                                if target_end <= cpaddr or source_end <= paddr:
                                    continue
                                # Overlap!
                                if cpaddr <= paddr and source_end >= target_end:
                                    # Full overlap, done!
                                    block[0:size] = chunk[paddr - cpaddr:target_end - cpaddr]
                                    if cpaddr == paddr and source_end == target_end:
                                        chunks_fully_used.add(cpaddr)
                                    break
                                elif cpaddr < paddr:
                                    # Partial overlap at the start of the target block / end of the source chunk
                                    block[:source_end - paddr] = chunk[paddr - cpaddr:]
                                elif source_end > target_end:
                                    # Partial overlap at the end of the target block / start of the source chunk
                                    block[cpaddr - paddr:] = chunk[:target_end - cpaddr]
                                else:
                                    # Partial overlap in the middle
                                    block[cpaddr - paddr:source_end - paddr] = chunk
                                    chunks_fully_used.add(cpaddr)
                            return block

                        # We have paging data! Add all mapped pages
                        used = set()
                        for vaddr, paddr, size, _ in client_data[self.client_address].paging:
                            block = get_pram(paddr, size, client_data[self.client_address].memory, used)
                            core.add_load_segment(vaddr, PF_R | PF_W | PF_X, block, paddr, may_reuse_other_by_paddr = True) # TODO: set permissions correctly

                        # If there are any fixed memory mappings based on architecture, add them now.
                        if client_data[self.client_address].architecture == 2: # MIPS32
                            # The k0seg (= cached) and k1seg (= uncached) ranges are mapped linearly,
                            # with physical addresses from 0 to 0x1fffffff mapping to virtual addresses
                            # from 0x80000000 to 0x9fffffff and 0xa0000000 to 0xbfffffff respectively.
                            end_offset = min(max_paddr, 0x20000000)
                            block = get_pram(min_paddr, end_offset - min_paddr, client_data[self.client_address].memory, used)
                            core.add_load_segment(0x80000000 + min_paddr, PF_R | PF_W | PF_X, block, min_paddr)
                            core.add_load_segment(0xa0000000 + min_paddr, PF_R | PF_W | PF_X, block, min_paddr)

                        # Make sure the rest of RAM is also in the dump, even if it is not paged
                        current_base = None
                        current_chunk = b''
                        for cpaddr, chunk in client_data[self.client_address].memory:
                            if cpaddr in used:
                                continue
                            if current_base == None:
                                current_base = cpaddr
                            elif current_base + len(current_chunk) == cpaddr:
                                current_chunk += chunk
                            else:
                                core.add_load_segment(0, PF_R | PF_W | PF_X, current_chunk, current_base, may_reuse_other_by_paddr = True)
                                current_base = cpaddr
                                current_chunk = chunk
                        if current_base:
                            core.add_load_segment(0, PF_R | PF_W | PF_X, current_chunk, current_base, may_reuse_other_by_paddr = True)

                    arch_name = architecture_names[client_data[self.client_address].architecture]
                    with open(pathlib.Path(self.server.args.output_directory) / f'{self.client_address[0]}-{self.client_address[1]}-{int(time.time())}-{arch_name}.{coretype}core', 'wb') as corefile:
                        core.write(corefile)

                    print('Corefile written', file=sys.stderr)

                    del core
                    del client_data[self.client_address]
                else:
                    print('An error occurred on the remote end:', errno, file=sys.stderr)
                return
            else:
                print(f'Dropping invalid status packet', file=sys.stderr)
        elif packet_type == 1: # Register data
            if client_data[self.client_address].registers != None:
                print('Warning: Overwriting register state', file=sys.stderr)
            client_data[self.client_address].registers = payload
        elif packet_type == 2: # Memory data
            physaddr = struct.unpack_from('>Q', payload, 0)[0]
            if physaddr & 0xfff == 0:
                print(f'{physaddr:#08x}\r', end='', file=sys.stderr)
            data = payload[8:]
            bisect.insort(client_data[self.client_address].memory, (physaddr, data))
        elif packet_type == 3: # Paging data
            vaddr, paddr, size = struct.unpack_from('>QQQ', payload, 0)
            arch_specific = payload[16:]
            bisect.insort(client_data[self.client_address].paging, (vaddr, paddr, size, arch_specific))
        elif packet_type == 4: # Text
            try:
                in_text = True
                print(payload.decode(), end='', flush=True)
            except UnicodeDecodeError:
                print(f'Received undecodable text message: {payload.hex()}', file=sys.stderr)
        elif packet_type == 5: # Hex
            print(payload.hex(), end='', flush=True)
        else:
            print(f'Dropping packet with unknown type {packet_type:#02x}', file=sys.stderr)
            return

def server(host, port, args):
    with socketserver.UDPServer((host, port), ukm_handler) as server:
        server.args = args
        server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='IP address or host name to bind to', default='0.0.0.0')
    parser.add_argument('-p', '--port', help='Port number to listen on', default=9999, type=int)
    parser.add_argument('-O', '--output-directory', help='Output directory', default='.')
    parser.add_argument('--consolidate', help='Consolidate page table entries regardless of permission flags', action='store_true')
    args = parser.parse_args()
    server(args.host, args.port, args)
