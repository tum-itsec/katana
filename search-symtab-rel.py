#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
import string
import re
import pagetable
import pickle
import os
import struct
import binascii
import time
import mmap
import concurrent.futures
import argparse
import itertools
from collections import namedtuple
from extract_cr3 import extract_cpu_states
from elfview import autoselect, NotMapped

from cffi import FFI

ffi = FFI()
ffi.cdef("""
    int64_t search_rel_pointer(const char* data, uint64_t len, uint64_t needle, uint64_t offset);
""")
lib = ffi.dlopen("./search-symtab-rel-helper.so")

#SYMBOL_NAME = b"init_task"
#SYMBOL_NAME = b"kallsyms_on_each_symbol"
SYMBOL_NAME = b"unregister_kprobe"

def parse_symtab(view, start, end, string_table, step=8):
    for i in range(start, end, step):
        chunk = view.get_phys(i, step)
        #print(chunk.hex())
        code_addr, name_addr = struct.unpack("<ii", chunk[:8])
        # FIXME: We have no idea which address to choose, so use max
        code_addr = max(view.phys_to_virt(code_addr + i), default=0)
        addr = name_addr + i + 4
        name = string_table.lookup_addr(addr)
        #print(name)
        if name is not None:
            name = name[1]
        yield (code_addr, name)

class RebasedList:
     def __init__(self, l, base):
         self.base = base
         self.l = l
     def __getitem__(self, val):
         if type(val) is slice:
             return self.l[slice(val.start - self.base, val.stop - self.base, val.step)]
         else:
             new_val = val - self.base
             if 0 <= new_val < len(self.l):
                 return self.l[new_val]
             else:
                 raise IndexError()

def check_both_dirs(data, fun, start, step=1):
     a_start = start
     a_end = start
     for i in itertools.count(start, step=-step):
         if not fun(data(i, step), i):
             break
         a_start = i
     for i in itertools.count(start=start+step, step=step):
         if not fun(data(i, step), i):
             break
         a_end = i
     return (a_start, a_end)

class StringTable:
    def __init__(self, raw_data):
        self.table = list(StringTable.parse_raw(raw_data))
        self.offset = 0
        self.raw_data = raw_data
    def lookup_addr(self, addr):
        res = None
        if addr - self.offset > 0:
            res = (addr, bytes(itertools.takewhile(lambda x: x != 0, self.raw_data[addr - self.offset:])))
            if len(res[1]) == 0:
                res = None
        return res
    def lookup_name(self, name):
        return next((x for x in self.table if x[1] == name), None)
    def rebase(self, offset):
        self.offset = offset
        self.table = [(x[0] + offset, x[1]) for x in self.table]
    def items(self):
        return self.table
    def __setitem__(self, key, value):
        self.table[key] = value
    def __getitem__(self, key):
        return self.table[key]
    def dump(self, filename):
        with open(filename, "w") as f:
            for e in self.table:
                f.write("0x{:x} - {}\n".format(*e))
    @staticmethod
    def parse_raw(raw_data):
        p = 0
        while True:
            e = raw_data.find(b"\x00", p)
            if e == -1:
                break
            name = raw_data[p:e]
            if name != b'':
                yield (p, name)
            p = e+1

import hexdump

def determine_size_symtab(view, cur_paddr, string_table):
    paddr, paddr_end, d = next(x for x in view.iter_loads() if x[0] <= cur_paddr < x[1])
    def is_ptr_to_stringtable(data, pos):
        paddr_entry = paddr + pos + struct.unpack(view.byte_order + 'i', data[4:8])[0] + 4
        sentry = string_table.lookup_addr(paddr_entry)
        print(paddr+pos, sentry)
        if sentry is None:
            return False
        return True

    # The structure is fn_code_addr, fn_name_addr. Therefore
    # we have to start our search -8 bytes before our match and
    # check with our filter
    start8, end8 = check_both_dirs(lambda offset, size: view.get_phys(paddr + offset, size), is_ptr_to_stringtable, cur_paddr - paddr - 4, 8)
    start12, end12 = check_both_dirs(lambda offset, size: view.get_phys(paddr + offset, size), is_ptr_to_stringtable, cur_paddr - paddr - 4, 12)
    print(end8 - start8, end12 - start12)
    if (end12 - start12) // 12 > (end8 - start8) // 8:
        return start12, end12, 12
    else:
        return start8, end8, 8

def find_symtab(view, string_table):
    """ Find the ksymtab with by looking for a section that contains
    only pointers to it"""

    # Take an entry that we now for sure is part of the symtab (not needed, we
    # should be able to take any here...)
    print(string_table[0])
    entry = string_table.lookup_name(SYMBOL_NAME)

    candidates = []
    for paddr, paddr_end, d in view.iter_loads():
        print(f"Searching {paddr}-{paddr_end} for {entry}")
        pos = 0
        d = memoryview(d) # this gives us zero copy
        if paddr < 0:
            # Correct mmap artefacts here
            d = d[-paddr:]
            paddr = 0
        chunk = d
        while True:
            chunk = chunk[pos:] 
            cbuf = ffi.from_buffer(chunk)
            pos = lib.search_rel_pointer(cbuf, len(chunk), entry[0], paddr)
            if pos == -1:
                break
            print("Hit! 0x{:016x}".format(pos + paddr))
            # Check how large the potential table is
            start_symtab, end_symtab, step = determine_size_symtab(view, paddr + pos, string_table)

            if end_symtab - start_symtab < 0x20:
                print(f"Withdrawn Ksymtab candidate 0x{start_symtab:x} - 0x{end_symtab:x}")
            else:
                print(f"Ksymtab candidate 0x{start_symtab:x} - 0x{end_symtab:x}")
                candidates.append((start_symtab + paddr, end_symtab + paddr, step))
            pos += 1

    # If multiple candidates, take the biggest one
    return max(candidates, default=None, key=lambda x: x[1]-x[0])

StringSection = namedtuple("StringSection", "start end")
def search_string_sections():
    sections = []
    regex = re.compile(b"(?:[a-zA-Z0-9_\\-]+\x00){100,}")
    for paddr,paddr_end,d in data:
        print(f"Searching {paddr}-{paddr_end}")
        sections.extend([StringSection(start=paddr + m.start(), end=paddr + m.end()) for m in regex.finditer(d)])
    return sections

def search_string_sections_fast(view):
    sections = []
    for paddr, paddr_end, d in view.iter_loads():
        size = paddr_end - paddr
        def d_at(index, to=None):
            nonlocal paddr
            size = 1 if to is None else to - index
            return view.get_phys(paddr + index, size)
        p = 0
        while True:
            p = d.find(SYMBOL_NAME + b"\x00", p)
            if p == -1:
                break
            # Check backward
            i = 0
            while p - i >= 0:
                try:
                    if d_at(p-i) not in string.ascii_letters.encode() + b"_-\x00" + string.digits.encode() or d_at(max(p-i-3, 0), p-i).strip(b'\x00') == b'': # three seq. null bytes
                        i -= 1
                        break
                except NotMapped:
                    i -= 1
                    break
                i += 1
            start = p-i
            # Check forward
            i = 0
            while p + i < size:
                try:
                    if d_at(p+i) not in string.ascii_letters.encode() + b"_-\x00" + string.digits.encode() or d_at(p+i, min(size,p+i+3)).strip(b'\x00') == b'': # three seq. null bytes
                        i -= 1
                        break
                except NotMapped:
                    i -= 1
                    break
                i += 1
            end = p+i
            print(paddr+start, paddr+end)
            sections.append(StringSection(start=paddr+start, end=paddr+end))
            p += 1
    return sections

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")

    args = parser.parse_args()
    view = autoselect(args.image)

    # Look for string sections
    import time
    t1 = time.time()
    res = search_string_sections_fast(view)
    print("Candiates ksymtab_strings:", len(res))
    print("Took {} secs".format(time.time() - t1))

    # Identify strings of strtab candidates
    candidates = []
    for n, i in enumerate(res):
        table_data = view.get_phys(i.start, i.end - i.start)
        print(f"Table #{n} - 0x{i.start:x} 0x{i.end - i.start:x}: {table_data[:1000]}")
        table = StringTable(table_data)
        table.rebase(i.start)
        table.dump("table-{}".format(n))
        if not table.lookup_name(SYMBOL_NAME):
            continue
        candidates.append((table, i.end - i.start))
    candidates = sorted(candidates, key=lambda tup: tup[1], reverse=True) # Start with the largest
    print(candidates)

    for candidate, size in candidates:
        res = find_symtab(view, candidate)
        if res:
            start_symtab, end_symtab, step = res
            symtab_candidate = candidate
            break

    print(start_symtab, end_symtab)
    symtab = list(parse_symtab(view, start_symtab, end_symtab, symtab_candidate, step))
    #symtab = list(parse_symtab(view, 5349144216, 5349221496, candidates[0]))
    print(symtab[:10])

    # Write results to file
    fout = open("{}-symtab".format(args.image) , "w")
    for addr, name in symtab:
        fout.write("{} {}\n".format(name.decode(), hex(addr)))
    fout.close()
    print("Done")
