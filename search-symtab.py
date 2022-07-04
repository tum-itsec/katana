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

SYMBOL_NAME = b"kallsyms_on_each_symbol"
#SYMBOL_NAME = b"unregister_kprobe"

def parse_symtab(view, data, string_table, namespaces=False):
    factor = 3 if namespaces else 2
    for i in range(0, len(data), factor * view.pointer_size):
        print(data[i:i+factor * view.pointer_size].hex())
        code_addr, name_addr, *ns = struct.unpack_from(view.byte_order + ("Q"*factor if view.pointer_size == 8 else "I"*factor), data[i:i+factor * view.pointer_size])
        addr = view.virt_to_phys(name_addr)
        name = string_table.lookup_addr(addr)
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
         if not fun(data(i, step)):
             break
         a_start = i
     for i in itertools.count(start=start+step, step=step):
         if not fun(data(i, step)):
             break
         a_end = i
     return (a_start, a_end)

class StringTable:
    def __init__(self, raw_data):
        self.table = list(StringTable.parse_raw(raw_data))
        self.offset = 0
    def lookup_addr(self, addr):
        return next((x for x in self.table if x[0] == addr), None)
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
            yield (p, raw_data[p:e])
            p = e+1

import hexdump

def find_symtab(view, string_table):
    """ Find the ksymtab with by looking for a section that contains
    only pointers to it"""

    # Take an entry that we now for sure is part of the symtab (not needed, we
    # should be able to take any here...)
    print(string_table[0])
    entry = string_table.lookup_name(SYMBOL_NAME)
    print(f'Symbol at physical address {entry[0]:x}')

    candidates = []
    for paddr,paddr_end,d in view.iter_loads():
        print(f"Searching {paddr}-{paddr_end}")
        for needle in view.phys_to_virt(entry[0]):
            print(f"Trying 0x{needle:x}")
            match = 0
            while True:
                match = d.find(struct.pack(view.byte_order + ("Q" if view.pointer_size == 8 else "I"), needle), match)
                if match == -1:
                    break

                # Check how large the potential table is

                def is_ptr_to_stringtable(d):
                    paddr_entry = view.virt_to_phys(struct.unpack(view.byte_order + ("Q" if view.pointer_size == 8 else "I"), d[view.pointer_size:2 * view.pointer_size])[0])
                    if paddr_entry is None:
                        return False
                    sentry = string_table.lookup_addr(paddr_entry)
                    if sentry is None:
                        return False
                    return True

                #pos = paddr + match
                #rd = RebasedList(d, paddr)

                # The structure is fn_code_addr, fn_name_addr. Therefore
                # we have to start our search -8 bytes before our match and
                # check with our filter
                # Try no namespaces first
                start_symtab, end_symtab = check_both_dirs(lambda offset, size: view.get_phys(paddr + offset, size), is_ptr_to_stringtable, match - view.pointer_size, 2 * view.pointer_size)
                start_symtab_ns, end_symtab_ns = check_both_dirs(lambda offset, size: view.get_phys(paddr + offset, size), is_ptr_to_stringtable, match - view.pointer_size, 3 * view.pointer_size)

                namespaces = False
                if end_symtab_ns - start_symtab_ns > end_symtab - start_symtab:
                    print(f"Assuming namespaces are present ({end_symtab_ns - start_symtab_ns} bytes > {end_symtab - start_symtab} bytes)")
                    start_symtab, end_symtab, namespaces = start_symtab_ns, end_symtab_ns, True

                if end_symtab - start_symtab < 0x20:
                    print(f"Withdrawn Ksymtab candidate 0x{start_symtab:x} - 0x{end_symtab:x}")
                else:
                    print(f"Ksymtab candidate 0x{start_symtab:x} - 0x{end_symtab:x}")
                    candidates.append((start_symtab + paddr, end_symtab + paddr, namespaces))

                match = match + 1

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
        def d_at(index):
            nonlocal paddr
            return view.get_phys(paddr + index, 1)
        p = 0
        while True:
            p = d.find(SYMBOL_NAME + b"\x00", p)
            if p == -1:
                break
            # Check backward
            i = 0
            while True:
                try:
                    if d_at(p-i) not in string.ascii_letters.encode() + b"_-\x00" + string.digits.encode() or (d_at(p-i-1) == 0 and d_at(p-i-2) == 0):
                        i -= 1
                        break
                except NotMapped:
                    break
                i += 1
            start = p-i
            # Check forward
            while True:
                try:
                    if d_at(p+i) not in string.ascii_letters.encode() + b"_-\x00" + string.digits.encode() or (d_at(p+i-1) == 0 and d_at(p+i) == 0):
                        i += 1
                        break
                except NotMapped:
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
    print(res)

    # Identify strings of strtab candidates
    candidates = []
    for n, i in enumerate(res):
        table_data = view.get_phys(i.start, i.end - i.start)
        print(f"Table #{n} - 0x{i.start:x} 0x{i.end - i.start:x}: {table_data[:100]}")
        table = StringTable(table_data)
        table.rebase(i.start)
        #table.dump("table-{}".format(n))
        for e in table.items():
            if SYMBOL_NAME in e[1]:
                candidates.append(table)
    """
    print("Phys Start of String Table: 0x{:x}".format(table[0][0]))
    print("Data:", view.get_phys(table[0][0], 0x10).hex())
    virts = list(view.phys_to_virt(table[0][0]))
    print("Virts:", ",".join([hex(i) for i in virts]))

    print("Locations where this pointer appears in memory")
    for paddr,paddr_end,d in view.iter_loads():
        print("Addr", paddr)
        for v in virts:
            p = 0
            while True:
                pos = d.find(struct.pack("<Q", v), p)
                if pos == -1:
                    break;
                print(pos)
                print(view.get_phys(pos + paddr, 0x20).hex())
                p = pos + 1

    import sys
    sys.exit(-1)"""

    # TODO: Handle the case when we find multiple string_tables
    for string_table in candidates:
        res = find_symtab(view, string_table)
        if res:
            symtab_start, symtab_end, namespaces = res
            break

    #hexdump.hexdump(get_physical_address(symtab_start, symtab_end - symtab_start))

    #symtab_start, symtab_end = 5136434696, 5136555112

    symtab = list(parse_symtab(view, view.get_phys(symtab_start, symtab_end - symtab_start), string_table, namespaces))
    print(symtab[:10])

    # Write results to file
    fout = open("{}-symtab".format(args.image) , "w")
    for addr, name in symtab:
        fout.write("{} {}\n".format(name.decode(), hex(addr)))
    fout.close()

    # Verify
    print(symtab[0][1])
    print(hexdump.hexdump(view.get_virt(symtab[0][0], 0x50)))

    ############
    # 2nd Step #
    ############

    for addr, name in (i for i in symtab if b"kallsyms" in i[1]):
        print(name)
        print(hex(addr))
        hexdump.hexdump(view.get_virt(addr,0x100))
