#!/usr/bin/env python3

from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
import argparse
from capstone import *
import sys
import elfview
import hexdump
import itertools
import struct
from linux_emulator import LinuxEmulator

# Mind: Kernel is compiled with -mregparm=3, so args are in EAX, EDX, ECX, and only then on the stack.

def on_symbol(*args):
    # fn(data, name, module, addr)
    esp = emu.emu.reg_read(UC_X86_REG_ESP)
    name_addr = emu.emu.reg_read(UC_X86_REG_EDX)
    try:
        name_mem = emu.emu.mem_read(name_addr,0x40)
    except UcError:
        base = name_addr & ~0xfff
        offset = name_addr & 0xfff

        print("Base", hex(base))
        buf = elf.get_virt(base, 0x1000)

        try:
            if offset + 0x40 > 0x1000:
                print("Base", hex(base + 0x1000))
                buf += elf.get_virt(base + 0x1000, 0x1000)
            name_mem = buf[offset:offset + 0x40]
        except elfview.NotMapped:
            name_mem = buf[offset:]

    name = bytes(itertools.takewhile(lambda x: x != 0, name_mem))
    addr = struct.unpack('<I', emu.emu.mem_read(esp + 4, 4))[0]
    print(name, hex(addr))
    fout.write("{} {}\n".format(name.decode(), hex(addr)))

    # For some reason the function checks our return code
    emu.emu.reg_write(UC_X86_REG_EAX, 0x0)
    symbols.append((name_mem, addr))

def find_kallsyms_on_each_symbol(elf):
    raise NotImplementedError('register_kprobe heuristic not implemented for i386 target')

INDENT = 0
def code_hook(uc, address, size, user_data):
    global INDENT
    ins = uc.mem_read(address, 17)
    ins = next(emu.dis.disasm(ins,address))
    print("{}{:08x}: {}\t{}".format('  ' * INDENT, ins.address, ins.mnemonic, ins.op_str))
    print("{}          eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x} edi={:#010x} esi={:#010x} esp={:#010x} ebp={:#010x}".format('  ' * INDENT, uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EBX), uc.reg_read(UC_X86_REG_ECX), uc.reg_read(UC_X86_REG_EDX), uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_ESI), uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP)))
    if ins.mnemonic == 'call':
        INDENT += 1
    elif ins.mnemonic == 'ret':
        INDENT -= 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    #parser.add_argument("call_addr")

    args = parser.parse_args()

    fout = open("{}-kallsym".format(args.image), "w")
    #ftrace = open("deb_bb-trace.txt", "w")
    #fpage = open("deb_pages.txt", "w")

    # Get addr of kallsym_each_symbol
    elf = elfview.autoselect(args.image)
    call_addr = None
    call_addr = elf.lookup_symbol("kallsyms_on_each_symbol")
    if call_addr is None:
        print("No kallsyms found! Using register_kprobes heuristic to find it!")
        call_addr = find_kallsyms_on_each_symbol(elf)
        print("Recovered kallsyms_on_each_symbol at: 0x{:x}".format(call_addr))
    else:
        print("Address of kallsyms_on_each_symbol 0x{:x}".format(call_addr))


    # Debugging - dump page mapping
    #for i in elf.mapping:
    #    fpage.write("{:x} - {:x} -> {:x}\n".format(i.virt, i.virt + i.size, i.phys))

    # Setup lists
    symbols = []

    emu = LinuxEmulator(elf)
    emu.emu.hook_add(UC_HOOK_INSN, on_symbol, None, 1, 0, UC_X86_INS_OUT)
    #emu.emu.hook_add(UC_HOOK_CODE, code_hook)

    # Setup callback
    emu.emu.mem_map(0x301000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    emu.emu.mem_write(0x301000, b"\xee\xc3") # out dx, al; ret
    emu.emu.reg_write(UC_X86_REG_EAX, 0x301000)
    emu.call(call_addr)
    print("EIP", hex(emu.emu.reg_read(UC_X86_REG_EIP)))
