#!/usr/bin/python3 -u

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

def code_hook(uc, address, size, user_data):
    ins = uc.mem_read(address, 16)
    ins = next(dis.disasm(ins,address))
    if ins.mnemonic == "call" or ins.mnemonic == "jmp":
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))
    else:
        pass
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

def on_block(uc, address, size, user_data):
    #print("Block: {:x} Size {:x}".format(address, size))
    ftrace.write("{:x}\n".format(address))

def on_syscall(*args):
    print("Syscall!")
    #print(emu.reg_read(UC_X86_REG_RDI))
    rsi = emu.emu.reg_read(UC_X86_REG_RSI)
    print(hex(rsi))
    try:
        rsi_mem = emu.emu.mem_read(rsi,0x40)
    except UcError:
        base = rsi & ~0xfff
        offset = rsi & 0xfff

        print("Base", hex(base))
        buf = elf.get_virt(base, 0x1000)

        try:
            if offset + 0x40 > 0x1000:
                print("Base", hex(base + 0x1000))
                buf += elf.get_virt(base + 0x1000, 0x1000)
            rsi_mem = buf[offset:offset + 0x40]
        except elfview.NotMapped:
            rsi_mem = buf[offset:]

    name = bytes(itertools.takewhile(lambda x: x != 0, rsi_mem))
    rcx = emu.emu.reg_read(UC_X86_REG_RCX)
    print(name, hex(rcx))
    fout.write("{} {}\n".format(name.decode(), hex(rcx)))

    # For some reason the function checks our return code
    emu.emu.reg_write(UC_X86_REG_RAX, 0x0)
    #print(hex(rcx))
    symbols.append((rsi_mem, rcx))

def on_call(*args):
    print("Call!")
    print(args)

def find_kallsyms_on_each_symbol(elf):
    emu = LinuxEmulator(elf)
    # Write struct somewhere
    emu.emu.mem_map(0x1337000, 0x1000, UC_PROT_READ | UC_PROT_EXEC | UC_PROT_WRITE)
    emu.emu.mem_write(0x1337000, b"kallsyms_on_each_symbol")
    emu.emu.mem_write(0x1337020, b"\x00"*48 + struct.pack("<Q", 0x1337000))

    # Set first param to kprobes struct
    emu.emu.reg_write(UC_X86_REG_RDI, 0x1337020)

    # Call register_kprobe
    call_addr = elf.lookup_symbol("register_kprobe")
    try:
        emu.call(call_addr)
    except:
        pass
    data = emu.emu.mem_read(0x1337020, 0x100)
    hexdump.hexdump(data)
    return struct.unpack("<Q", data[40:48])[0]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("-t", "--trace", help="Output instruction trace", action="store_true")
    parser.add_argument("-s", "--spinlock-detect", help="Trace instructions and stop on a spinlock", action="store_true")

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
    
    if cfi_addr := elf.lookup_symbol("__cfi_slowpath"):
        print("Kernel with __cfi_slowpath -> disable that function")
        emu.patch_addr(cfi_addr, bytes.fromhex("c3")) # Somehow CFI fucks with our emulation. Just return if it occurs
        
    emu.emu.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    # Setup callback
    emu.emu.mem_map(0x301000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    emu.emu.mem_write(0x301000, b"\x0f\x05\xc3") # syscall; ret
    emu.emu.reg_write(UC_X86_REG_RDI, 0x301000)
    emu.call(call_addr, trace = args.trace, break_spinlocks = args.spinlock_detect)
    print("RIP", hex(emu.emu.reg_read(UC_X86_REG_RIP)))
