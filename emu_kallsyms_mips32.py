#!/usr/bin/env python3

from unicorn import *
from unicorn.mips_const import *
from elftools.elf.elffile import ELFFile
import argparse
from capstone import *
import sys
import elfview
import hexdump
import itertools
import struct

def unmapped_page(uc, access, address, size, value, user_data):
    page_addr = address & ~0xfff
    try:
        data = elf.get_virt(page_addr, 0x1000)
        uc.mem_map(page_addr, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        uc.mem_write(page_addr, data)
        print('Handled page fault at address {:#10x}'.format(address))
        return True
    except elfview.NotMapped as e:
        print(e)
        print("Unhandled page fault, accessing page {:#10x} (address {:#10x})".format(page_addr, address))
        print("Access", access)
        pc = uc.reg_read(UC_MIPS_REG_PC)
        print("$pc:", '{:08x}'.format(pc))
        registers = [uc.reg_read(reg) for reg in range(32)]
        for i in range(0, len(registers), 4):
            print('${:02d}:'.format(i), ' '.join('{:08x}'.format(v) for v in registers[i:i+4]))
        print('$hi: {:08x}'.format(uc.reg_read(UC_MIPS_REG_HI)))
        print('$lo: {:08x}'.format(uc.reg_read(UC_MIPS_REG_LO)))
        print('$fp: {:08x}'.format(uc.reg_read(UC_MIPS_REG_FP)))
        print('$ra: {:08x}'.format(uc.reg_read(UC_MIPS_REG_RA)))
        ins = uc.mem_read(pc, 16)
        print(ins.hex())
        ins = next(dis.disasm(ins,pc))
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

def code_hook(uc, address, size, user_data):
    ins = uc.mem_read(address, 4)
    ins = next(dis.disasm(ins,address))
    print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

def intr_hook(uc, exception_code, user_data):
    #address = uc.reg_read(UC_MIPS_REG_PC)
    #ins = uc.mem_read(address, 4)
    #ins = next(dis.disasm(ins, address))
    #if ins.mnemonic == 'break' and ins.op_str == '': # break 0
    if exception_code != 17:
        uc.emu_stop()
        return
    name_ptr = uc.reg_read(UC_MIPS_REG_A1)
    fn_addr = uc.reg_read(UC_MIPS_REG_A3)
    try:
        name = emu.mem_read(name_ptr, 0x40)
    except UcError:
        base = name_ptr & ~0xfff
        offset = name_ptr & 0xfff
        buf = elf.get_virt(base, 0x1000)
        try:
            if offset + 0x40 > 0x1000:
                buf += elf.get_virt(base + 0x1000, 0x1000)
            name = buf[offset:offset + 0x40]
        except elfview.NotMapped:
            name = buf[offset:]
    name = bytes(itertools.takewhile(lambda x: x != 0, name))
    fout.write('{} {}\n'.format(name.decode(), hex(fn_addr)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--address", type=lambda v: int(v, 0))
    args = parser.parse_args()
    elf = elfview.autoselect(args.image)

    fout = open("{}-kallsym".format(args.image), "w")

    # Get address of kallsyms_on_each_symbol
    if args.address:
        call_addr = args.address
        print('Overriding address of kallsyms_on_each_symbol')
    else:
        call_addr = elf.lookup_symbol("kallsyms_on_each_symbol")
        print("Address of kallsyms_on_each_symbol 0x{:x}".format(call_addr))

    # Setup emulator and hooks
    mipsel = elf.byte_order == "<"
    cs_endian = CS_MODE_LITTLE_ENDIAN if mipsel else CS_MODE_BIG_ENDIAN
    uc_endian = UC_MODE_LITTLE_ENDIAN if mipsel else UC_MODE_BIG_ENDIAN
    dis = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | cs_endian)
    emu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | uc_endian)
    emu.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_page)
    emu.hook_add(UC_HOOK_INTR, intr_hook) # Because UC_MIPS_INS* don't exist, we need to hook like this
    # emu.hook_add(UC_HOOK_CODE, code_hook)

    # Setup stack
    emu.mem_map(0x77770000, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
    emu.reg_write(UC_MIPS_REG_SP, 0x77770f00)

    # Setup page for gp
    emu.mem_map(0x0, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    emu.reg_write(UC_MIPS_REG_GP, 0x0)

    # Setup callback & start. Note code is affected by byte order :/
    emu.mem_map(0x300000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

    callback = struct.pack(elf.byte_order + '3I', 0x0000000c, 0x3c020000, 0x03e00008)
    trampoline = struct.pack(elf.byte_order + '3I', 0x0200f809, 0x00000000, 0x0000000d)
    emu.mem_write(0x300000, callback) # syscall; lui $v0, 0 /* return 0 to continue */; jr $ra
    emu.mem_write(0x300100, trampoline) # jalr $s0; nop; break;

    emu.reg_write(UC_MIPS_REG_A0, 0x300000) # Target function
    emu.reg_write(UC_MIPS_REG_A1, 0) # Data argument

    # Map first code page
    fn_page = call_addr & ~0xfff
    emu.mem_map(fn_page, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    code = elf.get_virt(fn_page, 0x1000)

    hexdump.hexdump(code[call_addr - fn_page:])
    ins = emu.mem_read(0x300100, 16)
    for ins in dis.disasm(ins,0x300100):
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

    emu.mem_write(fn_page, code)
    emu.reg_write(UC_MIPS_REG_S0, call_addr)
    emu.emu_start(0x300100, 0x300108)
    print("pc", hex(emu.reg_read(UC_MIPS_REG_PC)))
