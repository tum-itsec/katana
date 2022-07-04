#!/usr/bin/env python3

from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile
import argparse
from capstone import *
import sys
import elfview
import hexdump
import itertools

def dump_regs(uc):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    lr = uc.reg_read(UC_ARM64_REG_LR)
    sp = uc.reg_read(UC_ARM64_REG_SP)
    print('pc : [<{:016x}>] lr : [<{:016x}>]'.format(pc, lr))
    print('sp: {:016x}'.format(sp))
    for rn in range(0, 30, 2):
        # this appears to be sane (?)
        left = uc.reg_read(UC_ARM64_REG_X0 + rn + 1)
        right = uc.reg_read(UC_ARM64_REG_X0 + rn)
        print('x{:<2d}: {:016x} x{:<2d}: {:016x}'.format(rn + 1, left, rn, right))

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
        dump_regs(uc)
        ins = uc.mem_read(pc, 16)
        print(ins.hex())
        ins = next(dis.disasm(ins,pc))
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

def code_hook(uc, address, size, user_data):
    ins = uc.mem_read(address, 4)
    ins = next(dis.disasm(ins,address))
    print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

SEEN = set()
def intr_hook(uc, exception_code, user_data):
    global SEEN
    if exception_code != 2:
        uc.emu_stop()
        return
    #print('\nHOOK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    #dump_regs(uc)
    name_ptr = uc.reg_read(UC_ARM64_REG_X1)
    fn_addr = uc.reg_read(UC_ARM64_REG_X3)
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
    print(name, hex(fn_addr))
    if (name, fn_addr) in SEEN:
        uc.emu_stop()
        return
    else:
        SEEN.add((name, fn_addr))
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
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    emu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    emu.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_page)
    emu.hook_add(UC_HOOK_INTR, intr_hook) # Because UC_ARM64_INS* don't exist, we need to hook like this
    #emu.hook_add(UC_HOOK_CODE, code_hook)

    # Setup stack
    stack_base = 0xffff7fffc0de0000
    emu.mem_map(stack_base, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
    emu.reg_write(UC_ARM64_REG_SP, stack_base + 0xf00)

    # Setup page for TLS/...
    emu.mem_map(0x0, 0x1000, UC_PROT_READ | UC_PROT_WRITE)

    # Setup callback & start
    emu.mem_map(0x300000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

    emu.mem_write(0x300000, bytes.fromhex('010000d4 00008052 c0035fd6')) # svc #0; mov w0, #0; ret
    emu.mem_write(0x300100, bytes.fromhex('60023fd6 000020d4')) # blr x19; brk #0

    emu.reg_write(UC_ARM64_REG_X0, 0x300000) # Target function
    emu.reg_write(UC_ARM64_REG_X1, 0) # Data argument

    # Map first code page
    fn_page = call_addr & ~0xfff
    emu.mem_map(fn_page, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    code = elf.get_virt(fn_page, 0x1000)
    for ins in dis.disasm(code[call_addr & 0xfff:], call_addr):
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

    hexdump.hexdump(code[call_addr - fn_page:])
    ins = emu.mem_read(0x300100, 16)
    for ins in dis.disasm(ins,0x300100):
        print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

    emu.mem_write(fn_page, code)
    emu.reg_write(UC_ARM64_REG_X19, call_addr)
    emu.emu_start(0x300100, 0x300108)
    print("pc", hex(emu.reg_read(UC_ARM64_REG_PC)))
