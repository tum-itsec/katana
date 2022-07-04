import elfview
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from collections import deque

class LinuxEmulator():
    def __init__(self, elf):
        self.elf = elf
        if self.elf.cpu_arch == 'x86-64':
            self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
            self.dis = Cs(CS_ARCH_X86, CS_MODE_64)
        elif self.elf.cpu_arch == 'i386':
            self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
            self.dis = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.elf.cpu_arch == 'arm64':
            self.emu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
            self.dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        elif self.elf.cpu_arch == 'mips':
            self.emu = Uc(UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN)
            self.dis = Cs(CS_ARCH_MIPS, CS_MODE_BIG_ENDIAN)
        else:
            raise NotImplementedError(f'No support for this architecture ({view.cpu_arch})')

        self.emu.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped_page)

        # Setup stack and gs
        if self.elf.cpu_arch == 'x86-64':
            self.emu.mem_map(0x777700000, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
            self.emu.reg_write(UC_X86_REG_RSP, 0x777700f00)
            self.emu.mem_map(0x0, 0x30000, UC_PROT_READ | UC_PROT_WRITE) # gs
        elif self.elf.cpu_arch == 'i386':
            self.emu.mem_map(0x77770000, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
            self.emu.reg_write(UC_X86_REG_ESP, 0x77770f00)
            self.emu.mem_map(0x0, 0x30000, UC_PROT_READ | UC_PROT_WRITE) # fs, on 32-bit

        self.last_instructions = deque(maxlen=10)
        self.stack = []
        self.in_spinlock = False

        # Allow for patching of functions
        self.patched_pages = set()
        self.patches = []

    def _hook_code(self, uc, address, size, user_data):
        ins = uc.mem_read(address, 16)
        disasm = self.dis.disasm(ins,address)
        ins = next(disasm)

        if self.trace:
            print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

        self.last_instructions.append(ins)
        if ins.mnemonic == "call":
            self.stack.append((ins.address, ins.op_str))
            if ins.op_str == "0xffffffff86d45260":
                ins_next = next(disasm)
                uc.reg_write(UC_X86_REG_RIP, ins_next.address)
        if ins.mnemonic == "ret":
            self.stack.pop()
        if self.break_spinlocks:
            if ins.mnemonic == "pause":
                if len(set(x.address for x in self.last_instructions)) < 5:
                    self.in_spinlock = True
                    print("Spinlock detected!")
            if self.in_spinlock and ins.mnemonic in ["jne", "je"]:
                print("Stack:")
                for s in self.stack:
                    print(hex(s[0]), s[1])

                import os
                os._exit(-1)
                ins_next = next(disasm)
                uc.reg_write(UC_X86_REG_RIP, ins_next.address)


    def _unmapped_page(self, uc, access, address, size, value, user_data):
        page_addr = address & ~0xfff
        try:
            data = self.elf.get_virt(page_addr, 0x1000)
            uc.mem_map(page_addr, 0x1000, UC_PROT_READ | UC_PROT_EXEC | UC_PROT_WRITE)
            uc.mem_write(page_addr, data)

            if page_addr in self.patched_pages:
                for addr, patch in self.patches:
                    if page_addr < addr < page_addr + 0x1000:
                        uc.mem_write(addr, patch)
                print("Handled Page fault {hex(address)} (patched page)")
            else:
                print("Handled Page fault {hex(address)} (unpatched page)")
            return True
        except elfview.NotMapped as e:
            print(e)
            print("Unhandled Page fault, accessing page 0x{:x} (addr 0x{:x})".format(page_addr, address))
            print("Access", access)
            if self.elf.cpu_arch == 'x86-64':
                rip = uc.reg_read(UC_X86_REG_RIP)
                print("RIP:", hex(rip))
                print("RAX:", hex(uc.reg_read(UC_X86_REG_RAX)))
                print("RDI:", hex(uc.reg_read(UC_X86_REG_RDI)))
                print("RSI:", hex(uc.reg_read(UC_X86_REG_RSI)))
                print("RSP:", hex(uc.reg_read(UC_X86_REG_RSP)))
                print("RBP:", hex(uc.reg_read(UC_X86_REG_RBP)))
                print("R8: ", hex(uc.reg_read(UC_X86_REG_R8)))
                print("R9: ", hex(uc.reg_read(UC_X86_REG_R9)))
                print("R10:", hex(uc.reg_read(UC_X86_REG_R10)))
                print("R11:", hex(uc.reg_read(UC_X86_REG_R11)))
                print("R12:", hex(uc.reg_read(UC_X86_REG_R12)))
                print("R13:", hex(uc.reg_read(UC_X86_REG_R13)))
                print("R14:", hex(uc.reg_read(UC_X86_REG_R14)))
                ins = uc.mem_read(rip, 16)
                print(ins.hex())
                ins = next(self.dis.disasm(ins,rip))
                print("{:08x}: {}\t{}".format(ins.address, ins.mnemonic, ins.op_str))

    def patch_addr(self, addr, data):
        self.patched_pages.add(addr & ~0xfff)
        self.patches.append((addr, data))

    def call(self, addr, stub_addr = 0x300000, trace = False, break_spinlocks = False):
        # TODO: argument setup
        try:
            self.emu.mem_unmap(stub_addr, 0x1000)
        except unicorn.UcError:
            pass

        self.trace = trace
        self.break_spinlocks = break_spinlocks
        if trace or break_spinlocks:
            self.emu.hook_add(UC_HOOK_CODE, self._hook_code)

        self.emu.mem_map(stub_addr, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        if self.elf.cpu_arch == 'x86-64':
            self.emu.mem_write(stub_addr, b"\xff\xd0\xf4") # call rax; hlt
            self.emu.reg_write(UC_X86_REG_RAX, addr)
            stub_end = stub_addr + 2
        elif self.elf.cpu_arch == 'i386':
            self.emu.mem_write(stub_addr, b"\xff\xd5\xf4") # call ebp; hlt
            # don't use eax here, that's sometimes used for arguments!
            self.emu.reg_write(UC_X86_REG_EBP, addr)
            stub_end = stub_addr + 2
        else:
            raise NotImplementedError('Missing architecture in LinuxEmulator.call, please complete stub')
        self.run(stub_addr, stub_end)

    def run(self, *args, **kwargs):
        self.emu.emu_start(*args, **kwargs)

