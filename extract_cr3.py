#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import sys
import struct
import ctypes
import binascii
import hexdump

#def hexdump(data):
#    for i in range(0, len(data), 16):
#        print("{:08x}: {}".format(i, binascii.hexlify(data[i:i+16]).decode())) 

def align_addr(addr, alignment):
    return (addr + alignment - 1) // alignment * alignment
    
class QemuCPUSegment(ctypes.Structure):
    _fields_ = [
        ("selector", ctypes.c_uint32),
        ("limit", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("pad", ctypes.c_uint32),
        ("base", ctypes.c_uint64),
    ]

    def __repr__(self):
        return " ".join("{}:{}".format(x[0], hex(getattr(self, x[0]))) for x in self._fields_)

class QemuCPUState(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("rax", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
        ("cs", QemuCPUSegment),
        ("ds", QemuCPUSegment),
        ("es", QemuCPUSegment),
        ("fs", QemuCPUSegment),
        ("gs", QemuCPUSegment),
        ("ss", QemuCPUSegment),
        ("ldt", QemuCPUSegment),
        ("tr", QemuCPUSegment),
        ("gdt", QemuCPUSegment),
        ("idt", QemuCPUSegment),
        ("cr0", ctypes.c_uint64),
        ("cr1", ctypes.c_uint64),
        ("cr2", ctypes.c_uint64),
        ("cr3", ctypes.c_uint64),
        ("cr4", ctypes.c_uint64),
    ]

class Elf64Note(ctypes.LittleEndianStructure):
    _fields_ = [
        ("n_namesz", ctypes.c_uint32),
        ("n_descsz", ctypes.c_uint32),
        ("n_type", ctypes.c_uint32),
    ]
    def __repr__(self):
        return " ".join("{}:{}".format(x[0], hex(getattr(self, x[0]))) for x in self._fields_)

def extract_cpu_states(elf_file):
    # Parse Notes
    # ... would have been easier with x.iter_notes() :-(
    try:
        x = next(x for x in elf_file.iter_segments() if x.header["p_type"] == "PT_NOTE")
    except StopIteration:
        return []
    d = x.data()
    i = 0

    cpu_states = []

    while i < len(d):
        note_header = Elf64Note.from_buffer_copy(d[i:])
        note_name = struct.unpack_from("{}s".format(note_header.n_namesz), d[i+ctypes.sizeof(Elf64Note):])[0]
        if note_name == b"QEMU\x00":
            d_start = align_addr(i + ctypes.sizeof(Elf64Note) + note_header.n_namesz, 4)
            d_end = d_start + note_header.n_descsz
            state = QemuCPUState.from_buffer_copy(d[d_start:d_end])
            cpu_states.append(state)
        # For some reason the notes are aligned to 0x4
        i += align_addr(note_header.n_descsz + note_header.n_namesz + ctypes.sizeof(Elf64Note), 4)
    return cpu_states

if __name__ == "__main__":
    e = ELFFile(open(sys.argv[1], "rb"))
    for cpu_no, state in enumerate(extract_cpu_states(e)):
        print("CPU No. {}".format(cpu_no))
        print("Version", hex(state.version))
        print("Size", hex(state.size))
        print("CR2", hex(state.cr2))
        print("CR3", hex(state.cr3))
        print("CR4", hex(state.cr4))
        print("gdt", state.gdt)
        print("cs", state.cs)
        print("ss", state.ss)
        print("fs", state.fs)
        print("gs", state.gs)
        print("ds", state.ds)
        print("es", state.es)
