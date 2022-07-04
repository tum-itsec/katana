import ctypes
import io
from enum import Enum

ET_NONE   = 0x0
ET_REL    = 0x1
ET_EXEC   = 0x2
ET_DYN    = 0x3
ET_CORE   = 0x4
ET_LOOS   = 0xfe00
ET_HIOS   = 0xfeff
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

PT_NULL     = 0x0
PT_LOAD     = 0x1
PT_DYNAMIC  = 0x2
PT_INTERP   = 0x3
PT_NOTE     = 0x4
PT_SHLIB    = 0x5

PF_R        = 0x4
PF_W        = 0x2
PF_X        = 0x1

REG_R8  = 0x5
REG_R9  = 0x4
REG_R10 = 0x3
REG_R11 = 0x2
REG_R12 = 0
REG_R13 = 0
REG_R14 = 0
REG_R15 = 0
REG_RDI = 0xa
REG_RSI = 0x9
REG_RBP = 0x0
REG_RBX = 0x1
REG_RDX = 0x8
REG_RAX = 0x6
REG_RCX = 0x7
REG_RSP = 0xf
REG_RIP = 0xc
REG_EFL = 17
REG_CSGSFS = 18
REG_ERR = 19
REG_TRAPNO = 20
REG_OLDMASK = 21
REG_CR2 = 22

NT_PRSTATUS = 1

# Only valid for x86-64
N_GREG = 23

class ELFSigInfo(ctypes.LittleEndianStructure):
    _fields_ = [
        ("si_signo", ctypes.c_int32),
        ("si_code", ctypes.c_int32),
        ("si_errno", ctypes.c_int32),
    ]

class ELFPRStatus(ctypes.LittleEndianStructure):
    _fields_ = [
        ("pr_info", ELFSigInfo),
        ("pr_cursig", ctypes.c_int16),
        ("pr_sigpend", ctypes.c_int32),
        ("pr_sighold", ctypes.c_int32),
        ("pr_pid", ctypes.c_int32),
        ("pr_ppid", ctypes.c_int32),
        ("pr_pgrp", ctypes.c_int32),
        ("pr_sid", ctypes.c_int32),
        ("pr_utime", ctypes.c_char*16),
        ("pr_stime", ctypes.c_char*16),
        ("pr_cutime", ctypes.c_char*16),
        ("pr_cstime", ctypes.c_char*16),
        ("pr_reg", ctypes.c_uint64*N_GREG),
        ("pr_fpvalid", ctypes.c_int32),
    ]

class ELFNote(ctypes.LittleEndianStructure):
    _fields_ = [
        ("n_namesz", ctypes.c_uint32),
        ("n_descsz", ctypes.c_uint32),
        ("n_type", ctypes.c_uint32),
    ]

class ELFPhdr(ctypes.LittleEndianStructure):
    _fields_ = [
            ("p_type", ctypes.c_uint32),
            ("p_flags", ctypes.c_uint32),
            ("p_offset", ctypes.c_uint64),
            ("p_vaddr", ctypes.c_uint64),
            ("p_paddr", ctypes.c_uint64),
            ("p_filesz", ctypes.c_uint64),
            ("p_memsz", ctypes.c_uint64),
            ("p_align", ctypes.c_uint64),
    ]

def align_addr(addr, alignment):
    return ((addr+alignment-1) // alignment) * alignment

class ELFCore(ctypes.LittleEndianStructure):
    _fields_ = [
        ("ident", ctypes.c_char * 16),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint64),
        ("e_phoff", ctypes.c_uint64),
        ("e_shoff", ctypes.c_uint64),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]

    def __init__(self):
        self.ident = bytes.fromhex("7f45 4c46 0201 0100 0000 0000 0000 0000")
        self.e_type = ET_CORE
        self.e_machine = 0x3e # x86-64
        self.e_version = 0x01# x86-64
        self.e_ehsize = ctypes.sizeof(ELFCore)
        self.e_phentsize = ctypes.sizeof(ELFPhdr)
        self.headers = []

    def add_load_segment(self, vaddr, flags, data, paddr = 0, *, may_reuse_other_by_paddr = False):
        phdr = ELFPhdr()
        phdr.p_type = PT_LOAD
        phdr.p_vaddr = vaddr
        phdr.p_paddr = paddr
        phdr.p_flags = flags
        phdr.p_align = 0x1
        self.headers.append((phdr, data, may_reuse_other_by_paddr))

    def add_note(self, name, desc_sz, note_type, data):
        assert isinstance(name, bytes) and name[-1] == 0, "Name must be a null-terminated byte string"
        phdr = ELFPhdr()
        phdr.p_type = PT_NOTE
        phdr.p_flags = PF_R
        phdr.p_align = 0x1

        buf = io.BytesIO()
        n = ELFNote()
        n.n_namesz = len(name)
        n.n_descsz = desc_sz
        n.n_type = note_type
        buf.write(n)
        buf.write(name)
        buf.write(b"\x00" * (align_addr(n.n_namesz, 0x4) - n.n_namesz))
        buf.write(data)
        buf.write(b"\x00" * (align_addr(n.n_descsz, 0x4) - n.n_descsz))
        d = bytes(buf.getbuffer())

        self.headers.insert(0, (phdr, d, False)) # Store notes at the front so we always have access to them

    def set_registers(self, rip, rsp, rbp):
        stat = ELFPRStatus()
        stat.pr_reg[REG_RIP] = rip
        stat.pr_reg[REG_RSP] = rsp
        stat.pr_reg[REG_RBP] = rbp
        #for i in range(N_GREG):
        #    stat.pr_reg[i] = i
        self.add_note(b"CORE\x00", ctypes.sizeof(ELFPRStatus), NT_PRSTATUS, stat)

    def _write_headers(self, f):
        data_offset = ctypes.sizeof(self) + len(self.headers) * self.e_phentsize
        offset_cache = {}
        did_reuse = []
        # Align if necessary
        data_offset = align_addr(data_offset, 0x10)
        for h,m,may_reuse_other in self.headers:
            if may_reuse_other and h.p_paddr in offset_cache:
                offset, size = offset_cache[h.p_paddr]
                if size >= len(m):
                    h.p_offset = offset
                    h.p_filesz = len(m)
                    h.p_memsz = len(m) if h.p_type == PT_LOAD else 0
                    f.write(h)
                    did_reuse.append(True)
                    continue
            h.p_offset = data_offset
            h.p_filesz = len(m)
            h.p_memsz = len(m) if h.p_type == PT_LOAD else 0
            f.write(h)
            offset_cache[h.p_paddr] = (data_offset, len(m))
            did_reuse.append(False)
            data_offset = align_addr(data_offset + len(m), 0x10)
        return did_reuse

    def write(self, f):
        if len(self.headers) >= 0xFFFF:
            # Store excess headers in a note.
            note = io.BytesIO()
            self._write_headers(note)
            self.add_note(b"ELF_TOO_MANY_PHDRS\x00", len(self.headers) * self.e_phentsize, 0xff, note.getbuffer())

        self.e_phoff = ctypes.sizeof(self)
        self.e_phnum = len(self.headers)
        f.write(self)

        did_reuse = self._write_headers(f)
        for reused, (h,m,_) in zip(did_reuse, self.headers):
            if not reused:
                f.seek(h.p_offset)
                f.write(m)

if __name__ == "__main__":
    core = ELFCore()
    core.set_registers(0x1000, 0x13371337, 0x13381338)
    core.add_load_segment(0x1000, PF_R | PF_W, b"das ist ein Test" + b"\x00" * 100)

    t = open("out.core", "wb")
    core.write(t)
