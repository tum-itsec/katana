import collections
import bisect

PageEntry = collections.namedtuple("PageEntry", ["virt", "phys", "size", "user_mode", "rw", "nx"])

def walk_level(idx, phys_addr, level, upper_nx, upper_write):
    page_mapping = []
    mem = get_physical_memory(phys_addr, 0x1000) # 2**9 * 8
    found = False
    for i, off in enumerate(range(0,len(mem),8)):
        entry = int.from_bytes(mem[off:off+8], byteorder="little")
        present = entry & 0x1
        if present:
            found = True
            #print(binascii.hexlify(mem[i:i+4]))
            read_write = entry >> 1 & 1
            user_mode = entry >> 2 & 1
            nx = entry >> 63 & 1
            
            nphys_addr = ((entry & (2**52 - 1)) >> 12) << 12
            if level == 0:
                virt = (idx << 9 | i) << 12
                if virt >> 47 & 1:
                    virt |= 0xffff000000000000
                #if user_mode == 0:
                    #import pdb;
                    #pdb.set_trace()
                page_mapping.append(PageEntry(virt, nphys_addr, 0x1000, user_mode, read_write & upper_write, nx | upper_nx))
            else:
                page_size = entry >> 7 & 1
                if page_size == 1 and level != 3:
                    #print("Aborting {}", phys_addr + i)
                    virt = ((idx << 9 | i) << 9*level) << 12
                    if virt >> 47 & 1:
                        virt |= 0xffff000000000000
                    page_mapping.append(PageEntry(virt, nphys_addr, 0x1000 << (9*level), user_mode, read_write & upper_write, nx | upper_nx))
                else:
                    #print(f"[L={level}] New entry {nphys_addr:x}")
                    page_mapping.extend(walk_level(idx << 9 | i, nphys_addr, level - 1, nx | upper_nx, read_write & upper_write))
            #print(f"     * phys_addr: {phys_addr} (RW: {read_write} User: {user_mode} NX: {nx})")
    #if not found:
        #print(f"[L={level}] Empty entry")

    return page_mapping

def do_4level_paging(cr3, get_physical_memory_func):
    global get_physical_memory
    get_physical_memory = get_physical_memory_func
    return walk_level(0, cr3, 3, False, True)

def merge_pages(mapping, only_virtual=False):
    if only_virtual:
        c = lambda a,b: all((a.virt + a.size == b.virt,
                             a.user_mode == b.user_mode,
                             a.rw == b.rw,
                             a.nx == b.nx))
    else:
        c = lambda a,b: all((a.virt + a.size == b.virt,
                             a.phys + a.size == b.phys,
                             a.user_mode == b.user_mode,
                             a.rw == b.rw,
                             a.nx == b.nx))
    return _merge_pages(mapping, c)

def _merge_pages(mapping, merge_condition):
    mapping = list(mapping)
    
    i = 0
    while i < (len(mapping) - 1):
        a, b = mapping[i], mapping[i+1]
        if merge_condition(a, b):
            mapping[i] = PageEntry(a.virt, a.phys, a.size + b.size, a.user_mode, a.rw, a.nx)
            del mapping[i+1]
        else:
            i += 1
    return sorted(mapping, key=lambda x: x.virt)

