#!/usr/bin/env python3

from common import *
from linux_emulator import *

import base64
import collections
import enum
import re
import textwrap

VERBOSE = False # More debug information

class Version(enum.Enum):
    AUTODETECT = -1
    V3_0_OR_EARLIER = 0
    V3_1_TO_3_9 = 1
    V3_10_TO_3_12 = 2
    V3_13_TO_3_17 = 3
    V3_18_OR_LATER = 4

VERSION_MAP = {
    '2.6-3.0':   Version.V3_0_OR_EARLIER,
    '3.1-3.9':   Version.V3_1_TO_3_9,
    '3.10-3.12': Version.V3_10_TO_3_12,
    '3.13-3.17': Version.V3_13_TO_3_17,
    '3.18+':     Version.V3_18_OR_LATER,
}

def identify_version(layout, view):
    # See extract_kernel_version.py
    banner_addr = view.lookup_symbol('linux_banner') or view.lookup_symbol('init_uts_namespace')
    if not banner_addr:
        raise ValueError('Failed to identify kernel version, use --version to override')
    banner = string(banner_addr, view)
    match = re.search(br'Linux version (\d+)\.(\d+)', banner, re.IGNORECASE)
    if not match:
        raise ValueError(f'Failed to identify kernel version from version string "{banner.decode()}", use --version to override')
    major, minor = [int(number) for number in match.groups()]
    if VERBOSE:
        print(f'Kernel version is {major}.{minor}')
    if major > 3 or major == 3 and minor >= 18:
        return Version.V3_18_OR_LATER
    elif major == 3 and 13 <= minor <= 17:
        return Version.V3_13_TO_3_17
    elif major == 3 and 10 <= minor <= 12:
        return Version.V3_10_TO_3_12
    elif major == 3 and 1 <= minor <= 9:
        return Version.V3_1_TO_3_9
    elif major < 3 or major == 3 and minor <= 1:
        return Version.V3_0_OR_EARLIER
    else:
        raise ValueError(f'Unknown kernel version {major}.{minor}, use --version to override')


class Allocator(enum.Enum):
    AUTODETECT = -1
    SLAB = 0
    SLUB = 1
    SLOB = 2

ALLOCATOR_MAP = {
    'SLAB': Allocator.SLAB,
    'SLUB': Allocator.SLUB,
    'SLOB': Allocator.SLOB
}

def identify_allocator(layout, view):
    if view.lookup_symbol('slub_nomerge') or \
       view.lookup_symbol('__setup_slub_nomerge') or \
       view.lookup_symbol('slub_debug_enabled'): # last requires CONFIG_SLUB_DEBUG
        return Allocator.SLUB
    if not view.lookup_symbol('create_kmalloc_caches'):
        return Allocator.SLOB
    return Allocator.SLAB


class page_to_address_emulator:
    # We don't always have s_mem to point to the first object here, so we need to find the
    # page mapping some other way.
    # Unfortunately, page_to_virt/phys are macros and the logic depends a lot on what system
    # you are on, and page_address is usally not a symbol either.
    # Volatility's logic sometimes just assumes we are using x86-64 without ASLR or 5-level paging,
    # so that is not exactly our first choice either.
    # We instead emulate a call to set_bh_page, which works except if the page is in highmem.
    def __init__(self, view):
        self.view = view
        self.target = view.lookup_symbol('set_bh_page')
        if not self.target:
            raise SymbolNotFound('set_bh_page is required to map SLUB pages to virtual addresses')
        self.emu = LinuxEmulator(self.view)
        self.result_addr = 0x400000
        self.emu.emu.mem_map(self.result_addr, 0x1000, UC_PROT_WRITE | UC_PROT_READ)

    def translate(self, page):
        if self.view.cpu_arch != 'x86-64':
            raise NotImplementedError('Missing arguments setup for emu.call')
        self.emu.emu.reg_write(UC_X86_REG_RDI, self.result_addr)
        self.emu.emu.reg_write(UC_X86_REG_RSI, page)
        self.emu.emu.reg_write(UC_X86_REG_RDX, 0)
        self.emu.call(self.target)
        # Sets bh->b_page to the page, and bh->b_data to the address.
        memory = self.emu.emu.mem_read(self.result_addr, 0x1000)
        self.emu.emu.mem_write(self.result_addr, b'\0' * 0x1000)
        pointers = []
        for index in range(0, len(memory), self.view.pointer_size):
            base = memory[index:index + self.view.pointer_size]
            pointer = decode_pointer(base, view)
            if pointer and pointer != page:
                pointers.append(pointer)
        assert len(pointers) == 1, 'Page mapping could not be resolved'
        return pointers[0]


def find_cache_by_name(name, layout, view, known_caches = ['names_cachep', 'kmem_cache']):
    kmem_cache_list_off = require(layout['kmem_cache']['list'], expr='kmem_cache->list') # Exists in all allocator types
    kmem_cache_name_off = require(layout['kmem_cache']['name'], expr='kmem_cache->name')
    list_next_off = require(layout['list_head']['next'], expr='list_head->next')
    print(f'    kmem_cache->list: {kmem_cache_list_off:#04x}')
    print(f'    kmem_cache->name: {kmem_cache_name_off:#04x}')
    print(f'    list_head->next:  {list_next_off:#04x}')
    candidates = set()
    for known in known_caches:
        if isinstance(known, str):
            any_cache_ptr = view.lookup_symbol(known)
            if any_cache_ptr is None:
                continue
            any_cache = pointer(any_cache_ptr, view)
            print(f'Found {known} at {any_cache:#x}')
        elif isinstance(known, int):
            any_cache = known
        else:
            raise TypeError('Unknown type for known cache')
        cache = any_cache
        while True:
            name = pointer(cache + kmem_cache_name_off, view)
            try:
                if name and string(name, view) == name:
                    candidates.add(cache)
            except NotMapped:
                pass # Name not mapped, don't care, it's not the one we want anyways
            cache = pointer(cache + kmem_cache_list_off + list_next_off, view) - kmem_cache_list_off
            if cache == any_cache:
                break
        break
    else:
        raise ValueError('Did not find any of the known caches')
    return candidates

def walk_kmem_cache(cache, layout, view, kernel_version = Version.AUTODETECT, allocator = Allocator.AUTODETECT, walk_free = False, print_output = True):
    nr_node_ids = view.lookup_symbol('nr_node_ids')
    if not nr_node_ids:
        nodes = 1
        if print_output:
            print(f'nr_node_ids not found - assuming one node; this is not a NUMA system')
    else:
        nodes = u32(nr_node_ids, view)
        if print_output:
            print(f'Found {nodes} node(s) via nr_node_ids')

    if kernel_version == Version.AUTODETECT:
        kernel_version = identify_version(layout, view)
        print('Identified version as', kernel_version.name)

    if allocator == Allocator.AUTODETECT:
        allocator = identify_allocator(layout, view)
        print('Identified allocator as', allocator.name)

    # v3.18+:      kmem_cache_node *node[MAX_NUMNODES]
    # v3.10-v3.17: kmem_cache_node **node
    # v3.1-v3.9:   kmem_list3 **nodelists
    # -v3.0:       kmem_list3 *nodelists[MAX_NUMNODES]
    is_array = kernel_version in (Version.V3_0_OR_EARLIER, Version.V3_18_OR_LATER)
    is_nodelist = kernel_version in (Version.V3_0_OR_EARLIER, Version.V3_1_TO_3_9)

    if is_nodelist:
        member_name = 'nodelist'
        node_type = 'kmem_list3'
    else:
        member_name = 'node'
        node_type = 'kmem_cache_node'

    # Shared members used by all allocators (see mm/slab.h)
    # SLOB seems to not have nodelist/node, so that's why that's below.

    # buffer_size exists until v3.5, then they renamed it to size...
    # This doesn't change any logic though, so no new version flag.
    size_offset = require(layout['kmem_cache']['buffer_size'], layout['kmem_cache']['size'], expr='kmem_cache->size')
    nodes_offset = require(layout['kmem_cache'][member_name], expr=f'kmem_cache->{member_name}')
    list_next_offset = require(layout['list_head']['next'], expr='list_head->next')

    object_size = u32(cache + size_offset, view)

    if allocator == Allocator.SLAB:
        # struct slab exists until v3.12, then it is merged with struct page...
        is_struct_slab = kernel_version in (Version.V3_0_OR_EARLIER, Version.V3_1_TO_3_9, Version.V3_10_TO_3_12)
        if is_struct_slab:
            slab_struct = 'slab'
            list_member = 'list'
            next_member = 'free'
        else:
            slab_struct = 'page'
            list_member = 'slab_list'
            next_member = 'active'

        num_offset = require(layout['kmem_cache']['num'], expr='kmem_cache->num')

        mem_offset = require(layout[slab_struct]['s_mem'], expr=f'{slab_struct}->s_mem')
        slab_list_offset = require(layout[slab_struct][list_member], expr=f'{slab_struct}->{list_member}')
        next_offset = require(layout[slab_struct][next_member], expr=f'{slab_struct}->{next_member}')

        if not is_struct_slab:
            freelist_member = 'freelist'
            freelist_offset = require(layout[slab_struct][freelist_member], expr=f'{slab_struct}->{freelist_member}')
        else:
            # bufctl after the struct slab
            # TODO: Provide a cleaner API for past-the-end "members"
            freelist_member = 'bufctl (behind object)'
            all_members = [layout[slab_struct][member] for member in ('list', 'colouroff', 's_mem', 'inuse', 'free', 'nodeid')]
            if None in all_members:
                print(f'\x1b[33mWarning: sizeof(struct {slab_struct}) is uncertain!\x1b[0m')
            estimated_size = align(max(all_members) + 2, view.pointer_size)
            print(f'Estimating sizeof(struct {slab_struct}) to be {estimated_size:#x} bytes after alignment')
            freelist_offset = estimated_size

        partial_offset = require(layout[node_type]['slabs_partial'], expr=f'{node_type}->slabs_partial')
        full_offset = require(layout[node_type]['slabs_full'], expr=f'{node_type}->slabs_full')
        free_offset = require(layout[node_type]['slabs_free'], expr=f'{node_type}->slabs_free')

        member_padding = ' ' * (8 - len(member_name))
        type_padding = ' ' * (15 - len(node_type))
        list_member_padding = ' ' * (9 - len(list_member))
        next_member_padding = ' ' * (6 - len(free_member))
        freelist_member_padding = ' ' * (22 - len(freelist_member))
        if print_output:
            print(textwrap.dedent(f'''\
                Extracted offsets:
                    kmem_cache->num:                {num_offset:#04x}
                    kmem_cache->size:               {size_offset:#04x}
                    kmem_cache->{member_name}:{member_padding}           {nodes_offset:#04x}
                    {node_type}->slabs_partial:{type_padding} {partial_offset:#04x}
                    {node_type}->slabs_full:{type_padding}    {full_offset:#04x}
                    {node_type}->slabs_free:{type_padding}    {free_offset:#04x}
                    {slab_struct}->s_mem:                    {mem_offset:#04x}
                    {slab_struct}->{list_member}:{list_member_padding}                {slab_list_offset:#04x}
                    {slab_struct}->{next_member}:{next_member_padding}                   {next_offset:#04x}
                    {slab_struct}->{freelist_member}:{freelist_member_padding}   {freelist_offset:#04x}
                    list_head->next:                {list_next_offset:#04x}
                '''))

        base_address = cache + nodes_offset
        if not is_array:
            base_address = pointer(base_address, view)

        object_count = u32(cache + num_offset, view)

        for entry in range(nodes):
            entry = pointer(base_address + view.pointer_size * entry, view)
            if not entry:
                continue

            beginning = entry + full_offset
            next_list = pointer(beginning + list_next_offset, view)
            while next_list != beginning:
                slab = next_list - slab_list_offset
                memory = pointer(slab + mem_offset, view)
                # Slab is full, so we can go the entire range
                for index in range(object_count):
                    # c.f. index_to_obj in mm/slab.c
                    yield (memory + index * object_size, True)
                next_list = pointer(slab + slab_list_offset + list_next_offset, view)

            beginning = entry + partial_offset
            next_list = pointer(beginning + list_next_offset, view)
            while next_list != beginning:
                slab = next_list - slab_list_offset
                memory = pointer(slab + mem_offset, view)
                is_allocated = [True] * object_count

                free = u32(slab + next_offset, view)
                if not is_struct_slab:
                    # Emulate slab_get_object with slab_freelist
                    freelist = pointer(slab + freelist_offset, view)
                    for inactive in range(free, object_size):
                        is_allocated[u32(freelist + inactive * 4, view)] = False
                else:
                    # Emulate slab_get_object with slab_bufctl
                    bufctl = slab + freelist_offset
                    while free != 0xffffffff: # BUFCTL_FREE
                        is_allocated[free] = False
                        free = u32(bufctl + free * 4, view)

                for index, allocated in enumerate(is_allocated):
                    if allocated or walk_free:
                        yield (memory + index * object_size, allocated)
                next_list = pointer(slab + slab_list_offset + list_next_offset, view)

            if not walk_free:
                continue # Remaining pages are entirely freed

            beginning = entry + full_offset
            next_list = pointer(beginning + list_next_offset, view)
            while next_list != beginning:
                slab = next_list - slab_list_offset
                memory = pointer(slab + mem_offset, view)
                # Slab is empty, so we can go the entire range
                for index in range(object_count):
                    # c.f. index_to_obj in mm/slab.c
                    yield (memory + index * object_size, False)
                next_list = pointer(slab + slab_list_offset + list_next_offset, view)

    elif allocator == Allocator.SLUB:
        # Note that SLUB uses struct page regardless of the kernel version, unlike SLAB.
        # SLUB keeps partial slabs in a list, but no full/empty slabs
        # Full slabs are only tracked with CONFIG_SLUB_DEBUG
        partial_offset = require(layout[node_type]['partial'], expr=f'{node_type}->partial')
        walk_full = True
        def _slub_no_full_warning():
            nonlocal walk_full
            if walk_full:
                print('\x1b[31mCannot walk full slabs in SLUB without CONFIG_SLUB_DEBUG (default: y)\x1b[0m')
                walk_full = False
        try:
            full_offset = maybe(layout[node_type]['full'], expr=f'{node_type}->full', default=0x30)
        except OffsetNotFound:
            _slub_no_full_warning()

        # Where is the free pointer stored inside the object?
        offset_offset = require(layout['kmem_cache']['offset'], expr=f'kmem_cache->offset') # :)
        freeptr_offset = u32(cache + offset_offset, view)

        # SLUB has a per-cpu page cache
        percpu_cache_offset = require(layout['kmem_cache']['cpu_slab'], expr=f'kmem_cache->cpu_slab')
        cpu_page_offset = require(layout['kmem_cache_cpu']['page'], expr=f'kmem_cache_cpu->page')
        cpu_freelist_offset = require(layout['kmem_cache_cpu']['freelist'], expr=f'kmem_cache_cpu->freelist')
        def _slub_no_cpu_partial_warning():
            nonlocal walk_percpu_partial
            if walk_percpu_partial:
                print('\x1b[31mList of per-CPU partial slabs in SLUB not found (CONFIG_SLUB_CPU_PARTIAL, default: y). This is only configurable after 4.13; otherwise, this is an error.\x1b[0m')
                walk_percpu_partial = False

        walk_percpu_partial = True
        try:
            cpu_partial_offset = maybe(layout['kmem_cache_cpu']['partial'], expr=f'kmem_cache_cpu->partial', default=0x18)
        except OffsetNotFound:
            # This is optional since v4.13
            _slub_no_cpu_partial_warning()

        slab_list_offset = require(layout['page']['slab_list'], layout['page']['lru'], layout['page']['next'], expr=f'page->slab_list || page->lru || page->next')
        page_freelist_offset = require(layout['page']['freelist'], expr=f'page->freelist')

        random_key = None # Per-cache. Only used for CONFIG_SLAB_FREELIST_HARDENED
        random_swab = True # ptr_addr => swab(ptr_addr) in some versions

        # We really want page->inuse and page->objects, but those are bitfields inside a union,
        # and we can't handle bit offsets yet. Unfortunately, the other stuff in the union changes,
        # but we pretty much always overlay with page->counters.
        # Try to find the other union members, then resolve the bit offsets
        counters_offset = maybe(layout['page']['counters'], expr=f'page->counters', default=None)
        # Generally, compilers fill up from LSB to MSB. This is a reasonable default assumption.
        objects_bits = (0x7FFF, 16)
        if counters_offset is not None:
            get_page_object_count = lambda page: extract_bits(u32(page + counters_offset, view), objects_bits)
        else:
            # Recompute number of objects, cf. allocate_slab
            print('\x1b[33mCould not find object count in the page - trying to recompute\x1b[0m')
            order_offset = maybe(layout['kmem_cache']['oo'], expr=f'kmem_cache->oo', default=None)
            # oo is a struct kmem_cache_order_objects, which just wraps an unsigned int for atomics.
            if order_offset is not None:
                OO_MASK = (1 << 16) - 1
                oo_objects = u32(cache + order_offset, view) & OO_MASK
                get_page_object_count = lambda _: oo_objects
            else:
                print('\x1b[31mCould not recompute object count, assuming based on page size\x1b[0m')
                get_page_object_count = lambda _: 0x1000 // object_size

        page_emulator = None

        # Walking helpers
        def _slub_demangle_freeptr(ptr, ptr_addr):
            # Try to fix mangled freelist pointers (CONFIG_SLAB_FREELIST_HARDENED)
            nonlocal random_key, random_swab
            decode_swab = lambda key: swab_pointer(ptr_addr, view) ^ ptr ^ key
            decode_noswab = lambda key: ptr_addr ^ ptr ^ key
            if (random_key or random_key is None) and ptr != 0:
                if random_key is None:
                    # Do not even try to load random if we don't think it's mangled...
                    if view.has_virt(ptr, view.pointer_size):
                        return ptr
                    if print_output and VERBOSE:
                        print(f'Pointer {ptr:#018x} appears to be mangled!')
                    try:
                        random_key_offset = require(layout['kmem_cache']['random'], expr=f'kmem_cache->random')
                        random_key = pointer(cache + random_key_offset, view)
                    except OffsetNotFound:
                        # Brute-force the offset of the random data instead
                        for index in range(0x40):
                            candidate = pointer(cache + index * view.pointer_size, view)
                            if not candidate or view.has_virt(candidate, 1):
                                continue
                            swabbed = decode_swab(candidate)
                            nonswabbed = decode_noswab(candidate)
                            valid = lambda p: not p or view.has_virt(p, 1)
                            if valid(swabbed):
                                random_key_offset = index * view.pointer_size
                                random_key = candidate
                                break
                            elif valid(nonswabbed):
                                random_swab = False
                                random_key_offset = index * view.pointer_size
                                random_key = candidate
                                break
                        else:
                            raise
                    if print_output and VERBOSE:
                        print(f'Found random key at offset {index * view.pointer_size:#x}: {random_key:#0x}')
                    if not random_key:
                        return ptr # Not mangled, random is zero
                # TODO: This is missing a kasan_reset_tag on ptr_addr, but that's only implemented on ARM anyways, and even then it needs to be enabled manually.
                return decode_swab(random_key) if random_swab else decode_noswab(random_key)
            return ptr

        def _slub_next_free(free_obj):
            freeptr_addr = free_obj + freeptr_offset
            return _slub_demangle_freeptr(pointer(freeptr_addr, view), freeptr_addr)

        def _slub_walk_page(page, freelist=None, all_full=False):
            walked = set()
            orig_freelist = freelist
            if not all_full:
                # Walk freelist if we have one, otherwise try to walk from slab.
                # We only need to demangle if we fetch it from an object, not directly
                while freelist:
                    yield (freelist, False)
                    walked.add(freelist)
                    freelist = _slub_next_free(freelist)
                # Try to grab the rest from the page
                freelist = pointer(page + page_freelist_offset, view)
                if not orig_freelist:
                    orig_freelist = freelist
                while freelist:
                    yield (freelist, False)
                    walked.add(freelist)
                    freelist = _slub_next_free(freelist)

            if orig_freelist:
                # We have a virtual pointer into the page
                page_base = orig_freelist & ~0xFFF
            else:
                # Oh no, we need to emulate
                nonlocal page_emulator
                if not page_emulator:
                    page_emulator = page_to_address_emulator(view)
                page_base = page_emulator.translate(page)

            page_object_count = get_page_object_count(page)
            for index in range(page_object_count):
                addr = page_base + index * object_size
                if addr not in walked:
                    yield (addr, True)

        def _slub_walk_list(head, all_full=False):
            # This is just a list of pages (via slab_list), so walk that.
            next_list = pointer(head + list_next_offset, view)
            while next_list and next_list != head:
                page = next_list - slab_list_offset
                # We don't have a freelist for this page.
                yield from _slub_walk_page(page, all_full=all_full)
                next_list = pointer(next_list + list_next_offset, view)

        # Walk the per-cpu caches first
        # This is a pointer indexed by CPU index
        for cpu_cache in percpu_pointers(cache + percpu_cache_offset, view):
            try:
                if view.get_virt(cpu_cache, 0x10) == b'\xcc' * 0x10: # CPU is off/dead/...
                    break
            except NotMapped:
                print(f'\x1b[33mPer-CPU cache pointer {cpu_cache:#018x} is not mapped!\x1b[0m')
                break
            current_page = pointer(cpu_cache + cpu_page_offset, view)
            if not current_page:
                continue
            current_fl = pointer(cpu_cache + cpu_freelist_offset, view)
            yield from _slub_walk_page(current_page, freelist=current_fl)
            if not walk_percpu_partial:
                continue
            partial = pointer(cpu_cache + cpu_partial_offset, view)
            if not view.has_virt(partial, view.pointer_size): # Not a valid pointer, probably bad offset
                _slub_no_cpu_partial_warning()
                continue
            while partial:
                yield from _slub_walk_page(partial)
                # This is via ->next, not via ->slab_list, so the pointer goes directly to the page
                partial = pointer(partial + slab_list_offset + list_next_offset, view)

        # Walk the global partial lists next
        base_address = cache + nodes_offset
        if not is_array:
            base_address = pointer(base_address, view)

        for entry in range(nodes):
            entry = pointer(base_address + view.pointer_size * entry, view)
            yield from _slub_walk_list(entry + partial_offset)

        # Walk the global full lists next
        if walk_full:
            for entry in range(nodes):
                entry = pointer(base_address + view.pointer_size * entry, view)
                yield from _slub_walk_list(entry + full_offset, all_full=True)

    elif allocator == Allocator.SLOB:
        raise NotImplementedError('SLOB support is not implemented')

Record = collections.namedtuple('Record', ('path', 'inode', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime'))

if __name__ == "__main__":
    def parser_setup(parser):
        parser.add_argument('--dentry-cache', help='Override address of dentry_cache', type=lambda i: int(i, 0), default=0)
        parser.add_argument('--version', help='Kernel version range (default: autodetect)', choices=VERSION_MAP.values(), type=VERSION_MAP.__getitem__, default=Version.AUTODETECT)
        parser.add_argument('--allocator', help='Allocator model (default: autodetect)', choices=ALLOCATOR_MAP.values(), type=ALLOCATOR_MAP.__getitem__, default=Allocator.AUTODETECT)
        parser.add_argument('-b', '--body-file', help='Write body file to this path')
        parser.add_argument('--verbose', action='store_true')
    args, layout, view = tool_setup(parser_setup)
    VERBOSE |= args.verbose

    dentry_cache = args.dentry_cache
    if not dentry_cache:
        if view.lookup_symbol('dentry_cache'):
            try:
                dentry_cache = pointer(view.lookup_symbol('dentry_cache'), view)
            except NotMapped:
                pass
    if not dentry_cache:
        print('Did not find dentry_cache, trying to recover via kmem_cache list')
        candidates = find_cache_by_name(b'dentry', layout, view)
        if not candidates:
            print('Failed to find dentry_cache')
            exit(1)
        if len(candidates) > 1:
            print('Found multiple candidates for dentry_cache, use --dentry-cache to select one:')
            for candidate in candidates:
                print(f' - {candidate:#018x}')
            exit(0)
        dentry_cache = next(candidates)
    if not args.dentry_cache:
        print(f'Found dentry_cache at {dentry_cache:#018x}')

    list_next_offset = require(layout['list_head']['next'], expr='list_head->next')
    dentry_parent_offset = require(layout['dentry']['d_parent'], expr='dentry->d_parent')
    dentry_name_offset = require(layout['dentry']['d_name'], expr='dentry->d_name')
    dentry_inode_offset = require(layout['dentry']['d_inode'], expr='dentry->d_inode')
    qstr_name_offset = require(layout['qstr']['name'], expr='qstr->name')

    inode_ino_offset = maybe(layout['inode']['i_ino'], expr='inode->i_ino', default=None)
    inode_uid_offset = maybe(layout['inode']['i_uid'], expr='inode->i_uid', default=None)
    inode_gid_offset = maybe(layout['inode']['i_gid'], expr='inode->i_gid', default=None)
    inode_size_offset = maybe(layout['inode']['i_size'], expr='inode->i_size', default=None)
    inode_atime_offset = maybe(layout['inode']['i_atime'], expr='inode->i_atime', default=None)
    inode_mtime_offset = maybe(layout['inode']['i_mtime'], expr='inode->i_mtime', default=None)
    inode_ctime_offset = maybe(layout['inode']['i_ctime'], expr='inode->i_ctime', default=None)

    tv_sec_offset = require(layout['timespec64']['tv_sec'], layout['timespec']['tv_sec'], expr='timespec64->tv_sec')

    # Offset for walking across FS boundaries
    # (Volatility can't do this :P)
    try:
        dentry_sb_offset = require(layout['dentry']['d_sb'], expr='dentry->d_sb')
        sb_mounts_offset = require(layout['super_block']['s_mounts'], expr='super_block->s_mounts')
        mount_instance_offset = require(layout['mount']['mnt_instance'], expr='mount->mnt_instance')
        mount_mountpoint_offset = require(layout['mount']['mnt_mountpoint'], expr='mount->mnt_mountpoint')
        walk_across_fs = True
    except OffsetNotFound:
        walk_across_fs = False
        print('\x1b[33mCannot walk paths across file systems\x1b[0m (forensic tools should not be affected by this: this applies to most tools, including Volatility)')

    def dentry_name(dentry):
        return string(pointer(dentry + dentry_name_offset + qstr_name_offset, view), view)
    def dentry_parent(dentry):
        return pointer(dentry + dentry_parent_offset, view)
    def dentry_inode(dentry):
        return pointer(dentry + dentry_inode_offset, view)
    def timespec_to_unix(timespec64, view):
        # TODO: Don't drop tv_nsec here (though I think mactime can only deal with integer times)
        return u64(timespec64 + tv_sec_offset, view)
    def inode_to_record(inode, path):
        i_ino = pointer(inode + inode_ino_offset, view) if inode_ino_offset else None
        i_uid = u32(inode + inode_uid_offset, view) if inode_uid_offset else None
        i_gid = u32(inode + inode_gid_offset, view) if inode_gid_offset else None
        i_size = u64(inode + inode_size_offset, view) if inode_size_offset else None
        i_atime = timespec_to_unix(inode + inode_atime_offset, view) if inode_atime_offset else None
        i_mtime = timespec_to_unix(inode + inode_mtime_offset, view) if inode_mtime_offset else None
        i_ctime = timespec_to_unix(inode + inode_ctime_offset, view) if inode_ctime_offset else None
        return Record(path, i_ino, i_uid, i_gid, i_size, i_atime, i_mtime, i_ctime)
    def dentry_mount_point(dentry, seen):
        try:
            sb = pointer(dentry + dentry_sb_offset, view)
            if not sb:
                return None
            list_start = sb + sb_mounts_offset
            entry = pointer(list_start + list_next_offset, view)
            while entry != list_start:
                mount = entry - mount_instance_offset
                mountpoint = pointer(mount + mount_mountpoint_offset, view)
                if mountpoint not in seen:
                    return mountpoint # Pick the first unknown dentry. NB: this may not be the exact path used, but it refers to the same location.
                entry = pointer(entry + list_next_offset, view)
            return None
        except NotMapped:
            return None # One of the offsets is probably wrong

    counter = 0
    entries = []
    # TODO: Expand via d_u
    def process_dentry(dentry, allocated):
        highlighted = '\x1b[32mLive\x1b[0m' if allocated == True else \
                      '\x1b[33mDead\x1b[0m' if allocated == False else \
                      '\x1b[36mUnknown\x1b[0m'
        parent = dentry_parent(dentry)
        inode = dentry_inode(dentry)
        seen = {dentry}
        path_nodes = []
        try:
            path_nodes.append(dentry_name(dentry))
            while True:
                while parent not in seen:
                    seen.add(parent)
                    next_parent = dentry_parent(parent)
                    if next_parent != parent: # Root dentries have bad names.
                        path_nodes.append(dentry_name(parent))
                    parent = next_parent
                # Check for a mount point
                if not walk_across_fs:
                    break
                parent = dentry_mount_point(parent, seen)
                if not parent:
                    break
        except NotMapped:
            name = b'/'.join(node for node in path_nodes[::-1] if node)
            name = f'corrupted ({base64.b64encode(name).decode()})'
        else:
            # Sanitize the name
            name = (b'/' if len(path_nodes) > 1 else b'') + b'/'.join(node for node in path_nodes[::-1] if node)
            try:
                name = name.decode()
            except UnicodeDecodeError:
                # Probably grabbed bad data; mark invalid and base64-encode
                name = f'invalid ({base64.b64encode(name).decode()})'

        # Produce mactime-compatible record
        if inode and view.has_virt(inode, 1):
            # If we have an inode pointer, use it
            entries.append(inode_to_record(inode, name))
            inode_text = f'{inode:#018x}'
        else:
            # Otherwise, add an empty entry with just the name
            entries.append(Record(name, 0, 0, 0, 0, 0, 0, 0))
            inode_text = f'\x1b[31m{inode:#018x}\x1b[0m'

        print(f'{highlighted} dentry @ {dentry:#018x} => inode @ {inode_text}: {name}')

    for dentry, allocated in walk_kmem_cache(dentry_cache, layout, view, args.version, args.allocator, walk_free=True):
        process_dentry(dentry, allocated)
        counter += 1
    print(f'Walked {counter} dentry slots')

    # Dump results in body file format if requested (like Volatility):
    # MD5 (0) | path | inode | str(mode) (0) | uid | gid | size | atime | mtime | ctime (0) | crtime
    # (cf. https://wiki.sleuthkit.org/index.php?title=Body_file)
    if args.body_file:
        with open(args.body_file, 'w') as output:
            for record in entries:
                # Avoid format bugs if the file name contains a pipe character
                path = record.path.replace('|', '\\x7c')
                print(f'0|{path}|{record.inode}|0|{record.uid}|{record.gid}|{record.size}|{record.atime}|{record.mtime}|0|{record.ctime}', file=output)

