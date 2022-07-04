#!/usr/bin/env python3
from common import *

import socket
import ipaddress

if __name__ == "__main__":
    args, layout, view = tool_setup()

    # TODO: No more defaults
    nht_offset = require(layout['neigh_table']['nht'], expr='neigh_table->nht')
    family_offset = maybe(layout['neigh_table']['family'], expr='neigh_table->family', default=0)
    bucket_offset = maybe(layout['neigh_hash_table']['hash_buckets'], expr='neigh_hash_table->hash_buckets', default=0)
    shift_offset = maybe(layout['neigh_hash_table']['hash_shift'], expr='neigh_hash_table->hash_shift', default=view.pointer_size)
    next_offset = maybe(layout['neighbour']['next'], expr='neighbour->next', default=0)
    ha_offset = require(layout['neighbour']['ha'], expr='neighbour->ha')
    key_offset = require(layout['neighbour']['primary_key'], expr='neighbour->primary_key')

    dev_offset = maybe(layout['neighbour']['dev'], expr='neighbour->dev', default=None)
    dev_name_offset = maybe(layout['net_device']['name'], expr='net_device->name', default=None)
    has_dev = dev_offset is not None and dev_name_offset is not None

    print(f'''
Extracted offsets:
    neigh_table->nht:               {nht_offset:#04x}
    neigh_table->family:            {family_offset:#04x}
    neigh_hash_table->hash_buckets: {bucket_offset:#04x}
    neigh_hash_table->hash_shift:   {shift_offset:#04x}
    neighbour->next:                {next_offset:#04x}
    neighbour->ha:                  {ha_offset:#04x}
    neighbour->primary_key:         {key_offset:#04x}
    neighbour->dev:                 {"unknown" if dev_offset is None else f"{dev_offset:#04x}"}
    net_device->name:               {"unknown" if dev_name_offset is None else f"{dev_name_offset:#04x}"}
''')

    tables = view.lookup_symbol('neigh_tables')
    if not tables:
        raise SymbolNotFound('neigh_tables')

    def walk_neigh_table(table, ha_format, key_format):
        try:
            family = i32(table + family_offset, view)
            nht = pointer(table + nht_offset, view)
            buckets = pointer(nht + bucket_offset, view)
            hash_shift = u32(nht + shift_offset, view)
            if hash_shift > 32:
                return
            bucket_count = 1 << hash_shift
        except NotMapped:
            return
        for i in range(bucket_count):
            start = neighbour = pointer(buckets + view.pointer_size * i, view)
            while neighbour:
                ha = view.get_virt(neighbour + ha_offset, 32) # 32 == MAX_ADDR_LEN
                key = view.get_virt(neighbour + key_offset, 32) # 32 == MAX_ADDR_LEN
                if family in key_format:
                    formatted = key_format[family](key)
                else:
                    try:
                        family_name = socket.AddressFamily(family).name
                    except ValueError:
                        formatted = f'<unknown address family ({family}): {key.hex()}>'
                    else:
                        formatted = f'<{family_name}: {key.hex()}>'
                print(ha_format(ha), formatted, end='')

                if has_dev:
                    try:
                        dev = pointer(neighbour + dev_offset, view)
                        name = string(dev + dev_name_offset, view)
                        try:
                            name = name.decode()
                        except UnicodeDecodeError:
                            name = f'<corrupted: {repr(name)[2:-1]}>'
                        print(f' {name}')
                    except NotMapped:
                        print()
                else:
                    print()
                neighbour = pointer(neighbour + next_offset, view)
                if neighbour == start or neighbour < 0x1000:
                    break

    ether_format = lambda ha: ':'.join(f'{b:02x}' for b in ha[:6])
    ipv4_format = lambda key: str(ipaddress.IPv4Address(key[:4]))
    ipv6_format = lambda key: str(ipaddress.IPv6Address(key[:16]))

    addr_formats = {
        socket.AF_INET: ipv4_format,
        socket.AF_INET6: ipv6_format,
    }

    # On kernels < 3.19, this is a linked list through neigh_table->next
    if 'next' in layout['neigh_table']:
        table_next_offset = require(layout['neigh_table']['next'], expr=f'neigh_table->next')
        while tables:
            walk_neigh_table(tables, ether_format, addr_formats)
            tables = pointer(tables + table_next_offset, view)
    else:
        # TODO: Can we find the number of tables dynamically
        # [0] == view.lookup_symbol('arp_tbl')
        NEIGH_NR_TABLES = 4
        for index in range(NEIGH_NR_TABLES):
            table = pointer(tables + index * view.pointer_size, view)
            if table:
                walk_neigh_table(table, ether_format, addr_formats)


