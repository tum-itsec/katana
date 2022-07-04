#!/usr/bin/env python3
import itertools
import os
import re
from common import *

def use_banner_addr(view, banner_addr):
    banner_data = view.get_virt(banner_addr, 0x100)
    banner = "".join(chr(x) for x in itertools.takewhile(lambda d: d!= 0, banner_data))
    return banner


def use_uts_namespace(view, init_uts_ns_addr):
    uts_ns = view.get_virt(init_uts_ns_addr, 0x100)
    strings = re.findall(b'[\x20-\x7e]+', uts_ns)
    banner = b' '.join(strings).decode()
    return banner


if __name__ == "__main__":
    args, _, view = tool_setup(layout_optional=True)

    banner_addr = view.lookup_symbol("linux_banner")
    init_uts_ns_addr = view.lookup_symbol("init_uts_ns")

    if not banner_addr and not init_uts_ns_addr:
        raise ValueError("Failed to recover either linux_banner or init_uts_ns")
    elif not banner_addr:
        print("\x1b[33mNo linux_banner, falling back to init_uts_ns\x1b[0m")
        banner = use_uts_namespace(view, init_uts_ns_addr)
    else:
        banner = use_banner_addr(view, banner_addr)

    print(banner)
    with open("{}-banner".format(args.image), "w") as f:
        f.write("{}\n".format(banner))

