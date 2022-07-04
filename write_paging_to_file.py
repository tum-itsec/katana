#!/usr/bin/env python3

import elfcore
from elfview import autoselect, NotMapped
import argparse

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("image", help="The Image file to generate mappings for")
    args = p.parse_args()

    view = autoselect(args.image)
    outfile = f"{args.image}-mappings"
    core = elfcore.ELFCore()
    print(f"Number of mappings: {len(view.mapping)}")
    with open(outfile, "w") as f:
        for i in view.mapping:
            flags = "R"
            flags += "W" if i.rw else ""
            flags += "X" if i.nx else ""

            try:
                dummy = view.get_phys(i.phys, i.size)
                f.write(f"{hex(view.virt_to_file_offset(i.virt))} {hex(i.virt)} {i.size} {flags}\n")
            except NotMapped:
                print(f"Skipping address {i.virt:016x}")
