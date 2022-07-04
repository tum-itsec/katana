# Katana

1. Find the symbol table in the memory snapshot. If no CR3 is present, find that too:

    make # to build the C helper that makes symtab searching faster
    ./search-any-symtab.sh <snapshot>

2. Extend the symbol information with Kallsyms data (for your architecture):

    ./emu_kallsyms_x64.py <snapshot>

3. Match against the accessor function database (hint: pick a fields.txt that roughly matches your snapshot; you should also already be able to run `./extract_kernel_version.py -n <snapshot>` (or `strings`) to obtain the exact kernel version). Make sure to use the correct script for your architecture:

    ./evaluation/recover-offsets-from-dump.sh <snapshot> kernel-db/fields.v5.7.11-def.txt kernel-db/structinfo.v5.7.11.json

4. Show dmesg buffer contents (optionally with recovered global variables). Your snapshot's layout file should be autodetected, otherwise you will want to use the `<snapshot>-layout-processed` layout file:

    ./extract_dmesg.py -n <snapshot>
    ./extract_dmesg.py --structinfo kernel-db/structinfo.v5.7.11.json <snapshot>

5. List processes in the memory snapshot

    ./list_procs.py --structinfo kernel-db/structinfo.v5.7.11.json <snapshot>
    ./list_procs.py --structinfo kernel-db/structinfo.v5.7.11.json <snapshot> --gencore    # Generates ELF core files for each process

6. List loaded kernel modules

    ./list_modules.py --structinfo kernel-db/structinfo.v5.7.11.json <snapshot>

7. Run other analyses (`list_files.py`, `list_envs.py`, `list_arp_table.py`, `list_sockets.py`, `recover_dentry_cache.py`) with the same arguments. You can use `--help` to view detailed usage instructions.

If you want to generate the accessor function database yourself, you can use the provided Docker container, which will place the output files in an `output/` directory:

    docker build -t build-kernel .                # This takes quite some time
    ./build-kernel.sh --def v4.17.19
    ./build-kernel.sh --def --gcc 4.8 v3.9.11     # Build with GCC 4.8 for kernels that do not support GCC 5 or 6

## Dependencies

We developed this tool on an up-to-date ArchLinux.

 - capstone
 - unicorn
 - gcc (with plugin headers)
 - docker
 - python (>= 3.8)
   - python bindings for capstone and unicorn
   - pyelftools
   - hexdump
   - numpy
   - sympy
 - ghidra

