#!/bin/sh

set -eu

VMLINUX="$(readlink -f "$1")"
BASE="$(readlink -f "$2")"
STRUCTINFO="$(readlink -f "$3")"
../pcode/ghidra-verify-offsets-split.py --layout "${VMLINUX}-layout-processed" --structinfo "${STRUCTINFO}" --check ../volatility-offsets.json --pretty --output "${VMLINUX}-eval-split" --check-extra ../katana-required-members.json "${VMLINUX}-eval-katana" "${VMLINUX}" | tee "${VMLINUX}-eval-split-log"
./compare-vmlinux.py "${VMLINUX}" "${BASE}" --check ../volatility-offsets.json --output "${VMLINUX}-comparison" | tee "${VMLINUX}-comparison-log"
