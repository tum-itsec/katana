#!/bin/sh

set -eu

VMLINUX="$(readlink -f "$1")"
FIELDS="$(readlink -f "$2")"
STRUCTLAYOUT="$(readlink -f "$3")"

# 1. Generate symbol files from the vmlinux
python ../gen-ghidra-symbols.py "$VMLINUX"
cp "${VMLINUX}-symbols" "${VMLINUX}-kallsym"

# 2. Import the vmlinux file into ghidra and run the analysis
#    This generates a -layout file in the current directory
PROJECT_DIR="$(mktemp -d)"
function cleanup {
	rm -rf "$PROJECT_DIR"
}
trap cleanup EXIT

PROJECT_NAME="automated-analysis"
export _JAVA_OPTIONS="-Xmx12g"

cd ../pcode
ghidra-analyzeHeadless "$PROJECT_DIR" $PROJECT_NAME \
	-import "$VMLINUX" \
	-noanalysis \
	-readOnly \
	-postScript main.py "$FIELDS" "analyze_vmlinux" \
	-scriptPath "./" \
	-scriptlog "./log.txt" \
	| tee "${VMLINUX}-analysis"

python3 ../resolve_direct_accesses.py "${VMLINUX}-layout" "${STRUCTLAYOUT}" | tee -a "${VMLINUX}-analysis"

