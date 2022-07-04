#!/bin/bash

set -eu

MAIN="$(dirname "$(dirname "$(readlink -f "$0")")")"
DUMP="$(readlink -f "$1")"
FIELDS="$(readlink -f "$2")"
STRUCTLAYOUT="$(readlink -f "$3")"

PROJECT_DIR="$(mktemp -d)"
function cleanup {
	rm -rf "$PROJECT_DIR"
}
trap cleanup EXIT

PROJECT_NAME="automated-analysis"
export _JAVA_OPTIONS="-Xmx12g"

python3 "${MAIN}/write_paging_to_file.py" "${DUMP}"
mv "${DUMP}-mappings" "${DUMP}-oldmappings"
uniq < "${DUMP}-oldmappings" > "${DUMP}-mappings"
rm "${DUMP}-oldmappings"

cd "${MAIN}/pcode"
ghidra-analyzeHeadless "$PROJECT_DIR" $PROJECT_NAME \
	-import "$DUMP" \
	-noanalysis \
	-readOnly \
	-loader BinaryLoader \
	-loader-baseAddr 0x0 \
	-cspec default \
	-processor AARCH64:LE:64:v8A \
	-postScript main.py "$FIELDS" "analyze_dump" \
	-scriptPath "./" \
	-scriptlog "./log.txt" \
	| tee "${DUMP}-analysis"

python3 "${MAIN}/resolve_direct_accesses.py" "${DUMP}-layout" "${STRUCTLAYOUT}" | tee -a "${DUMP}-analysis"

