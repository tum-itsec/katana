#!/bin/bash
PROJECT_DIR=pcode_analyze_tmp
PROJECT_NAME=ghidra_analyze_tmp

mkdir $PROJECT_DIR

if [[ $# == 2 ]]; then
    file="$1"
    db="$2"
else
    file="vmlinux-4.4.0-142-generic"
    db="../kernel-db/fields.v4.4.txt"
fi

ghidra-analyzeHeadless $PROJECT_DIR $PROJECT_NAME \
    -import $file \
    -loader BinaryLoader \
    -loader-baseAddr 0x0 \
    -cspec gcc \
    -processor x86:LE:64:default \
    -noanalysis \
    -readOnly \
    -postScript pcode_tracker.py "$db" \
	-scriptPath "./" \
	-scriptlog "./log.txt"

rm -r $PROJECT_DIR
