#!/bin/bash
PROJECT_DIR=./
PROJECT_NAME=ghidrapod

if [[ $# == 2 ]]; then
    file="$1"
    db="$2"
else
    file="vmlinux-4.4.0-142-generic"
    db="../kernel-db/fields.v4.4.txt"
fi

ghidra-analyzeHeadless $PROJECT_DIR $PROJECT_NAME \
    -import $file \
    -noanalysis \
    -readOnly \
    -postScript pcode_tracker.py "$db" \
	-scriptPath "./" \
	-scriptlog "./log.txt"
