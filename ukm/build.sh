#!/bin/sh
set -eu

if [ "$#" -lt 3 ]; then
	echo 'Usage: ./build.sh <compiler prefix> <kernel arch> <configured kernel source tree> <flags...>' >&2
    echo '    <compiler prefix>: Cross compiler prefix, e.g. aarch64-linux-gnu-' >&2
    echo '    <kernel arch>: Kernel architecture tag, e.g. arm64' >&2
    echo '    <configured kernel source tree>: Kernel (reasonably new) configured for the target architecture' >&2
    echo '    <flags>: Compiler flags for loader and module, e.g. -EL' >&2
	exit 1
fi

export CROSS_COMPILE="$1"
export ARCH="$2"
export KERNEL_TREE="$3"
if [ "$#" -gt 3 ]; then
    shift 3
    export FLAGS="$@"
fi

set -x

make UKM_FLAGS="$FLAGS" ARCH="$ARCH" KERNEL="$KERNEL_TREE" CROSS_COMPILE="$CROSS_COMPILE" module
"${CROSS_COMPILE}gcc" -DUNLOAD_MODULE -I. -Wl,-e_start $FLAGS -nostdlib ukm-loader.c -o loader."$ARCH"
