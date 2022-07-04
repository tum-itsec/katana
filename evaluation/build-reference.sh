#!/bin/sh

set -eu

TAG="$1"
shift

# Find the correct GCC version to build this tag
#   gcc6   -> 4.x 5.x
#   gcc4.8 -> 3.x
# TODO: Verify that this is actually correct
shopt -sq extglob
MAJOR_VERSION="${TAG%%.*}"
MAJOR_VERSION="${MAJOR_VERSION##*([^0-9])}"
case "${MAJOR_VERSION}" in
	"0"|"1")
		die "Kernel version ${MAJOR_VERSION} not supported"
		;;
	"2")
		die "Kernel version ${MAJOR_VERSION} not yet supported"
		;;
	"3")
		GCC="4.8"
		;;
	"4"|"5"|*)
		GCC="6"
		;;
esac

mkdir -p "output/${TAG}"

# 1. Create a defconfig base image with debug symbols
if [ ! -e "output/${TAG}/vmlinux.${TAG}-def" ]; then
	../build-kernel.sh "$@" --gcc "${GCC}" --def "${TAG}"
fi
find output -mindepth 1 -maxdepth 1 -name "fields.${TAG}-def.txt" -o -name "config.${TAG}-def" -o -name "vmlinux.${TAG}-def" -exec mv {} "output/${TAG}/" ';'
