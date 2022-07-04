#!/bin/bash

set -eu

function die {
	echo "$@" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "Usage: $0 <tag> <count>"
TAG="$1"
COUNT="$2"

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

# Make sure we get an _empty_ output directory.
mkdir -p "output/${TAG}"

# 2. Create variant images via randstruct
for INDEX in $(seq ${COUNT}); do
	SUFFIX="-randstruct-${INDEX}"
	if [ -e "output/vmlinux.${TAG}${SUFFIX}" -o -e "output/${TAG}/vmlinux.${TAG}${SUFFIX}" ]; then
		continue
	fi
	../build-kernel.sh --def \
		--randstruct \
		--gcc "${GCC}" \
		--suffix "${SUFFIX}" \
		"${TAG}"
done
find output -mindepth 1 -maxdepth 1 -name "config.${TAG}-*" -o -name "vmlinux.${TAG}-*" -exec mv {} "output/${TAG}/" ';'
