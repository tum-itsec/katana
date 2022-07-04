#!/bin/bash

set -eu

function die {
	echo "$@" >&2
	exit 1
}

[ "$#" -eq 1 ] || die "Usage: $0 <tag>"
TAG="$1"

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

# Splits are in N:M:L format
#   * N: percentage of booleans set to 'y'
#   * M: percentage of tristates set to 'y'
#   * L: percentage of tristates set to 'm'
SPLITS=(
	"0:0:0"
	"5:5:5"
	"10:10:10"
	"15:10:10"
	"20:10:10"
	"30:15:15"
	"40:20:20"
	"40:25:25"
	"50:25:25"
	"50:30:30"
	"60:30:30"
	"60:35:35"
)
#	"70:35:35"
#	"80:40:40"
#	"90:45:45"
#	"100:50:50"

# 2. Create variant images via randconfig
for SPLIT in "${SPLITS[@]}"; do
	SUFFIX="-randomized-${SPLIT//:/-}"
	if [ -e "output/vmlinux.${TAG}${SUFFIX}" -o -e "output/${TAG}/vmlinux.${TAG}${SUFFIX}" ]; then
		continue
	fi
	RFILE="output/${TAG}/randomization.${TAG}-${SPLIT//:/-}.txt"
	if [ -e "${RFILE}"  ]; then
		source "${RFILE}"
	else
		SEED="$(od -l -N8 < /dev/urandom | sed 's/.* \(-*[0-9]*\)$/\1/;q')"
		echo -e "SEED=${SEED}\nSPLIT=\"${SPLIT}\"" > "${RFILE}"
	fi
	../build-kernel.sh --randomize \
		--env "KCONFIG_PROBABILITY=${SPLIT}" \
		--env "KCONFIG_SEED=${SEED}" \
		--gcc "${GCC}" \
		--no-plugin --suffix "${SUFFIX}" \
		"${TAG}"
done
find output -mindepth 1 -maxdepth 1 -name "config.${TAG}-*" -o -name "vmlinux.${TAG}-*" -exec mv {} "output/${TAG}/" ';'
