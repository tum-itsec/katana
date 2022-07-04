#!/bin/bash

set -eu

REFRESH="n"
REEVALUATE="n"
DRY_RUN="n"
FIXED_TAG=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		-R|--refresh)
			shift
			REFRESH="y"
			;;
		-E|--reevaluate)
			shift
			REEVALUATE="y"
			;;
		-t|--tag)
			shift
			FIXED_TAG="$1"
			shift
			;;
		-n|--dry-run)
			shift
			DRY_RUN="y"
			;;
		-h|--help|*)
			echo "Usage: $0 [-R|-E] [-t TAG]"
			exit 0
			;;
	esac
done

if [ ! -d output ]; then
	echo 'Output directory does not exist.' >&2
	exit 1
fi

rm -f 'output/status'

function analyze_tagdir {
	TAGDIR="$1"
	DRY_RUN="$2"
	# In the tag directory, find the fields file, and
	FIELDS="$(find "${TAGDIR}" -name 'fields.*' -print -quit)"
	STRUCTINFO="$(find "${TAGDIR}" -name 'structinfo.*' -print -quit)"
	echo "Found fields file: ${FIELDS}" | tee -a 'output/status'
	# for each vmlinux file in the tag directory,
	while IFS= read -r -d '' VMLINUX; do
		echo "Analyzing ${VMLINUX}" | tee -a 'output/status'
		# if `-layout` does not exist or is older than the source files, run the analysis pass
		if [ '(' ! -e "${VMLINUX}-layout-processed" ')' -o "${VMLINUX}" -nt "${VMLINUX}-layout-processed" -o "${REFRESH}" = "y" ]; then
			if [ "${DRY_RUN}" = "y" ]; then
				echo " => Dry run, would recover offsets" | tee -a 'output/status'
			else
				./recover-offsets-from-vmlinux.sh "${VMLINUX}" "${FIELDS}" "${STRUCTINFO}"
			fi
		fi
		# if `-eval` does not exist or is older than the source files, run the evaluation pass
		if [ '(' ! -e "${VMLINUX}-eval-split" ')' -o "${VMLINUX}" -nt "${VMLINUX}-eval" -o "${REFRESH}" = "y" -o "${REEVALUATE}" = "y" ]; then
			if [ "${DRY_RUN}" = "y" ]; then
				echo " => Dry run, would evaluate offsets" | tee -a 'output/status'
			else
				./evaluate-offsets.sh "${VMLINUX}" "$(find "${TAGDIR}" -name 'vmlinux.*-def' -executable -print -quit)" "${STRUCTINFO}"
			fi
		fi
	done < <(find "${TAGDIR}" -name 'vmlinux.*' -a -executable -print0 | sort -Vz)
}

if [ -z "${FIXED_TAG}" ]; then
	# For each tag directory in the output directory, ...
	while IFS= read -r -d '' TAGDIR; do
		analyze_tagdir "${TAGDIR}" "${DRY_RUN}"
	done < <(find output -mindepth 1 -maxdepth 1 -type d -print0 | sort -Vzr)
else
	analyze_tagdir "output/${FIXED_TAG}" "${DRY_RUN}"
fi
