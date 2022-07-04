#!/bin/sh
set -eux
HERE="$(dirname "$(readlink -f "$0")")"
[ "$#" -gt 0 ] || exit 2
"${HERE}/search-symtab.py" "$@" || "${HERE}/search-symtab-rel.py" "$@"
