#!/bin/bash
OUTPUT="$(pwd)/output"
if [ "$#" -ge 2 ]; then
    if [ "$1" = "--output" ]; then
        OUTPUT="$2"
        shift 2
    fi
fi
exec docker run --rm --mount type=bind,source="${OUTPUT}",dst=/output -it build-kernel "$@"
