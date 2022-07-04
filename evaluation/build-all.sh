#!/bin/sh

set -eu

TAG="$1"

./build-reference.sh "${TAG}"
./build-images.sh "${TAG}"
./build-randstruct.sh "${TAG}" 2
