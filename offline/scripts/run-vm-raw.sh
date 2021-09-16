#!/bin/bash
#
# This file was automatically generated by s2e-env at 2019-04-25 18:03:09.909337
#
# This script is used to run the S2E analysis. Additional QEMU command line
# arguments can be passed to this script at run time.
#

ENV_DIR="/home/alan/Work/s2e"
INSTALL_DIR="$ENV_DIR/install"
BUILD_DIR="$ENV_DIR/build"
BUILD=debug

# Comment this out to enable QEMU GUI
GRAPHICS=-nographic

if [ "x$1" = "xdebug" ]; then
  DEBUG=1
  shift
fi

IMAGE_PATH="$ENV_DIR/images/debian-9.2.1-x86_64/image.raw.s2e"
IMAGE_JSON="$(dirname $IMAGE_PATH)/image.json"

if [ ! -f "$IMAGE_PATH" -o ! -f "$IMAGE_JSON" ]; then
    echo "$IMAGE_PATH and/or $IMAGE_JSON do not exist. Please check that your images are build properly."
    exit 1
fi

QEMU_EXTRA_FLAGS=$(jq -r '.qemu_extra_flags' "$IMAGE_JSON")
QEMU_MEMORY=$(jq -r '.memory' "$IMAGE_JSON")
QEMU_SNAPSHOT=$(jq -r '.snapshot' "$IMAGE_JSON")
QEMU_DRIVE="-drive file=$IMAGE_PATH,format=raw,cache=writeback"

#QEMU_NET="-net nic,model=e1000 -net bridge,br=qemubr0"

QEMU="$INSTALL_DIR/bin/qemu-system-x86_64"

$QEMU $QEMU_DRIVE \
    -k en-us $GRAPHICS -monitor null -m $QEMU_MEMORY -enable-kvm \
    -serial file:serial.txt $QEMU_NET #$QEMU_EXTRA_FLAGS

