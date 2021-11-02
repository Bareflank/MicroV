#!/bin/bash
set -e

# Notes:
#
# Before running this script, OVMF needs to be installed. e.g. on Ubuntu:
# sudo apt install ovmf
#

# Default variables

if [ -z ${QEMU_PATH+x} ]; then
  QEMU_PATH=$(dirname $(which qemu-system-x86_64))
fi

if [ -z ${STRACE_PATH+x} ]; then
  STRACE_PATH=$(dirname $(which strace))
fi

if [ -z ${BUILD_DIR+x} ]; then
  BUILD_DIR="$(pwd)/qemu"
fi

if [ -z ${KERNEL_PATH+x} ]; then
  KERNEL_PATH="$(pwd)/vm_cross_compile/bin/bzImage-debug"
fi

if [ -z ${INITRD_PATH+x} ]; then
  INITRD_PATH="$(pwd)/vm_cross_compile/bin/initrd.cpio.gz"
fi

echo STRACE_PATH=${STRACE_PATH}
echo QEMU_PATH=${QEMU_PATH}
echo BUILD_DIR=${BUILD_DIR}
echo KERNEL_PATH=${KERNEL_PATH}
echo INITRD_PATH=${INITRD_PATH}
echo

setup() {
  mkdir -p $BUILD_DIR/vm_storage/EFI/BOOT

  cp /usr/share/OVMF/OVMF_CODE.fd $BUILD_DIR/
  cp /usr/share/OVMF/OVMF_VARS.fd $BUILD_DIR/

  shell_url="https://github.com/tianocore/edk/blob/master/Other/Maintained/Application/UefiShell/bin/x64/Shell_Full.efi?raw=true"
  wget -O $BUILD_DIR/vm_storage/EFI/BOOT/BOOTX64.EFI $shell_url
}

run() {
  echo Exit console with: ctrl + a, x

  $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -drive format=raw,file=fat:rw:$BUILD_DIR/vm_storage \
    -bios $BUILD_DIR/OVMF_CODE.fd \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_efi.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -m size=64M \
    -nographic
}

run_linux() {
  mkdir -p ${BUILD_DIR}

  echo Exit console with: ctrl + a, x

  $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -kernel ${KERNEL_PATH} \
    -initrd ${INITRD_PATH} \
    -append "console=uart,io,0x3F8,115200n8,keep" \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_linux.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -m size=64M \
    -nographic
}

case "$1" in
  setup)
    setup
    ;;

  run)
    run
    ;;

  run_linux)
    run_linux
    ;;

  *)
    echo $"Usage: $0 {setup|run|run_linux}"
    exit 1
esac
