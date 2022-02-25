#!/bin/bash
set -e

# Notes:
#
# Before running this script, OVMF needs to be installed. e.g. on Ubuntu:
# sudo apt install ovmf
#

# Default variables

if [ -z ${QEMU_PATH+x} ]; then
  # QEMU_PATH=$(dirname $(which qemu-system-x86_64))
  QEMU_PATH="${HOME}/qemu/x86_64-softmmu/"
fi

if [ -z ${STRACE_PATH+x} ]; then
  STRACE_PATH=$(dirname $(which strace))
fi

if [ -z ${BUILD_DIR+x} ]; then
  BUILD_DIR="$(pwd)/qemu"
fi

if [ -z ${KERNEL_PATH+x} ]; then
  KERNEL_PATH="${HOME}/microv/build/qemu/vm_storage/EFI/bzImage.efi"
fi

if [ -z ${INITRD_PATH+x} ]; then
  INITRD_PATH="$(pwd)/vm_cross_compile/bin/initrd.cpio.gz"
fi

if [ -z ${VM_NAME+x} ]; then
  VM_NAME=32bit_endless_loop_test
fi

if [[ -z ${BIOS_PATH+x} ]]; then
  BIOS_PATH="${HOME}/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd"
fi

if [[ -f $BIOS_PATH ]]; then
  BIOS_ARG="-bios ${BIOS_PATH}"
else
  echo ${BIOS_PATH} does not exist. Using default bios instead.
  BIOS_PATH=
  BIOS_ARG=
fi

TASKSET="taskset 4" # pin qemu to CPU #2
# TASKSET=

echo STRACE_PATH=${STRACE_PATH}
echo QEMU_PATH=${QEMU_PATH}
echo BUILD_DIR=${BUILD_DIR}
echo KERNEL_PATH=${KERNEL_PATH}
echo INITRD_PATH=${INITRD_PATH}
echo BIOS_PATH=${BIOS_PATH}
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
  $TASKSET $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -drive format=raw,file=fat:rw:$BUILD_DIR/vm_storage \
    -bios ${BIOS_PATH} \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_efi.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -m size=64M \
    -nographic \
    -debugcon file:debugcon.log -global isa-debugcon.iobase=0x402

  grep KVM $BUILD_DIR/strace.log > $BUILD_DIR/strace_kvm_only.log
}

#######################################################################################

best_run() {
  echo BEST RUN
  echo Exit console with: ctrl + a, x
    # -drive format=raw,file=fat:rw:$BUILD_DIR/vm_storage \

  $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $TASKSET $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -drive format=raw,file=fat:rw:$BUILD_DIR/vm_storage \
    -bios ${BIOS_PATH} \
    -m size=64M \
    -nographic \
    -debugcon file:best.log -global isa-debugcon.iobase=0x402 \
    -D qemu-dbg.log

# -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_chardev.log,signal=off \
#     -serial chardev:char0 -mon chardev=char0 \
    # -s -S

}

run_linux_best() {
  mkdir -p ${BUILD_DIR}

  echo Exit console with: ctrl + a, x

  $TASKSET $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -bios ${BIOS_PATH} \
    -m size=2G \
    -hda /home/sharkeyj/2004_serial.img \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_linux.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -nographic \
    -D qemu-dbg.log
    # --trace 'kvm_*' \
    # -s -S \

    # -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_linux.log,signal=off \
    # -serial chardev:char0 -mon chardev=char0 \
    # -nographic \
    # -boot d\
    # -cdrom /home/sharkeyj/Downloads/ubuntu-20.04.4-live-server-amd64.iso \

  grep KVM $BUILD_DIR/strace.log > $BUILD_DIR/strace_kvm_only.log
}

#######################################################################################

run_linux() {
  mkdir -p ${BUILD_DIR}

  echo Exit console with: ctrl + a, x

  $TASKSET $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -bios ${BIOS_PATH} \
    -kernel ${KERNEL_PATH} \
    -initrd ${INITRD_PATH} \
    -append "console=uart,io,0x3F8,115200n8,keep noapic" \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_linux.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -m size=296M \
    -nographic \
    -debugcon file:best.log -global isa-debugcon.iobase=0x402 \
    -D qemu-dbg.log
    # --trace 'kvm_*' \
    # -s -S \


  grep KVM $BUILD_DIR/strace.log > $BUILD_DIR/strace_kvm_only.log
}

run_raw() {
  mkdir -p ${BUILD_DIR}

  echo VM_NAME=${VM_NAME}
  echo

  echo Exit console with: ctrl + a, x

  $TASKSET $STRACE_PATH/strace -f -o $BUILD_DIR/strace.log  \
  $QEMU_PATH/qemu-system-x86_64 \
    -machine type=q35,accel=kvm \
    -cpu host \
    -device loader,file=$BUILD_DIR/../vm_cross_compile/bin/${VM_NAME},addr=0x1000,cpu-num=0,force-raw=on \
    -chardev stdio,id=char0,mux=on,logfile=$BUILD_DIR/qemu_linux.log,signal=off \
    -serial chardev:char0 -mon chardev=char0 \
    -m size=2M \
    -nographic \
    --trace 'kvm_*' \
    # -s -S \

  grep KVM $BUILD_DIR/strace.log > $BUILD_DIR/strace_kvm_only.log
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

  run_linux_best)
    run_linux_best
    ;;

  best_run)
    best_run
    ;;

  run_raw)
    run_raw
    ;;

  *)
    echo $"Usage: $0 {setup|run|run_linux}"
    exit 1
esac
