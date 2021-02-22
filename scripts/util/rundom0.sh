#!/bin/bash

# This is a helper script used to run guests with uvctl.
# Currently the size of the xsvm rootfs.cpio.gz varies depending
# what packages are installed and what additional vms are compiled
# in to it, so you may need to adjust the --ram option if you're
# seeing initramfs write errors on boot.
#
# Obviously adjust any paths as needed for your system. Also,
# be sure that the builder driver is loaded prior to running this
# script (i.e. set BUILD_BUILDER to ON in your config.cmake, then
# run make builder_build && make builder_load).
#
# To passthrough network devices to the ndvm, add a line such as
#
#  --cmdline "xen-pciback.passthrough=1 xen-pciback.hide=(bb:dd.f)"
#
# below, where bb:dd.f is the bus/device/function of the device.
# You can concatenate multiple (bb:dd.f)'s given to hide= if there
# is more than one network device you want to passthrough. Note
# that passthrough works only if 1) the hypervisor has been started
# from EFI (i.e. ENABLE_BUILD_EFI is ON in your config.cmake, and
# bareflank.efi is run prior to launching the host OS) and 2) visr
# has been built and loaded, using steps analagous to builder above.

sudo ./prefixes/x86_64-userspace-elf/bin/uvctl \
    --hvc \
    --ram 550000000 \
    --xsvm \
    --verbose \
    --kernel ../cache/brbuild/xsvm/images/vmlinux \
    --initrd ../cache/brbuild/xsvm/images/rootfs.cpio.gz
