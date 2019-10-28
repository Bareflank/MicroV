#!/bin/bash

./prefixes/x86_64-userspace-pe/bin/uvctl \
    --hvc \
    --ram 550000000 \
    --xsvm \
    --verbose \
    --kernel ../images/xsvm-vmlinux \
    --initrd ../images/xsvm-rootfs.cpio.gz
