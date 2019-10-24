#!/bin/bash

sudo ./prefixes/x86_64-userspace-elf/bin/uvctl \
    --hvc \
    --ram 380000000 \
    --xsvm \
    --verbose \
    --kernel ../cache/brbuild/xsvm/images/vmlinux \
    --initrd ../cache/brbuild/xsvm/images/rootfs.cpio.gz
