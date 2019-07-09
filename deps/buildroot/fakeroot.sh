#!/bin/bash

# $1 == the path to the rootfs

rm -rf $1/usr/lib/systemd/system/systemd-modules-load.service
rm -rf $1/usr/lib/systemd/system/systemd-update-utmp.service
rm -rf $1/usr/lib/systemd/system/systemd-update-utmp-runlevel.service
rm -rf $1/usr/lib/systemd/system/sysinit.target.wants/systemd-update-utmp.service
rm -rf $1/usr/lib/systemd/system/sysinit.target.wants/systemd-update-utmp-runlevel.service

rm -rf $1/etc/systemd/system/network.service
rm -rf $1/etc/systemd/system/multi-user.target.wants/network.service

echo '/proc/xen /proc/xen xenfs' >> $1/etc/fstab
