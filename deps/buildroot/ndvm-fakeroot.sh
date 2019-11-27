#!/bin/bash

# $1 == the path to the rootfs

pushd $1

rm -rf usr/lib/systemd/system/systemd-modules-load.service
rm -rf usr/lib/systemd/system/systemd-update-utmp.service
rm -rf usr/lib/systemd/system/systemd-update-utmp-runlevel.service
rm -rf usr/lib/systemd/system/sysinit.target.wants/systemd-update-utmp.service
rm -rf usr/lib/systemd/system/sysinit.target.wants/systemd-update-utmp-runlevel.service

rm -rf etc/systemd/system/network.service
rm -rf etc/systemd/system/multi-user.target.wants/network.service

ln -s ../../../lib/systemd/system/demo.service \
      etc/systemd/system/multi-user.target.wants/demo.service

popd
