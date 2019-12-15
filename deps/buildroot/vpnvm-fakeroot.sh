#!/bin/bash

# $1 == the path to the rootfs

pushd $1

rm -rf etc/systemd/system/multi-user.target.wants/named.service
rm -rf etc/systemd/system/multi-user.target.wants/dhcpd.service

ln -s ../../../lib/systemd/system/demo.service \
      etc/systemd/system/multi-user.target.wants/demo.service
ln -s ../../../lib/systemd/system/dhcpd.service \
      etc/systemd/system/multi-user.target.wants/dhcpd.service

popd
