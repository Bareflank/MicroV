#!/bin/bash

# $1 == the path to the rootfs

pushd $1

ln -s ../../../lib/systemd/system/demo.service \
      etc/systemd/system/multi-user.target.wants/demo.service

popd
