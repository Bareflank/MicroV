#!/bin/bash

# $1 == the path to the rootfs

pushd $1

# The vpnvm only uses xenstore-{read,write} and its dependencies, so
# we remove the rest of the unused libraries and executables from the
# installed from xen-tools

rm -rf var/lib/xen
rm -rf var/lib/xen/xenpaging
rm -rf var/lib/xenstored
rm -rf var/log/xen
rm -rf usr/bin/xenstore-exists
rm -rf usr/bin/xenstore-chmod
rm -rf usr/bin/xen-cpuid
rm -rf usr/bin/xenstore-list
rm -rf usr/bin/xenstore
rm -rf usr/bin/xenstore-control
rm -rf usr/bin/xenstore-ls
rm -rf usr/bin/xencov_split
rm -rf usr/bin/xencons
#rm -rf usr/bin/xenstore-write
rm -rf usr/bin/xenstore-watch
rm -rf usr/bin/xenstore-rm
#rm -rf usr/bin/xenstore-read
rm -rf usr/bin/xen-detect
rm -rf usr/lib/libxenlight.so.4.13.0
rm -rf usr/lib/modules-load.d/xen.conf
rm -rf usr/lib/libxenlight.so
rm -rf usr/lib/libxenguest.so
rm -rf usr/lib/libxenctrl.so
rm -rf usr/lib/libxencall.so.1.2
rm -rf usr/lib/libxenevtchn.so
#rm -rf usr/lib/libxentoolcore.so.1.0
rm -rf usr/lib/libxenlight.so.4.13
rm -rf usr/lib/libxenctrl.so.4.13.0
rm -rf usr/lib/libxenctrl.so.4.13
#rm -rf usr/lib/libxenstore.so.3.0.3
rm -rf usr/lib/libxentoollog.so.1.0
rm -rf usr/lib/libxentoollog.so.1
rm -rf usr/lib/libxengnttab.so.1.2
rm -rf usr/lib/libxendevicemodel.so.1
#rm -rf usr/lib/libxenstore.so.3.0
#rm -rf usr/lib/xen
rm -rf usr/lib/xen/bin/xendomains
rm -rf usr/lib/xen/bin/init-xenstore-domain
rm -rf usr/lib/xen/bin/xenconsole
rm -rf usr/lib/xen/bin/xenpvnetboot
rm -rf usr/lib/xen/bin/xenpaging
rm -rf usr/lib/xen/bin/xen-init-dom0
rm -rf usr/lib/libxencall.so
rm -rf usr/lib/libxenforeignmemory.so.1.3
#rm -rf usr/lib/libxenstore.so
rm -rf usr/lib/libxengnttab.so
#rm -rf usr/lib/libxentoolcore.so
rm -rf usr/lib/libxenevtchn.so.1.1
rm -rf usr/lib/systemd/system/xendomains.service
rm -rf usr/lib/systemd/system/xen-init-dom0.service
rm -rf usr/lib/systemd/system/xen-qemu-dom0-disk-backend.service
rm -rf usr/lib/systemd/system/proc-xen.mount
rm -rf usr/lib/systemd/system/xenstored.service
rm -rf usr/lib/systemd/system/var-lib-xenstored.mount
rm -rf usr/lib/systemd/system/xenconsoled.service
rm -rf usr/lib/systemd/system/xen-watchdog.service
rm -rf usr/lib/systemd/system/xendriverdomain.service
rm -rf usr/lib/python2.7/site-packages/xen
rm -rf usr/lib/python2.7/site-packages/xen-3.0-py2.7.egg-info
rm -rf usr/lib/libxendevicemodel.so.1.3
rm -rf usr/lib/libxendevicemodel.so
rm -rf usr/lib/libxenvchan.so.4.13
rm -rf usr/lib/libxenguest.so.4.13
rm -rf usr/lib/libxenvchan.so.4.13.0
rm -rf usr/lib/libxenevtchn.so.1
rm -rf usr/lib/libxenforeignmemory.so.1
#rm -rf usr/lib/libxentoolcore.so.1
rm -rf usr/lib/libxengnttab.so.1
rm -rf usr/lib/libxenforeignmemory.so
rm -rf usr/lib/libxenguest.so.4.13.0
rm -rf usr/lib/libxencall.so.1
rm -rf usr/lib/libxentoollog.so
rm -rf usr/lib/libxenvchan.so
rm -rf usr/sbin/xenlockprof
rm -rf usr/sbin/xen-diag
rm -rf usr/sbin/xen-lowmemd
rm -rf usr/sbin/xenperf
rm -rf usr/sbin/xenconsoled
rm -rf usr/sbin/xenpm
rm -rf usr/sbin/xenwatchdogd
rm -rf usr/sbin/xen-mfndump
rm -rf usr/sbin/xen-hptool
rm -rf usr/sbin/xen-hvmctx
rm -rf usr/sbin/xenstored
rm -rf usr/sbin/xen-livepatch
rm -rf usr/sbin/xencov
rm -rf usr/sbin/xen-hvmcrash
rm -rf etc/init.d/xendomains
rm -rf etc/init.d/xen-watchdog
rm -rf etc/init.d/xencommons
rm -rf etc/init.d/xendriverdomain
rm -rf etc/xen
rm -rf etc/xen/scripts/xen-script-common.sh
rm -rf etc/xen/scripts/launch-xenstore
rm -rf etc/xen/scripts/xen-hotplug-common.sh
rm -rf etc/xen/scripts/xen-network-common.sh
rm -rf etc/default/xendomains
rm -rf etc/default/xencommons
rm -rf run/xen
rm -rf run/xenstored

rm -rf usr/lib/systemd/system/systemd-modules-load.service
rm -rf etc/systemd/system/multi-user.target.wants/systemd-modules-load.service
rm -rf etc/systemd/system/multi-user.target.wants/named.service
rm -rf etc/systemd/system/multi-user.target.wants/dhcpd.service

ln -s ../../../lib/systemd/system/demo.service \
      etc/systemd/system/multi-user.target.wants/demo.service
ln -s ../../../lib/systemd/system/dhcpd.service \
      etc/systemd/system/multi-user.target.wants/dhcpd.service

popd
