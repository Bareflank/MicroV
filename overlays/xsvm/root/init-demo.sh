#!/bin/sh

connected=4
vpnvm_domid=2
winpv_domid=32751

vif_backend="/local/domain/$vpnvm_domid/backend/vif/$winpv_domid/0"
vif_frontend="/local/domain/$winpv_domid/device/vif/0"
winpv_drv="/local/domain/$winpv_domid/drivers/0"

#
# Create the NDVM and the VPNVM, then connect netfront
# in the VPNVM to netback in the NDVM
#

xl create /etc/xen/ndvm.cfg
xl create /etc/xen/vpnvm.cfg
xl network-attach vpnvm backend=ndvm

#
# "Create" the Windows PV domain and signal
# xenstore readiness to the Windows PV xenbus driver
#

xl create /etc/xen/winpv.cfg
/usr/lib/xen/bin/init-winpv

#
# Wait for xenbus to acknowledge
#

xenbus_ready=$(xenstore-read $winpv_drv | grep XENBUS)
while [[ $? -ne 0 ]];
do
    sleep 0.2
    xenbus_ready=$(xenstore-read $winpv_drv | grep XENBUS)
done

#
# Attach the Windows PV netfront to the netback in the VPNVM
#

xl network-attach winpv backend=vpnvm

#
# Wait for xenvif to signal its connected
#

xenvif_ready=$(xenstore-read $vif_frontend/state | grep $connected)
while [[ $? -ne 0 ]];
do
    sleep 0.2
    xenvif_ready=$(xenstore-read $vif_frontend/state | grep $connected)
done

#
# Signal to VPNVM netback that Windows netfront is ready
#

xenstore-write $vif_backend/state $connected
