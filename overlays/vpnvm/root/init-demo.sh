#!/bin/sh

phy="eth0"
vpn="wg0"
vif="vif32751.0"

#
# Wait for the physical link to come up
#

present=$(ip a | grep $phy)
while [[ $? -ne 0 ]];
do
    sleep 1
    present=$(ip a | grep $phy)
done

#
# Assign an IP, default gateway, and DNS server.
# The gateway IP is the IP of vif2.0 in the NDVM.
#

echo 'nameserver 8.8.8.8' > /etc/resolv.conf
echo 'nameserver 8.8.4.4' >> /etc/resolv.conf
ip addr add 169.254.249.58/16 dev $phy
ip link set dev $phy up
ip route add default via 169.254.249.59 dev $phy

#
# Start the wireguard tunnel on interface wg0.
# This routes all traffic through the VPN server
# in Paris on a 192.168.4.0/24 subnet.
#

vpn_up=$(/root/wgclient.sh default-route)
while [[ $? -ne 0 ]];
do
    sleep 1
    vpn_up=$(/root/wgclient.sh default-route)
done

present=$(ip a | grep $vpn)
while [[ $? -ne 0 ]];
do
    sleep 1
    present=$(ip a | grep $vpn)
done

#
# Wait for the vif backend to come up
#

present=$(ip a | grep $vif)
while [[ $? -ne 0 ]];
do
    sleep 1
    present=$(ip a | grep $vif)
done

#
# Initialize NAT for the frontend
#

ip addr add 192.168.5.1/24 dev $vif
ip link set up dev $vif
/root/init-nat.sh $vpn $vif 192.168.5.0/24
