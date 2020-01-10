#!/bin/sh

if [[ $# -ne 3 ]]; then
    echo "USAGE: init-nat.sh <phy-iface> <vif-iface> <cidr-mask>"
    echo "Where <phy-iface> is the interface connected to the Internet"
    echo "      <vif-iface> is the vif interface to enable NAT for"
    echo "      <cidr-mask> is the subnet the vif is on in CIDR notation"
    exit 22
fi

phy=$1
vif=$2
cidr=$3

echo "Configuring NAT for $phy -> $vif on subnet $cidr"

sysctl net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o $phy -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $vif -o $phy -j ACCEPT

iptables -I INPUT -p udp --dport 53 -s $cidr -j ACCEPT # DNS
iptables -I INPUT -p tcp --dport 53 -s $cidr -j ACCEPT # DNS
