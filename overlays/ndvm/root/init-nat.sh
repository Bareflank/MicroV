#!/bin/sh

if [[ $# -ne 2 ]]; then
    echo "USAGE: init-nat.sh <phy-iface> <vif-iface>"
    echo ""
    echo "Where <phy-iface> is the name of the interface connected to"
    echo "the Internet and <vif-iface> is the vif interface to enable NAT for"
    exit 22
fi

phy=$1
vif=$2

echo "Configuring NAT: $phy -> $vif"

sysctl net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o $phy -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $vif -o $phy -j ACCEPT

iptables -I INPUT -p udp --dport 67 -i $vif -j ACCEPT # DHCP
iptables -I INPUT -p udp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
iptables -I INPUT -p tcp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
