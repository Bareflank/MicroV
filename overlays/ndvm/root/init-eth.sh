#!/bin/sh

if [[ $# -ne 2 ]]; then
    echo "USAGE: init-eth.sh <eth-iface> <vif-iface>"
    exit 22
fi

echo "Configuring NAT: $1 -> $2"

sysctl net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o $1 -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $2 -o $1 -j ACCEPT

iptables -I INPUT -p udp --dport 67 -i $2 -j ACCEPT # DHCP
iptables -I INPUT -p udp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
iptables -I INPUT -p tcp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
