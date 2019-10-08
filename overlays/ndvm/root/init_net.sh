#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "USAGE: init_net.sh <phy-iface>"
    exit 22
fi

echo "Configuring interface: $1"

wpa_supplicant -B -i $1 -c /etc/wpa_supplicant.conf
sysctl net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o $1 -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i vif0.0 -o $1 -j ACCEPT

iptables -I INPUT -p udp --dport 67 -i vif0.0 -j ACCEPT # DHCP
iptables -I INPUT -p udp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
iptables -I INPUT -p tcp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
