#!/bin/sh

#/root/init-wifi.sh <iface> <ssid> <pass>

present=$(ip a | grep vif2.0)

while [[ $? -ne 0 ]];
do
    sleep 1
    present=$(ip a | grep vif2.0)
done

#/root/init-nat.sh <iface> vif2.0
/root/init-nat.sh enp2s0 vif2.0 169.254.0.0/16
