#!/bin/sh

phy="wlp0s20f3"
vif="vif2.0"
cidr="169.254.0.0/16"
ssid="yourmom"
pass="yourmom"

/root/init-wifi.sh $phy $ssid $pass

present=$(ip a | grep $vif)
while [[ $? -ne 0 ]];
do
    sleep 1
    present=$(ip a | grep $vif)
done

/root/init-nat.sh $phy $vif $cidr
