#!/bin/sh

if [[ $# -ne 3 ]]; then
    echo "USAGE: init-wifi.sh <wireless-iface> <ssid> <password>"
    exit 22
fi

config=/etc/wpa_supplicant.conf

touch $config

echo 'country=US' >> $config
echo 'p2p_disabled=1' >> $config

wpa_passphrase $2 $3 >> $config
wpa_supplicant -B -i $1 -c $config
