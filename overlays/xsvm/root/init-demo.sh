#!/bin/sh

xl create /etc/xen/ndvm.cfg
xl create /etc/xen/vpnvm.cfg
xl network-attach vpnvm backend=ndvm
