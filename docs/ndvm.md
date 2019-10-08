General instructions for using the NDVM

* Connect the physical NIC and ensure it has an IP.
* In the domain with netfront, attach a new network device
  with the NDVM as the backend. For dom0 as netfront this would be:

  $ xl network-attach 0 backend=ndvm

* Ensure the front-end has an IP before continuing. Usually if dhcpcd is
  installed and DHCP is being used in the backend, it should acquire one
  after the network device is created.
* In the NDVM, configure iptables for NAT forwarding. In this example,
  'phy0' is the interface name of the physical device and 'vif0.0' is the
  netback interface. The phy0 has an IP of 192.168.0.17/24 and vif0.0 has an
  IP of 169.254.159.162/16:

  # sysctl net.ipv4.ip_forward=1
  # iptables -t nat -A POSTROUTING -o phy0 -j MASQUERADE
  # iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # iptables -A FORWARD -i vif0.0 -o phy0 -j ACCEPT

* Now open up DHCP and DNS ports (optional):

  # iptables -I INPUT -p udp --dport 67 -i vif0.0 -j ACCEPT # DHCP
  # iptables -I INPUT -p udp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS
  # iptables -I INPUT -p tcp --dport 53 -s 169.254.0.0/16 -j ACCEPT # DNS

* In the frontend domain, add vif0.0 as the default gateway. Here 'eth0' is
  the name of the netfront interface:

  # ip route add default via 169.254.159.162 dev eth0

* From here you should have a working connection. You may need to add a
  nameserver entry to /etc/resolv.conf in order for DNS to work
