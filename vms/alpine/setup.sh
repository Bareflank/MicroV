#!/bin/bash
set -e

# Assumes an existing virbr0 with inet 192.168.122.1/24
BRIDGE=virbr0

MASTER_HOSTNAME="k3s-controller"
MASTER_IP="192.168.122.250"
MASTER_MAC="DE:AD:BE:EF:27:B0"
MASTER_TAP=tap0

NODE0_HOSTNAME="k3s-node0"
NODE0_IP="192.168.122.251"
NODE0_MAC="DE:AD:BE:EF:27:B1"
NODE0_TAP=tap1

NODE1_HOSTNAME="k3s-node1"
NODE1_IP="192.168.122.252"
NODE1_MAC="DE:AD:BE:EF:27:B2"
NODE1_TAP=tap2

NODE2_HOSTNAME="k3s-node2"
NODE2_IP="192.168.122.253"
NODE2_MAC="DE:AD:BE:EF:27:B3"
NODE2_TAP=tap3

USER_PASSWORD=kryptonite

ISO_URL="https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/x86_64/alpine-virt-3.15.1-x86_64.iso"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TMP_DIR=/tmp/alpine_demo
ISO_PATH=$TMP_DIR/$(basename $ISO_URL)

mkdir -p $TMP_DIR

if [ ! -f $ISO_PATH ]; then
  wget $ISO_URL -P $TMP_DIR
fi

if ! ip addr show $BRIDGE; then
    echo "Please setup a bridge $BRIDGE with inet 192.168.122.1/24"
fi

if ! command -v expect &> /dev/null
then
    echo "Please install 'expect'"
    exit
fi

setup_tap() {
  local tap_interface=$1

  if ! ip addr show $tap_interface; then
    sudo ip tuntap add dev $tap_interface mode tap user $USER
    sudo ip link set dev $tap_interface up
    sudo ip link set $tap_interface master $BRIDGE
  fi
}

echo Setting up network...
setup_tap tap0
setup_tap tap1

build_guest_script() {
  local hostname=$1
  local ip_address=$2
  local guest_script=$TMP_DIR/setup_guest_${hostname}.sh

  cat > $guest_script <<_EOF
#!/bin/bash

setup-timezone -z US/Eastern
setup-keymap us us

setup-hostname -n ${hostname}
rc-service hostname --quiet restart

cat <<'EOF' > /etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0

iface eth0 inet static
        address ${ip_address}/24
        gateway 192.168.122.1
EOF

cat <<'EOF' > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

/etc/init.d/networking restart

setup-ntp -c busybox

_EOF

  if [ $hostname = k3s-controller ]; then
    echo -ne "wget -O - -o /dev/null https://get.k3s.io | K3S_TOKEN=kryptonite sh -\n\n" >> $guest_script
  else
    echo -ne "wget -O - -o /dev/null https://get.k3s.io | K3S_URL=https://${MASTER_IP}:6443 K3S_TOKEN=kryptonite sh -\n\n" >> $guest_script
  fi

  echo $guest_script
}

master_script=$(build_guest_script $MASTER_HOSTNAME $MASTER_IP)
node0_script=$(build_guest_script $NODE0_HOSTNAME $NODE0_IP)

# Start
MASTER_CMD="$SCRIPT_DIR/alpine_iso_k3s.exp $MASTER_MAC $MASTER_TAP $ISO_PATH $USER_PASSWORD $master_script"
NODE0_CMD="$SCRIPT_DIR/alpine_iso_k3s.exp $NODE0_MAC $NODE0_TAP $ISO_PATH $USER_PASSWORD $node0_script"

tmux new-session -d 'k3s-demo' \; \
  split-window -c $PWD -h -d $NODE0_CMD \; \
  split-window -c $PWD -v -d "sleep 120; $MASTER_CMD" \; \
  attach

# time $MASTER_CMD
