#!/bin/bash
set -e

# Assumes an existing virbr0 with inet 192.168.122.1/24
BRIDGE=virbr0

SERVER_HOSTNAME="k3s-server"
SERVER_IP="192.168.122.250"
SERVER_MAC="DE:AD:BE:EF:27:B0"
SERVER_TAP=tap0

AGENT0_HOSTNAME="k3s-agent0"
AGENT0_IP="192.168.122.251"
AGENT0_MAC="DE:AD:BE:EF:27:B1"
AGENT0_TAP=tap1

AGENT1_HOSTNAME="k3s-agent1"
AGENT1_IP="192.168.122.252"
AGENT1_MAC="DE:AD:BE:EF:27:B2"
AGENT1_TAP=tap2

NODE2_HOSTNAME="k3s-agent2"
NODE2_IP="192.168.122.253"
NODE2_MAC="DE:AD:BE:EF:27:B3"
NODE2_TAP=tap3

USER_PASSWORD=kryptonite

ISO_URL="https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/x86_64/alpine-virt-3.15.2-x86_64.iso"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TMP_DIR=/tmp/alpine_demo
ISO_PATH=$TMP_DIR/$(basename $ISO_URL)

BOOT_SLEEP=5

BLU='\033[0;95m'
MAG='\033[0;94m'
RST='\033[0m'

# ------------------------------------------------------------------------------

setup_tap() {
  local tap_interface=$1

  if ! ip addr show $tap_interface; then
    sudo ip tuntap add dev $tap_interface mode tap user $USER
    sudo ip link set dev $tap_interface up
    sudo ip link set $tap_interface master $BRIDGE
  fi
}

build_guest_script() {
  local hostname=$1
  local ip_address=$2
  local color=$3

  local guest_script=${TMP_DIR}/setup_guest_${hostname}.sh
  local ps1="${color}\h${RST}:\w\# "

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

cat <<'EOF' > /root/.profile
export PS1="${ps1}"
EOF

_EOF

  if [ $hostname = k3s-server ]; then
    echo -ne "wget -O - -o /dev/null https://get.k3s.io | K3S_TOKEN=kryptonite sh -s - --node-taint CriticalAddonsOnly=true:NoExecute\n\n" >> $guest_script
  else
    echo -ne "wget -O - -o /dev/null https://get.k3s.io | K3S_URL=https://${SERVER_IP}:6443 K3S_TOKEN=kryptonite sh -\n\n" >> $guest_script
  fi

  echo $guest_script
}

# ------------------------------------------------------------------------------

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

# Setup taps
setup_tap tap0
setup_tap tap1
setup_tap tap2

# Setup scripts
server_script=$(build_guest_script $SERVER_HOSTNAME $SERVER_IP $RST)
agent0_script=$(build_guest_script $AGENT0_HOSTNAME $AGENT0_IP $BLU)
agent1_script=$(build_guest_script $AGENT1_HOSTNAME $AGENT1_IP $MAG)

# Commands to run
SERVER_CMD="$SCRIPT_DIR/alpine_iso_k3s.exp $SERVER_MAC $SERVER_TAP $ISO_PATH $USER_PASSWORD $server_script"
AGENT0_CMD="$SCRIPT_DIR/alpine_iso_k3s.exp $AGENT0_MAC $AGENT0_TAP $ISO_PATH $USER_PASSWORD $agent0_script"
AGENT1_CMD="$SCRIPT_DIR/alpine_iso_k3s.exp $AGENT1_MAC $AGENT1_TAP $ISO_PATH $USER_PASSWORD $agent1_script"

# Demo with tmux
tmux new-session -d 'k3s-demo' \; \
  split-window -c $PWD -h -d "echo server; sleep $(( 2*$BOOT_SLEEP )); $SERVER_CMD; bash" \; \
  split-window -c $PWD -v -d "echo agent1; sleep $(( 1*$BOOT_SLEEP )); $AGENT1_CMD; bash" \; \
  resize-pane -L 35 \; \
  split-window -c $PWD -h -d "echo agent0; sleep $(( 0*$BOOT_SLEEP )); $AGENT0_CMD; bash" \; \
  attach

# time $SERVER_CMD
