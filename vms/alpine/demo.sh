#!/bin/sh
set -e

SLEEP=${1:-20}
OUT_FILE=/tmp/out.txt

sleep_till() {
    local sleep_condition=$1

    if [ -n "$sleep_condition" ]; then
        while eval $sleep_condition; do
            sleep $SLEEP
        done
    fi
}

do_cmd() {
    local cmd=$1
    local print_output_file=$2

    echo "k3s-server:~# $cmd"
    if $print_output_file; then
        cat $OUT_FILE
    else
        $cmd > $OUT_FILE
    fi
}

sleep $SLEEP

# Wait for nodes to be ready
echo "Waiting for nodes to be ready..."
while kubectl get nodes>$OUT_FILE; [ $(cat $OUT_FILE | grep ' Ready' | wc -l) -ne 3 ]; do
    sleep $SLEEP
done

# Show nodes
cmd="kubectl get nodes"
echo "k3s-server:~# $cmd"
cat $OUT_FILE

#do_cmd "kubectl get pods -o wide" false

# Apply configuration
cmd="kubectl apply -f https://raw.githubusercontent.com/chp-io/MicroV/demo/vms/alpine/deployment.yaml"
echo "k3s-server:~# $cmd"
$cmd

# Wait for pods to be ready
echo "Waiting for pods to be ready..."
while kubectl get pods -o wide 2>/dev/null >$OUT_FILE; [ $(cat $OUT_FILE | grep nginx-deployment | grep Running | wc -l) -ne 2 ]; do
    if cat $OUT_FILE | grep "CrashLoopBackOff"; then
        cat $OUT_FILE
        sh
        echo Resuming...
    fi
    sleep $SLEEP
done

# Show pods
cmd="kubectl get pods -o wide"
echo "k3s-server:~# $cmd"
cat $OUT_FILE

# Start load balancer
cmd="kubectl expose deploy nginx-deployment --type=LoadBalancer --port=8080 --target-port=80"
echo "k3s-server:~# $cmd"
$cmd

# Wait services to be ready
echo "Waiting for services to be ready..."
while kubectl get svc -o wide > $OUT_FILE; cat $OUT_FILE | grep 192.168.122.250; [ $? -ne 0 ]; do
    sleep $SLEEP
done

# Show services
cmd="kubectl get svc -o wide"
echo "k3s-server:~# $cmd"
cat $OUT_FILE
