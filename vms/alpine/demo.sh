#!/bin/sh

SLEEP=2

do_cmd() {
    local cmd=$1
    local sleep_condition=$2
    echo "k3s-server:~# $cmd"
    $cmd

    if [ -n "$sleep_condition" ]; then
        while $sleep_condition; do
            sleep $SLEEP
        done
    fi
}

do_cmd "kubectl get nodes"
do_cmd "kubectl get pods -o wide"

do_cmd "kubectl apply -f https://raw.githubusercontent.com/chp-io/MicroV/demo/vms/alpine/deployment.yaml" \
    '[ $(kubectl get pods -o wide | grep nginx-deployment | grep Running | wc -l) -ne 2 ]'

do_cmd "kubectl get pods -o wide"

do_cmd "kubectl expose deploy nginx-deployment --type=LoadBalancer --port=8080 --target-port=80" \
    'kubectl get svc -o wide | grep 192.168.122.250; [ $? -ne 0 ]'

do_cmd "kubectl get svc -o wide"
