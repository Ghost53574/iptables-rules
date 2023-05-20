#!/bin/bash

source "./helper_funcs.sh"

NMAP="$(which nmap)"
TARGET="#target"
PORTS=(#ports)
for PORT in ${PORTS[@]};
do
    print_info "port knocking" "Knocking on ${PORT}"
    ${NMAP} -Pn --host-timeout 201 --max-retries 0 -p ${PORT} ${TARGET} >/dev/null
    sleep 1
done
ssh -i ~/Documents/s1_rsa -p #SSH root@c0z.red
