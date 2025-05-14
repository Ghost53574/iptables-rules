#!/bin/bash

source "./common.sh"
NMAP="$(which nmap)"
TARGET="12.23.45.67"
PORTS=(1025 1026 1027)
for PORT in ${PORTS[@]};
do
    print_info "${BASH_SOURCE[0]}" "Knocking on ${PORT}"
    ${NMAP} -Pn --host-timeout 201 --max-retries 0 -p ${PORT} ${TARGET} >/dev/null
    sleep 1
done
