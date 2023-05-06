#!/bin/bash

source "./helper_funcs.sh"

TIMESTAMP="$(date +%s)"
SCRIPT_NAME="iptables"

# Change this to suit your needs
INTERFACE="eth0"
DISABLE_ICMP=1
SSH_PORT=65534
ARGUMENTS=$@

IPTABLES="$(which iptables)"
if [[ -z "${IPTABLES}" ]];
then
    print_error "${SCRIPT_NAME}" "iptables is not installed"
    exit 1
fi

IPTABLES_SAVE="$(which iptables-save)"
if [[ -z "${IPTABLES_SAVE}" ]];
then
    print_warning "${SCRIPT_NAME}" "iptables-save is not installed, no backups available"
fi

IP_SET="$(which ipset)"
if [[ -z "${IPTABLES_SAVE}" ]];
then
    print_warning "${SCRIPT_NAME}" "ipset is not installed"
fi

function banner () {
    echo """
██╗██████╗ ████████╗ █████╗ ██████╗ ██╗     ███████╗███████╗
██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝
██║██████╔╝   ██║   ███████║██████╔╝██║     █████╗  ███████╗
██║██╔═══╝    ██║   ██╔══██║██╔══██╗██║     ██╔══╝  ╚════██║
██║██║        ██║   ██║  ██║██████╔╝███████╗███████╗███████║
╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝
"""

    print_menu "[ - ]" "Booting Up Menu.."
    sleep 1
    print_menu "[ - ]" "Loading Menu [${LIGHTGREEN}########                 ${LIGHTRED}(38%)"
    sleep 1
    print_menu "[ - ]" "Loading Menu [${LIGHTGREEN}###################      ${LIGHTRED}(80%)"
    sleep 1
    print_menu "[ - ]" "Loading Menu [${LIGHTCYAN}######################## ${LIGHTRED}(100%)"
    sleep 1
}

function save_table () {
    if [[ ! -z "${IPTABLES_SAVE}" ]];
    then
        print_info "${SCRIPT_NAME}" "Backing up current rules"
        ${IPTABLES_SAVE} > "${TIMESTAMP}_iptables.bak"
    fi
    print_good "${SCRIPT_NAME}" "[+] Saved iptables rules"
}

function restore_table () {
    latest_backup=$(find . -name '*_iptables.bak' | awk -F'_' '{print substr($1,3)}' | sort -rn | head -n 1)
    if [[ ! -z "${latest_backup}" ]];
    then
        read -p  "Do you want to restore ${latest_backup}_iptables.bak (y/n)? " RESTORE
        case "${RESTORE}" in
            "y"|"Y")
                ${IPTABLES}-restore "${latest_backup}_iptables.bak"
            ;;
            *)
            ;;
        esac
        echo 0
    else
        echo 1
    fi
}

function reset_table () {
    print_info "${SCRIPT_NAME}" "[+] Reset table rules"
    ${IPTABLES} -P INPUT ACCEPT
    ${IPTABLES} -P FORWARD ACCEPT
    ${IPTABLES} -P OUTPUT ACCEPT
    ${IPTABLES} -t nat -F
    ${IPTABLES} -t mangle -F
    ${IPTABLES} -F
    ${IPTABLES} -X
    print_good "${SCRIPT_NAME}" "[+] Reset done"
}

function block_prerouting ( ) {
    print_info "${SCRIPT_NAME}" "[ + ] Prerouting blocking"
    print_info "${SCRIPT_NAME}" "[ + ] Block INVALID packets"
    ${IPTABLES} -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
    print_info "${SCRIPT_NAME}" "[ + ] Block weird MSS valued packets"
    ${IPTABLES} -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
    print_info "${SCRIPT_NAME}" "[ + ] Blocking private IP address ranges"
    ${IPTABLES} -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
    ${IPTABLES} -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 127.0.0.0/8 -i lo -j DROP
    print_info "${SCRIPT_NAME}"  "[ + ] Block bogus packets"
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG
    print_info "${SCRIPT_NAME}" "[+] Blocking weird tcp connections by weird flags"
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags ACK,PSH PSH -j DROP
    ${IPTABLES} -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
    print_good "${SCRIPT_NAME}" "[+] block prerouting done"
}

function limit_connections ( ) {
    print_info "${SCRIPT_NAME}" "[+] Limiting connections per IP"
    ${IPTABLES} -A INPUT -p tcp --syn -m multiport --dports ${1} -m connlimit --connlimit-above 5 -j REJECT --reject-with tcp-reset
    print_good "${SCRIPT_NAME}" "[+] done limiting connections"
}

function enable_logging ( ) {
    print_info "${SCRIPT_NAME}" "[+] Create logging for PSAD"
    ${IPTABLES} -A INPUT -j LOG
    ${IPTABLES} -A FORWARD -j LOG
    print_info "${SCRIPT_NAME}" "[+] Creating and setting up fail2ban rules"
    ${IPTABLES} -N f2b-sshd
    ${IPTABLES} -A INPUT -p tcp -m multiport --dports ${SSH_PORT} -j f2b-sshd
    ${IPTABLES} -A f2b-sshd -j RETURN
    print_good "${SCRIPT_NAME}" "[+] Done with creating logging"
}

function allow_connections ( ) {
    print_info "${SCRIPT_NAME}" "[+] Allowing connection to services"
    ${IPTABLES} -A INPUT -i lo -j ACCEPT -m comment --comment 'Allow connections on local interface: lo'
    ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
    ${IPTABLES} -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    ${IPTABLES} -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
    print_good "${SCRIPT_NAME}" "[+] Done allowing connections"
}

function disable_icmp ( ) {
    if [[ "${1}" == "1" ]];
    then
        print_info "${SCRIPT_NAME}" "[+] Deny icmp requests from outside"
        ${IPTABLES} -A OUTPUT -p icmp --icmp-type echo-request -j DROP
        ${IPTABLES} -A INPUT -p icmp --icmp-type echo-reply -j DROP
    elif [[ "${1}" == "0" ]];
    then
        print_info "${SCRIPT_NAME}" "[+] Allow icmp requests from outside"
        ${IPTABLES} -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
        ${IPTABLES} -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    fi
    print_good "${SCRIPT_NAME}" "[+] Done with icmp enable / disable"
}

function default_drop ( ) {
    print_info "${SCRIPT_NAME}" "[+] Default to DROP"
    ${IPTABLES} -A INPUT -j DROP
    print_good "${SCRIPT_NAME}" "[+] Done with default drop"
}

function restart_services ( ) {
    print_info "${SCRIPT_NAME}" "[+] Resetting services, psad & fail2ban"
    systemctl restart psad.service
    systemctl restart fail2ban.service
    systemctl status psad.service
    systemctl status fail2ban.service
    print_good "${SCRIPT_NAME}" "[+] Done with restarting services"
}

function setup_ipset_rules () {
    print_info "${SCRIPT_NAME}" "Setting up ipset rules" 
    ${IP_SET} -q flush ipsum
    ${IP_SET} -q create ipsum hash:net
    IPSET_LIST=$(curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v '#' | grep -v -E "\s[1-2]$" | cut -f 1)
    for ip in ${IPSET_LIST};
    do
        ipset add ipsum $ip
    done
    ${IPTABLES} -I INPUT -m set --match-set ipsum src -j DROP
    print_good "${SCRIPT_NAME}" "[+] Done with dropping IPSET IPs"
}

function list_rules ( ) {
    ${IPTABLES} -L
}

function usage ( ) {
    echo -e """${WHITE}
./iptables.sh [ports]
- - - - - - - - - - - - -
PORTS : Like 80,22,53

Example:
./iptables.sh 21,22,80,443,8080,8443
${NC}"""
}

if [[ "$#" -ne 1 ]];
then
    usage
    exit 1
fi

banner
print_warning "${SCRIPT_NAME}" "[+] Using iptables version: $(${IPTABLES} --version)"
#restore_table
save_table
reset_table
setup_ipset_rules
disable_icmp ${DISABLE_ICMP}
block_prerouting
enable_logging
limit_connections ${ARGUMENTS}
allow_connections ${ARGUMENTS}
default_drop
restart_services
list_rules
print_good "${SCRIPT_NAME}" "[+] Finished"
