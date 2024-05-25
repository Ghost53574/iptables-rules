#!/bin/bash

source "./helper_funcs.sh"

TIMESTAMP="$(date +%s)"
SCRIPT_NAME="iptables"

# Change this to suit your needs
INTERFACE="eth0"
DISABLE_ICMP=1
ENABLE_TCPSTACK_PROT=1
ENABLE_PORT_KNOCKING=1
SSH_PORT=#SSH
GATE1=#Gate1
GATE2=#Gate2
GATE3=#Gate3
ARGUMENTS=$@

MODPROBE="$(which modprobe)"
DEPMOD="$(which depmod)"

IPTABLES="$(which iptables)"
if [[ -z "${IPTABLES}" ]];
then
    print_error "${SCRIPT_NAME}" "[!] iptables is not installed"
    exit 1
fi

IPTABLES_SAVE="$(which iptables-save)"
if [[ -z "${IPTABLES_SAVE}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] iptables-save is not installed, no backups available"
fi

IPTABLES_RESTORE="$(which iptables-restore)"
if [[ -z "${IPTABLES_RESTORE}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] iptables-restore is not installed, no restore available"
fi

IP_SET="$(which ipset)"
if [[ -z "${IPTABLES_SAVE}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] ipset is not installed"
fi

PSAD=$(which psad)
if [[ -z "${PSAD}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] psad is not installed"
fi

FAIL2BAN=$(which fail2ban-server)
if [[ -z "${FAIL2BAN}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] fail2ban is not installed"
fi

FWSNORT=$(which fwsnort)
if [[ -z "${FWSNORT}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] fwsnort is not installed"
fi

if [[ -z "${IP_SET}" || -z "${PSAD}" || -z "${FAIL2BAN}" || -z "${FWSNORT}" ]];
then
    read -p "Do you want to install ipset, psad, fail2ban and fwsnort?" INSTALL
    case "${INSTALL}" in
        "Y"|"y")
            install_pkgs
            ;;
        *)
            ;;
    esac
    IP_SET="$(which ipset)"
    PSAD=$(which psad)
    FAIL2BAN=$(which fail2ban-server)
    FWSNORT=$(which fwsnort)
fi

function banner () {
    echo -e """${BOLD_WHITE}
                                       %                                       
                          &/            %&@*          **                        
                          &#,           .             *#.                       
                          .             ,                                       
                          *           .@@@           .,                         
                        .@@@/         @@@@@         %@@@                        
                       #@@@@@&      .@@@@@@@       @@@@@@,                      
                      .........    .@@@@@@@@@     .........                     
                     %&&&&&&&&&&   @@@@@@@@@@&  .&&&&&&&&&&#                    
                      @@&@@@@@@   #((((((((((((  /@&@@@@&@(                     
                      @( @@@ .@   @@@@@@@@@@@@&  /@ /@@( @(                     
                      @@@@@@@@@   @@@@@@@@@@@@&  /@@@@@@@@(                     
                      @@@@ &@@@  .@*,@,,@,(&,#%, /@@@  @@@(                     
                      @@@@@@@@@.@@@@@@@@@@@@@@@@@/@@@@@@@@(                     
            #@&&@&&@&*@& @@@,*@.@@@@@@@@@@@@@@@@@/@.#@@%.@(&@@&@@&&@,           
            #@@@@@@@@/@#,@@@,*@.@@@@    #   (@@@@/@,(@@#,@(@@@@@@@@@,           
            #@@@@@@@@/@@@@@@@@@.@@@.    #    %@@@/@@@@@@@@(@@@@@@@@@,           
            #@@@@@@@@/@@@@@@@@@.@@@     #    %@@@/@@@@@@@@(@@@@@@@@@,           
            ,********.********* *****************.********.*********   
            ██╗██████╗ ████████╗ █████╗ ██████╗ ██╗     ███████╗███████╗
            ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝
            ██║██████╔╝   ██║   ███████║██████╔╝██║     █████╗  ███████╗
            ██║██╔═══╝    ██║   ██╔══██║██╔══██╗██║     ██╔══╝  ╚════██║
            ██║██║        ██║   ██║  ██║██████╔╝███████╗███████╗███████║
            ╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝
                              \"Fuck em...\" - c0z
${NC}"""
    print_menu "[-]" "Booting Up Menu..."
    sleep 1
    print_menu "[-]" "Loading Menu [${LIGHTGREEN}########                ]${LIGHTRED}(38%)"
    sleep 1
    print_menu "[-]" "Loading Menu [${LIGHTGREEN}###################     ]${LIGHTRED}(80%)"
    sleep 1
    print_menu "[-]" "Loading Menu [${LIGHTCYAN}########################]${LIGHTRED}(100%)"
    sleep 1
}

function update_psad_rules () {
    ${PSAD} --sig-update
}

function save_table () {
    print_info "${SCRIPT_NAME}" "[+] Backing up current rules"
    ${IPTABLES_SAVE} > "${TIMESTAMP}_iptables.bak"
}

function restore_table () {
    print_good "${SCRIPT_NAME}" "[+] Restoring iptables rules"
    latest_backup=$(find . -name '*_iptables.bak' | awk -F'_' '{print substr($1,3)}' | sort -rn | head -n 1)
    if [[ ! -z "${latest_backup}" ]];
    then
        read -p  "Do you want to restore ${latest_backup}_iptables.bak (y/n)? " RESTORE
        case "${RESTORE}" in
            "y"|"Y")
                ${IPTABLES}-restore "${latest_backup}_iptables.bak"
                return 0
            ;;
            *)
            ;;
        esac
    fi
    return 1
}

function load_modules () {
    print_info "${SCRIPT_NAME}" "[+] Loading modules"
    ${DEPMOD} -a
    ${MODPROBE} nf_conntrack
    ${MODPROBE} nf_nat
    ${MODPROBE} nf_nat_ipv4
    ${MODPROBE} nf_tables
    ${MODPROBE} nft_chain_nat_ipv4
}

function enable_tcpstack_protections () {
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=1/g' /etc/sysctl.conf
}

function disable_tcpstack_protections () {
    echo 0 > /proc/sys/net/ipv4/tcp_syncookies
    sed -i 's/net.ipv4.conf.all.rp_filter=1/#net.ipv4.conf.all.rp_filter=1/g' /etc/sysctl.conf
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
}

function setup_jump_gates () {
    print_info "${SCRIPT_NAME}" "[+] Setting up port knocking gates"
    ${IPTABLES} -N KNOCKING
    ${IPTABLES} -N GATE1
    ${IPTABLES} -N GATE2
    ${IPTABLES} -N GATE3
    ${IPTABLES} -N PASSED
}

function setup_jump () {
    ${IPTABLES} -A INPUT -j KNOCKING
}

function setup_gate1 () {
    print_info "${SCRIPT_NAME}" "Setting up Gate1 table"
    ${IPTABLES} -A GATE1 -p tcp --dport ${GATE1} -m recent --name AUTH1 --set -j DROP
    ${IPTABLES} -A GATE1 -j DROP
}

function setup_gate2 () {
    print_info "${SCRIPT_NAME}" "Setting up Gate2 table"
    ${IPTABLES} -A GATE2 -m recent --name AUTH1 --remove
    ${IPTABLES} -A GATE2 -p tcp --dport ${GATE2} -m recent --name AUTH2 --set -j DROP
    ${IPTABLES} -A GATE2 -j GATE1
}

function setup_gate3 () {
    print_info "${SCRIPT_NAME}" "Setting up Gate3 table"
    ${IPTABLES} -A GATE3 -m recent --name AUTH2 --remove
    ${IPTABLES} -A GATE3 -p tcp --dport ${GATE3} -m recent --name AUTH3 --set -j DROP
    ${IPTABLES} -A GATE3 -j GATE1
}

function setup_passage () {
    print_info "${SCRIPT_NAME}" "[+] Setting up passage table"
    ${IPTABLES} -A PASSED -m recent --name AUTH3 --remove
    ${IPTABLES} -A PASSED -p tcp --dport ${SSH_PORT} -j ACCEPT
    ${IPTABLES} -A PASSED -j GATE1
}

function setup_knocking () {
    print_info "${SCRIPT_NAME}" "[+] Setting up knocking table"
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds ${KNOCKING_TIME} --name AUTH3 -j PASSED
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds 10 --name AUTH2 -j GATE3
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds 10 --name AUTH1 -j GATE2
    ${IPTABLES} -A KNOCKING -j GATE1
}

function block_prerouting () {
    print_info "${SCRIPT_NAME}" "[+] Prerouting blocking"
    print_info "${SCRIPT_NAME}" "[+] Block INVALID packets"
    ${IPTABLES} -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
    print_info "${SCRIPT_NAME}" "[+] Block weird MSS valued packets"
    ${IPTABLES} -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
    print_info "${SCRIPT_NAME}" "[+] Blocking private IP address ranges"
    ${IPTABLES} -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
    ${IPTABLES} -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
    ${IPTABLES} -t mangle -A PREROUTING -s 127.0.0.0/8 -i lo -j DROP
    print_info "${SCRIPT_NAME}"  "[+] Block bogus packets"
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
}

function limit_connections () {
    print_info "${SCRIPT_NAME}" "[+] Limiting connections per IP"
    ${IPTABLES} -A INPUT -p tcp --syn -m multiport --dports ${1} -m connlimit --connlimit-above 5 -j REJECT --reject-with tcp-reset
}

function enable_logging () {
    print_info "${SCRIPT_NAME}" "[+] Create logging for PSAD"
    ${IPTABLES} -A INPUT -j LOG
    ${IPTABLES} -A FORWARD -j LOG
    print_info "${SCRIPT_NAME}" "[+] Creating and setting up fail2ban rules"
    ${IPTABLES} -N f2b-sshd
    ${IPTABLES} -A INPUT -p tcp -m multiport --dports ${SSH_PORT} -j f2b-sshd
    ${IPTABLES} -A f2b-sshd -j RETURN
}

function allow_connections () {
    print_info "${SCRIPT_NAME}" "[+] Allowing current connections"
    ${IPTABLES} -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    print_info "${SCRIPT_NAME}" "[+] Allowing connection to services"
    ${IPTABLES} -A INPUT -i lo -j ACCEPT -m comment --comment 'Allow connections on local interface: lo'
    print_info "${SCRIPT_NAME}" "[+] Allowing inbound connections on: ${1}"
    ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    ${IPTABLES} -A OUTPUT -i ${INTERFACE} -p tcp -m multiport --sports ${1} -m state --state ESTABLISHED -j ACCEPT
    print_info "${SCRIPT_NAME}" "[+] Allowing outbound connections on: ${1}"
    ${IPTABLES} -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    ${IPTABLES} -A INPUT -o ${INTERFACE} -p tcp -m multiport --sports ${1} -m state --state ESTABLISHED -j ACCEPT
}

function disable_icmp () {
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
}

function default_drop () {
    print_info "${SCRIPT_NAME}" "[+] Default to DROP"
    ${IPTABLES} -A INPUT -j DROP
}

function restart_services () {
    print_info "${SCRIPT_NAME}" "[+] Resetting services, psad & fail2ban"
    systemctl restart psad.service
    systemctl restart fail2ban.service
    systemctl status psad.service
    systemctl status fail2ban.service
}

function setup_ipset_rules () {
    print_info "${SCRIPT_NAME}" "Setting up ipset rules" 
    ${IP_SET} -q flush ipsum
    ${IP_SET} -q create ipsum hash:net
    for ip in ($(curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v '#' | grep -v -E "\s[1-2]$" | cut -f 1));
    do
        ipset add ipsum ${ip}
    done
    ${IPTABLES} -I INPUT -m set --match-set ipsum src -j DROP
}

function list_rules () {
    ${IPTABLES} -L
}

function install_pkgs () {
    apt-get install iptables fail2ban psad fwsnort ipset -y
}

function usage () {
    print_menu "" """${WHITE}
./iptables.sh [ports]

Example:
./iptables.sh 21,22,80,443,8080,8443

Note:
Set your SSH Port in the script if using port knocking.
${NC}"""
}

if [[ "$#" -ne 1 ]];
then
    usage
    exit 1
fi

banner
print_info "${SCRIP_NAME}" "[!] Loading modules"
load_modules
if [[ "${ENABLE_TCPSTACK_PROT}" == 1 ]];
then
    print_info "${SCRIPT_NAME}" "[!] Enable TCP stack protections"
    enable_tcpstack_protections
else
    print_info "${SCRIPT_NAME}" "[!] Disable TCP stack protections"
    disable_tcpstack_protections
fi
print_warning "${SCRIPT_NAME}" "[+] Using iptables version: $(${IPTABLES} --version)"
if [[ ! -z "${IPTABLES_RESTORE}" ]];
then
    restore_table
    if [[ "${?}" != "0" ]];
    then
        if [[ ! -z "${IPTABLES_SAVE}" ]];
        then
            save_table
        fi
        reset_table
        if [[ "${ENABLE_PORT_KNOCKING}" == 1 ]];
        then
            print_info "${SCRIPT_NAME}" "[!] Port knocking enabled"
            setup_jump_gates
        fi
        if [[ ! -z "${IP_SET}" ]];
        then
            setup_ipset_rules
        fi
        disable_icmp ${DISABLE_ICMP}
        block_prerouting
        limit_connections ${ARGUMENTS}
        if [[ ! -z "${PSAD}" && ! -z "${FAIL2BAN}" ]];
        then
            enable_logging
        fi
        allow_connections ${ARGUMENTS}
        if [[ "${ENABLE_PORT_KNOCKING}" == 1 ]];
        then
            jump_gate
            setup_gate1
            setup_gate2
            setup_gate3
            setup_passage
            setup_knocking
        fi
        default_drop
        if [[ ! -z "${PSAD}" && ! -z "${FAIL2BAN}" ]];
        then
            update_psad_rules
            restart_services
        fi
        list_rules
    fi
    print_good "${SCRIPT_NAME}" "[+] Finished"
else
    print_error "${SCRIPT_NAME}" "One or more errors detected."
fi
