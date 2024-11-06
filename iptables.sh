#!/bin/bash

# I, c0z, created this script to automate the setup and configuration of iptables and overall Linux network security with added features to piss people off
# I don't care if you disagree with this script or complain if you have issues with it
# I don't care if you're the attacker who gets frustrated bceause I made a private tool public that makes you're life more difficult
# I don't care that you're even reading these comments
# Have fun <3

source "./common.sh"

TIMESTAMP="$(date +%s)"
SCRIPT_NAME="iptables"

# The interface that you're protecting (WAN)
INTERFACE="ens33"

# Disable ICMP?
DISABLE_ICMP=1

# Only open ports for a specific time during the day?
ENABLE_SPECIFIC_TIME=0
DAYS_DURING_WEEK="Mon,Tue,Wed,Thu,Fri"
START_TIME="$(date -u -d @$(date "+%s" -d "09:00") +%H:%M)"
END_TIME="$(date -u -d @$(date "+%s" -d "10:00") +%H:%M)"

# Whitelist file of IPs
WHITELIST_FILE="good_ips.txt"

# Enable TCP stack protections?
ENABLE_TCPSTACK_PROT=1

# Enable better TCP optimizations?
ENABLE_TCP_OPT=1

# Look like a windows machine?
LOOK_LIKE_WINDOWS=1

# How many connections per IP?
CONNECTIONS_PER_IP=10

# What's the SSH port?
SSH_PORT=22

ARGUMENTS=$@

# Enables port knocking with configuration
ENABLE_PORT_KNOCKING=0
KNOCKING_TIME=10
GATE1=1025
GATE2=1026
GATE3=1027

MODPROBE="$(which modprobe)"
DEPMOD="$(which depmod)"
IPTABLES="$(which iptables)"

LINUX_VERSION="$(uname -v)"

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

IPSPOOF=$(which ipspoof)
if [[ -z "${IPSPOOF}" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] ipspoof is not installed"
fi

if [[ -z "${IP_SET}" || -z "${PSAD}" || -z "${FAIL2BAN}" || -z "${FWSNORT}" ]];
then
    read -p "Do you want to install ipset, psad, fail2ban, fwsnort and portspoof?" INSTALL
    case "${INSTALL}" in
        "Y"|"y")
            apt-get install iptables fail2ban psad fwsnort ipset -y
            # install and configure portspoof with patches
            ;;
        *)
            ;;
    esac
    IP_SET="$(which ipset)"
    PSAD=$(which psad)
    FAIL2BAN=$(which fail2ban-server)
    FWSNORT=$(which fwsnort)
    IPSPOOF=$(which ipspoof)
fi

function banner () {
    echo -e """${BOLD_WHITE}
                                        Using iptables version: $(${IPTABLES} --version)
@@@@@@@@@@@@@@@@@@@@@@@%+**#%####%##%#%%%##%%#%#*%%%%%%%%%%%%%####=*+++@@@@@@@@%%:       .  =@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%****+%#*********+**+*+#=+=*****#*#########+++==@@@@@@%%:  . -*===-+=:*@@@@@@@@@@@@@@@@@@@@@@@@@@
%@@%@@%@@%@@%@@%@@%@@%@%***+*%#****+++++++++==  :  --+===========*+++++@%%@@%% ..:..%%@%@@@@@%.@%@@%@@%@@%@@%@@%@@%@@%@@
@@@@@@@@@@@@@@@@@@@@@@@%***=+##+*++*+*+++===:#=##%%%%@@%#========*====+%@%@@%: .:#%%@@@@@@@@@@%+@@@@@@@@@@@@@@@@@@@@@@@%
@@%@@%@@%@@%@@%@@%@@%@@@**+++*#******++++==%#:.::..::#@@%#=-=----*====+%@@@@# ##%@@@@%@@%@@%@@@#@%@@%@@%@@%@@%@@%@@%@@@@
@@@@@@@@@@@@@@@@@@@@@@@%*+*+=+#**++=+++++=%@%::::..::=@@@@-------*:===+%@%@@%=%#@@@@@%@@@@@@%%@%#@@@@@@@@@@@@@@@@@@@@%@@
%@@%@@%@@%@@%@@%@@%@@%@@***===#**+*++++++=%@% .:::#+#-=%@@+---:--=:====@@%@%%%=%%%%%**##%@%=#%@@@@%@@%@@%@@%@@%@@%@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%***+==##**+++++++=-%%:+-:-::::-%=@%-:::--+-====%@%%@%@@@%*==#+:=+%@+*@@@@@@@@@@@@@@@@@@@@@@%@@%@
%@@@%@@%@@%@@%@@%@@%@@@@***+==#******++++--%%-:: ::.:--%#%+::::::*=====%%@%%%@@@.+++#==+##%*#%@%@@@%@@%@@%@@%@@%@@@@@@@@
@@%@@@@@@@@@@@@@@@@@@%@@**#*==#*+*++++++=-:#%=:.::::--=%@%#::::::#+====%%%%%@@%%#@%**=+*#@#+*#=@@%@@@@@@@@@@@@@@@%@@%@@%
@@%@@%@@%@@%@@%@@%@@@@@@****-=#*++++=+===-::%%==+*====%@%@%::::::+=====%%@%%@%@@%#%*#%*##*+*#. %%@@@%@@%@@%@@%@@@@@@@@@@
%%@@%@%@@@@@@@@@@@@%@@%@****==#+++=    ..:::%@:*=-==#%@@@%%::::::+-====%%%%%%@@%@%@%#@%%#** .  @@#-:=@@@@@@@@@@%@@%@@%@@
%%%%@%#- .%%@%@@%@@@@@@@#***+*%##=:. :::==%==#. -##### %@@%*=++***=====%%#=.::=:-:==++: %  .  .@@@@==--::.%@%@@@@@@@@@@@
 .=.  +==...%@@@@@%@@%@%#***=+= :  . =*#@@@@#%%    : ..:+@@@%%#= :=:===%%===:-@*==-:= .:%    .#@%@@@%@#*#%#+%@@@%@@%@@%@
::=. .%+:#:.:%%%%%%%%%#.   =*%#=. :%#%%%@@@@@#%.  .%     @@@@@@@%@-:--=%==@#%%@@*+=+%: %% .   %@@@@@@%#@@@@@@@%@@@@@@@@@
%%%%#%:%%##*+=    ..##+-:.:::=#@@@%@@@@@@@%@%%%# .=  .:- %@@@@%@@@@.::=:.::%@@@@@@@@@ %%%  . :@@@%@@@@@@@@@@@@@@@%@@%@@@
%@%:: %%%*:#*+:.*-%-*. .@@@#%#@@%@@@@@@@%@@=  .-***+**:-- #%@@%@@%+ :::.@*%@@@%@@%@@@ @@%   .%@%@@@%@@@@%@@%@@@%@@@@@@%@
@@@%*=***###+*++*#:#%@@@@@@@@@@@@@@@%@%@@@@++%%#####%#=@#=##     ..::.#@=%@@@@@@@@@%@.@%% .  @@@@@@@@@%@@@@@@%@@@@%@@@@@
%%@@% :**+#-#*++#%:*@@@@%@@@@@%%%%%%@%@@@%@@@@%#:#::*+@%####:.#:*=@-:-=@@@@@%@@%@@@@%#@%*  .*@%@@%@@%@@@@%@@@@@@%@@@%@@@
%%@@%%%%##%@@@-%@.#@@%@@@%@%===     %@@@@@@@@@%--#%%%%##*%##%%.%@@@@@@@@@@@@@@@@@%@@*@@@:.  %@@@@@@@@@@%@@@%@@%@@@@@@@%@
@@%@%@@@@@@@%@@@@@@@@@@%@+++:==  .  %%@%@@%@@@%:=+% %%#%%+#%%%:#@@%@@@@%@@%@@%@@@@@% @@@  . @@@%@@%@@%@@@@@@@@@@@%@@@@@@
@@@%@@@%@@%@@@@@@@@%@@%@%+++:== .  *%@@@@@@@%@@:.=#.%%##*#@==+%%@@@@%==%%%%@@@@%@@@@:@@@  .#@@@@@@@@@@@@%@@@%@@%@@@%@@@%
@%%@@%@@@@@@@%@@%@@@@@@@@+++-==   .#%@@@%@@@@@%.:.%@@#:..@@@@@@@@@@@%:=%%%%@@@@@@%@%%@@@ .-@@%@@%@@%@@%@@@%@@@@@@@%@@@@%
@@@@@@@@%@@%@@@@@@%@@%@%@=++=+= .  #%@@@@@%@@@:.::=%%@:==%@@@@@@%@@@@.+#%%@@%@@@@@@+%@@@:=#@@@@@@@@@@@@@@@@@@%@@%%%%%%%%
@@%@%@%@@@@@@@%@@@@@@@@@@+++======:%%@@%@@@@%@...:#@%@::.%@@%@@@@@%@@*+%%%@@@@%@@@@%@@@%=+#@@@%@@%@@%@@%@@@%@@@@%%%%%%%#
%@@@%@@%@%@@%@@@%@@%@@@@@++++++.  :%%@@@@%@@@@..:.*%@@...@@@@@%@@@@@@@+%%@@@@@@@%@@%@@@@=*@@%@@@@@@@@@@@@%@@@@%@@%%%%%##
@%@@@%@@@@@%@@@@@@@@@%@@@++*++=   :%@@@@@@@%@**..-+@@%=:-@@%@@@@%@@%@@*%%@@%@@@@@@@@@%@@-#@@@@@%@@%@@%@@@@@@%@@@@@%@%#%#
@@%@@@@@@@@@@%@%@@%@@@@%@****++- .-@@@%@@@@@@=+=.:#%%%#:=@@@@@@@@@@@@@%@@@@@@%@@@%@%@@@@-#@@@%@@@@@@@@@%@@%@@@@%@%%%%%%#
%@@%@@%@@%@@@@@@@@@@@@@@@#**+++- :#@%@@@%@@@###-:.#%%@#=#@@@%@@%@@%@@@@@@%@@@@@%@@%%@@%@=#@@@@@@%@@%@@@@@@@@@%@@@@%%%%%#
@@@@@@@@@@@%@@%@@%@@%@@@%%***+++:=@@@@@@@@%*+:=-: =@%@*.:@@@@@@:@@@@%@@%@@@%@@@@@%%%@@@@=*@@%@@@@@@@@%@@%@@%@@@@%@@@%%%#
@%%@@%@@%@@@%@@@@@@@@@%@@%*#*++.=@@%@@%@@@@@%*:::-*@%%.:#@@%@@@@%@@@@@@@@@@@@%@@@%#%@@@@+#@@@@%@@%@@@@@@@@@@@@%@@@%%@%@#
@@@@@@@@@@%@@@@%@@%@@@@@@%**#+::%@@@@@@@%@@@@@@@@@@@@@@@@@@@@%@@%@@%@@%@@%@@@@@%@@@%@@%%#@@%@@@@@@@%@@%@@%@@%@@@@%@@@@%#
@@@%@@%@@@@@@%@@@@@@%@@%@%#**:=@@@@@%@@@@@%@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@%@@@@@@@@@+@@@@@@@@@%@@@@@@@@@@@@@@@%@@@@%@@%
@%@@@@@@%@@%@@@@%@@@@@@@@@%##=%@@@%@@@%@@@@@%@@%@@%@@%@@@@@%@@%@@%@@%@@%@@@@@%@@%@@@@@%%@%@@%@@@@%@@%@@%@@%@@%@@@@@@@@@%
@@@@%@@@@@@@@@%@@@%@@%@@@@%%=%@@@@@@@@@@%@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@%@@@@@@@@%@@@@@@@@@@@%@@@@@@@@@@@@@@@@@%@@%@@%@
@@%@@@%@@%@@%@@@%%%%#%%@%##-#@@@%@%%%@@@@@%@@%@@%@@%@@@@@%@@%@@%@@%@@%@@@@@%@@%@@@@@%@@%@@%@@@@@@@%@@%@@%@@%@@%@@@@@@@@@
@@@%######%@%%%%%####@@%%%:#@@@@@%%%%@@%@@@@@@@@@@@@@%@@@@@@@@@@#%%%@@@%@@@@@@@@%@@@@@@@@@@@%@@%@@@@@@@@@@@@@@@@@%@@%@@%
##%%###*#%@%#%%%%####%%@@:%%@%@@@@@@@@@@@@@%@@%@@%@@@@@%@@%@@%@@*#%@@@@@@%@@%@@@@@%@@%@@%@@@@@@@@%@@%@@%@@%@@%@@@@@@@.=@
##%%#*####%%@@#%%%%@@@@@@@@*@@@%@@@@@%@@%@@@@@@@@@@%@@@@@@@@@@@@#=-@@%@@@@@@@@%@@@@@@@@@@@%@@%@@@@@@@@@@@@@@@@@%@@%:+#:-
%%%%%%%@@%@@@@@@@@@@@@@%@@@@@%@@@%@%@@@@@@%@@%@@%@@@@%@@%@@%@@%@-%%@@@@%@@%@@@@@%@@%@@%@@@@@@@@%@@%@@%@@%%=.=*%@@@@%==--
@@@@%@@@%@@@@%@@@@@@%@%%####*=::.... %@@@@@@@@@@@@@@@@@@@@@@@@@+=%@%@@@@@@@@%@@@@@@@@@@@%@@%@@@@@@@@@@@@@@%%@@@@@%@+%@@-
@@@@%@@@@@@%%@%@@%@@%@@@@%%##+=-:::==+@@%@@%@@%@@%@@%@@%@@%@@%@==%@*==++%%@@@@%@@%@@%@@@@@@@@%@@%@@%@@%@@%%%%#%%@@@@@@@@
%%%##*+=*#########%@@@@%%@%%%%+%@%%# %@@@@@@@@@@@@@@@@@@@@@@@@@ :.=*:--===*#%@@@@@@@@@%@@%@@@@@@@@@@@@@@@@%%% -=%@@@@@%@
###=#===+*#####===*#%@@@%%%@@@%#%#:#=:@@@%@@%@@%@@%@@%@@%@@%@@@+#*#%*=*##%##%%@@%@@%@@@@@@@%@@%@@%@@%@@%@@@@#@@@@@%@@@@@
+#==--======*+=====-=%@@@@@@###:. : .=%@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@%@@@@@@@@@@@%@@@
                                        ,********.********* *****************.********.*********.*\.
                                        ██╗██████╗ ████████╗ █████╗ ██████╗ ██╗     ███████╗███████╗
                                        ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝
                                        ██║██████╔╝   ██║   ███████║██████╔╝██║     █████╗  ███████╗
                                        ██║██╔═══╝    ██║   ██╔══██║██╔══██╗██║     ██╔══╝  ╚════██║
                                        ██║██║        ██║   ██║  ██║██████╔╝███████╗███████╗███████║
                                        ╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝
                \"Blessed is he, who in the name of charity and good will, shepherds the weak through the valley of darkness, for he is truly 
                his brother's keeper and the finder of lost children. And I will strike down upon thee with great vengeance and furious anger 
                those who would attempt to poison and destroy my brothers.\" - A badass motherfucker
${NC}"""
}

function update_psad_rules () {
    ${PSAD} --sig-update
}

function save_table () {
    ${IPTABLES_SAVE} > "${TIMESTAMP}_iptables.bak"
}

function restore_table () {
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
    ${MODPROBE} nf_tables
    ${MODPROBE} nft_chain_nat

    if [[ $(printf '%s\n' "4.9" "${LINUX_VERSION}" | sort -V | head -n1) = "4.9" ]];
    then
        ${MODPROBE} tcp_bbr
        echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
    fi
}

function look_like_windows () {
    echo 128 > /proc/sys/net/ipv4/ip_default_ttl
    echo 1460 > /proc/sys/net/ipv4/tcp_base_mss
    echo 2 > /proc/sys/net/ipv4/tcp_mtu_probing
}

function look_like_linux () {
    echo 64 > /proc/sys/net/ipv4/ip_default_ttl
    echo 1024 > /proc/sys/net/ipv4/tcp_base_mss
    echo 0 > /proc/sys/net/ipv4/tcp_mtu_probing
}

function enable_tcpstack_protections () {
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
    echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
    echo 1 > /proc/sys/net/ipv4/tcp_ecn
    echo 3 > /proc/sys/net/ipv4/tcp_synack_retries
    echo 15 > /proc/sys/net/ipv4/tcp_fin_timeout
    echo 1800 > /proc/sys/net/ipv4/tcp_keepalive_time
}

function disable_tcpstack_protections () {
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/all/log_martians
    echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects
    echo 2 > /proc/sys/net/ipv4/tcp_ecn
    echo 5 > /proc/sys/net/ipv4/tcp_synack_retries
    echo 60 > /proc/sys/net/ipv4/tcp_fin_timeout
    echo 7200 > /proc/sys/net/ipv4/tcp_keepalive_time
}

function enable_tcp_optimizations () {
    if [[ $(printf '%s\n' "4.9" "${LINUX_VERSION}" | sort -V | head -n1) = "4.9" ]];
    then
        echo "bbr" > /proc/sys/net/ipv4/tcp_congestion_control
        echo "fq" > /proc/sys/net/core/default_qdisc
    fi
}

function disable_tcp_optimizations () {
    echo "reno" > /proc/sys/net/ipv4/tcp_congestion_control
    echo "pfifo_fast" > /proc/sys/net/core/default_qdisc
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
    ${IPTABLES} -A GATE1 -p tcp --dport ${1} -m recent --name AUTH1 --set -j DROP
    ${IPTABLES} -A GATE1 -j DROP
}

function setup_gate2 () {
    print_info "${SCRIPT_NAME}" "Setting up Gate2 table"
    ${IPTABLES} -A GATE2 -m recent --name AUTH1 --remove
    ${IPTABLES} -A GATE2 -p tcp --dport ${1} -m recent --name AUTH2 --set -j DROP
    ${IPTABLES} -A GATE2 -j GATE1
}

function setup_gate3 () {
    print_info "${SCRIPT_NAME}" "Setting up Gate3 table"
    ${IPTABLES} -A GATE3 -m recent --name AUTH2 --remove
    ${IPTABLES} -A GATE3 -p tcp --dport ${1} -m recent --name AUTH3 --set -j DROP
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
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds ${1} --name AUTH3 -j PASSED
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds ${1} --name AUTH2 -j GATE3
    ${IPTABLES} -A KNOCKING -m recent --rcheck --seconds ${1} --name AUTH1 -j GATE2
    ${IPTABLES} -A KNOCKING -j GATE1
}

function block_prerouting () {
    print_info "${SCRIPT_NAME}" "[+] Block INVALID packets"
    ${IPTABLES} -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
    print_info "${SCRIPT_NAME}" "[+] Block weird MSS valued packets"
    ${IPTABLES} -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
    print_info "${SCRIPT_NAME}" "[+] Blocking private IP address ranges"
    ${IPTABLES} -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
    #${IPTABLES} -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
    #${IPTABLES} -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
    #${IPTABLES} -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
    #${IPTABLES} -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
    #${IPTABLES} -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
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
    ${IPTABLES} -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
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
    print_info "${SCRIPT_NAME}" "[+] Limiting connections per IP to ${CONNECTIONS_PER_IP}"
    ${IPTABLES} -A INPUT -p tcp --syn -m multiport --dports ${1} -m connlimit --connlimit-above ${CONNECTIONS_PER_IP} -j REJECT --reject-with tcp-reset
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
    print_info "${SCRIPT_NAME}" "[+] Allowing connection to localhost"
    ${IPTABLES} -A INPUT -i lo -j ACCEPT -m comment --comment 'Allow connections on local interface: lo'
    ${IPTABLES} -A OUTPUT -p udp -o ${INTERFACE} --dport 53 -j ACCEPT
    ${IPTABLES} -A INPUT -p udp -i ${INTERFACE} --sport 53 -j ACCEPT
    if [[ ${ENABLE_SPECIFIC_TIME} == 1 ]];
    then
        print_info "${SCRIPT_NAME}" "[+] Allowing inbound connections on: ${1} only during ${START_TIME} - ${END_TIME}"
        ${IPTABLES} -A OUTPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED --match time --weekdays ${DAYS_DURING_WEEK} --timestart ${START_TIME} --timestop ${END_TIME} -j ACCEPT
        ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED --match time --weekdays ${DAYS_DURING_WEEK} --timestart ${START_TIME} --timestop ${END_TIME} -j ACCEPT
        print_info "${SCRIPT_NAME}" "[+] Allowing outbound connections on: ${1} only during ${START_TIME} - ${END_TIME}"
        ${IPTABLES} -A OUTPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED --match time --weekdays ${DAYS_DURING_WEEK} --timestart ${START_TIME} --timestop ${END_TIME} -j ACCEPT
        ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED --match time --weekdays ${DAYS_DURING_WEEK} --timestart ${START_TIME} --timestop ${END_TIME} -j ACCEPT
    else
        print_info "${SCRIPT_NAME}" "[+] Allowing inbound connections on: ${1}"
        ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
        ${IPTABLES} -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --sports ${1} -m state --state ESTABLISHED -j ACCEPT
        print_info "${SCRIPT_NAME}" "[+] Allowing outbound connections on: ${1}"
        ${IPTABLES} -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
        ${IPTABLES} -A INPUT -i ${INTERFACE} -p tcp -m multiport --sports ${1} -m state --state ESTABLISHED -j ACCEPT
    fi
}

function whitelist_ips () {
    IPS="$(cat ${WHITELIST_FILE})"
    for IP in ${IPS};
    do
        ${IPTABLES} -A INPUT -s ${IP} -j ACCEPT
    done
}

function disable_icmp () {
    if [[ "${1}" == "1" ]];
    then
        print_info "${SCRIPT_NAME}" "[+] Denying icmp requests from outside"
        ${IPTABLES} -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
        ${IPTABLES} -A INPUT -p icmp --icmp-type echo-request -j DROP
    elif [[ "${1}" == "0" ]];
    then
        print_info "${SCRIPT_NAME}" "[+] Allowing icmp requests from outside"
        ${IPTABLES} -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
        ${IPTABLES} -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    fi
}

function default_drop () {
    ${IPTABLES} -A INPUT -j DROP
}

function restart_services () {
    systemctl restart psad.service
    systemctl restart fail2ban.service
    systemctl status psad.service
    systemctl status fail2ban.service
}

function setup_ipset_rules () {
    ${IP_SET} -q flush ipsum
    ${IP_SET} -q create ipsum hash:net
    IP_BLACKLIST="$(curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v '#' | grep -v -E "\s[1-2]$" | cut -f 1)"
    for ip in ${IP_BLACKLIST};
    do
        ipset add ipsum ${ip}
    done
    ${IPTABLES} -I INPUT -m set --match-set ipsum src -j DROP
}

function list_rules () {
    ${IPTABLES} -L
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
sleep 3
load_modules
if [[ "${ENABLE_TCPSTACK_PROT}" == 1 ]];
then
    print_info "${SCRIPT_NAME}" "[!] Enable TCP stack protections"
    enable_tcpstack_protections
else
    print_info "${SCRIPT_NAME}" "[!] Disable TCP stack protections"
    disable_tcpstack_protections
fi
if [[ "${ENABLE_TCP_OPT}" == 1 ]];
then
    print_info "${SCRIPT_NAME}" "[!] Enable TCP Optimization"
    enable_tcp_optimizations
fi
if [[ "${LOOK_LIKE_WINDOWS}" == 1 ]];
then
    print_info "${SCRIPT_NAME}" "[!] Looking like a Windows machine"
    look_like_windows
else
    print_info "${SCRIPT_NAME}" "[!] Looking like a Linux machine"
    look_like_linux
fi
print_warning "${SCRIPT_NAME}" "[!] Saving /proc/sys/net/ipv4 values to sysctl..."
sysctl -p
if [[ "${?}" != "0" ]];
then
    print_warning "${SCRIPT_NAME}" "[!] sysctl failed to set values"
else
    print_good "${SCRIPT_NAME}" "[+] sysctl set values from /proc successfully"
fi
if [[ ! -z "${IPTABLES_RESTORE}" ]];
then
    print_info "${SCRIPT_NAME}" "[!] Restoring iptables rules"
    restore_table
    if [[ "${?}" != "0" ]];
    then
        if [[ ! -z "${IPTABLES_SAVE}" ]];
        then
            print_info "${SCRIPT_NAME}" "[!] Backing up current rules"
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
            print_info "${SCRIPT_NAME}" "[!] Setting up ipset rules"
            setup_ipset_rules
        fi
        disable_icmp ${DISABLE_ICMP}
        print_info "${SCRIPT_NAME}" "[+] Prerouting blocking"
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
            setup_gate1 ${GATE1}
            setup_gate2 ${GATE2}
            setup_gate3 ${GATE3}
            setup_passage
            setup_knocking ${KNOCKING_TIME}
        fi
        print_info "${SCRIPT_NAME}" "[+] Setting the explicit default to DROP"
        default_drop
        if [[ ! -z "${PSAD}" && ! -z "${FAIL2BAN}" ]];
        then
            update_psad_rules
            print_info "${SCRIPT_NAME}" "[!] Restarting services"
            restart_services
        fi
        list_rules
    fi
    print_good "${SCRIPT_NAME}" "[+] Finished"
else
    print_error "${SCRIPT_NAME}" "One or more errors detected."
fi
