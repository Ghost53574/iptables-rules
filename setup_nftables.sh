#!/bin/bash

source "./common.sh"

TIMESTAMP="$(date +%s)"
SCRIPT_NAME="${BASH_SOURCE[0]}"

# Default values
PORTS="22,80,443"
INTERFACE="ens33"
OUTPUT_FILE="/etc/nftables.conf"
ENABLE_FIREWALLD=0
ENABLE_PORT_KNOCKING=0
APPLY_RULES=0
FIREWALL_ZONE="public"
AUTO_INSTALL=0

if [[ $(sudo -l >/dev/null) ]]; 
then
    print_error "${SCRIPT_NAME}" "ERROR: This script must be run as with sudo permisssions cached"
    exit 1
fi

BANNER="""      
                              █████████████████████████████████████████████████████████  ████████████████████████████████████                                 
                              ███  ██  ███    ████     ██   ██  ██    ██      ███     ██████     ███    ███   ██ ██  █      ███                                
                              ██  ██  ███    ███  ██   █   █  ███  ████   █  ██  ██  █████  ██   ██  █ ███   ██ ███ ███  ████                                 
                              ██  ██  ██  ██ ███  ██   █   █  ███  ████   █  ███  █████ ██  ██   ██  █  ██    █ ███████  ███                                  
                              ██      ██  ██  ██  ██████      ███    ██   █ ██████   █████  ███████ ██  ██      ███  ██  ███                                  
                              ██  ██  ██  ██  ██  ██   █   █  ███  ████   █  ██████   ████  ██   █   █  ██  ██  ███  ██  ███                                  
                              ██  ██  ██  ██  ██  ██   █   ██  ██  ████   █  ███  █  █████  ██  ██  ██  ██  ██  ███  ██  ███                                  
                              ████████████████████  █████████████████████████████   ████████  █████████████████████  ███████                                  
                              ████████████████████████████████████████████████████████    ████████████████████████    █████                                   
      ████████████████████████████████████████████████████████████████████████████████████ ██████████████████████████████████████████████████████████          
      ██      ██      ███    ███    ███   █  ██   █   ████  ██  ██  ██  ██   █  ███     ██████    ██  ██      ██     █  ██   ██  ███    ███  ████  ██          
      ██  ██  ██   ██  ██  █████ █  ███  ██  ██   █   █████  █ ███  ██  ██   █  ███  ██  █████  ████  ██  ██  ██   ████  █   ██  ███ █  ███  ████  ██          
      ██  ██ ███   █  ███    ██  ██ ███  ██████       ██ ██    ███  ██  ██   █  ███  █  ██████    ██  ██   █  ██     ██  █   ██  ██  ██ ███  ████  ██          
      ██  ██  ██   ██ ███  ████  ██ ███  ██████   █   ██ ███  ████  ██  ██   █  ███  ██ ██████  ████  ██   █  ██   ████  █ █  █  ██  ██ ███  ████  ██          
      ██  ██   █   ██  ██  ████      ██  ██  ██   █   ██  ██  ████  ██  ██   █  ███  ██  █████  ████  ██  ██  ██   ████    ██    ██      ██  ████  ████        
      ██       █   ██  ██    █   ██  ██  ██  ██   █   ██  ██  ████  ██  ███  █  ███  ██  █████  ████  ██  ██  ██     ██    ██   ██   ██  ██    ██    ██        
      ██████████████████████████████████████████████████  █████████████████████████████████████████████████████████████████████████████████████████████        
                                        ████                       ████     ███                                                                                
                                                                                                                                                              
                                                                                                                                                              
                                                                                                                                                              
  ██                                                                                                                                                           
  ████                                                                                                                                                         
  █████                                                                                                                                                        
  █████                                                                                                                                                        
  ██████                                                                                                                                                       
  ████████                                                                                                                                                     
  ████████                   ███████                                                                                                                           
  ██████████      ██████    █████████                                                                                                                          
  ███████████    ███████    █████████                                                                                                                          
  █████████████ ████████    █████████                                                                                                                          
  ██████████████████████   ███████████                                                                                                                         
  ████████████████████    ████████████                                                                        ██  █████                                        
  ███████████████████    ████████████                                                                        ████████████                                      
  █████████████████████ █████████████                                                                        ██████████████                                    
  ███████████████████████████████████                                                                        ████████████████                                  
  ███████████████████████████████████                                                                         ███████████████████                              
  █████████████████████████████████                                                                          █████████████████████                         ██  
  █████████████████████████████████                                                                           ████████████████████                      █████  
  ████████████████████████████████████                                ████████████████                         █████████████████████                █████████  
  █████████████████████████████████████████                          █████████████████████████████████████████    ███████████████████              ██████████  
  ██████████████████████████████████████████████                      ████████████████████████████████████████      █████████████████         ███████████████  
  ███████████████████████████████████████████████████                █████████████████████████████████████████       █████████████████  █████████████████████  
  ███████████████████████████████████████████████████████          ██████████████████████████████████████████         ███████████████████████████████████████  
  ███████████████████████████████████████████████████████████    ████████████████████████████████████████████          ██████████████████████████████████████  
  ████████████████████████████████████████████████████████████████████████████████████████████      █████               █████████████████████████████████████  
  ██████████████████████████████████████████████████████████████████████████████████████████                             ████████████████████████████████████  
  ██████████████████████████████████████████████████████████████████████████████████ ███████                               ██████████████████████████████████  
  █████████████████████████████████████████████████████████████████████████████████████████                                   ███████████████████████████████  
  █████████████   ███████████████████████████████████████████████████████████████████                                                ███████████████████       
  ████████████       ███████████████████████████████████████████████████████████████                                                   █████████               
  ███████████            ███████████████████████████████████████████████████████████                                                                           
  ████████                  ███████████████████████████████████████████████████████                                                                            
  █████                           █████████████████████████████████████████████████                                                                            
                                        ██████████████████      █  ███████████████                                                                             
                                              ███████                        █                                                                                
                                                                                                                                                              
                                                                                                                                                                  
                                                                            Just say no...${NC}
"""

echo -e "${BANNER}"

show_help() {
    print_menu "${SCRIPT_NAME}" "Convert iptables rules to nftables and integrate with firewalld${NC}"
    print_menu "${SCRIPT_NAME}" ""
    print_menu "${SCRIPT_NAME}" "Usage: $0 [options]"
    print_menu "${SCRIPT_NAME}" "Options:"
    print_menu "${SCRIPT_NAME}" "    -p, --ports PORTS                    Comma-separated list of ports to allow (default: $PORTS)"
    print_menu "${SCRIPT_NAME}" "    -i, --interface INTERFACE            Network interface to protect (default: $INTERFACE)"
    print_menu "${SCRIPT_NAME}" "    -o, --output FILE                    Output file for nftables rules (default: $OUTPUT_FILE)"
    print_menu "${SCRIPT_NAME}" "    -f, --firewalld                      Enable firewalld integration"
    print_menu "${SCRIPT_NAME}" "    -k, --port-knocking                  Enable port knocking"
    print_menu "${SCRIPT_NAME}" "    -a, --apply                          Apply the ruleset immediately"
    print_menu "${SCRIPT_NAME}" "    -z, --zone ZONE                      Firewalld zone to use (default: $FIREWALL_ZONE)"
    print_menu "${SCRIPT_NAME}" "    -A, --auto-install                   Auto install missing packages"
    print_menu "${SCRIPT_NAME}" "    -h, --help                           Show this help message"
    print_menu "${SCRIPT_NAME}" ""
    print_menu "${SCRIPT_NAME}" "Example:"
    print_menu "${SCRIPT_NAME}" "       ${SCRIPT_NAME} --ports 22,80,443 --interface eth0 --firewalld --apply"
    print_menu "${SCRIPT_NAME}" ""
}

while [[ ${#} -gt 0 ]]; 
do
    case $1 in
        -p|--ports)
            PORTS="$2"
            shift 2
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--firewalld)
            ENABLE_FIREWALLD=1
            shift
            ;;
        -k|--port-knocking)
            ENABLE_PORT_KNOCKING=1
            shift
            ;;
        -a|--apply)
            APPLY_RULES=1
            shift
            ;;
        -z|--zone)
            FIREWALL_ZONE="$2"
            shift 2
            ;;
        -A| --auto-install)
            AUTO_INSTALL=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "${SCRIPT_NAME}" "ERROR: Unknown option: ${1}"
            show_help
            exit 1
            ;;
    esac
done

check_dependency() {
    if ! command -v $1 &> /dev/null; 
    then
        print_warning "${SCRIPT_NAME}" "WARNING: ${1} not found."
        return 1
    else
        print_info "${SCRIPT_NAME}" "Found $1: $(which $1)"
        return 0
    fi
}

print_menu "${SCRIPT_NAME}" "Checking packages dependencies..."

# Base dependencies that are always required
PKG_DEPENDS=("python3" "nft" "python3-nftables" "ebtables" "ipset")

# Add firewalld-related dependencies only if firewalld integration is enabled
if [[ ${ENABLE_FIREWALLD} -eq 1 ]];
then
    PKG_DEPENDS+=("firewall-cmd" "python3-firewall" "python3-dbus" "python3-cap-ng" "firewalld")
fi

for PKG in ${PKG_DEPENDS[@]};
do
    case ${PKG} in
        python3)
        if ! check_dependency python3; 
        then
            if [[ ${AUTO_INSTALL} -eq 1 ]];
            then
                print_info "${SCRIPT_NAME}" "Installing python3..."
                apt-get install python3 -y
            else
                print_error "${SCRIPT_NAME}" "ERROR: Python 3 is required for this script."
                exit 1
            fi
        fi
        ;;
        firewall-cmd)
        if [[ ${ENABLE_FIREWALLD} -eq 1 ]]; 
        then
            if ! check_dependency firewall-cmd; 
            then
                if [[ ${AUTO_INSTALL} -eq 1 ]];
                then
                    print_info "${SCRIPT_NAME}" "Installing firewalld..."
                    apt-get install firewalld -y
                else
                    print_error "${SCRIPT_NAME}" "ERROR: firewalld is required when --firewalld is specified."
                    exit 1
                fi
            fi
        fi
        ;;
        nft)
        if ! check_dependency nft; 
        then
            if [[ ${AUTO_INSTALL} -eq 1 ]];
            then
                print_info "${SCRIPT_NAME}" "Installing nftables..."
                apt-get install nftables -y
            else
                print_warning "${SCRIPT_NAME}" "WARNING: nftables (nft) is required to apply rules."
                print_warning "${SCRIPT_NAME}" "The script will generate the rules, but you'll need to install nftables to apply them."
            fi
        fi
        ;;
        *)
        if ! check_dependency ${PKG};
        then
            if [[ ${AUTO_INSTALL} -eq 1 ]];
            then
                print_info "${SCRIPT_NAME}" "Installing ${PKG}..."
                apt-get install ${PKG} -y
            else
                print_error "${SCRIPT_NAME}" "ERROR: ${PKG} is required. Please install it with apt..."
                exit 1
            fi
        fi
        ;;
    esac
done

print_menu "${SCRIPT_NAME}" "Checking Python dependencies..."
PYTHON_DEPS=("gobjects" "")

if [[ ${ENABLE_FIREWALLD} -eq 1 ]]; 
then
    print_menu "${SCRIPT_NAME}" "Checking for firewalld Python package..."
    if ! python3 -c "import firewall.config" &> /dev/null; 
    then
        print_error "${SCRIPT_NAME}" "ERROR: firewalld Python package not found. Please install the python3-firewall package."
        print_warning "${SCRIPT_NAME}" "For Debian/Ubuntu: sudo apt-get install python3-firewall"
        print_warning "${SCRIPT_NAME}" "For RHEL/CentOS/Fedora: sudo dnf install python3-firewall"
        exit 1
    else
        print_info "${SCRIPT_NAME}" "Found firewalld Python package"
    fi
fi

for dep in "${PYTHON_DEPS[@]}"; 
do
    if ! python3 -c "import ${dep}" &> /dev/null; 
    then
        print_warning "${SCRIPT_NAME}" "WARNING: Python module '${dep}' not found."
    fi
    if [[ ${AUTO_INSTALL} -eq 1 ]];
    then
        print_info "${SCRIPT_NAME}" "Installing pypi package ${dep}"
        python3 -m pip install -U ${dep} --user --break-system-packages
    fi
done

if [[ ! -x "nftables_converter.py" ]];
then
    chmod +x nftables_converter.py
fi
if [[ ! -x "nftables_converter.py" ]];
then
    chmod +x firewalld_integration.py
fi

CONVERTER_ARGS="--ports ${PORTS} --interface ${INTERFACE} --output ${OUTPUT_FILE}"

if [[ ${ENABLE_PORT_KNOCKING} -eq 1 ]]; 
then
    print_info "${SCRIPT_NAME}" "Enabling port knocking..."
    CONVERTER_ARGS="${CONVERTER_ARGS} --enable-port-knocking 1"
fi

if [[ ${APPLY_RULES} -eq 1 ]]; 
then
    print_info "${SCRIPT_NAME}" "Applying rules after creation..."
    CONVERTER_ARGS="${CONVERTER_ARGS} --apply"
fi

print_menu "${SCRIPT_NAME}" "Converting iptables rules to nftables..."
if [[ $(python3 nftables_converter.py ${CONVERTER_ARGS}) -ne 0 ]]; 
then
    print_error "${SCRIPT_NAME}" "ERROR: Failed to convert iptables rules to nftables."
    exit 1
fi

print_info "${SCRIPT_NAME}" "Successfully converted iptables rules to nftables."

if [[ ${ENABLE_FIREWALLD} -eq 1 ]]; 
then
    print_menu "${SCRIPT_NAME}" "Integrating with firewalld..."
    if [[ $(python3 firewalld_integration.py "--nftables-file ${OUTPUT_FILE} --ports ${PORTS} --zone ${FIREWALL_ZONE}") -ne 0 ]]; 
    then
        print_error "${SCRIPT_NAME}" "ERROR: Failed to integrate with firewalld."
        exit 1
    fi
    print_info "${SCRIPT_NAME}" "Successfully integrated with firewalld."
fi

print_info "${SCRIPT_NAME}" "All done!"
print_menu "${SCRIPT_NAME}" "Next steps:"
print_menu "${SCRIPT_NAME}" "1. Review the generated nftables ruleset in ${OUTPUT_FILE}"

if [[ ${APPLY_RULES} -eq 1 ]]; 
then
    print_menu "${SCRIPT_NAME}" "2. The rules have been applied. To verify, run: ${YELLOW}nft list ruleset"
else
    print_menu "${SCRIPT_NAME}" "2. To apply the rules, run: ${YELLOW}nft -f ${OUTPUT_FILE}"
fi

if [[ ${ENABLE_FIREWALLD} -eq 1 ]]; 
then
     print_menu "${SCRIPT_NAME}" "3. To check firewalld configuration, run: ${YELLOW}firewall-cmd --list-all --zone=${FIREWALL_ZONE}"
fi

exit 0
