#!/bin/bash

# Script to convert iptables rules to nftables and integrate with firewalld
# Author: Cline
# Date: 2025-04-06

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PORTS="22,80,443"
INTERFACE="ens33"
OUTPUT_FILE="/etc/nftables.conf"
ENABLE_FIREWALLD=0
ENABLE_PORT_KNOCKING=0
APPLY_RULES=0
FIREWALL_ZONE="public"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ERROR: This script must be run as root${NC}"
  exit 1
fi

# Function to display help message
show_help() {
  echo -e "${BLUE}Convert iptables rules to nftables and integrate with firewalld${NC}"
  echo ""
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  -p, --ports PORTS          Comma-separated list of ports to allow (default: $PORTS)"
  echo "  -i, --interface INTERFACE  Network interface to protect (default: $INTERFACE)"
  echo "  -o, --output FILE          Output file for nftables rules (default: $OUTPUT_FILE)"
  echo "  -f, --firewalld            Enable firewalld integration"
  echo "  -k, --port-knocking        Enable port knocking"
  echo "  -a, --apply                Apply the ruleset immediately"
  echo "  -z, --zone ZONE            Firewalld zone to use (default: $FIREWALL_ZONE)"
  echo "  -h, --help                 Show this help message"
  echo ""
  echo "Example:"
  echo "  $0 --ports 22,80,443 --interface eth0 --firewalld --apply"
  echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
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
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo -e "${RED}ERROR: Unknown option: $1${NC}"
      show_help
      exit 1
      ;;
  esac
done

# Check for required dependencies
echo -e "${BLUE}Checking dependencies...${NC}"
MISSING_DEPS=0

check_dependency() {
  if ! command -v $1 &> /dev/null; then
    echo -e "${YELLOW}WARNING: $1 not found.${NC}"
    return 1
  else
    echo -e "${GREEN}Found $1: $(which $1)${NC}"
    return 0
  fi
}

# Check for Python
if ! check_dependency python3; then
  echo -e "${RED}ERROR: Python 3 is required for this script.${NC}"
  exit 1
fi

# Check for nftables
check_dependency nft
NFT_MISSING=$?

# Check for firewalld if integration is enabled
if [ $ENABLE_FIREWALLD -eq 1 ]; then
  check_dependency firewall-cmd
  FIREWALLD_MISSING=$?
  
  if [ $FIREWALLD_MISSING -eq 1 ]; then
    echo -e "${RED}ERROR: firewalld is required when --firewalld is specified.${NC}"
    exit 1
  fi
fi

# Warn if nftables is missing but don't exit
if [ $NFT_MISSING -eq 1 ]; then
  echo -e "${YELLOW}WARNING: nftables (nft) is required to apply rules.${NC}"
  echo -e "${YELLOW}The script will generate the rules, but you'll need to install nftables to apply them.${NC}"
fi

# Check for Python dependencies
echo -e "${BLUE}Checking Python dependencies...${NC}"
PYTHON_DEPS=("argparse" "logging" "subprocess" "os" "sys" "json" "re" "datetime")

# Check for firewalld Python API if firewalld integration is enabled
if [ $ENABLE_FIREWALLD -eq 1 ]; then
  echo -e "${BLUE}Checking for firewalld Python API...${NC}"
  if ! python3 -c "import firewall.config" &> /dev/null; then
    echo -e "${RED}ERROR: firewalld Python API not found. Please install the python3-firewall package.${NC}"
    echo -e "${YELLOW}For Debian/Ubuntu: sudo apt-get install python3-firewall${NC}"
    echo -e "${YELLOW}For RHEL/CentOS/Fedora: sudo dnf install python3-firewall${NC}"
    exit 1
  else
    echo -e "${GREEN}Found firewalld Python API${NC}"
  fi
fi

for dep in "${PYTHON_DEPS[@]}"; do
  if ! python3 -c "import $dep" &> /dev/null; then
    echo -e "${YELLOW}WARNING: Python module '$dep' not found.${NC}"
    MISSING_DEPS=1
  fi
done

if [ $MISSING_DEPS -eq 1 ]; then
  echo -e "${YELLOW}Some Python dependencies are missing. Try installing them:${NC}"
  echo -e "${YELLOW}python3 -m pip install argparse datetime${NC}"
  # We'll proceed anyway since most are standard library modules
fi

# Ensure scripts are executable
chmod +x nftables_converter.py
chmod +x firewalld_integration.py

# Prepare command arguments
CONVERTER_ARGS="--ports $PORTS --interface $INTERFACE --output $OUTPUT_FILE"

if [ $ENABLE_PORT_KNOCKING -eq 1 ]; then
  CONVERTER_ARGS="$CONVERTER_ARGS --enable-port-knocking 1"
fi

if [ $APPLY_RULES -eq 1 ]; then
  CONVERTER_ARGS="$CONVERTER_ARGS --apply"
fi

# Run the nftables converter
echo -e "${BLUE}Converting iptables rules to nftables...${NC}"
python3 nftables_converter.py $CONVERTER_ARGS

# Check if conversion was successful
if [ $? -ne 0 ]; then
  echo -e "${RED}ERROR: Failed to convert iptables rules to nftables.${NC}"
  exit 1
fi

echo -e "${GREEN}Successfully converted iptables rules to nftables.${NC}"

# Integrate with firewalld if requested
if [ $ENABLE_FIREWALLD -eq 1 ]; then
  echo -e "${BLUE}Integrating with firewalld...${NC}"
  
  FIREWALLD_ARGS="--nftables-file $OUTPUT_FILE --ports $PORTS --zone $FIREWALL_ZONE"
  
  python3 firewalld_integration.py $FIREWALLD_ARGS
  
  if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to integrate with firewalld.${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}Successfully integrated with firewalld.${NC}"
fi

echo -e "${GREEN}All done!${NC}"

# Print next steps
echo -e "${BLUE}Next steps:${NC}"
echo -e "1. Review the generated nftables ruleset in $OUTPUT_FILE"

if [ $APPLY_RULES -eq 1 ]; then
  echo -e "2. The rules have been applied. To verify, run: ${YELLOW}nft list ruleset${NC}"
else
  echo -e "2. To apply the rules, run: ${YELLOW}nft -f $OUTPUT_FILE${NC}"
fi

if [ $ENABLE_FIREWALLD -eq 1 ]; then
  echo -e "3. To check firewalld configuration, run: ${YELLOW}firewall-cmd --list-all --zone=$FIREWALL_ZONE${NC}"
fi

exit 0
