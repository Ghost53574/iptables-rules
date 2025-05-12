#!/usr/bin/env python3
"""
nftables_converter.py - Convert iptables rules to nftables and integrate with firewalld
"""

import os
import sys
import subprocess
import argparse
import re
import shutil
from datetime import datetime
import logging
from typing import Dict, List, Any, Optional

class CustomFormatter(logging.Formatter):
    grey = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    bold_red = f'\033[1m{red}'
    reset = '\033[0m'
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{grey}{fmt}{reset}",
        logging.WARNING: f"{yellow}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{bold_red}{fmt}{reset}"
    }

    def format(self, record):
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)

logger = logging.Logger(__name__, level=4)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logger.addHandler(handler)

# Configuration with defaults matching the iptables.sh script
DEFAULT_CONFIG = {
    "interface": "ens33",
    "disable_icmp": 1,
    "enable_specific_time": 0,
    "days_during_week": "Mon,Tue,Wed,Thu,Fri",
    "start_time": "09:00",
    "end_time": "10:00",
    "whitelist_file": "good_ips.txt",
    "enable_tcpstack_prot": 1,
    "enable_tcp_opt": 1,
    "look_like_windows": 1,
    "connections_per_ip": 10,
    "ssh_port": 22,
    "enable_port_knocking": 0,
    "knocking_time": 10,
    "gate1": 1025,
    "gate2": 1026,
    "gate3": 1027
}

class NftablesConverter:
    """Class for converting iptables rules to nftables and managing firewall configs"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the converter with configuration"""
        self.config = DEFAULT_CONFIG.copy()
        if config is not None:
            self.config.update(config)
        
        # Commands
        self.cmd_nft = self._find_command("nft")
        self.cmd_firewall_cmd = self._find_command("firewall-cmd")
        self.cmd_modprobe = self._find_command("modprobe")
        self.cmd_depmod = self._find_command("depmod")
        
        # Check for necessary commands
        if not self.cmd_nft:
            logger.error("nft command not found. Please install nftables package.")
            sys.exit(1)
            
        # Initialize nftables ruleset structure
        self.ruleset = {
            "tables": []
        }
        
    def _find_command(self, command: str) -> Optional[str]:
        """Find the full path of a command"""
        return shutil.which(command)
    
    def load_kernel_modules(self) -> None:
        """Load necessary kernel modules for nftables"""
        logger.info("Loading kernel modules for nftables")
        
        modules = [
            "nf_conntrack",
            "nf_nat",
            "nf_tables",
            "nft_chain_nat"
        ]
        
        # Load the TCP BBR module if kernel version supports it
        kernel_version = self._get_kernel_version()
        if kernel_version and self._version_greater_than_or_equal(kernel_version, "4.9"):
            modules.append("tcp_bbr")
            
        # First run depmod
        if self.cmd_depmod:
            try:
                subprocess.run([self.cmd_depmod, "-a"], check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to run depmod: {e}")
        else:
            logger.warning("depmod command not found, skipping module dependency resolution")
            
        # Now load each module
        if self.cmd_modprobe:
            for module in modules:
                try:
                    subprocess.run([self.cmd_modprobe, module], check=True)
                    logger.info(f"Loaded kernel module: {module}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to load kernel module {module}: {e}")
        else:
            logger.warning("modprobe command not found, skipping module loading")
    
    def _get_kernel_version(self) -> Optional[str]:
        """Get the Linux kernel version"""
        try:
            result = subprocess.run(
                ["uname", "-r"],
                capture_output=True,
                text=True,
                check=True
            )
            version = result.stdout.strip()
            # Extract just the major.minor version
            match = re.match(r"^(\d+\.\d+)", version)
            if match:
                return match.group(1)
            return version
        except subprocess.CalledProcessError:
            return None
    
    def _version_greater_than_or_equal(self, version1: str, version2: str) -> bool:
        """Compare two version strings"""
        v1_parts = list(map(int, version1.split('.')))
        v2_parts = list(map(int, version2.split('.')))
        
        # Pad with zeros if necessary
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
            
        # Compare each part
        for i in range(len(v1_parts)):
            if v1_parts[i] > v2_parts[i]:
                return True
            elif v1_parts[i] < v2_parts[i]:
                return False
                
        # If we get here, they're equal
        return True
    
    def configure_system_settings(self) -> None:
        """Configure system settings including TCP stack protections"""
        logger.info("Configuring system settings")
        
        # TCP stack protections
        tcp_settings = {}
        
        if self.config["enable_tcpstack_prot"] == 1:
            logger.info("Enabling TCP stack protections")
            tcp_settings.update({
                "net.ipv4.tcp_syncookies": "1",
                "net.ipv4.icmp_echo_ignore_broadcasts": "1",
                "net.ipv4.conf.all.accept_redirects": "0",
                "net.ipv4.conf.all.accept_source_route": "0",
                "net.ipv4.conf.all.rp_filter": "1",
                "net.ipv4.conf.all.log_martians": "1",
                "net.ipv4.conf.all.send_redirects": "0",
                "net.ipv4.tcp_ecn": "1",
                "net.ipv4.tcp_synack_retries": "3",
                "net.ipv4.tcp_fin_timeout": "15",
                "net.ipv4.tcp_keepalive_time": "1800"
            })
        else:
            logger.info("Using default TCP stack settings")
            tcp_settings.update({
                "net.ipv4.tcp_syncookies": "1",
                "net.ipv4.icmp_echo_ignore_broadcasts": "1",
                "net.ipv4.conf.all.accept_redirects": "1",
                "net.ipv4.conf.all.accept_source_route": "0",
                "net.ipv4.conf.all.rp_filter": "0",
                "net.ipv4.conf.all.log_martians": "0",
                "net.ipv4.conf.all.send_redirects": "1",
                "net.ipv4.tcp_ecn": "2",
                "net.ipv4.tcp_synack_retries": "5",
                "net.ipv4.tcp_fin_timeout": "60",
                "net.ipv4.tcp_keepalive_time": "7200"
            })
            
        # TCP optimizations
        if self.config["enable_tcp_opt"] == 1:
            kernel_version = self._get_kernel_version()
            if kernel_version and self._version_greater_than_or_equal(kernel_version, "4.9"):
                logger.info("Enabling TCP BBR congestion control")
                tcp_settings.update({
                    "net.ipv4.tcp_congestion_control": "bbr",
                    "net.core.default_qdisc": "fq"
                })
                
                # Create module load config
                with open("/etc/modules-load.d/bbr.conf", "w") as f:
                    f.write("tcp_bbr\n")
            else:
                logger.warning("Kernel version doesn't support TCP BBR, skipping this optimization")
                
        # OS fingerprint settings (Look like Windows or Linux)
        if self.config["look_like_windows"] == 1:
            logger.info("Configuring network stack to look like Windows")
            tcp_settings.update({
                "net.ipv4.ip_default_ttl": "128",
                "net.ipv4.tcp_base_mss": "1460",
                "net.ipv4.tcp_mtu_probing": "2"
            })
        else:
            logger.info("Configuring network stack to look like Linux")
            tcp_settings.update({
                "net.ipv4.ip_default_ttl": "64",
                "net.ipv4.tcp_base_mss": "1024",
                "net.ipv4.tcp_mtu_probing": "0"
            })
            
        # Apply settings
        for setting, value in tcp_settings.items():
            self._write_sysctl_setting(setting, value)
            
        # Save settings to sysctl
        try:
            subprocess.run(["sysctl", "-p"], check=True)
            logger.info("Applied sysctl settings")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to apply sysctl settings: {e}")
            
    def _write_sysctl_setting(self, setting: str, value: str) -> None:
        """Write a setting to the appropriate sysctl file"""
        # Convert setting name to path
        path_parts = setting.split('.')
        
        # Ensure the setting path exists in /proc/sys
        proc_path = "/proc/sys/" + "/".join(path_parts)
        
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "w") as f:
                    f.write(f"{value}\n")
                logger.debug(f"Set {setting} = {value}")
            except Exception as e:
                logger.warning(f"Failed to write {setting}: {e}")
        else:
            logger.warning(f"Setting path {proc_path} does not exist")
    
    def create_nftables_base_structure(self) -> None:
        """Create the base nftables structure with tables and chains"""
        logger.info("Creating nftables base structure")
        
        # Create filter table with named chains
        filter_table = {
            "family": "inet",
            "name": "filter",
            "chains": {
                "input": {
                    "type": "filter",
                    "hook": "input",
                    "priority": 0,
                    "policy": "accept",  # We'll set to drop after rules are added
                    "rules": []
                },
                "forward": {
                    "type": "filter",
                    "hook": "forward",
                    "priority": 0,
                    "policy": "accept",
                    "rules": []
                },
                "output": {
                    "type": "filter",
                    "hook": "output",
                    "priority": 0,
                    "policy": "accept",
                    "rules": []
                }
            }
        }
        
        # Add custom chains for port knocking if enabled
        if self.config["enable_port_knocking"] == 1:
            port_knocking_chains = self._create_port_knocking_chains()
            # Merge the port knocking chains into the filter table chains
            filter_table["chains"].update(port_knocking_chains)
        
        # Create nat table with named chains
        nat_table = {
            "family": "inet",
            "name": "nat",
            "chains": {
                "prerouting": {
                    "type": "nat",
                    "hook": "prerouting",
                    "priority": -100,
                    "policy": None,
                    "rules": []
                },
                "postrouting": {
                    "type": "nat",
                    "hook": "postrouting",
                    "priority": 100,
                    "policy": None,
                    "rules": []
                }
            }
        }
        
        # Create mangle table with named chains
        mangle_table = {
            "family": "inet",
            "name": "mangle",
            "chains": {
                "prerouting": {
                    "type": "filter",
                    "hook": "prerouting",
                    "priority": -150,
                    "policy": None,
                    "rules": []
                }
            }
        }
        
        # Add tables to ruleset
        self.ruleset["tables"].extend([filter_table, nat_table, mangle_table])
        
    def _create_port_knocking_chains(self) -> Dict[str, Dict[str, Any]]:
        """Create chains for port knocking if enabled"""
        logger.info("Creating port knocking chains")
        
        chains = {
            "knocking": {
                "type": None,  # Regular chain, not a base chain
                "rules": []
            },
            "gate1": {
                "type": None,
                "rules": []
            },
            "gate2": {
                "type": None,
                "rules": []
            },
            "gate3": {
                "type": None,
                "rules": []
            },
            "passed": {
                "type": None,
                "rules": []
            }
        }
        
        return chains
    
    def add_prerouting_block_rules(self) -> None:
        """Add rules to block malicious packets in prerouting"""
        logger.info("Adding prerouting block rules")
        
        # Find the mangle table and prerouting chain
        mangle_table = next((t for t in self.ruleset["tables"] if t["name"] == "mangle"), None)
        if not mangle_table:
            logger.warning("Mangle table not found")
            return
        
        prerouting_chain = next((c for c in mangle_table["chains"] if c == "prerouting"), None)
        if not prerouting_chain:
            logger.warning("Prerouting chain not found in mangle table")
            return
            
        # Rules for invalid CT state
        mangle_table["chains"][prerouting_chain]["rules"].append(
            "ct state invalid drop"
        )
        
        # Rules for invalid MSS values
        mangle_table["chains"][prerouting_chain]["rules"].append(
            "tcp flags syn tcp option maxseg size 1-535 drop"
        )
        
        # Block bogon and special IP ranges
        bogon_ranges = [
            "224.0.0.0/3",
            "0.0.0.0/8",
            "240.0.0.0/5"
        ]
        
        for bogon in bogon_ranges:
            mangle_table["chains"][prerouting_chain]["rules"].append(
                f"ip saddr {bogon} drop"
            )
        
        # Block invalid localhost source from external interfaces
        mangle_table["chains"][prerouting_chain]["rules"].append(
            f"iif != lo ip saddr 127.0.0.0/8 drop"
        )
        
        # Block bogus TCP flag combinations
        tcp_flag_rules = [
            "tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop",
            "tcp flags & (fin|syn) == (fin|syn) drop",
            "tcp flags & (syn|rst) == (syn|rst) drop",
            "tcp flags & (fin|rst) == (fin|rst) drop",
            "tcp flags & (fin|ack) == fin drop",
            "tcp flags & (ack|urg) == urg drop",
            "tcp flags & (ack|fin) == fin drop",
            "tcp flags & (ack|psh) == psh drop",
            "tcp flags == (fin|syn|rst|psh|ack|urg) drop",
            "tcp flags == 0x0 drop",
            "tcp flags & (fin|psh|urg) == (fin|psh|urg) drop",
            "tcp flags & (fin|syn|psh|urg) == (fin|syn|psh|urg) drop",
            "tcp flags & (fin|syn|rst|ack|urg) == (fin|syn|rst|ack|urg) drop"
        ]
        
        for rule in tcp_flag_rules:
            mangle_table["chains"][prerouting_chain]["rules"].append(rule)
            
    def add_input_basic_rules(self) -> None:
        """Add basic input chain rules"""
        logger.info("Adding basic input chain rules")
        
        # Find the filter table and input chain
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        if not input_chain:
            logger.warning("Input chain not found in filter table")
            return
            
        # Block invalid TCP flags (same as in prerouting)
        tcp_flag_rules = [
            "tcp flags & (syn|fin) == (syn|fin) drop",
            "tcp flags & (syn|rst) == (syn|rst) drop",
            "tcp flags == 0x0 drop",
            "tcp flags & (fin|syn|rst|ack|urg) == (fin|syn|rst|ack|urg) drop",
            "tcp flags & (fin|rst) == (fin|rst) drop",
            "tcp flags & (ack|fin) == fin drop",
            "tcp flags & (ack|psh) == psh drop",
            "tcp flags & (ack|urg) == urg drop"
        ]
        
        for rule in tcp_flag_rules:
            filter_table["chains"][input_chain]["rules"].append(rule)
        
        # Allow established connections
        filter_table["chains"][input_chain]["rules"].append(
            "ct state established,related accept"
        )
        
        # Allow localhost
        filter_table["chains"][input_chain]["rules"].append(
            "iif lo accept comment \"Allow connections on local interface: lo\""
        )
        
        # Add port rules (handled in separate method)
        
        # Add connection limit rules
        # Will be handled in another method
        
    def add_port_rules(self, ports: str) -> None:
        """Add rules for specific ports"""
        logger.info(f"Adding rules for ports: {ports}")
        
        # Split ports string into a list
        port_list = ports.split(",")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input and output chains
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        output_chain = next((c for c in filter_table["chains"] if c == "output"), None)
        
        if not input_chain or not output_chain:
            logger.warning("Input or output chains not found")
            return
            
        interface = self.config["interface"]
        
        # Handle time-specific rules if enabled
        if self.config["enable_specific_time"] == 1:
            days = self.config["days_during_week"]
            start_time = self.config["start_time"]
            end_time = self.config["end_time"]
            
            # Inbound connections during specific time
            filter_table["chains"][input_chain]["rules"].append(
                f"iif {interface} tcp dport {{ {','.join(port_list)} }} ct state new,established " +
                f"meta hour \"{start_time}\"-\"{end_time}\" meta day {days} accept"
            )
            
            filter_table["chains"][output_chain]["rules"].append(
                f"oif {interface} tcp sport {{ {','.join(port_list)} }} ct state established " +
                f"meta hour \"{start_time}\"-\"{end_time}\" meta day {days} accept"
            )
            
            # Outbound connections during specific time
            filter_table["chains"][output_chain]["rules"].append(
                f"oif {interface} tcp dport {{ {','.join(port_list)} }} ct state new,established " +
                f"meta hour \"{start_time}\"-\"{end_time}\" meta day {days} accept"
            )
            
            filter_table["chains"][input_chain]["rules"].append(
                f"iif {interface} tcp sport {{ {','.join(port_list)} }} ct state established " +
                f"meta hour \"{start_time}\"-\"{end_time}\" meta day {days} accept"
            )
        else:
            # Inbound connections
            filter_table["chains"][input_chain]["rules"].append(
                f"iif {interface} tcp dport {{ {','.join(port_list)} }} ct state new,established accept"
            )
            
            filter_table["chains"][output_chain]["rules"].append(
                f"oif {interface} tcp sport {{ {','.join(port_list)} }} ct state established accept"
            )
            
            # Outbound connections
            filter_table["chains"][output_chain]["rules"].append(
                f"oif {interface} tcp dport {{ {','.join(port_list)} }} ct state new,established accept"
            )
            
            filter_table["chains"][input_chain]["rules"].append(
                f"iif {interface} tcp sport {{ {','.join(port_list)} }} ct state established accept"
            )
            
        # Add DNS rules
        filter_table["chains"][output_chain]["rules"].append(
            f"oif {interface} udp dport 53 accept"
        )
        
        filter_table["chains"][input_chain]["rules"].append(
            f"iif {interface} udp sport 53 accept"
        )
            
    def limit_connections(self, ports: str) -> None:
        """Limit connections per IP for specified ports"""
        logger.info(f"Adding connection limits for ports: {ports}")
        
        # Split ports string into a list
        port_list = ports.split(",")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input chain
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        
        if not input_chain:
            logger.warning("Input chain not found")
            return
            
        connections_per_ip = self.config["connections_per_ip"]
        
        # Add limit rule (before accept rules)
        for port in port_list:
            filter_table["chains"][input_chain]["rules"].insert(0,
                f"tcp dport {port} tcp flags & (syn) == syn " +
                f"meter syn_per_ip {{ ip saddr limit rate over {connections_per_ip}/minute }} " +
                f"reject with tcp reset"
            )
            
    def add_icmp_rules(self) -> None:
        """Add ICMP handling rules"""
        logger.info("Adding ICMP rules")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input and output chains
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        output_chain = next((c for c in filter_table["chains"] if c == "output"), None)
        
        if not input_chain or not output_chain:
            logger.warning("Input or output chains not found")
            return
            
        # Configure ICMP based on disable_icmp setting
        if self.config["disable_icmp"] == 1:
            logger.info("Disabling ICMP echo requests and replies")
            filter_table["chains"][output_chain]["rules"].append(
                "icmp type echo-reply drop"
            )
            
            filter_table["chains"][input_chain]["rules"].append(
                "icmp type echo-request drop"
            )
        else:
            logger.info("Allowing ICMP echo requests and replies")
            filter_table["chains"][output_chain]["rules"].append(
                "icmp type echo-reply accept"
            )
            
            filter_table["chains"][input_chain]["rules"].append(
                "icmp type echo-request accept"
            )
            
    def add_whitelist_rules(self) -> None:
        """Add whitelist rules for IPs in whitelist file"""
        whitelist_file = self.config["whitelist_file"]
        
        logger.info(f"Adding whitelist rules from {whitelist_file}")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input chain
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        
        if not input_chain:
            logger.warning("Input chain not found")
            return
            
        # Read whitelist file if it exists
        try:
            with open(whitelist_file, 'r') as f:
                whitelist_ips = f.read().splitlines()
                
            # Add rules for each IP (at the beginning of the chain)
            for ip in whitelist_ips:
                ip = ip.strip()
                if ip:  # Skip empty lines
                    filter_table["chains"][input_chain]["rules"].insert(0,
                        f"ip saddr {ip} accept comment \"Whitelisted IP\""
                    )
        except FileNotFoundError:
            logger.warning(f"Whitelist file {whitelist_file} not found")
            
    def add_ip_blacklist(self) -> None:
        """Add blacklist rules using sets"""
        logger.info("Adding IP blacklist set and rules")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input chain
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        
        if not input_chain:
            logger.warning("Input chain not found")
            return
            
        # Create a blacklist set definition in the filter table
        if "sets" not in filter_table:
            filter_table["sets"] = {}
            
        # Add the ipsum set to the filter table
        filter_table["sets"]["ipsum"] = {
            "type": "ipv4_addr",
            "elements": []  # Will be populated by an external script via nft command
        }
        
        # Add rule to drop traffic from blacklisted IPs
        filter_table["chains"][input_chain]["rules"].insert(0,
            "ip saddr @ipsum drop comment \"Blacklisted IPs\""
        )
            
    def setup_port_knocking(self) -> None:
        """Set up port knocking rules if enabled"""
        if self.config["enable_port_knocking"] != 1:
            logger.info("Port knocking disabled, skipping")
            return
            
        logger.info("Setting up port knocking rules")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get chains
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        knocking_chain = next((c for c in filter_table["chains"] if c == "knocking"), None)
        gate1_chain = next((c for c in filter_table["chains"] if c == "gate1"), None)
        gate2_chain = next((c for c in filter_table["chains"] if c == "gate2"), None)
        gate3_chain = next((c for c in filter_table["chains"] if c == "gate3"), None)
        passed_chain = next((c for c in filter_table["chains"] if c == "passed"), None)
        
        # Check that all chains exist
        if not all([input_chain, knocking_chain, gate1_chain, gate2_chain, gate3_chain, passed_chain]):
            logger.warning("Not all required chains for port knocking exist")
            return
            
        # Extract config values
        gate1 = self.config["gate1"]
        gate2 = self.config["gate2"]
        gate3 = self.config["gate3"]
        knocking_time = self.config["knocking_time"]
        ssh_port = self.config["ssh_port"]
        
        # Add jump to knocking chain in input chain
        if input_chain and "rules" in input_chain:
            filter_table["chains"][input_chain]["rules"].insert(0, "jump knocking")
        
        # Set up the knocking chain
        if knocking_chain and "rules" in knocking_chain:
            filter_table["chains"][knocking_chain]["rules"].extend([
                f"meta skuid . meta skgid {{ 'AUTH3', 'AUTH3' }} ct mark set 1 jump passed",
                f"meta skuid . meta skgid {{ 'AUTH2', 'AUTH2' }} ct mark set 1 jump gate2",
                f"meta skuid . meta skgid {{ 'AUTH1', 'AUTH1' }} ct mark set 1 jump gate3",
                "jump gate1"
            ])
        
        # Set up gate1
        if gate1_chain and "rules" in gate1_chain:
            filter_table["chains"][gate1_chain]["rules"].extend([
                f"tcp dport {gate1} meta skuid set AUTH1 meta skgid set AUTH1 drop",
                "drop"
            ])
        
        # Set up gate2
        if gate2_chain and "rules" in gate2_chain:
            filter_table["chains"][gate2_chain]["rules"].extend([
                "meta skuid unset meta skgid unset",
                f"tcp dport {gate2} meta skuid set AUTH2 meta skgid set AUTH2 drop",
                "jump gate1"
            ])
        
        # Set up gate3
        if gate3_chain and "rules" in gate3_chain:
            filter_table["chains"][gate3_chain]["rules"].extend([
                "meta skuid unset meta skgid unset",
                f"tcp dport {gate3} meta skuid set AUTH3 meta skgid set AUTH3 drop",
                "jump gate1"
            ])
        
        # Set up passed
        if passed_chain and "rules" in passed_chain:
            filter_table["chains"][passed_chain]["rules"].extend([
                "meta skuid unset meta skgid unset",
                f"tcp dport {ssh_port} accept",
                "jump gate1"
            ])
            
    def add_logging_rules(self) -> None:
        """Add logging rules for PSAD and fail2ban"""
        logger.info("Adding logging rules for PSAD and fail2ban")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Get input and forward chains
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        forward_chain = next((c for c in filter_table["chains"] if c == "forward"), None)
        
        if not input_chain or not forward_chain:
            logger.warning("Input or forward chain not found")
            return
            
        # Add logging rules for PSAD
        filter_table["chains"][input_chain]["rules"].append(
            "log prefix \"[NFTABLES] INPUT: \" flags all"
        )
        
        filter_table["chains"][forward_chain]["rules"].append(
            "log prefix \"[NFTABLES] FORWARD: \" flags all"
        )
        
        # Create a chain for fail2ban in the dictionary style
        filter_table["chains"]["f2b-sshd"] = {
            "type": None,
            "rules": []
        }
        
        # Add jump to fail2ban chain
        ssh_port = self.config["ssh_port"]
        filter_table["chains"][input_chain]["rules"].append(
            f"tcp dport {ssh_port} jump f2b-sshd"
        )
        
    def set_default_policy(self) -> None:
        """Set default policies for base chains"""
        logger.info("Setting default policies for base chains")
        
        # Find the filter table
        filter_table = next((t for t in self.ruleset["tables"] if t["name"] == "filter"), None)
        if not filter_table:
            logger.warning("Filter table not found")
            return
            
        # Set drop policy for input chain
        input_chain = next((c for c in filter_table["chains"] if c == "input"), None)
        if input_chain:
            filter_table["chains"][input_chain]["policy"] = "drop"
        
    def generate_nftables_ruleset(self) -> str:
        """Generate nftables ruleset file content from the ruleset structure"""
        logger.info("Generating nftables ruleset file")
        
        ruleset_str = "#!/usr/sbin/nft -f\n\n"
        ruleset_str += "# Generated by nftables_converter.py\n"
        ruleset_str += f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Flush existing rules
        ruleset_str += "flush ruleset\n\n"
        
        # Generate tables and chains
        for table in self.ruleset["tables"]:
            family = table["family"]
            name = table["name"]
            
            ruleset_str += f"table {family} {name} {{\n"
            
            # Generate sets if any
            if "sets" in table and table["sets"]:
                for nft_set_name, nft_set in table["sets"].items():
                    set_name = nft_set_name
                    set_type = nft_set["type"]
                    
                    ruleset_str += f"    set {set_name} {{\n"
                    ruleset_str += f"        type {set_type}\n"
                    
                    if "elements" in nft_set and nft_set["elements"]:
                        elements_str = ", ".join(nft_set["elements"])
                        ruleset_str += f"        elements = {{ {elements_str} }}\n"
                        
                    ruleset_str += "    }\n\n"
            
            # Generate chains
            for chain in table["chains"]:
                chain_name = chain
                chain = table["chains"][chain]
                if chain["type"] is not None:  # Base chain
                    hook = chain["hook"]
                    priority = chain["priority"]
                    policy = chain["policy"]
                    
                    ruleset_str += f"    chain {chain_name} {{\n"
                    ruleset_str += f"        type {chain['type']} hook {hook} priority {priority}"
                    
                    if policy:
                        ruleset_str += f"; policy {policy}"
                        
                    ruleset_str += ";\n"
                else:  # Regular chain
                    ruleset_str += f"    chain {chain_name} {{\n"
                
                # Add rules
                if "rules" in chain and chain["rules"]:
                    for rule in chain["rules"]:
                        ruleset_str += f"        {rule}\n"
                        
                ruleset_str += "    }\n\n"
                
            ruleset_str += "}\n\n"
            
        return ruleset_str
        
    def save_ruleset_to_file(self, file_path: str) -> bool:
        """Save the generated ruleset to a file"""
        ruleset_str = self.generate_nftables_ruleset()
        try:
            logger.info(f"Saving ruleset to {file_path}")
            try:
                with open(file_path, "w") as f:
                    f.write(ruleset_str)
                    
                # Make the file executable
                os.chmod(file_path, 0o755)
            except:
                logger.warning(f"Ruleset file could not be saved to {file_path}, trying local path instead")
                filename: str = os.path.basename(file_path)
                file_path = f"{os.getcwd()}/{filename}"
                with open(file_path, "w") as fp:
                    fp.write(ruleset_str)
                os.chmod(file_path, 0o755)
            
            logger.info(f"Ruleset saved to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save ruleset: {e}")
            return False
            
    def apply_ruleset(self, file_path: str) -> bool:
        """Apply the ruleset using nft command"""
        logger.info("Applying nftables ruleset")
        
        if not os.path.exists(file_path):
            logger.error(f"Ruleset file {file_path} not found")
            return False
            
        if not self.load_ip_blacklist():
            logger.warning("Blacklist wasn't loaded into nftables")
            
        try:
            if self.cmd_nft:
                subprocess.run([self.cmd_nft, "-f", file_path], check=True)
                logger.info("Ruleset applied successfully")
                return True
            else:
                raise Exception()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply ruleset: {e}")
            return False
            
    def load_ip_blacklist(self) -> bool:
        """Load IP blacklist from the internet"""
        logger.info("Loading IP blacklist")
        
        if not self.cmd_nft:
            logger.error("nft command not found. Cannot load IP blacklist.")
            return False
            
        try:
            import requests
            
            # Fetch the blacklist
            response = requests.get(
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch blacklist: {response.status_code}")
                return False
                
            # Parse the blacklist
            ip_blacklist = []
            for line in response.text.splitlines():
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) > 1:
                        ip_blacklist.append(parts[0])
                        
            if not ip_blacklist:
                logger.warning("No IPs found in the blacklist")
                return False
                
            # Add IPs to the blacklist set using nft command
            logger.info(f"Adding {len(ip_blacklist)} IPs to blacklist set")
            
            # First flush the set
            subprocess.run([self.cmd_nft, "flush", "set", "inet", "filter", "ipsum"], check=True)
            
            # Add IPs in batches to avoid command line length limits
            batch_size = 1000
            for i in range(0, len(ip_blacklist), batch_size):
                batch = ip_blacklist[i:i+batch_size]
                elements = ", ".join(batch)
                subprocess.run([self.cmd_nft, "add", "element", "inet", "filter", "ipsum", "{" + elements + "}"], check=True)
                
            logger.info("IP blacklist loaded successfully")
            return True
        except ImportError:
            logger.error("Requests library not found. Install it with: pip install requests")
            return False
        except Exception as e:
            logger.error(f"Failed to load IP blacklist: {e}")
            return False
            
    # Removed integrate_with_firewalld method - firewalld integration is handled in firewalld_integration.py
            
    def create_port_knocking_client(self, file_path: str, target: str, ports: List[int], ssh_port: int) -> bool:
        """Create a port knocking client script"""
        logger.info(f"Creating port knocking client script at {file_path}")
        
        script_content = f"""#!/bin/bash
# Port knocking client script
# Generated by nftables_converter.py

NMAP="$(which nmap)"
if [ -z "$NMAP" ]; then
    echo "nmap is not installed. Please install it."
    exit 1
fi

TARGET="{target}"
PORTS=({" ".join(map(str, ports))})

for PORT in "${{PORTS[@]}}"; do
    echo "Knocking on $PORT"
    $NMAP -Pn --host-timeout 201 --max-retries 0 -p $PORT $TARGET >/dev/null
    sleep 1
done

echo "Connecting to SSH on port {ssh_port}"
ssh -p {ssh_port} $TARGET
"""
        
        try:
            with open(file_path, "w") as f:
                f.write(script_content)
                
            # Make the file executable
            os.chmod(file_path, 0o755)
            
            logger.info(f"Port knocking client script created at {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to create port knocking client script: {e}")
            return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Convert iptables rules to nftables and integrate with firewalld")
    parser.add_argument("--ports", type=str, help="Comma-separated list of ports to allow", required=True)
    parser.add_argument("--interface", type=str, help="Network interface to protect")
    parser.add_argument("--disable-icmp", type=int, choices=[0, 1], help="Disable ICMP")
    parser.add_argument("--whitelist-file", type=str, help="File containing whitelisted IPs")
    parser.add_argument("--enable-port-knocking", type=int, choices=[0, 1], help="Enable port knocking")
    parser.add_argument("--output", type=str, default="/etc/nftables.conf", help="Output file path")
    parser.add_argument("--port-knocking-script", type=str, help="Path to create port knocking client script")
    parser.add_argument("--target", type=str, help="Target for port knocking")
    parser.add_argument("--enable-firewalld", action="store_true", help="Integrate with firewalld")
    parser.add_argument("--apply", action="store_true", help="Apply the ruleset immediately")
    
    args = parser.parse_args()
    
    # Create a config object from command-line arguments
    config = {}
    
    if args.interface:
        config["interface"] = args.interface
    
    if args.disable_icmp is not None:
        config["disable_icmp"] = args.disable_icmp
        
    if args.whitelist_file:
        config["whitelist_file"] = args.whitelist_file
        
    if args.enable_port_knocking is not None:
        config["enable_port_knocking"] = args.enable_port_knocking
        
    # Configure system settings
    #converter.configure_system_settings()
    
    # Load kernel modules
    #converter.load_kernel_modules()
    
    # Create the converter
    converter = NftablesConverter(config)
    
    # Set up the base structure
    converter.create_nftables_base_structure()
    
    # Add rules
    converter.add_prerouting_block_rules()
    converter.add_input_basic_rules()
    converter.add_port_rules(args.ports)
    converter.limit_connections(args.ports)
    converter.add_icmp_rules()
    converter.add_whitelist_rules()
    converter.add_ip_blacklist()
    
    if config.get("enable_port_knocking", 0) == 1:
        converter.setup_port_knocking()
        
    converter.add_logging_rules()
    
    # Set default policy after all rules are added
    converter.set_default_policy()
    
    # Save the ruleset
    if not converter.save_ruleset_to_file(args.output):
        logger.error("Failed to save ruleset")
        sys.exit(1)
        
    # Create port knocking client script if requested
    if args.port_knocking_script and args.target and config.get("enable_port_knocking", 0) == 1:
        ports = [config.get("gate1", 1025), config.get("gate2", 1026), config.get("gate3", 1027)]
        ssh_port = config.get("ssh_port", 22)
        
        if not converter.create_port_knocking_client(args.port_knocking_script, args.target, ports, ssh_port):
            logger.error("Failed to create port knocking client script")
    
    # Apply the ruleset if requested
    if args.apply:
        if not converter.apply_ruleset(args.output):
            logger.error("Failed to apply ruleset")
            sys.exit(1)
    
    # Check if firewalld integration is requested - this is handled by firewalld_integration.py
    if args.enable_firewalld:
        logger.info("Firewalld integration requested - this will be handled by firewalld_integration.py")
            
    logger.info("Done")

if __name__ == "__main__":
    main()
