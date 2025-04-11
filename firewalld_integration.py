#!/usr/bin/env python3
"""
firewalld_integration.py - Integrate nftables rules with firewalld using the Python API
"""

import os
import sys
import subprocess
import argparse
import logging
from typing import List, Optional
import xml.etree.ElementTree as ET

# Import firewalld Python modules
try:
    import firewall.config
    from firewall.client import FirewallClient
    from firewall.core.io.service import Service
    from firewall.core.io.direct import Direct
except ImportError:
    print("Error: firewalld Python modules not found. Please install 'python3-firewall' package.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('firewalld-integration')

class FirewalldIntegration:
    """Class for integrating nftables rules with firewalld using the Python API"""
    
    def __init__(self):
        """Initialize the firewalld integration"""
        self.cmd_systemctl = self._find_command("systemctl")
        self.fw_client = None
        
        try:
            self.fw_client = FirewallClient()
            logger.info("Connected to firewalld D-Bus service")
        except Exception as e:
            logger.error(f"Error connecting to firewalld: {e}")
            sys.exit(1)
            
        if not self.cmd_systemctl:
            logger.warning("systemctl not found. Cannot start firewalld automatically.")
            
    def _find_command(self, command: str) -> Optional[str]:
        """Find the full path of a command"""
        try:
            result = subprocess.run(
                ["which", command],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
            
    def ensure_firewalld_running(self) -> bool:
        """Ensure firewalld is running"""
        logger.info("Checking if firewalld is running")
        
        # Check if we have a valid client connection
        if not self.fw_client:
            try:
                self.fw_client = FirewallClient()
                logger.info("Connected to firewalld")
                return True
            except Exception:
                # If we can't connect, try to start the service
                if self.cmd_systemctl:
                    logger.info("Starting firewalld")
                    try:
                        subprocess.run([self.cmd_systemctl, "start", "firewalld"], check=True)
                        # Try to connect again
                        try:
                            self.fw_client = FirewallClient()
                            logger.info("firewalld started successfully")
                            return True
                        except Exception as e:
                            logger.error(f"Failed to connect to firewalld after starting: {e}")
                    except Exception as e:
                        logger.error(f"Failed to start firewalld: {e}")
                
                return False
        
        # Check if firewalld is running by testing a simple operation
        try:
            self.fw_client.get_zones()
            return True
        except Exception:
            # Try to restart the connection
            try:
                self.fw_client = FirewallClient()
                return True
            except Exception:
                return False
            
    def create_direct_rules(self, rules_file: str) -> bool:
        """Create direct rules for firewalld using the Python API"""
        logger.info(f"Creating direct rules in {rules_file}")
        
        # Ensure firewalld is running
        if not self.ensure_firewalld_running() or not self.fw_client:
            return False
        
        try:
            # Create a new Direct configuration object
            direct = Direct()
            
            # Add direct rules
            direct.add_rule("ipv4", "filter", "INPUT", 0, ["-j", "nftables-input"])
            direct.add_rule("ipv4", "filter", "FORWARD", 0, ["-j", "nftables-forward"])
            direct.add_rule("ipv4", "filter", "OUTPUT", 0, ["-j", "nftables-output"])
            
            # Write the direct rules to the file
            direct.write(rules_file)
            
            # Reload firewalld to recognize the new direct rules
            self.fw_client.reload()
            
            logger.info(f"Direct rules created in {rules_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to create direct rules: {e}")
            return False
            
    def create_custom_service(self, service_name: str, ports: List[str]) -> bool:
        """Create a custom service for the specified ports using the Python API"""
        logger.info(f"Creating custom service {service_name} for ports {ports}")
        
        # Ensure firewalld is running
        if not self.ensure_firewalld_running() or not self.fw_client:
            return False
            
        try:
            # Create a new service
            service = Service()
            service.name = service_name
            service.version = "1.0"
            service.short = service_name
            service.description = f"Custom service for ports {', '.join(ports)}"
            
            # Add ports to the service
            for port in ports:
                service.add_port(port, "tcp")
            
            # Create the services directory if it doesn't exist
            service_dir = firewall.config.ETC_FIREWALLD_SERVICES
            os.makedirs(service_dir, exist_ok=True)
            
            # Save the service
            service_path = os.path.join(service_dir, f"{service_name}.xml")
            service.export_config(service_path)
            
            # Reload firewalld to recognize the new service
            self.fw_client.reload()
            
            logger.info(f"Custom service {service_name} created")
            return True
        except Exception as e:
            logger.error(f"Failed to create custom service: {e}")
            return False
            
    def add_service_to_zone(self, service_name: str, zone: str = "public", permanent: bool = True) -> bool:
        """Add the custom service to a firewalld zone using the Python API"""
        logger.info(f"Adding service {service_name} to zone {zone}")
        
        # Ensure firewalld is running
        if not self.ensure_firewalld_running() or not self.fw_client:
            return False
            
        try:
            # Add the service to the zone
            if permanent:
                # Add permanently
                self.fw_client.add_service(zone, service_name, permanent=True)
                # Also add to runtime configuration for immediate effect
                self.fw_client.add_service(zone, service_name, permanent=False)
            else:
                # Add only to runtime configuration
                self.fw_client.add_service(zone, service_name, permanent=False)
            
            logger.info(f"Service {service_name} added to zone {zone}")
            return True
        except Exception as e:
            logger.error(f"Failed to add service to zone: {e}")
            return False
            
    def apply_nftables_rules(self, nftables_file: str) -> bool:
        """Apply nftables rules using firewalld integration"""
        logger.info(f"Applying nftables rules from {nftables_file}")
        
        if not os.path.exists(nftables_file):
            logger.error(f"nftables file {nftables_file} not found")
            return False
            
        try:
            # Create direct rules using the Python API
            direct_rule_file = os.path.join(firewall.config.ETC_FIREWALLD, "direct.xml")
            
            self.create_direct_rules(direct_rule_file)
            
            # Create a systemd service to load the nftables rules at boot
            systemd_dir = "/etc/systemd/system"
            os.makedirs(systemd_dir, exist_ok=True)
            
            service_file = os.path.join(systemd_dir, "nftables-firewalld.service")
            
            service_content = f"""[Unit]
Description=Load nftables rules for firewalld integration
After=firewalld.service
Requires=firewalld.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f {nftables_file}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
            
            with open(service_file, "w") as f:
                f.write(service_content)
                
            # Enable and start the service
            if self.cmd_systemctl:
                subprocess.run([self.cmd_systemctl, "daemon-reload"], check=True)
                subprocess.run([self.cmd_systemctl, "enable", "nftables-firewalld.service"], check=True)
                subprocess.run([self.cmd_systemctl, "start", "nftables-firewalld.service"], check=True)
                
            logger.info("nftables rules applied with firewalld integration")
            return True
        except Exception as e:
            logger.error(f"Failed to apply nftables rules: {e}")
            return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Integrate nftables rules with firewalld")
    parser.add_argument("--nftables-file", type=str, default="/etc/nftables.conf", help="Path to nftables ruleset file")
    parser.add_argument("--service-name", type=str, default="custom-ports", help="Name for the custom firewalld service")
    parser.add_argument("--ports", type=str, required=True, help="Comma-separated list of ports to allow")
    parser.add_argument("--zone", type=str, default="public", help="Firewalld zone to add the service to")
    
    args = parser.parse_args()
    
    # Initialize firewalld integration
    integration = FirewalldIntegration()
    
    # Ensure firewalld is running
    if not integration.ensure_firewalld_running():
        logger.error("Failed to ensure firewalld is running")
        sys.exit(1)
        
    # Create a custom service for the ports
    port_list = args.ports.split(",")
    if not integration.create_custom_service(args.service_name, port_list):
        logger.error("Failed to create custom service")
        sys.exit(1)
        
    # Add the service to the specified zone
    if not integration.add_service_to_zone(args.service_name, args.zone):
        logger.error("Failed to add service to zone")
        sys.exit(1)
        
    # Apply the nftables rules
    if not integration.apply_nftables_rules(args.nftables_file):
        logger.error("Failed to apply nftables rules")
        sys.exit(1)
        
    logger.info("Successfully integrated nftables rules with firewalld")

if __name__ == "__main__":
    main()
