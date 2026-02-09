## Iptables, nftables, and firewalld scripts

This repository is useful for setting up iptables, nftables, and/or firewalld automatically. This creates Ease of Use (EoU) for mass deployment making sure that your infrastructure stays just that much more secure.

## iptables to nftables Converter with Firewalld Integration

This project has utility to convert iptables firewall rules to nftables syntax and provides integration with firewalld. It preserves all the security features of the original iptables rules while leveraging the improved performance and features of nftables.

## Overview

The project consists of three main components:

1. **nftables_converter.py**: Python script that converts iptables rules to nftables format
2. **firewalld_integration.py**: Python script that integrates the nftables rules with firewalld
3. **setup_nftables.sh**: Shell script that orchestrates the conversion and integration process
4. **iptables.sh** Shell script that sets up iptables **only**

## Features

- Converts all iptables rules to equivalent nftables syntax
- Preserves security features:
  - TCP stack protections
  - Connection rate limiting
  - Port knocking
  - ICMP blocking
  - IP blacklisting
  - Integration with PSAD and fail2ban
  - Time-based access control
  - OS fingerprint manipulation (can look like Windows or Linux)
- Integrates with firewalld using direct rules
- Generates and applies nftables rulesets
- Creates client scripts for port knocking

## Requirements

- Python 3.6+
- nftables
- Root privileges (to apply rules)

### Optional (only needed with `--firewalld` flag)

- firewalld
- python3-firewall package (for the firewalld Python API)

> **Note:** On VPS boxes using cloud-init, the `firewalld` package often conflicts with `cloud-init`. The nftables script works perfectly without firewalld — just omit the `--firewalld` flag.

### Installing Dependencies

For Debian/Ubuntu:
```bash
# Core dependencies (always required)
sudo apt-get install nftables python3

# Optional: only if using --firewalld integration
sudo apt-get install firewalld python3-firewall
```

For RHEL/CentOS/Fedora:
```bash
# Core dependencies (always required)
sudo dnf install nftables python3

# Optional: only if using --firewalld integration
sudo dnf install firewalld python3-firewall
```

## Installation

1. Clone this repository or copy the files to your server
2. Make sure the scripts are executable:
   ```bash
   chmod +x setup_nftables.sh
   chmod +x nftables_converter.py
   chmod +x firewalld_integration.py
   chmod +x iptables.sh
   ```
3. Run the setup script (see Usage section)

## Usage

### Basic Usage

For using iptables
```bash
sudo ./iptables.sh 22,80,443
```

For using nftables
```bash
sudo ./setup_nftables.sh --ports 22,80,443 --interface eth0 --apply
```

This will:
1. Convert iptables rules to nftables for ports 22, 80, and 443
2. Protect the eth0 interface
3. Apply the rules immediately

### Options

If using nftables
```
Usage: ./setup_nftables.sh [options]

Options:
  -p, --ports PORTS          Comma-separated list of ports to allow (default: 22,80,443)
  -i, --interface INTERFACE  Network interface to protect (default: ens33)
  -o, --output FILE          Output file for nftables rules (default: /etc/nftables.conf)
  -f, --firewalld            Enable firewalld integration
  -k, --port-knocking        Enable port knocking
  -a, --apply                Apply the ruleset immediately
  -z, --zone ZONE            Firewalld zone to use (default: public)
  -h, --help                 Show this help message
```

### Examples

#### Enable Port Knocking

```bash
sudo ./setup_nftables.sh --ports 22,80,443 --enable-port-knocking --apply
```

#### Integrate with Firewalld

```bash
sudo ./setup_nftables.sh --ports 22,80,443 --firewalld --zone=internal --apply 
```

#### Custom Output File

```bash
sudo ./setup_nftables.sh --ports 22,80,443 --output /etc/nftables/custom.conf
```

## How It Works

### nftables Conversion

The conversion process:

1. Analyzes the original iptables rules structure
2. Creates equivalent nftables tables and chains
3. Converts each iptables rule to nftables syntax
4. Preserves special features like port knocking
5. Generates a complete nftables ruleset file

### Firewalld Integration

Firewalld integration works by:

1. Creating custom services for the allowed ports
2. Adding direct rules to pass traffic to nftables
3. Setting up a systemd service to load nftables rules at boot
4. Configuring firewalld zones with the correct services

### Port Knocking

Port knocking is implemented using nftables sets and marks:

1. Creates a sequence of "gates" (ports that must be accessed in order)
2. Uses connection tracking to remember clients that have knocked correctly
3. Only allows SSH access to clients that complete the knocking sequence

## Advanced Configuration

### TCP Stack Protections

The converter preserves TCP stack protections by applying the same sysctl settings:

```
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
```

### TCP Optimizations

TCP optimizations include using BBR congestion control:

```
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
```

### OS Fingerprinting

The TTL and TCP options can be configured to make the server look like Windows:

```
net.ipv4.ip_default_ttl = 128
net.ipv4.tcp_base_mss = 1460
net.ipv4.tcp_mtu_probing = 2
```

Or like Linux:

```
net.ipv4.ip_default_ttl = 64
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_mtu_probing = 0
```

## Troubleshooting

### Common Issues

1. **Rules not being applied**: Ensure you're running the script with sudo or as root
2. **Missing dependencies**: Install nftables and firewalld if needed
3. **Port access issues**: Check the ruleset output file for errors

### Checking Ruleset

```bash
nft list ruleset
```

### Firewalld Status

```bash
firewall-cmd --state
firewall-cmd --list-all --zone=public
```

### Future work

This has been and will be a heavily utilized set of utilities for my own personal use. Eventually integrating XDP, and kernel patching to further modify the TCP/IP stack of Linux to make identification more difficult and therefore attacks more difficult.

## License

See the LICENSE file.
