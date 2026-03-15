<div align="center">
  <img src="./assets/img/header.svg" alt="nmap-blueteam" width="100%"/>
</div>

---

Practical Nmap guide for Blue Team operations. Covers host discovery, port scanning, service and version detection, OS fingerprinting, NSE scripts, and result analysis — with a focus on defensive workflows for SOC analysts and junior practitioners.

> Nmap sends packets to network targets. Never run it against systems or networks you don't own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

## Contents

- [Why Nmap for Blue Team](#why-nmap-for-blue-team)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Port States](#port-states)
- [Flag Reference](#flag-reference)
- [Essential Commands](#essential-commands)
- [NSE Scripts for Defense](#nse-scripts-for-defense)
- [Reading Output](#reading-output)
- [Blue Team Workflows](#blue-team-workflows)
- [Scripts](#scripts)
- [Contributing](#contributing)

---

## Why Nmap for Blue Team

Nmap is not just an attacker's tool. For a defender it answers the most fundamental question: **what is actually running on my network?**

Without scanning your own infrastructure you're relying on documentation that's usually wrong, outdated, or incomplete. Nmap gives you ground truth.

Concrete defensive uses:

- **Shadow IT discovery** — find devices that weren't added to the asset inventory
- **Attack surface audit** — identify ports open to the internet that shouldn't be
- **Vulnerability management** — version detection feeds directly into CVE lookups
- **Firewall verification** — confirm that ACLs and segmentation rules work as intended
- **Change detection** — compare scans over time with `ndiff` to catch unauthorized changes
- **Incident response** — quickly map an affected network segment during an investigation

---

## Installation

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install nmap

# Fedora / CentOS / RHEL
sudo dnf install nmap

# macOS
brew install nmap

# Windows — download the installer from https://nmap.org/download.html
```

Most useful Nmap features (SYN scan, OS detection, raw packet operations) require root/administrator privileges. On Linux and macOS, prefix commands with `sudo`.

Verify: `nmap --version`

---

## Core Concepts

**1. Target specification**
```bash
192.168.1.1           # single IP
192.168.1.1-20        # IP range
192.168.1.0/24        # CIDR subnet
server.local          # hostname
-iL targets.txt       # read from file
```

Always define the smallest authorized scope.

**2. Host discovery**

Before scanning ports, Nmap checks if a host is alive. Options:

```bash
-sn     # host discovery only, no port scan
-PE     # ICMP echo ping
-PR     # ARP ping — fastest on local networks
-Pn     # skip discovery, assume all hosts are up
```

On local networks `-PR` (ARP) is most reliable. On remote networks use `-PE` or `-Pn` if ICMP is blocked.

**3. Service and version detection**

`-sV` probes open ports to identify the exact application and version. This is the most operationally valuable flag for defenders — it bridges "port 443 is open" and "Apache 2.4.52 is running, which has CVE-2022-31813."

**4. Output — always save results**
```bash
-oN scan.txt      # normal format, human-readable
-oX scan.xml      # XML, use with ndiff and other tools
-oA scan_name     # all formats at once (recommended)
```

---

## Port States

| State | What it means | What to do |
|-------|--------------|------------|
| `open` | A service is actively listening | Check inventory. Identify with `-sV`. Look up version in CVE databases. |
| `closed` | No service listening, but host responds | Host is alive. Service may have been stopped recently. |
| `filtered` | Firewall is likely blocking — state unknown | Expected on internet-facing ports. Unexpected internally = investigate. |
| `open\|filtered` | Can't distinguish — common with UDP | Run a more targeted scan to clarify. |

**Key insight:** Every `open` port is potential attack surface. Every *unexpected* `open` port is an incident waiting to happen.

---

## Flag Reference

### Scan types

| Flag | Name | When to use |
|------|------|-------------|
| `-sS` | SYN scan | Default for root. Fast, relatively stealthy. Best for most Blue Team use. |
| `-sT` | TCP connect | No root required. Slower, more detectable. |
| `-sU` | UDP scan | Find UDP services (DNS, SNMP, DHCP). Slow — use with `-F` or specific ports. |
| `-sA` | ACK scan | Map firewall rules. Shows `filtered` vs `unfiltered`. |
| `-sn` | Ping scan | Host discovery only, no port scanning. |

### Port selection

| Flag | Effect |
|------|--------|
| `-p 22,80,443` | Specific ports |
| `-p 1-1024` | Port range |
| `-p-` | All 65535 ports |
| `-F` | Fast — top 100 ports |
| `--top-ports 1000` | Top 1000 most common |

### Detection

| Flag | Effect |
|------|--------|
| `-sV` | Service and version detection |
| `-O` | OS fingerprinting (root required) |
| `-sC` | Run default NSE scripts |
| `--script=<name>` | Run specific NSE script |
| `-A` | Aggressive: `-sV -O -sC --traceroute` |

### Timing

| Flag | Name | Use case |
|------|------|----------|
| `-T3` | Normal | Default — safe for most environments |
| `-T4` | Aggressive | Fast internal networks — use this for lab and internal audits |
| `-T2` | Polite | Reduce network load on production |
| `-T1` | Sneaky | Slow, low detection risk |

For internal audits `-T4` is the right choice. For production systems or external targets use `-T3`.

---

## Essential Commands

**Host discovery — find live hosts**
```bash
# ARP ping — fastest on local networks
sudo nmap -sn -PR -T4 192.168.1.0/24

# Save live hosts for chained scans
sudo nmap -sn -PR -T4 192.168.1.0/24 -oG - | grep "Status: Up" | awk '{print $2}' > live_hosts.txt
```

**Quick check — top 100 ports**
```bash
sudo nmap -F -T4 192.168.1.10
```

**Standard audit — top 1000 ports + versions**
```bash
sudo nmap -sS -sV --top-ports 1000 -T4 192.168.1.10 -oA scan_$(date +%Y%m%d)
```

**Targeted scan — specific services**
```bash
# Web, SSH, RDP, WinRM
sudo nmap -sS -sV -p 22,80,443,3389,5985,8080,8443 -T4 192.168.1.0/24

# All common admin ports
sudo nmap -sS -sV -p 21,22,23,25,53,80,110,143,389,443,445,3389,5985 -T4 192.168.1.10
```

**Full scan — all ports + OS + scripts**
```bash
# Use on specific hosts after fast discovery — takes time
sudo nmap -sS -sV -O -sC -p- -T4 192.168.1.10 -oA fullscan_$(date +%Y%m%d)
```

**UDP services**
```bash
# Top 100 UDP ports
sudo nmap -sU --top-ports 100 -T4 192.168.1.10

# Specific UDP services: DNS, DHCP, NTP, SNMP
sudo nmap -sU -p 53,67,123,161 -sV -T4 192.168.1.10
```

**Firewall rule verification — ACK scan**
```bash
# Shows filtered vs unfiltered — not open vs closed
sudo nmap -sA -p 22,80,443,3389 -T4 192.168.1.10
```

**Compare two scans for changes**
```bash
ndiff scan_20241101.xml scan_20241115.xml
# + = new findings, - = removed
```

---

## NSE Scripts for Defense

NSE (Nmap Scripting Engine) adds detection capabilities beyond basic port scanning. Browse available scripts:

```bash
ls /usr/share/nmap/scripts/
ls /usr/share/nmap/scripts/ | grep smb
```

**SSL/TLS audit**
```bash
# Enumerate TLS versions and cipher suites
nmap --script ssl-enum-ciphers -p 443 192.168.1.10

# Check certificate details and expiry
nmap --script ssl-cert -p 443 192.168.1.10

# Check for Heartbleed
nmap --script ssl-heartbleed -p 443 192.168.1.10
```

**SMB security**
```bash
# Check SMB signing and protocol version
nmap --script smb-security-mode,smb2-security-mode -p 445 192.168.1.0/24

# Check for SMBv1 (should be zero everywhere)
nmap --script smb-protocols -p 445 192.168.1.0/24

# Check SMB vulnerabilities
nmap --script smb-vuln* -p 445 192.168.1.0/24
```

**SSH**
```bash
# Enumerate algorithms and key exchange methods
nmap --script ssh2-enum-algos -p 22 192.168.1.10

# Check authentication methods
nmap --script ssh-auth-methods -p 22 192.168.1.10
```

**HTTP**
```bash
# Enumerate methods, headers, and page titles
nmap --script http-methods,http-headers,http-title -p 80,443,8080 192.168.1.10

# Look for web vulnerabilities
nmap --script http-vuln* -p 80,443 192.168.1.10
```

**DNS**
```bash
# Attempt zone transfer — should fail; success is a critical finding
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 192.168.1.1
```

---

## Reading Output

A real Nmap output and what each part tells you:

```
Nmap scan report for 192.168.1.50 (web-server-01.local)
Host is up (0.00042s latency).
MAC Address: 00:1A:2B:3C:4D:5E (Dell Inc.)

PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp    open     http       Apache httpd 2.4.52 (Ubuntu)
443/tcp   open     https      Apache httpd 2.4.52
8080/tcp  filtered http-proxy
3306/tcp  closed   mysql

OS details: Linux 5.15 - 5.19
```

**What to do with each result:**

`22/tcp open ssh OpenSSH 8.9p1` → Search NVD for "OpenSSH 8.9p1". Is this version in your approved software list? Is SSH supposed to be accessible from your scanning position?

`80/tcp open http Apache httpd 2.4.52` → Apache 2.4.52 has known CVEs. Is HTTP (unencrypted) supposed to be enabled? Should traffic be redirected to HTTPS?

`8080/tcp filtered` → Firewall is blocking this from your current position. Was it open in the previous scan? If yes, investigate whether the service is still running behind the firewall.

`3306/tcp closed` → MySQL isn't running. Was it in the last scan? If yes — was this a planned change, or did something stop it unexpectedly?

**Three questions for every open port:**

1. Is this port supposed to be open on this host? (Check asset inventory and change management)
2. Is this software version patched? (`CVE + service name + version` in NVD or your scanner)
3. Has this changed since the last scan? (`ndiff old.xml new.xml`)

---

## Blue Team Workflows

**Weekly network inventory check**
```bash
#!/bin/bash
DATE=$(date +%Y%m%d)
SUBNET="192.168.1.0/24"

# Discover live hosts
sudo nmap -sn -PR -T4 "$SUBNET" -oG - | grep "Status: Up" | awk '{print $2}' > /tmp/live.txt
echo "$(wc -l < /tmp/live.txt) hosts found"

# Scan live hosts
sudo nmap -sS -sV --top-ports 1000 -T4 -iL /tmp/live.txt -oA "weekly_$DATE"

# Compare with last scan
LAST=$(ls weekly_*.xml 2>/dev/null | sort | tail -2 | head -1)
[ -n "$LAST" ] && ndiff "$LAST" "weekly_$DATE.xml"
```

**Firewall rule verification**
```bash
# Scan from outside the perimeter (authorized jump host) — what's visible?
sudo nmap -sS -sV -p 22,80,443,3389,8080,8443 -T4 [external-target-ip] -oA fw_check_$(date +%Y%m%d)

# Any port open externally that's not in your approved exposure list = finding
```

**Incident response — quick network map**
```bash
# Fast map of affected segment
sudo nmap -sS -sV -F -T4 10.0.1.0/24 -oA ir_$(date +%Y%m%d_%H%M)

# Check for lateral movement indicators — unusual ports on workstations
sudo nmap -sS -p 445,3389,5985,4444,8080 -T4 10.0.1.0/24
```

**Version audit for vulnerability management**
```bash
# Scan and export to XML for import into your VM platform
sudo nmap -sS -sV --top-ports 1000 -T4 192.168.1.0/24 -oX vuln_audit_$(date +%Y%m%d).xml
```

---

## Scripts

| Script | Purpose |
|--------|---------|
| [`scan_basico_red.sh`](scripts/scan_basico_red.sh) | Basic network sweep — discover hosts, scan top 100 ports, save results |

```bash
cd scripts/
chmod +x scan_basico_red.sh
sudo ./scan_basico_red.sh 192.168.1.0/24
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the process. Open an issue to suggest new commands, workflows, or corrections.

---

License: [MIT](LICENSE)
