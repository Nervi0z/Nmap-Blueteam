#!/usr/bin/env bash
# ==============================================================================
# network_sweep.sh — Blue Team Network Sweep
#
# Usage:
#   sudo bash network_sweep.sh <SUBNET_CIDR> [OUTPUT_DIR]
#
# Examples:
#   sudo bash network_sweep.sh 192.168.1.0/24
#   sudo bash network_sweep.sh 10.0.0.0/16 /var/log/nmap/scans
#
# What it does:
#   1. Discovers live hosts via ARP ping (-PR) for local subnets
#   2. Scans top 1000 TCP ports + version detection on live hosts
#   3. Saves results in all formats (.nmap, .xml, .gnmap)
#   4. Diffs against the previous scan if one exists
#   5. Prints a summary of open ports and flags high-risk services
#
# Requirements: nmap, ndiff (included with nmap), awk, grep
# Requires root: yes (for -sS and -PR)
# ==============================================================================

set -euo pipefail

# --- Configuration ---
readonly DATE=$(date +%Y%m%d_%H%M%S)
readonly DATE_SHORT=$(date +%Y%m%d)
readonly RISKY_PORTS="21 23 69 111 512 513 514 2049 3389 5900 6379 27017"

# --- Colors ---
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
RESET='\033[0m'

# --- Argument validation ---
if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: sudo $0 <SUBNET_CIDR> [OUTPUT_DIR]"
    echo "  Example: sudo $0 192.168.1.0/24"
    echo "  Example: sudo $0 192.168.1.0/24 /var/log/nmap/scans"
    exit 1
fi

SUBNET="$1"
OUTPUT_DIR="${2:-./nmap_results}"

# Validate CIDR format (basic check)
if ! echo "$SUBNET" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'; then
    echo "Error: '$SUBNET' does not look like a valid CIDR range (e.g. 192.168.1.0/24)"
    exit 1
fi

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    echo "Error: this script requires root privileges for SYN scan and ARP ping."
    echo "Run with: sudo $0 $*"
    exit 1
fi

# --- Dependency check ---
for cmd in nmap ndiff awk grep; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed or not in PATH."
        exit 1
    fi
done

# --- Setup output directory ---
mkdir -p "$OUTPUT_DIR"

# Derive safe base name from subnet (replaces / and . with _)
SUBNET_SAFE=$(echo "$SUBNET" | tr './' '__')
SCAN_BASE="${OUTPUT_DIR}/${SUBNET_SAFE}_${DATE}"
HOSTS_TMP=$(mktemp /tmp/nmap_hosts_XXXXXX.txt)

# Find the most recent previous XML scan for this subnet
PREV_SCAN=$(find "$OUTPUT_DIR" -maxdepth 1 -name "${SUBNET_SAFE}_*.xml" 2>/dev/null \
    | sort | tail -n 1)

echo ""
echo -e "${CYAN}=== Blue Team Network Sweep ===${RESET}"
echo -e "  Subnet:     ${GREEN}$SUBNET${RESET}"
echo -e "  Output:     $SCAN_BASE.*"
echo -e "  Previous:   ${PREV_SCAN:-none found}"
echo ""

# ==============================================================================
# STEP 1 — Host discovery
# ==============================================================================
echo -e "${CYAN}[1/3] Host discovery — ARP ping on $SUBNET${RESET}"

nmap -sn -PR -T4 "$SUBNET" -oG - \
    | grep "Status: Up" \
    | awk '{print $2}' \
    > "$HOSTS_TMP"

LIVE_COUNT=$(wc -l < "$HOSTS_TMP" | tr -d ' ')

if [[ "$LIVE_COUNT" -eq 0 ]]; then
    echo "  No live hosts found in $SUBNET."
    echo "  If this is not a local subnet, try running without -PR:"
    echo "  nmap -sn $SUBNET"
    rm -f "$HOSTS_TMP"
    exit 0
fi

echo -e "  Found ${GREEN}$LIVE_COUNT live hosts${RESET}:"
awk '{print "    " $0}' "$HOSTS_TMP"
echo ""

# ==============================================================================
# STEP 2 — Port scan + version detection
# ==============================================================================
echo -e "${CYAN}[2/3] Port scan + version detection on $LIVE_COUNT hosts${RESET}"
echo "  Flags: -sS -sV --top-ports 1000 -T4"
echo ""

nmap -sS -sV --top-ports 1000 -T4 \
    -iL "$HOSTS_TMP" \
    -oA "$SCAN_BASE"

# ==============================================================================
# STEP 3 — Summary and diff
# ==============================================================================
echo ""
echo -e "${CYAN}[3/3] Summary${RESET}"
echo ""

# Count open ports from .gnmap
OPEN_COUNT=$(grep -c "Ports:.*open" "${SCAN_BASE}.gnmap" 2>/dev/null || echo "0")
echo -e "  Open ports found: ${GREEN}$OPEN_COUNT${RESET}"
echo ""

# Extract and display open ports
if grep -q "open" "${SCAN_BASE}.nmap" 2>/dev/null; then
    echo -e "  Open port details:"
    grep "/tcp.*open\|/udp.*open" "${SCAN_BASE}.nmap" | while read -r line; do
        PORT=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        # Flag risky ports
        IS_RISKY=false
        for RISKY in $RISKY_PORTS; do
            if [[ "$PORT" == "$RISKY" ]]; then
                IS_RISKY=true
                break
            fi
        done
        if $IS_RISKY; then
            echo -e "  ${RED}  $line  <-- REVIEW${RESET}"
        else
            echo -e "  ${GRAY}  $line${RESET}"
        fi
    done
    echo ""
fi

# Risky port warning
FOUND_RISKY=()
for PORT in $RISKY_PORTS; do
    if grep -q "^${PORT}/tcp.*open\|^${PORT}/udp.*open" "${SCAN_BASE}.nmap" 2>/dev/null; then
        FOUND_RISKY+=("$PORT")
    fi
done

if [[ ${#FOUND_RISKY[@]} -gt 0 ]]; then
    echo -e "  ${RED}High-priority findings:${RESET}"
    for PORT in "${FOUND_RISKY[@]}"; do
        case "$PORT" in
            21)  echo -e "  ${RED}  Port 21 (FTP) open — plaintext protocol, migrate to SFTP${RESET}" ;;
            23)  echo -e "  ${RED}  Port 23 (Telnet) open — everything plaintext, disable immediately${RESET}" ;;
            69)  echo -e "  ${YELLOW}  Port 69 (TFTP) open — no authentication, review if necessary${RESET}" ;;
            3389) echo -e "  ${YELLOW}  Port 3389 (RDP) open — ensure not internet-facing, require MFA${RESET}" ;;
            5900) echo -e "  ${YELLOW}  Port 5900 (VNC) open — review authentication and access controls${RESET}" ;;
            6379) echo -e "  ${RED}  Port 6379 (Redis) open — check if auth is required${RESET}" ;;
            27017) echo -e "  ${RED}  Port 27017 (MongoDB) open — check if auth is required${RESET}" ;;
            *)   echo -e "  ${YELLOW}  Port $PORT open — review necessity and access controls${RESET}" ;;
        esac
    done
    echo ""
fi

# ndiff against previous scan
if [[ -n "$PREV_SCAN" && -f "$PREV_SCAN" ]]; then
    DIFF_FILE="${OUTPUT_DIR}/diff_${DATE_SHORT}.txt"
    echo -e "  ${CYAN}Changes since last scan ($(basename "$PREV_SCAN")):${RESET}"
    ndiff "$PREV_SCAN" "${SCAN_BASE}.xml" > "$DIFF_FILE" 2>/dev/null || true
    if [[ -s "$DIFF_FILE" ]]; then
        # Show only changed lines (lines starting with + or -)
        grep -E "^\+|^-" "$DIFF_FILE" | grep -v "^---\|^+++" | head -30 \
            | while read -r line; do
                if [[ "$line" == +* ]]; then
                    echo -e "  ${GREEN}$line${RESET}"
                else
                    echo -e "  ${RED}$line${RESET}"
                fi
              done
        echo "  Full diff saved to: $DIFF_FILE"
    else
        echo -e "  ${GREEN}No changes detected.${RESET}"
    fi
    echo ""
fi

# Cleanup
rm -f "$HOSTS_TMP"

# Final summary
echo -e "${CYAN}Results saved:${RESET}"
echo "  ${SCAN_BASE}.nmap  (human-readable)"
echo "  ${SCAN_BASE}.xml   (machine-readable, for ndiff)"
echo "  ${SCAN_BASE}.gnmap (grepable)"
echo ""
echo -e "${CYAN}Done.${RESET}"
echo ""
