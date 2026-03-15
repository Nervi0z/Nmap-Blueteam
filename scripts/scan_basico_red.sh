#!/bin/bash
# =============================================================================
# scan_basico_red.sh — Basic network sweep for Blue Team
#
# Usage:  sudo ./scan_basico_red.sh <SUBNET_CIDR>
# Example: sudo ./scan_basico_red.sh 192.168.1.0/24
#
# Steps:
#   1. Discover live hosts via ARP ping (-PR)
#   2. Scan top 100 ports + service/version on live hosts (-F -sV)
#   3. Save results in .nmap, .xml, and .gnmap formats
#
# Requirements: nmap, awk, grep, root privileges (sudo)
# =============================================================================

set -euo pipefail

# --- Input validation --------------------------------------------------------
if [ "$#" -ne 1 ]; then
    echo "Usage: sudo $0 <SUBNET_CIDR>"
    echo "       sudo $0 192.168.1.0/24"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script requires root privileges (sudo) for -PR and -sS."
    exit 1
fi

SUBNET="$1"
DATE=$(date +%Y%m%d_%H%M)
NET_BASE=$(echo "$SUBNET" | sed 's|/.*||')
HOSTS_TMP="hosts_live_${NET_BASE}_${DATE}.tmp"
OUTPUT_BASE="scan_${NET_BASE}_${DATE}"

echo "=== Nmap Blue Team Sweep ==="
echo "Subnet  : $SUBNET"
echo "Date    : $(date)"
echo "Output  : ${OUTPUT_BASE}.*"
echo ""

# --- Step 1: Host discovery --------------------------------------------------
echo "[1/3] Discovering live hosts in $SUBNET (ARP ping)..."

nmap -sn -PR -T4 "$SUBNET" -oG - \
    | grep "Status: Up" \
    | awk '{print $2}' \
    > "$HOSTS_TMP"

HOST_COUNT=$(wc -l < "$HOSTS_TMP")

if [ "$HOST_COUNT" -eq 0 ]; then
    echo "No live hosts found in $SUBNET."
    rm -f "$HOSTS_TMP"
    exit 0
fi

echo "  Found $HOST_COUNT live hosts"
echo ""

# --- Step 2: Port scan + version detection -----------------------------------
echo "[2/3] Scanning top 100 ports + version detection on $HOST_COUNT hosts..."

nmap -sS -sV -F -T4 \
    -iL "$HOSTS_TMP" \
    -oA "$OUTPUT_BASE"

echo ""
echo "[3/3] Cleaning up temporary files..."
rm -f "$HOSTS_TMP"

# --- Summary -----------------------------------------------------------------
echo ""
echo "=== Scan complete ==="
echo "Results saved:"
echo "  ${OUTPUT_BASE}.nmap  (human-readable)"
echo "  ${OUTPUT_BASE}.xml   (machine-readable, use with ndiff)"
echo "  ${OUTPUT_BASE}.gnmap (grepable)"
echo ""
echo "Next steps:"
echo "  - Check open ports against your asset inventory"
echo "  - Look up service versions in CVE databases"
echo "  - Compare with previous scan: ndiff old.xml ${OUTPUT_BASE}.xml"
echo "==="

exit 0
