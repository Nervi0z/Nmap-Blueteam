#!/bin/bash
# =============================================================================
# service_audit.sh — Service version audit for vulnerability management
#
# Usage:  sudo ./service_audit.sh <TARGET>
# Example: sudo ./service_audit.sh 192.168.1.0/24
#          sudo ./service_audit.sh 192.168.1.10
#
# Scans common service ports, extracts versions, and outputs a summary
# ready for CVE database lookup.
#
# Requirements: nmap, root privileges (sudo)
# =============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: sudo $0 <TARGET>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: root privileges required."
    exit 1
fi

TARGET="$1"
DATE=$(date +%Y%m%d_%H%M)
OUTPUT_BASE="service_audit_${DATE}"

# Common service ports for Blue Team audits
PORTS="21,22,23,25,53,80,110,143,389,443,445,465,587,993,995,3306,3389,5432,5985,5986,8080,8443,8888"

echo "=== Service Version Audit ==="
echo "Target : $TARGET"
echo "Ports  : $PORTS"
echo "Date   : $(date)"
echo ""

echo "[1/2] Scanning services and detecting versions..."
nmap -sS -sV \
    -p "$PORTS" \
    -T4 \
    --version-intensity 7 \
    "$TARGET" \
    -oA "$OUTPUT_BASE"

echo ""
echo "[2/2] Extracting open services for CVE lookup..."
echo ""
echo "--- OPEN SERVICES (version lookup targets) ---"

# Parse the .nmap output for open ports with versions
grep -E "^[0-9]+/(tcp|udp)\s+open" "${OUTPUT_BASE}.nmap" \
    | awk '{printf "  %-20s %-10s %s\n", $1, $3, $4" "$5" "$6" "$7}' \
    | sed 's/ *$//'

echo ""
echo "=== Audit complete ==="
echo "Results saved:"
echo "  ${OUTPUT_BASE}.nmap"
echo "  ${OUTPUT_BASE}.xml"
echo ""
echo "CVE lookup: https://nvd.nist.gov/vuln/search"
echo "            https://cve.mitre.org"
echo "  Search: '<service name> <version>' — e.g. 'Apache 2.4.52'"
echo "==="

exit 0
