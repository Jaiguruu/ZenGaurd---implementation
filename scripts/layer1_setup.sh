#!/usr/bin/env bash
# =============================================================================
# File: scripts/layer1_setup.sh
# Project: ZenGuard Zero Trust SIEM - Layer 1 Endpoint Provisioning
# Description: Idempotent bootstrap script for a fresh Ubuntu 22.04 endpoint.
#              Installs and configures:
#                1. Filebeat 8.x  — log shipper → Logstash
#                2. Snort 3        — IDS outputting fast-mode alerts
#                3. iptables       — host firewall with logging rules
#              Run as root or with sudo.
#
# Usage:
#   chmod +x layer1_setup.sh
#   sudo LOGSTASH_HOST=<layer2-ip> bash layer1_setup.sh
#
# LOGSTASH_HOST env var MUST be set to the IP or hostname of the Layer 2
# server running Logstash on port 5044.
# =============================================================================

set -euo pipefail  # exit on error, unset variable use, or pipe failure

# ---------------------------------------------------------------------------
# 0. GLOBALS & VALIDATION
# ---------------------------------------------------------------------------
LOGSTASH_HOST="${LOGSTASH_HOST:-}"
FILEBEAT_VERSION="8.13.0"
SNORT_IFACE="${SNORT_IFACE:-eth0}"   # network interface Snort listens on
LOG_DIR="/var/log/zenguard"

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Validate required environment variables
[[ -z "$LOGSTASH_HOST" ]] && error "LOGSTASH_HOST must be set. e.g.: LOGSTASH_HOST=192.168.1.100 bash layer1_setup.sh"

# Must run as root
[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)."

info "=== ZenGuard Layer 1 Endpoint Setup ==="
info "Logstash target: $LOGSTASH_HOST:5044"
info "Snort interface: $SNORT_IFACE"


# ---------------------------------------------------------------------------
# 1. SYSTEM HOUSEKEEPING
# ---------------------------------------------------------------------------
info "Step 1/6 — Updating package index and installing prerequisites..."

apt-get update -qq
apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg2 \
    apt-transport-https \
    ca-certificates \
    software-properties-common \
    jq \
    net-tools \
    iptables \
    iptables-persistent   # persists iptables rules across reboots

# Create ZenGuard log directory for custom application logs
mkdir -p "$LOG_DIR/app"
chmod 755 "$LOG_DIR"

# ---------------------------------------------------------------------------
# 2. INSTALL FILEBEAT 8.x
# ---------------------------------------------------------------------------
info "Step 2/6 — Installing Filebeat ${FILEBEAT_VERSION}..."

# Add the Elastic GPG key and APT repository (once, idempotently)
if [[ ! -f /etc/apt/sources.list.d/elastic-8.x.list ]]; then
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
        | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main" \
        | tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null

    apt-get update -qq
fi

apt-get install -y filebeat="${FILEBEAT_VERSION}"

# Prevent accidental auto-upgrade breaking the pinned version
apt-mark hold filebeat

# Deploy the ZenGuard filebeat.yml (expects it to be in the same dir as this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../filebeat/filebeat.yml" ]]; then
    cp "${SCRIPT_DIR}/../filebeat/filebeat.yml" /etc/filebeat/filebeat.yml
    # Substitute the LOGSTASH_HOST placeholder with the actual value
    sed -i "s/LOGSTASH_HOST/${LOGSTASH_HOST}/g" /etc/filebeat/filebeat.yml
    info "filebeat.yml deployed and configured for $LOGSTASH_HOST"
else
    warn "filebeat.yml not found next to this script — Filebeat will use its existing config."
fi

# Validate the configuration before starting
filebeat test config -c /etc/filebeat/filebeat.yml && info "Filebeat config validation: OK"

# Enable and start Filebeat
systemctl enable filebeat
systemctl restart filebeat
systemctl is-active --quiet filebeat && info "Filebeat service: RUNNING" || error "Filebeat failed to start — check: journalctl -u filebeat"


# ---------------------------------------------------------------------------
# 3. INSTALL SNORT 3 (IDS)
# ---------------------------------------------------------------------------
info "Step 3/6 — Installing Snort 3..."

# Snort3 dependencies
apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    bison \
    flex \
    zlib1g-dev \
    liblzma-dev \
    openssl \
    libssl-dev \
    libnghttp2-dev \
    libluajit-5.1-dev

# Install Snort 3 from the Ubuntu universe repository.
# On Ubuntu 22.04, snort3 is available directly.
# For production, compile from source at snort.org for latest rules.
apt-get install -y snort3 || {
    warn "snort3 not found in repos — attempting to install snort (v2 fallback)..."
    apt-get install -y snort
    SNORT_BIN="snort"
}

SNORT_BIN="${SNORT_BIN:-snort3}"

# Create necessary directories
mkdir -p /var/log/snort
mkdir -p /etc/snort/rules

# ---------------------------------------------------------------------------
# 3a. CONFIGURE SNORT — Basic fast-alert output
# We configure Snort to:
#   - Listen on the specified interface in promiscuous mode
#   - Output alerts in "fast" single-line format Filebeat can tail
#   - Use the Snort community rules as a starting ruleset
# ---------------------------------------------------------------------------

# Download community rules (requires no registration, unlike ET Pro or Snort VRT)
if [[ ! -f /etc/snort/rules/community.rules ]]; then
    COMMUNITY_RULES_URL="https://www.snort.org/downloads/community/community-rules.tar.gz"
    info "Downloading community Snort rules..."
    wget -q -O /tmp/community-rules.tar.gz "$COMMUNITY_RULES_URL" || warn "Could not download community rules — using empty ruleset"
    tar -xzf /tmp/community-rules.tar.gz -C /etc/snort/rules/ --strip-components=1 2>/dev/null || true
fi

# Write a minimal snort.conf (Snort 2 syntax; Snort 3 uses snort.lua)
cat > /etc/snort/snort.conf << SNORT_CONF
# ==========================================================
# ZenGuard Snort configuration — fast alert output for Filebeat
# ==========================================================

# Network variable: adjust to your actual LAN subnet
var HOME_NET 192.168.0.0/16
var EXTERNAL_NET !\$HOME_NET

# Rule paths
var RULE_PATH /etc/snort/rules

# Output plugin: alert_fast writes one line per alert to a file.
# This is what Filebeat tails and ships to Logstash.
output alert_fast: /var/log/snort/alert

# Load community rules
include \$RULE_PATH/community.rules

# Include a local rules file for custom ZenGuard signatures
include \$RULE_PATH/local.rules
SNORT_CONF

# Minimal local rules: detect port scans and common brute-force patterns
cat > /etc/snort/rules/local.rules << 'LOCAL_RULES'
# ZenGuard Custom Snort Rules
# SID range 9000000+ is reserved for local rules

# Detect SSH brute force (>5 SYN packets to port 22 in 1 second)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ZenGuard SSH Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 1; sid:9000001; rev:1; classtype:attempted-admin;)

# Detect Nmap SYN scan signature
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ZenGuard Nmap SYN Scan Detected"; flags:S12; threshold:type threshold, track by_src, count 20, seconds 2; sid:9000002; rev:1; classtype:network-scan;)

# Detect ICMP flood
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ZenGuard ICMP Flood"; itype:8; threshold:type both, track by_src, count 20, seconds 1; sid:9000003; rev:1; classtype:denial-of-service;)

# Detect suspicious DNS queries (large payload = potential exfiltration)
alert udp $HOME_NET any -> any 53 (msg:"ZenGuard Suspicious Large DNS Query"; dsize:>200; sid:9000004; rev:1; classtype:suspicious-filename-detect;)
LOCAL_RULES

info "Snort configuration written."

# Create a systemd service for Snort so it survives reboots
cat > /etc/systemd/system/snort.service << SNORT_SERVICE
[Unit]
Description=ZenGuard Snort IDS
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/${SNORT_BIN} -c /etc/snort/snort.conf -i ${SNORT_IFACE} -D -l /var/log/snort
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SNORT_SERVICE

systemctl daemon-reload
systemctl enable snort
systemctl restart snort
systemctl is-active --quiet snort && info "Snort IDS service: RUNNING" || warn "Snort failed to start — check: journalctl -u snort"

# Ensure Filebeat can read Snort alerts (Snort writes as root)
chmod 644 /var/log/snort/alert 2>/dev/null || true
# Set future-created alert files to be group-readable
chown root:adm /var/log/snort
chmod g+s /var/log/snort


# ---------------------------------------------------------------------------
# 4. IPTABLES HARDENING WITH LOGGING
# ---------------------------------------------------------------------------
info "Step 4/6 — Applying iptables firewall rules with logging..."

# Flush all existing rules to start from a known clean state
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# --- Default policies: deny all inbound/forward, allow outbound ---
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# --- Allow established and related connections (stateful firewall) ---
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- Allow loopback ---
iptables -A INPUT -i lo -j ACCEPT

# --- Allow SSH (rate-limited to 3 new connections per minute from any IP) ---
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --set --name SSH_TRACK
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH_TRACK \
    -j LOG --log-prefix "ZenGuard_IPTABLES_BRUTE: " --log-level 4
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH_TRACK \
    -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# --- Allow ICMP ping (useful for diagnostics, but rate-limited) ---
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT

# --- Log ALL other dropped inbound packets before final DROP ---
# These logs appear in /var/log/kern.log and can be shipped by Filebeat
# for complete network visibility (augments Snort IDS alerts).
iptables -A INPUT -j LOG \
    --log-prefix "ZenGuard_IPTABLES_DROP: " \
    --log-level 4 \
    --log-ip-options \
    --log-tcp-options

iptables -A INPUT -j DROP

# Persist rules across reboots (iptables-persistent)
netfilter-persistent save
info "iptables rules saved and will persist across reboots."


# ---------------------------------------------------------------------------
# 5. VALIDATE END-TO-END CONNECTIVITY
# ---------------------------------------------------------------------------
info "Step 5/6 — Testing connectivity to Logstash on $LOGSTASH_HOST:5044..."

if nc -z -w5 "$LOGSTASH_HOST" 5044 2>/dev/null; then
    info "Connectivity to Logstash: OK"
else
    warn "Cannot reach Logstash at $LOGSTASH_HOST:5044. Filebeat will buffer and retry when the connection is available."
fi


# ---------------------------------------------------------------------------
# 6. STATUS SUMMARY
# ---------------------------------------------------------------------------
info "Step 6/6 — Final service status:"
echo ""
echo "──────────────────────────────────────────────────"
printf "  %-20s %s\n" "SERVICE" "STATUS"
echo "──────────────────────────────────────────────────"
for svc in filebeat snort; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "not found")
    [[ "$STATUS" == "active" ]] \
        && printf "  %-20s ${GREEN}%s${NC}\n" "$svc" "RUNNING" \
        || printf "  %-20s ${RED}%s${NC}\n" "$svc" "$STATUS"
done
echo "──────────────────────────────────────────────────"

echo ""
info "=== Layer 1 provisioning complete ==="
info "Logs being shipped:"
info "  /var/log/auth.log         → event_type: auth"
info "  /var/log/snort/alert      → event_type: snort_alerts"
info "  /var/ossec/logs/alerts/   → event_type: wazuh_alert (if Wazuh installed)"
info "  /var/log/zenguard/app/    → event_type: app_generic"
echo ""
