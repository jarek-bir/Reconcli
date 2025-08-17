#!/bin/bash

# 🎯 Automated VHost Hunter
# Usage: ./vhost_hunter.sh domain.com ip_address

DOMAIN=$1
IP=$2

if [ -z "$DOMAIN" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <domain> <ip>"
    echo "Example: $0 example.com 192.168.1.100"
    exit 1
fi

echo "🎯 Starting VHost hunting for $DOMAIN ($IP)"

# Create output directory
OUTPUT_DIR="vhost_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "📁 Output directory: $OUTPUT_DIR"

# Step 1: Basic enumeration
echo "🔍 Step 1: Basic VHost discovery..."
reconcli vhostcli \
    --domain "$DOMAIN" \
    --ip "$IP" \
    --wordlist vhost_training_wordlist.txt \
    --output-dir "$OUTPUT_DIR/basic" \
    --verbose

# Step 2: Enhanced scan with port discovery
echo "🚀 Step 2: Enhanced scan with port discovery..."
reconcli vhostcli \
    --domain "$DOMAIN" \
    --ip "$IP" \
    --wordlist target_specific_wordlist.txt \
    --port-scan --port-scanner jfscan \
    --output-dir "$OUTPUT_DIR/enhanced" \
    --verbose

# Step 3: Security assessment
echo "🔒 Step 3: Security assessment..."
reconcli vhostcli \
    --domain "$DOMAIN" \
    --ip "$IP" \
    --wordlist vhost_training_wordlist.txt \
    --nuclei-scan --nuclei-severity medium,high,critical \
    --screenshot \
    --output-dir "$OUTPUT_DIR/security" \
    --verbose

echo "✅ VHost hunting completed!"
echo "📊 Results in: $OUTPUT_DIR"
