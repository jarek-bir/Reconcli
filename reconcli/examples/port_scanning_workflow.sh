# Port Scanning Workflow Example
# Comprehensive port scanning and service enumeration pipeline

# Step 1: Basic IP discovery from domains
reconcli dns --domain example.com --resolve --output-dir /tmp/recon

# Step 2: Port scanning on discovered IPs
reconcli portcli --input /tmp/recon/example.com_resolved.txt \
  --only-web --json --markdown --verbose \
  --output-dir /tmp/recon/ports

# Step 3: Advanced port scan with custom settings
reconcli portcli --input /tmp/recon/example.com_resolved.txt \
  --scanner nmap --ports 80,443,8080,8443,3000,5000,8000 \
  --nmap-flags "-sS -sV -O" --json --verbose

# Step 4: Full range scan (use with caution)
reconcli portcli --input /tmp/recon/high_value_targets.txt \
  --scanner naabu --full --rate 1000 --json

# Step 5: VHOST checking on discovered web ports
reconcli vhostcheck --input /tmp/recon/web_servers.txt \
  --domain example.com --vhost admin \
  --save-output --output-format json

# Step 6: URL discovery on discovered web services
reconcli urlcli --input /tmp/recon/web_services.txt \
  --tools katana,gau --output-dir /tmp/recon/urls
