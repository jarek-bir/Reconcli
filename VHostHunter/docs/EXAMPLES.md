# 🎯 VHostHunter Usage Examples

## Basic Usage

### Simple Virtual Host Discovery
```bash
# Basic scan with common wordlist
./vhosthunter --domain example.com --ip 192.168.1.100 --wordlist wordlists/common.txt

# With verbose output
./vhosthunter --domain example.com --ip 192.168.1.100 --wordlist wordlists/common.txt --verbose
```

### Multi-Target Scanning
```bash
# Scan multiple IPs from file
./vhosthunter --domain example.com --ip-list ips.txt --wordlist wordlists/comprehensive.txt

# Scan IP range
./vhosthunter --domain example.com --ip-range 192.168.1.1-192.168.1.100 --wordlist wordlists/common.txt
```

## Engine Selection

### FFUF (Default - Fast)
```bash
# FFUF with custom rate limiting
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --engine ffuf --rate-limit 50 --timeout 15
```

### Gobuster (Reliable)
```bash
# Gobuster with custom threads
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --engine gobuster --threads 20
```

### VhostFinder (Specialized)
```bash
# VhostFinder with custom options
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --engine vhostfinder
```

## Port Scanning Integration

### Pre-Discovery Port Scanning
```bash
# Quick port scan with naabu
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner naabu

# Advanced scanning with JFScan
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner jfscan

# Traditional nmap scanning
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner nmap
```

## Security Assessment

### Nuclei Vulnerability Scanning
```bash
# Basic vulnerability scan
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --nuclei-scan

# High-severity vulnerabilities only
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --nuclei-scan --nuclei-severity high,critical

# Custom templates directory
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --nuclei-scan --nuclei-templates /path/to/custom/templates
```

## Screenshot Automation

### Visual Evidence Collection
```bash
# Basic screenshots with Gowitness
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --screenshot

# Full-page screenshots
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --screenshot --fullpage

# Screenshots with Aquatone
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --screenshot --screenshot-tool aquatone
```

## Advanced Features

### AI-Powered Analysis
```bash
# Enable AI analysis (requires OpenAI API key)
export OPENAI_API_KEY="your-api-key"

./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --ai-mode --screenshot
```

### Database Storage
```bash
# Store results in database for bug bounty programs
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --store-db --program "HackerOne Program" --target-domain example.com
```

### Resume Capability
```bash
# Resume interrupted scan
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --resume

# Custom resume file
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --resume --resume-file /path/to/resume.json
```

## Proxy and Rate Limiting

### Burp Suite Integration
```bash
# Route through Burp Suite proxy
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --proxy http://127.0.0.1:8080
```

### Rate Limiting
```bash
# Custom rate limiting and timeouts
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --rate-limit 25 --timeout 30 --retries 5
```

## Complete Workflows

### Bug Bounty Discovery Workflow
```bash
# Complete bug bounty scan
./vhosthunter --domain target.com --ip TARGET_IP \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner jfscan \
    --nuclei-scan --nuclei-severity medium,high,critical \
    --screenshot --ai-mode \
    --store-db --program "Bug Bounty Program" \
    --slack-webhook "$SLACK_WEBHOOK" \
    --verbose
```

### Penetration Testing Workflow
```bash
# Comprehensive penetration test
./vhosthunter --domain internal.company.com --ip-range 10.0.1.1-10.0.1.254 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner nmap \
    --nuclei-scan \
    --screenshot --fullpage \
    --proxy http://127.0.0.1:8080 \
    --rate-limit 10 \
    --output-dir pentest_results \
    --verbose
```

### Quick Assessment
```bash
# Fast discovery for initial assessment
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/common.txt \
    --engine ffuf --rate-limit 100 \
    --screenshot \
    --verbose
```

## Automation Script

### Using the Hunt Script
```bash
# Simple automated hunting
./hunt.sh example.com 192.168.1.100

# With custom wordlist
WORDLIST=wordlists/specialized.txt ./hunt.sh example.com 192.168.1.100

# With environment variables
export NUCLEI_SEVERITY="high,critical"
export SCREENSHOT_ENABLED="true"
export AI_MODE="true"
./hunt.sh example.com 192.168.1.100
```

## Output and Reporting

### Export Formats
```bash
# JSON export
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --export json

# CSV export for spreadsheet analysis
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --export csv

# Markdown report
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --export markdown
```

### Custom Output Directory
```bash
# Organized output structure
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --output-dir "results/$(date +%Y%m%d)_example_com"
```

## Notifications

### Real-Time Alerts
```bash
# Slack notifications
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --slack-webhook "$SLACK_WEBHOOK"

# Discord notifications
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --discord-webhook "$DISCORD_WEBHOOK"
```

## Performance Optimization

### High-Performance Scanning
```bash
# Maximum performance configuration
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --engine ffuf --rate-limit 200 \
    --threads 50 --timeout 5 \
    --cache-enabled
```

### Memory-Efficient Scanning
```bash
# Large-scale scanning with memory optimization
./vhosthunter --domain example.com --ip-list large_ip_list.txt \
    --wordlist wordlists/comprehensive.txt \
    --batch-size 10 --rate-limit 50 \
    --cache-enabled
```

## Troubleshooting

### Debug Mode
```bash
# Enable debug output
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --debug --verbose
```

### Dry Run Mode
```bash
# Test configuration without actual scanning
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --dry-run --verbose
```

---

## Tips and Best Practices

### Wordlist Selection
- Use **common.txt** for quick discovery
- Use **comprehensive.txt** for thorough enumeration
- Create custom wordlists based on target research

### Rate Limiting
- Start with conservative rates (25-50 req/s)
- Increase gradually based on target response
- Monitor for rate limiting or blocking

### Target Selection
- Always verify scope before testing
- Test on intentionally vulnerable applications first
- Respect target infrastructure and policies

### Result Analysis
- Focus on HTTP 200, 403, 401, 302 responses
- Look for different content lengths
- Investigate unusual server headers
- Screenshot interesting findings

---

**Happy hunting! 🎯**
