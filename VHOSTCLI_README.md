# 🎯 VHostCLI - Advanced Virtual Host Discovery Tool

**ReconCLI Virtual Host Enumeration Module with Multi-Engine Support**

VHostCLI is a powerful virtual host discovery tool that supports multiple scanning engines, AI-powered analysis, automated screenshots, and comprehensive reporting capabilities.

## 🚀 Features

### 🔧 **Multi-Engine Support**
- **FFUF** - Fast web fuzzer (default, recommended)
- **Gobuster** - Reliable directory/vhost bruteforcer  
- **HTTPx** - Python-based HTTP toolkit
- **VhostFinder** - Specialized similarity-based detection

### 📸 **Automated Screenshots**
- **Gowitness** - Modern web screenshotter (default)
- **Aquatone** - Alternative screenshot tool
- Full-page screenshot support
- Configurable timeouts and thread control

### 🧠 **AI-Powered Analysis**
- OpenAI GPT integration for result analysis
- Security assessment and risk evaluation
- Pattern detection and anomaly identification
- Actionable recommendations

### 💾 **Advanced Storage & Reporting**
- ReconCLI database integration
- JSON and Markdown output formats
- Resume functionality for interrupted scans
- Comprehensive scan metadata

### 🔔 **Notifications**
- Slack webhook integration
- Discord webhook support
- Real-time scan updates

## 📦 Installation

### Quick Install (All Dependencies)
```bash
# Download and run the universal installer
curl -sSL https://raw.githubusercontent.com/jarek-bir/Reconcli/main/install_vhostcli_deps.sh | bash

# Or clone and run locally
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli
./install_vhostcli_deps.sh
```

### Manual Installation

#### Core Engines
```bash
# FFUF (Fast web fuzzer)
go install github.com/ffuf/ffuf/v2@latest

# Gobuster (Directory/vhost bruteforcer)
go install github.com/OJ/gobuster/v3@latest

# HTTPx (Python HTTP toolkit)
pip install httpx

# VhostFinder (Specialized engine)
git clone https://github.com/wdahlenburg/VhostFinder.git
cd VhostFinder && go build -o VhostFinder
sudo cp VhostFinder /usr/local/bin/
```

#### Screenshot Tools
```bash
# Gowitness (Default screenshotter)
go install github.com/sensepost/gowitness@latest

# Aquatone (Alternative screenshotter)
go install github.com/michenriksen/aquatone@latest
```

#### Optional Dependencies
```bash
# AI Analysis
pip install openai

# Database Storage
pip install sqlalchemy>=2.0.0

# Additional packages
pip install click requests rich
```

### Verify Installation
```bash
# Check all dependencies
./check_vhostcli_deps.sh
```

## 🎯 Usage Examples

### Basic Virtual Host Discovery
```bash
# Simple scan with FFUF (default engine)
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt

# Verbose output with detailed progress
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --verbose
```

### Multi-Target Scanning
```bash
# Scan multiple IPs from file
reconcli vhostcli --domain example.com --ip-list targets.txt --wordlist wordlist.txt

# Show all responses (not just 200/403/401)
reconcli vhostcli --domain example.com --ip-list targets.txt --wordlist wordlist.txt --show-all
```

### Engine Selection
```bash
# Use Gobuster engine
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --engine gobuster

# Use HTTPx engine
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --engine httpx

# Use VhostFinder (specialized)
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --engine vhostfinder
```

### Advanced Features
```bash
# Screenshots with Gowitness
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --screenshot

# Full-page screenshots
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --screenshot --fullpage

# AI-powered analysis
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --ai-mode

# Database storage for bug bounty programs
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --store-db --program "HackerOne" --target-domain example.com
```

### Proxy & Rate Limiting
```bash
# Through Burp Suite proxy
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --proxy http://127.0.0.1:8080

# Custom rate limiting and timeouts
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --rate-limit 50 --timeout 15 --retries 5
```

### Enhanced Discovery with Port Scanning
```bash
# Pre-discovery port scanning with naabu (fast)
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --port-scan --port-scanner naabu

# Advanced scanning with JFScan (masscan + nmap integration)
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --port-scan --port-scanner jfscan

# Traditional nmap scanning
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --port-scan --port-scanner nmap

# Full security assessment with Nuclei
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --port-scan --nuclei-scan

# Advanced: Port scan + vulnerability assessment + screenshots
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt \
    --port-scan --port-scanner jfscan \
    --nuclei-scan --nuclei-severity medium,high,critical \
    --screenshot --ai-mode --store-db
```

### Resume Functionality
```bash
# Enable resume capability
reconcli vhostcli --domain example.com --ip-list targets.txt --wordlist wordlist.txt --resume

# Custom resume file
reconcli vhostcli --domain example.com --ip-list targets.txt --wordlist wordlist.txt --resume --resume-file my_scan.json
```

### Notifications
```bash
# Slack notifications
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --slack-webhook "https://hooks.slack.com/..."

# Discord notifications
reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist wordlist.txt --discord-webhook "https://discord.com/api/webhooks/..."
```

### Complete Bug Bounty Workflow
```bash
# Full-featured reconnaissance scan
reconcli vhostcli \
  --domain target.com \
  --ip-list discovered_ips.txt \
  --wordlist ~/.reconcli/wordlists/vhost_common.txt \
  --engine ffuf \
  --screenshot \
  --screenshot-tool gowitness \
  --fullpage \
  --ai-mode \
  --store-db \
  --program "Bug Bounty Program" \
  --target-domain target.com \
  --proxy http://127.0.0.1:8080 \
  --rate-limit 100 \
  --timeout 10 \
  --retries 3 \
  --resume \
  --slack-webhook "https://hooks.slack.com/..." \
  --verbose
```

## 📝 Command Line Options

### Required Parameters
```
--domain TEXT       Domain name (e.g. example.com) [required]
--wordlist PATH     VHOST wordlist file [required]
```

### Target Specification
```
--ip TEXT           Single target IP address
--ip-list PATH      File containing list of IP addresses
```

### Engine Configuration
```
--engine [ffuf|httpx|gobuster|vhostfinder]  Scanning engine (default: ffuf)
--rate-limit INT    Requests per second (default: 100)
--timeout INT       Request timeout in seconds (default: 10)  
--retries INT       Number of retries for failed requests (default: 3)
--proxy TEXT        HTTP proxy URL (e.g. http://127.0.0.1:8080)
--show-all          Show all responses, not just 200/403/401
```

### Screenshot Options
```
--screenshot                            Enable screenshots
--screenshot-tool [gowitness|aquatone]  Screenshot tool (default: gowitness)
--screenshot-timeout INT                Screenshot timeout (default: 15)
--screenshot-threads INT                Screenshot threads (default: 5)
--fullpage                             Full-page screenshots (gowitness only)
```

### AI & Analysis
```
--ai-mode           Enable AI-powered analysis
--ai-model TEXT     AI model to use (default: gpt-3.5-turbo)
```

### Storage & Resume
```
--store-db          Store results in ReconCLI database
--target-domain     Primary target domain for database
--program TEXT      Bug bounty program name
--resume            Resume from previous scan
--resume-file PATH  Custom resume file path
```

### Output & Notifications
```
--output-dir PATH       Output directory (default: vhostcli_output)
--verbose              Enable verbose output
--slack-webhook URL    Slack webhook for notifications
--discord-webhook URL  Discord webhook for notifications
```

### Port Scanning & Security Assessment
```
--port-scan                    Run port scan before vhost discovery
--port-scanner SCANNER         Port scanner: naabu, nmap, masscan, jfscan (default: naabu)
--nuclei-scan                  Run Nuclei vulnerability scan on discovered hosts
--nuclei-templates PATH        Custom Nuclei templates directory
--nuclei-severity SEVERITY     Nuclei severity filter: info,low,medium,high,critical
```

## 📊 Output Formats

### JSON Output
```json
{
  "scan_info": {
    "domain": "example.com",
    "target_ip": "192.168.1.100", 
    "engine": "ffuf",
    "timestamp": "20250729_143022",
    "total_words": 1000,
    "results_found": 5,
    "proxy_used": null
  },
  "results": [
    {
      "host": "admin.example.com",
      "status": 200,
      "length": 1234,
      "source": "ffuf"
    }
  ],
  "ai_analysis": "Security assessment and recommendations..."
}
```

### Markdown Report
```markdown
# 🎯 VHOST Scan Results

**Domain:** `example.com`  
**Target IP:** `192.168.1.100`  
**Engine:** `ffuf`  
**Scan Time:** `20250729_143022`  

## 🚨 Discovered Virtual Hosts

| Host | Status Code | Length | Source |
|------|------------|--------|---------|
| `admin.example.com` | ✅ 200 | 1234 | ffuf |
| `api.example.com` | ⚠️ 403 | 567 | ffuf |

## 🧠 AI Analysis
```

## 🗂️ Wordlists

### Included Wordlist
The installer creates `~/.reconcli/wordlists/vhost_common.txt` with 100+ common virtual host names:

- admin, api, app, auth, blog, cms
- dev, test, staging, prod, production
- mail, webmail, cpanel, phpmyadmin
- secure, portal, dashboard, panel
- And many more...

### Custom Wordlists
Popular wordlist sources:
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/dns)
- [Seclists Discovery/Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

## 🔧 Engine Comparison

| Engine | Speed | Reliability | Features | Best For |
|--------|-------|-------------|----------|----------|
| **FFUF** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | JSON output, rate limiting | General purpose, fast scans |
| **Gobuster** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Thread control, exclude patterns | Reliable, thorough scans |
| **HTTPx** | ⭐⭐⭐ | ⭐⭐⭐⭐ | Python-based, flexible | Custom logic, integration |
| **VhostFinder** | ⭐⭐⭐ | ⭐⭐⭐⭐ | Similarity detection | Advanced detection techniques |

## 🐛 Troubleshooting

### Common Issues

**"Tool not found" errors:**
```bash
# Check installation status
./check_vhostcli_deps.sh

# Reinstall missing tools
./install_vhostcli_deps.sh
```

**Permission denied for VhostFinder:**
```bash
# Manual installation
sudo cp VhostFinder /usr/local/bin/
sudo chmod +x /usr/local/bin/VhostFinder
```

**Rate limiting issues:**
```bash
# Reduce rate limit for unstable targets
--rate-limit 20 --timeout 15 --retries 5
```

**AI analysis failures:**
```bash
# Set OpenAI API key
export OPENAI_API_KEY="your_api_key_here"
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FFUF** - [@joohoi](https://github.com/ffuf/ffuf)
- **Gobuster** - [@OJ](https://github.com/OJ/gobuster)
- **VhostFinder** - [@wdahlenburg](https://github.com/wdahlenburg/VhostFinder)
- **Gowitness** - [@sensepost](https://github.com/sensepost/gowitness)
- **Aquatone** - [@michenriksen](https://github.com/michenriksen/aquatone)

---

**Made with ❤️ by the ReconCLI team**

For more tools and documentation, visit: [ReconCLI Repository](https://github.com/jarek-bir/Reconcli)
