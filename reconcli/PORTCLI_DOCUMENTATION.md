# 🔍 PortCLI - Advanced Port Scanning Module

PortCLI is an advanced port scanning module in ReconCLI, offering comprehensive scanning capabilities using multiple scanners, resume functionality, automatic CDN detection, port tagging, and professional reporting.

## 📋 Table of Contents

- [🎯 Features](#-features)
- [🛠️ Supported Scanners](#️-supported-scanners)
- [⚡ Installation](#-installation)
- [🔧 Basic Usage](#-basic-usage)
- [📊 Advanced Features](#-advanced-features)
- [🤖 AI Analysis](#-ai-analysis)
- [💾 Cache System](#-cache-system)
- [🏷️ Tagging System](#️-tagging-system)
- [📝 Practical Examples](#-practical-examples)
- [⚙️ Configuration Options](#️-configuration-options)
- [📊 Output Formats](#-output-formats)

## 🎯 Features

### ✨ Key Capabilities

- **🔄 Multi-Scanner Support**: naabu, rustscan, nmap, masscan, rush
- **⚡ Parallel Scanning**: rush for parallel job execution
- **🧠 AI Analysis**: Automatic result analysis with AI assistance
- **💾 Intelligent Cache**: Fast scan repetition with caching
- **🏷️ Automatic Tagging**: Intelligent service categorization
- **☁️ CDN/Cloud Detection**: Automatic cloud provider detection
- **🔄 Resume Function**: Resume interrupted scans
- **📊 Professional Reports**: JSON, Markdown, database storage
- **🎯 Advanced Filtering**: By tags, services, providers

### 🛡️ Security and Performance

- **✅ Target Validation**: IP and CIDR format checking
- **⏱️ Timeout/Retry**: Configurable timeout and retries
- **🚀 Optimization**: Cache for repeatable scans
- **📈 Monitoring**: Scan progress for large ranges

## 🛠️ Supported Scanners

### 1. **Naabu** (Default)

```bash
# Fast, efficient port scanner
reconcli portcli --ip 192.168.1.100 --scanner naabu
```

### 2. **RustScan**

```bash
# Very fast Rust-based scanner
reconcli portcli --ip 192.168.1.100 --scanner rustscan
```

### 3. **Nmap**

```bash
# Classic, feature-rich scanner
reconcli portcli --ip 192.168.1.100 --scanner nmap
```

### 4. **Masscan**

```bash
# Mass scanning with high speed
reconcli portcli --ip 192.168.1.100 --scanner masscan --masscan-rate 2000
```

### 5. **Rush** ⭐ (NEW!)

```bash
# Parallel execution of other scanners
reconcli portcli --input targets.txt --scanner rush --rush-base-scanner nmap --rush-jobs 20
```

## ⚡ Instalacja

### Wymagane Binaria

```bash
# Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# RustScan
cargo install rustscan

# Nmap
sudo apt install nmap          # Ubuntu/Debian
brew install nmap              # macOS

# Masscan
sudo apt install masscan       # Ubuntu/Debian
brew install masscan           # macOS

# Rush
go install github.com/shenwei356/rush@latest
```

## � Basic Usage

### Single IP

```bash
# Simple scan of single IP
reconcli portcli --ip 192.168.1.100

# With port selection
reconcli portcli --ip 192.168.1.100 --ports "21,22,23,53,80,443,993,995"

# With specific scanner
reconcli portcli --ip 192.168.1.100 --scanner rustscan
```

### CIDR Range

```bash
# Scan entire network
reconcli portcli --cidr 192.168.1.0/24

# With rush for faster scanning
reconcli portcli --cidr 192.168.1.0/24 --scanner rush --rush-jobs 16
```

### File with Targets

```bash
# Prepare file with targets (can include IPs, domains, and CIDRs)
echo -e "192.168.1.100\nexample.com\n10.0.0.0/24" > targets.txt

# Scan from file
reconcli portcli --input targets.txt --scanner naabu
```

### Single Domain

```bash
# Simple domain scan
reconcli portcli --domain example.com

# Domain with specific ports
reconcli portcli --domain target.com --ports "80,443,8080,8443"

# Domain with top ports
reconcli portcli --domain example.com --top-ports 1000

# Domain with AI analysis
reconcli portcli --domain target.com --ai --scanner rush
```

## 📊 Advanced Features

### 🚀 Rush - Parallel Scanning

```bash
# Basic rush usage
reconcli portcli --input targets.txt --scanner rush --rush-jobs 10

# Rush with nmap backend
reconcli portcli --input ips.txt --scanner rush \
  --rush-base-scanner nmap \
  --rush-jobs 20 \
  --rush-timeout 30

# Rush with masscan for speed
reconcli portcli --input large_targets.txt --scanner rush \
  --rush-base-scanner masscan \
  --rush-jobs 15 \
  --rush-retries 2

# Rush with naabu for stealth
reconcli portcli --cidr 192.168.0.0/16 --scanner rush \
  --rush-base-scanner naabu \
  --rush-jobs 5 \
  --ports 80,443,8080
```

### ⚙️ Rush Options

- `--rush-jobs INTEGER`: Number of parallel jobs (default: 12)
- `--rush-timeout INTEGER`: Job timeout in seconds
- `--rush-retries INTEGER`: Maximum retries (default: 0)
- `--rush-base-scanner`: Base scanner (nmap/naabu/rustscan/masscan)

## 🤖 AI Analysis

### Basic AI Analysis

```bash
# Enable AI
reconcli portcli --input targets.txt --ai

# With AI cache
reconcli portcli --input targets.txt --ai --ai-cache

# Specific AI provider
reconcli portcli --input targets.txt --ai --ai-provider openai
```

### AI Analysis Example

```text
🤖 Running AI analysis...

📋 AI Analysis Results:
   • Total targets analyzed: 5
   • Total open ports: 23
   • Unique ports: 8

💡 Recommendations:
   • SSH service detected - ensure key-based authentication
   • Web services detected - consider security headers analysis
   • Database services exposed - verify access controls

🔐 Security Insights:
   • Cloud infrastructure detected - review security groups
   • Development services found - check production exposure
```

## 💾 Cache System

### Enabling Cache

```bash
# Basic cache
reconcli portcli --ip 192.168.1.100 --cache

# Custom cache directory
reconcli portcli --ip 192.168.1.100 --cache --cache-dir /tmp/my_cache

# Expiration time
reconcli portcli --ip 192.168.1.100 --cache --cache-max-age 12
```

### Cache Management

```bash
# Cache statistics
reconcli portcli --cache-stats

# Clear cache
reconcli portcli --clear-cache
```

## 🏷️ Tag System

### Automatic Tags

PortCLI automatically assigns tags to ports:

- **web**: 80, 443, 8080, 8443
- **database**: 3306, 5432, 27017
- **remote**: 22, 3389, 5900
- **cloud**: Kubernetes, Docker ports
- **dev**: 3000, 5000, 8000
- **prod**: 80, 443 (main services)

### Tag Filtering

```bash
# Only web services
reconcli portcli --input targets.txt --filter-tags web

# Exclude dev ports
reconcli portcli --input targets.txt --exclude-tags dev

# Complex filtering
reconcli portcli --input targets.txt --filter-tags "web,prod" --exclude-tags "dev,staging"
```

### Service Detection

```bash
# Filter by detected services
reconcli portcli --input targets.txt --filter-services "web-stack,kubernetes-cluster"

# Available service patterns:
# - web-stack (80+443)
# - database-server
# - kubernetes-cluster
# - jenkins-server
# - elasticsearch-stack
# - docker-host
# - git-server
# - monitoring-stack
```

## 📝 Practical Examples

### 🎯 Bug Bounty Scanning

```bash
# Comprehensive bug bounty scanning
reconcli portcli --input subdomains.txt \
  --scanner rush \
  --rush-base-scanner naabu \
  --rush-jobs 10 \
  --top-ports 1000 \
  --exclude-cdn \
  --ai \
  --cache \
  --json \
  --markdown \
  --verbose

# Quick web ports scanning
reconcli portcli --input targets.txt \
  --only-web \
  --filter-tags prod \
  --json \
  --ai-cache
```

### 🏢 Internal Network Assessment

```bash
# Internal network scanning
reconcli portcli --cidr 192.168.0.0/16 \
  --scanner rush \
  --rush-base-scanner masscan \
  --rush-jobs 20 \
  --full \
  --cache \
  --store-db \
  --target-domain internal.company.com

# Infrastructure services detection
reconcli portcli --cidr 10.0.0.0/8 \
  --filter-services "kubernetes-cluster,docker-host,monitoring-stack" \
  --markdown
```

### 🚀 Performance Testing

```bash
# Maximum performance with rush + masscan
reconcli portcli --input large_scope.txt \
  --scanner rush \
  --rush-base-scanner masscan \
  --rush-jobs 50 \
  --rush-timeout 10 \
  --masscan-rate 5000 \
  --cache \
  --silent

# Resume interrupted scans
reconcli portcli --resume --verbose
```

## ⚙️ Configuration Options

### 📊 Scanning

```bash
--scanner [naabu|rustscan|nmap|masscan|rush]  # Scanner selection
--ports TEXT                                   # Port list (80,443,8080)
--top-ports INTEGER                           # Top N ports
--full                                        # Full range 1-65535
--rate INTEGER                               # Rate limit
--timeout INTEGER                            # Timeout in ms
```

### 🎯 Targets

```bash
--ip TEXT                                    # Single IP
--domain TEXT                                # Single domain
--cidr TEXT                                  # CIDR range
--input TEXT                                 # Target file (IPs, domains, CIDRs)
--exclude-cdn                                # Exclude CDN
```

### 🏷️ Filtering

```bash
--filter-tags TEXT                           # Filter by tags
--exclude-tags TEXT                          # Exclude tags
--filter-services TEXT                       # Filter by services
--only-web                                   # Only web ports
```

### 💾 Results and Cache

```bash
--json                                       # JSON output
--markdown                                   # Markdown report
--cache                                      # Enable cache
--cache-dir TEXT                            # Cache directory
--cache-max-age INTEGER                     # Cache age (hours)
```

### 🤖 AI and Analysis

```bash
--ai                                         # AI analysis
--ai-provider [openai|anthropic|gemini]     # AI provider
--ai-cache                                   # AI cache
--ai-context TEXT                           # AI context
```

### 📈 Management

```bash
--resume                                     # Resume scan
--verbose                                    # Verbose logs
--silent                                     # Silent mode
--store-db                                   # Store to database
```

## 📊 Output Formats

### JSON Output

```json
{
  "ip": "192.168.1.100",
  "scanner": "naabu",
  "open_ports": [22, 80, 443],
  "port_details": [
    {
      "port": 22,
      "service": "SSH",
      "tags": ["ssh", "remote", "tcp"]
    }
  ],
  "tags": ["ssh", "web", "https", "remote"],
  "detected_services": ["web-stack"],
  "cdn": false,
  "cloud_provider": "aws",
  "scan_time": "2025-07-24T18:30:00"
}
```

### Markdown Report
```markdown
# 🛠️ Port Scan Report – 2025-07-24 18:30:00

## 📊 Summary
- **Total Targets:** 5
- **Targets with Open Ports:** 4
- **Total Open Ports Found:** 23
- **Success Rate:** 80.0%

## 🎯 Detailed Results

### [1] Target: 192.168.1.100
- 🛰️ **Scanner:** naabu
- 🌐 **CDN:** ❌ No
- ⏰ **Scan Time:** 2025-07-24T18:30:00
- ✅ **Open Ports (3):**
  - **22** (SSH) `ssh,remote,tcp`
  - **80** (HTTP) `http,web,tcp,prod`
  - **443** (HTTPS) `https,web,ssl,tcp,prod`
- 🏷️ **Tags:** `ssh,web,https,remote,prod,ssl,tcp`
- 🔍 **Detected Services:** `web-stack`
```

### Example with Rush + AI

```bash
reconcli portcli --input vip_targets.txt \
  --scanner rush \
  --rush-base-scanner nmap \
  --rush-jobs 15 \
  --rush-timeout 60 \
  --top-ports 1000 \
  --ai \
  --ai-cache \
  --cache \
  --json \
  --markdown \
  --store-db \
  --target-domain example.com \
  --program "HackerOne" \
  --verbose
```

## 🔧 Troubleshooting

### Common Issues

1. **Scanner not found**

```bash
[!] naabu binary not found in PATH
# Solution: Install required scanner
```

2. **Masscan permissions**

```bash
# Masscan may require root privileges
sudo setcap cap_net_raw+ep /usr/bin/masscan
```

3. **Rush timeout**

```bash
# Increase timeout for slow targets
--rush-timeout 120
```

### Performance Tips

1. **Use rush for large scans**

```bash
--scanner rush --rush-jobs 20
```

2. **Enable cache for repeated tests**

```bash
--cache --cache-max-age 24
```

3. **Use masscan for speed**

```bash
--scanner rush --rush-base-scanner masscan --masscan-rate 5000
```

## 📞 Support

- **GitHub Issues**: [ReconCLI Issues](https://github.com/jarek-bir/Reconcli/issues)
- **Dokumentacja**: [GitHub Wiki](https://github.com/jarek-bir/Reconcli/wiki)
- **Przykłady**: Sprawdź folder `examples/` w repozytorium

---

*PortCLI - Część zaawansowanego zestawu narzędzi ReconCLI do profesjonalnego rozpoznania bezpieczeństwa.*
