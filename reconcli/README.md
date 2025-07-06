# ReconCLI - Modular Reconnaissance Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/releases)
[![GitHub stars](https://img.shields.io/github/stars/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/network)
[![GitHub issues](https://img.shields.io/github/issues/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/issues)
[![GitHub last commit](https://img.shields.io/github/last-commit/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/commits/main)

A comprehensive, modular reconnaissance toolkit designed for security professionals and bug bounty hunters.

🔗 **GitHub Repository**: [https://github.com/jarek-bir/Reconcli](https://github.com/jarek-bir/Reconcli)

## 🚀 Quick Start

```bash
# Install from GitHub
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli
pip install -e .

# Verify installation
reconcli --help
```

## ✨ Features

### 🎯 Virtual Host Discovery (`vhostcli`)
- **Engines**: FFuf and HTTPx support
- **Flexible Input**: Single IP or IP list
- **Output Formats**: JSON and Markdown reports
- **Proxy Support**: HTTP/HTTPS proxy configuration
- **Notifications**: Slack/Discord webhook integration
- **Verbose Mode**: Detailed progress tracking

```bash
# Basic VHOST discovery
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt

# With notifications
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --slack-webhook "https://hooks.slack.com/..." \
  --discord-webhook "https://discord.com/api/webhooks/..." \
  --verbose
```

### 🔍 Virtual Host Check (`vhostcheck`)
- **Individual VHOST Testing**: Test specific virtual hosts on target IPs
- **Batch Processing**: Test against multiple IPs from file with progress tracking
- **Technology Detection**: Automatic detection of web technologies (Nginx, Apache, IIS, WordPress, Drupal, etc.)
- **Response Analysis**: Detailed HTTP response analysis with status codes, sizes, and response times
- **Comprehensive Error Handling**: Proper handling of timeouts, connection errors, and HTTP errors
- **Output Formats**: Save results in JSON, CSV, or TXT formats (with special batch formats)
- **Proxy Support**: HTTP/HTTPS proxy configuration for testing through tools like Burp Suite
- **SSL/TLS Options**: HTTPS support with insecure certificate handling
- **Verbose Mode**: Detailed response headers and final URL information
- **Statistics**: Success rate calculation and summary reporting for batch operations

```bash
# Basic VHOST check
reconcli vhostcheck --ip 192.168.1.100 --domain example.com --vhost admin

# Multiple IPs from file with progress tracking
reconcli vhostcheck --input ips.txt --domain example.com --vhost admin --verbose

# HTTPS with proxy and verbose output
reconcli vhostcheck --ip 192.168.1.100:8443 --domain example.com --vhost api \
  --https --proxy http://127.0.0.1:8080 --verbose

# Batch processing with results saving
reconcli vhostcheck --input target_ips.txt --domain example.com --vhost store \
  --save-output --output-format json --verbose
```

### 🛠️ Port Scanning (`portcli`)
- **Multiple Scanners**: naabu, rustscan, and nmap support with unified interface
- **Flexible Input**: Single IPs, CIDR ranges, or batch processing from files
- **Resume Functionality**: Continue interrupted scans with built-in state management
- **🏷️ Automatic Tagging System**: Smart service categorization and filtering
- **🔍 Service Recognition**: Automatic detection of technology stacks and services
- **☁️ Cloud & CDN Detection**: Identify cloud providers and CDN IP ranges
- **🎯 Advanced Filtering**: Filter by tags, services, or exclude specific categories
- **📊 Professional Reports**: JSON and enhanced Markdown output with comprehensive analysis
- **⚡ Performance Optimized**: Concurrent scanning with progress tracking

#### 🏷️ Comprehensive Tagging System

**Service Categories:**
- `web`, `database`, `remote`, `mail`, `dns`, `ftp`, `monitoring`, `cloud`, `mgmt`, `voip`, `game`, `iot`, `messaging`

**Environment Detection:**
- `prod` (80,443,8080,9090,etc.), `dev` (3000,4200,8000,etc.), `staging` (8080,9000,etc.)

**Protocol & Security:**
- `tcp`, `udp`, `ssl`, `http`, `https`, `encrypted`

**Technology Stacks:**
- `jenkins`, `k8s-api`, `docker`, `prometheus`, `grafana`, `elk-stack`, `redis`, `postgres`, `mysql`

**Cloud Providers:**
- `aws`, `gcp`, `azure`, `digitalocean`, `cloudflare`

#### 🔍 Service Recognition Patterns

**Automatically detects:**
- **CI/CD**: Jenkins, GitLab, GitHub Enterprise, TeamCity, Bamboo
- **Kubernetes**: API servers, ingress controllers, dashboard
- **Monitoring**: ELK Stack (Elasticsearch, Logstash, Kibana), Prometheus+Grafana
- **Containers**: Docker registries, container management platforms
- **Databases**: Redis, PostgreSQL, MySQL, MongoDB clusters
- **Version Control**: Git services, code repositories
- **Cloud Services**: AWS services, GCP, Azure endpoints

#### 🎯 Advanced CLI Options

**Filtering & Selection:**
- `--filter-tags TAG1,TAG2`: Show only results with specific tags
- `--exclude-tags TAG1,TAG2`: Exclude results with specific tags  
- `--filter-services SERVICE1,SERVICE2`: Show only specific detected services
- `--web-only`: Scan only common web ports (80,443,8080,8443,etc.)
- `--top-ports N`: Scan top N most common ports
- `--ports PORT_LIST`: Scan specific ports (e.g., "22,80,443,8080-8090")

**Scanner Configuration:**
- `--scanner {naabu,rustscan,nmap}`: Choose scanning engine
- `--nmap-flags "FLAGS"`: Pass custom flags to nmap
- `--timeout SECONDS`: Set scan timeout per target
- `--rate RATE`: Control scan rate (naabu/nmap)

**Output & Reporting:**
- `--json`: Generate JSON report with full details
- `--markdown`: Generate enhanced Markdown report
- `--output-dir DIR`: Specify custom output directory
- `--verbose`: Show detailed scanning progress and results

```bash
# Basic single IP scan with automatic tagging
reconcli portcli --ip 192.168.1.100

# Scan CIDR showing only production web services
reconcli portcli --cidr 192.168.1.0/24 --filter-tags prod,web --top-ports 1000

# Find Jenkins and Kubernetes services only
reconcli portcli --input targets.txt --filter-services jenkins,k8s-api --verbose

# Database services scan with detailed service detection
reconcli portcli --input targets.txt --filter-tags database --scanner nmap \
  --nmap-flags "-sV -sC" --json --markdown

# Cloud infrastructure scan excluding CDN noise
reconcli portcli --cidr 10.0.0.0/16 --exclude-tags cdn --filter-tags cloud,mgmt

# Development environment discovery
reconcli portcli --input internal_ips.txt --filter-tags dev,staging \
  --exclude-tags prod --verbose

# Security-focused scan for encrypted services
reconcli portcli --input targets.txt --filter-tags ssl,encrypted \
  --scanner nmap --nmap-flags "-sV --script ssl-enum-ciphers"

# Batch scan with resume capability
reconcli portcli --input large_network.txt --resume --top-ports 10000 \
  --json --markdown --verbose

# Monitor and messaging services discovery
reconcli portcli --cidr 172.16.0.0/12 --filter-tags monitoring,messaging \
  --filter-services prometheus,grafana,elk-stack --verbose

# Web application discovery with service recognition
reconcli portcli --input webservers.txt --web-only \
  --filter-services jenkins,gitlab --markdown
```

### � Enhanced Subdomain Enumeration (`subdocli`)
- **11 Tools Integration**: Subfinder, Findomain, Assetfinder, Amass, Chaos, RapidDNS, crt.sh, BufferOver, Gobuster, FFuf, DNSRecon
- **DNS Resolution**: Multi-threaded IP resolution
- **HTTP Probing**: Automatic HTTP/HTTPS service detection
- **Resume Support**: Continue interrupted scans
- **Advanced Analytics**: Tool performance statistics and comprehensive reporting
- **Professional Reports**: JSON and enhanced Markdown output

```bash
# Basic subdomain enumeration
reconcli subdocli --domain example.com --verbose

# Full scan with resolution and HTTP probing
reconcli subdocli --domain example.com --resolve --probe-http \
  --all-tools --markdown --show-stats --verbose

# Resume interrupted scan
reconcli subdocli --domain example.com --resume --verbose
```

### 🌐 DNS Resolution & Analysis (`dns`)
- **Enhanced DNS Resolution**: Multi-threaded IP resolution with PTR record tagging
- **Subdomain Bruteforcing**: Custom wordlist support for subdomain discovery
- **Custom DNS Resolvers**: Use custom resolver lists for improved performance
- **WHOIS Integration**: Enrich DNS results with WHOIS data from WhoisFreaks
- **Advanced Filtering**: Tag-based filtering and unresolved exclusion
- **Resume Support**: Continue interrupted DNS scans
- **Professional Reports**: JSON and Markdown output with detailed statistics
- **Notification Support**: Real-time alerts via Slack/Discord webhooks

```bash
# Basic DNS resolution
reconcli dns --input subdomains.txt --verbose

# Advanced DNS with custom resolvers and wordlists
reconcli dns --input subdomains.txt --resolvers custom_resolvers.txt \
  --wordlists bruteforce_wordlist.txt --threads 100 --verbose

# DNS resolution with WHOIS enrichment
reconcli dns --input subdomains.txt --whois-file whois_results.json \
  --save-json --save-markdown --verbose

# Resume interrupted DNS scan with notifications
reconcli dns --input large_subdomain_list.txt --resume \
  --slack-webhook "https://hooks.slack.com/..." \
  --exclude-unresolved --filter-tags "CDN,Cloud" --verbose

# Quick resolution-only mode
reconcli dns --input subdomains.txt --resolve-only \
  --threads 200 --timeout 3 --retries 1 --verbose
```

### 🔗 URL Discovery & Analysis (`urlcli`)
- **Multiple Tools**: GAU, Katana, Gospider, Waybackurls integration
- **Advanced Katana Options**: Depth control, JS crawling, headless mode, form filling, tech detection
- **Configurable Timeouts**: Per-tool timeout settings
- **YAML Flow Support**: Predefined configuration templates
- **Comprehensive Filtering**: URL deduplication and pattern matching
- **Professional Reporting**: Detailed analysis with statistics

```bash
# Basic URL discovery
reconcli urlcli --domain example.com --verbose

# Advanced Katana crawling
reconcli urlcli --domain example.com --katana-depth 3 --katana-js-crawl \
  --katana-headless --katana-tech-detect --verbose

# Using flow configuration
reconcli urlcli --domain example.com --flow flows/url_katana_advanced.yaml
```

### 🔗 URL Sorting & Processing (`urlsorter`)
- **Advanced Pattern Recognition**: Technology stacks, sensitive files, API endpoints
- **Multiple Input Sources**: Files, stdin, and URL lists
- **Smart Filtering**: Duplicates, query parameters, extensions
- **Resume Support**: Continue large processing tasks
- **Professional Reports**: Categorized analysis with statistics
- **Flexible Output**: JSON and Markdown formats

```bash
# Sort URLs from file
reconcli urlsorter --input urls.txt --verbose

# Process URLs from stdin with advanced patterns
cat urls.txt | reconcli urlsorter --stdin --advanced-patterns \
  --remove-duplicates --markdown --verbose

# Resume interrupted processing
reconcli urlsorter --input large_urls.txt --resume --verbose
```

### 🔍 WHOIS Intelligence (`whoisfreakscli`)
- **WhoisFreaks API Integration**: Professional WHOIS data retrieval
- **Risk Assessment**: Domain risk scoring and analysis
- **Expiry Monitoring**: Domain expiration tracking
- **Bulk Processing**: Multiple domain analysis
- **Professional Reports**: Comprehensive JSON and Markdown output
- **Resume & Notifications**: Progress tracking and alert integration

```bash
# Single domain analysis
reconcli whoisfreakscli --domain example.com --verbose

# Bulk analysis with risk assessment
reconcli whoisfreakscli --input domains.txt --risk-assessment \
  --expiry-check --json --markdown --verbose

# With notifications for high-risk domains
reconcli whoisfreakscli --input domains.txt --risk-assessment \
  --slack-webhook "https://hooks.slack.com/..." --verbose
```

### �🚨 Subdomain Takeover Detection (`takeover`)
- **Tools**: Subzy and tko-subs integration
- **Resume System**: Continue interrupted scans
- **Professional Reports**: JSON and Markdown output
- **Error Handling**: Robust timeout and error management
- **Notifications**: Real-time alerts for vulnerabilities

```bash
# Basic takeover scan
reconcli takeover --input subdomains.txt

# With resume and notifications
reconcli takeover --input subdomains.txt --resume \
  --slack-webhook "https://hooks.slack.com/..." \
  --json --markdown --verbose
```

### 🔍 JavaScript Analysis (`jscli`)
- **Secret Detection**: API keys, tokens, credentials
- **Endpoint Discovery**: URL patterns and paths
- **Concurrent Processing**: Multi-threaded analysis
- **Resume Support**: Continue large scans
- **Raw File Saving**: Preserve original JS files

```bash
# Analyze JavaScript files
reconcli jscli --input js_urls.txt --threads 10 \
  --save-raw --json --markdown --verbose
```

### ☁️ Cloud Provider Detection & S3 Enumeration (`cloudcli`)
- **60+ Cloud Providers**: Comprehensive detection including AWS, Azure, Google Cloud, Cloudflare, DigitalOcean, and many more
- **Multi-Source Detection**: ASN, CNAME, PTR, HTTP headers, SSL certificates analysis
- **S3 Bucket Enumeration**: 73+ bucket naming patterns with multi-region support
- **Batch Processing**: Process multiple domains from file with progress tracking
- **Resume Support**: Continue interrupted scans with `--resume`, `--clear-resume`, `--show-resume`
- **Rate Limiting**: Configurable threading and timeout controls
- **Professional Reports**: JSON, TXT, and CSV output formats
- **Intermediate Saves**: Progress saved every 10 domains for large batch scans
- **Interruption Handling**: Graceful Ctrl+C handling with resume capability
- **Detailed Analytics**: Comprehensive cloud provider identification with confidence scoring

```bash
# Single domain cloud detection
reconcli cloudcli --domain example.com --verbose

# Batch cloud detection with resume support
reconcli cloudcli --domains-file domains.txt --resume --verbose

# Cloud detection with S3 enumeration
reconcli cloudcli --domain example.com --s3-enum --s3-regions --verbose

# Batch processing with S3 enumeration and custom threading
reconcli cloudcli --domains-file domains.txt --s3-enum --s3-threads 20 \
  --resume --output-format json --verbose

# Resume management
reconcli cloudcli --show-resume          # Show previous scan status
reconcli cloudcli --clear-resume         # Clear all resume states
reconcli cloudcli --domains-file domains.txt --resume  # Continue scan
```

### 🌍 TLD Reconnaissance (`tldr`)
- **Massive TLD Coverage**: Systematically check domains across **2,672+ TLD variations**
- **9 Comprehensive Categories**: Popular, country, new generic, business, crypto/blockchain, emerging tech, geographic, industry-specific, and specialized TLDs
- **DNS & HTTP Probing**: Full resolution and HTTP/HTTPS status verification with detailed analytics
- **Custom TLD Lists**: Support for custom TLD files and flexible category selection
- **Wildcard Detection**: Automatic detection and filtering of wildcard domains
- **Active Filtering**: Focus on active/responsive domains only
- **WHOIS Integration**: Basic domain availability checking with typosquatting detection
- **Professional Reports**: JSON and Markdown output with detailed statistics and categorization
- **Typosquatting Research**: Built-in variations and common typos for security research
- **Cryptocurrency Focus**: Specialized blockchain, DeFi, and crypto-related TLD categories

**🎯 TLD Category Breakdown**:
- **Popular** (81): Classic TLDs like .com, .net, .org, plus trending ones (.app, .dev, .tech)
- **Country** (253): Complete list of country-code TLDs from all regions
- **New Generic** (582): Modern gTLDs covering technology, business, lifestyle, and entertainment
- **Business** (423): Corporate structures, professional services, and industry-specific domains
- **Crypto/Blockchain** (106): Cryptocurrency, DeFi, NFT, and blockchain-focused TLDs
- **Emerging Tech** (107): AI, machine learning, IoT, quantum computing, and futuristic domains
- **Geographic** (351): Major cities, regions, states, and geographic features worldwide
- **Industry Specific** (559): Automotive, real estate, healthcare, legal, financial, and more
- **Specialized** (210): Adult content, suspicious/alternative, typosquatting variations for security research

```bash
# Basic TLD reconnaissance with popular and country TLDs
reconcli tldr -d example --categories popular,country --verbose

# Advanced comprehensive TLD scan across all 2,672+ TLDs
reconcli tldr -d mycompany --categories all --http-check \
  --filter-active --save-json --verbose

# Cryptocurrency and blockchain focused reconnaissance
reconcli tldr -d cryptobrand --categories crypto_blockchain,emerging_tech \
  --http-check --filter-active --save-markdown

# Security research with typosquatting and specialized TLDs
reconcli tldr -d target --categories specialized,geographic \
  --exclude-wildcards --whois-check --verbose

# Custom TLD list with industry-specific focus
reconcli tldr -d brand --categories business,industry_specific \
  --http-check --filter-active --slack-webhook "https://hooks.slack.com/..."

# Maximum coverage scan for comprehensive domain discovery
reconcli tldr -d enterprise --categories all --threads 100 \
  --http-check --whois-check --exclude-wildcards \
  --save-json --save-markdown --verbose
```

### 🌐 Additional Core Modules
- **Cloud Detection & S3 Enumeration** (`cloudcli`): Comprehensive cloud provider detection and S3 bucket enumeration
- **CNAME Analysis** (`cnamecli`): Advanced CNAME resolution and subdomain takeover detection
- **DNS Enumeration** (`dnscli`): Comprehensive DNS discovery and analysis
- **HTTP Analysis** (`httpcli`): Web application assessment and fingerprinting
- **IP Analysis** (`ipscli`): Network reconnaissance and IP intelligence
- **Zone Walking** (`zonewalkcli`): DNS zone transfer testing and enumeration

## Installation

```bash
# Clone repository
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli

# Install package
pip install -e .

# Verify installation
reconcli --help
```

## Dependencies

### Required Tools

#### For Subdomain Enumeration (`subdocli`)
- **Subfinder**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **Findomain**: Download from [GitHub releases](https://github.com/Findomain/Findomain/releases)
- **Assetfinder**: `go install github.com/tomnomnom/assetfinder@latest`
- **Amass**: `go install -v github.com/owasp-amass/amass/v4/...@master`
- **Chaos**: `go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest`
- **Gobuster**: `go install github.com/OJ/gobuster/v3@latest`
- **FFuf**: `go install github.com/ffuf/ffuf/v2@latest`
- **DNSRecon**: `pip install dnsrecon` or install from package manager

#### For URL Discovery (`urlcli`)
- **GAU**: `go install github.com/lc/gau/v2/cmd/gau@latest`
- **Katana**: `go install github.com/projectdiscovery/katana/cmd/katana@latest`
- **Gospider**: `go install github.com/jaeles-project/gospider@latest`
- **Waybackurls**: `go install github.com/tomnomnom/waybackurls@latest`

#### For Virtual Host Discovery (`vhostcli`)
- **FFuf**: `go install github.com/ffuf/ffuf/v2@latest`
- **HTTPx**: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

#### For Takeover Detection (`takeover`)
- **Subzy**: Download from [GitHub releases](https://github.com/LukaSikic/subzy/releases)
- **tko-subs**: `go install github.com/anshumanbh/tko-subs@latest`

#### For Port Scanning (`portcli`)
- **naabu**: `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`
- **rustscan**: `cargo install rustscan`
- **nmap**: Install from [nmap.org](https://nmap.org/download.html)

#### For CNAME Analysis (`cnamecli`)
- **Subjack**: `go install github.com/haccer/subjack@latest`
- **Tko-subs**: `go install github.com/anshumanbh/tko-subs@latest`

### API Keys

#### WhoisFreaks API (for `whoisfreakscli`)
1. Register at [WhoisFreaks](https://whoisfreaks.com/)
2. Get your API key from the dashboard
3. Set environment variable: `export WHOISFREAKS_API_KEY="your_api_key"`
4. Or store in `~/.env_secrets` file: `WHOISFREAKS_API_KEY=your_api_key`

### Python Dependencies
- click >= 8.0
- requests >= 2.28
- httpx >= 0.24
- pathlib
- concurrent.futures
- json
- yaml

## Configuration

### Notification Setup

#### Slack Webhooks
1. Create a Slack app in your workspace
2. Enable incoming webhooks
3. Copy the webhook URL
4. Use with `--slack-webhook` option

#### Discord Webhooks
1. Go to your Discord server settings
2. Navigate to Integrations → Webhooks
3. Create a new webhook
4. Copy the webhook URL
5. Use with `--discord-webhook` option

## Project Structure

```
reconcli/
├── __init__.py
├── main.py                 # Main CLI entry point
├── cloudcli.py            # Cloud provider detection & S3 enumeration (NEW)
├── subdocli.py            # Enhanced subdomain enumeration (NEW)
├── urlcli.py              # URL discovery and analysis (ENHANCED)
├── urlsorter.py           # URL sorting and processing (NEW)
├── whoisfreakscli.py      # WHOIS intelligence (NEW)
├── vhostcli.py            # Virtual host discovery
├── takeovercli.py         # Subdomain takeover detection
├── jscli.py               # JavaScript analysis
├── dnscli.py              # DNS enumeration
├── httpcli.py             # HTTP analysis
├── ipscli.py              # IP reconnaissance
├── zonewalkcli.py         # DNS zone walking
├── vhostcheckcli.py       # Advanced VHOST discovery and validation
├── portcli.py             # Port scanning and service enumeration
├── cnamecli.py            # CNAME analysis and subdomain takeover detection (NEW)
├── utils/
│   ├── __init__.py
│   ├── cloud_detect.py    # Cloud provider detection engine (NEW)
│   ├── s3_enum.py         # S3 bucket enumeration engine (NEW)
│   ├── notifications.py   # Notification system
│   ├── resume.py          # Resume functionality
│   ├── loaders.py         # Data loading utilities
│   └── mdexport.py        # Markdown export utilities
├── flows/                 # Workflow definitions (YAML configs)
│   ├── README.md          # Flow documentation
│   ├── url_katana_advanced.yaml
│   ├── url_katana_headless.yaml
│   ├── url_katana_fast.yaml
│   ├── url_passive.yaml
│   ├── url_aggressive.yaml
│   ├── url_deep.yaml
│   └── custom_patterns.yaml
└── wordlists/            # Default wordlists
    ├── resolvers-trickest.txt
    └── wordlist.txt
```

## Advanced Usage

### Resume Functionality
Most modules support resume functionality for long-running scans:

```bash
# Start a scan
reconcli takeover --input large_subdomain_list.txt --resume

# If interrupted, resume with same command
reconcli takeover --input large_subdomain_list.txt --resume

# Check resume status
reconcli takeover --show-resume

# Clear resume state
reconcli takeover --clear-resume
```

### Proxy Configuration
Use proxies for all HTTP requests:

```bash
reconcli vhostcli --domain example.com --ip 1.2.3.4 \
  --wordlist wordlist.txt --proxy http://127.0.0.1:8080
```

### Output Formats
Generate professional reports in multiple formats:

```bash
# JSON output
reconcli takeover --input subdomains.txt --json

# Markdown output
reconcli takeover --input subdomains.txt --markdown

# Both formats
reconcli takeover --input subdomains.txt --json --markdown
```

## Examples

### Advanced Port Scanning Workflows

```bash
# Comprehensive infrastructure assessment
reconcli portcli \
  --input infrastructure.txt \
  --scanner nmap \
  --nmap-flags "-sV -sC -O" \
  --json \
  --markdown \
  --verbose

# Production web services discovery
reconcli portcli \
  --cidr 10.0.0.0/8 \
  --filter-tags prod,web \
  --exclude-tags dev,staging \
  --top-ports 1000 \
  --json

# Security assessment focusing on management interfaces
reconcli portcli \
  --input targets.txt \
  --filter-tags mgmt,remote \
  --filter-services jenkins,k8s-api \
  --scanner nmap \
  --nmap-flags "-sV --script vuln" \
  --markdown

# Database and messaging service discovery
reconcli portcli \
  --cidr 172.16.0.0/12 \
  --filter-tags database,messaging \
  --exclude-tags dev \
  --verbose

# Cloud infrastructure analysis
reconcli portcli \
  --input cloud_ips.txt \
  --filter-tags cloud,ssl \
  --exclude-tags cdn \
  --json \
  --markdown

# Development environment assessment
reconcli portcli \
  --input dev_network.txt \
  --filter-tags dev,staging \
  --filter-services jenkins,gitlab \
  --web-only \
  --verbose
```

### Advanced IP Analysis and Intelligence Workflows

```bash
# Basic IP enrichment and geolocation analysis
reconcli ipscli \
  --input ips.txt \
  --enrich \
  --verbose

# Comprehensive IP analysis with cloud detection and port scanning
reconcli ipscli \
  --input subdomains_resolved.txt \
  --resolve-from subs \
  --enrich \
  --scan rustscan \
  --filter-cdn \
  --markdown \
  --verbose

# CIDR range expansion and analysis with uncover integration
reconcli ipscli \
  --input cidrs.txt \
  --cidr-expand \
  --enrich \
  --use-uncover \
  --uncover-engine shodan \
  --json \
  --verbose

# Geographic and cloud provider filtering
reconcli ipscli \
  --input global_ips.txt \
  --enrich \
  --filter-country US \
  --filter-cloud aws,gcp,azure \
  --exclude-tags cdn,honeypot \
  --markdown

# Advanced threat intelligence with honeypot detection
reconcli ipscli \
  --input suspicious_ips.txt \
  --enrich \
  --honeypot \
  --filter-tags government,education \
  --exclude-tags cloud \
  --json \
  --verbose

# ASN-based IP discovery and analysis
reconcli ipscli \
  --input sample_ips.txt \
  --enrich \
  --use-uncover \
  --uncover-query 'asn:"AS13335"' \
  --filter-asn cloudflare \
  --scan simple \
  --markdown

# Resume interrupted large-scale analysis
reconcli ipscli \
  --resume \
  --verbose

# Extract and analyze IPs from existing uncover JSON results
reconcli ipscli \
  --uncover-json uncover_results.json \
  --enrich \
  --scan rustscan \
  --filter-cloud aws \
  --json

# High-performance concurrent IP analysis
reconcli ipscli \
  --input massive_ip_list.txt \
  --enrich \
  --threads 20 \
  --timeout 15 \
  --scan simple \
  --filter-tags hosting,isp \
  --markdown \
  --verbose
```

### Complete Subdomain Discovery Workflow
```bash
# Comprehensive subdomain enumeration with all features
reconcli subdocli \
  --domain target.com \
  --all-tools \
  --resolve \
  --probe-http \
  --threads 100 \
  --timeout 60 \
  --markdown \
  --show-stats \
  --verbose
```

### Advanced URL Discovery and Analysis
```bash
# Deep URL crawling with Katana advanced features
reconcli urlcli \
  --domain target.com \
  --katana-depth 5 \
  --katana-js-crawl \
  --katana-headless \
  --katana-tech-detect \
  --katana-form-fill \
  --gau-timeout 120 \
  --verbose

# Using predefined flow configuration
reconcli urlcli --domain target.com --flow flows/url_katana_advanced.yaml
```

### Smart URL Processing
```bash
# Process and categorize large URL lists
reconcli urlsorter \
  --input massive_urls.txt \
  --advanced-patterns \
  --remove-duplicates \
  --remove-query-params \
  --markdown \
  --resume \
  --verbose

# Real-time URL processing from stdin
cat urls.txt | reconcli urlsorter --stdin --advanced-patterns --verbose
```

### WHOIS Intelligence Gathering
```bash
# Bulk domain analysis with risk assessment
reconcli whoisfreakscli \
  --input domains.txt \
  --risk-assessment \
  --expiry-check \
  --json \
  --markdown \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --verbose
```

### Complete Cloud Provider Discovery & S3 Enumeration
```bash
# Single domain cloud detection with S3 enumeration
reconcli cloudcli \
  --domain target.com \
  --s3-enum \
  --s3-regions \
  --s3-threads 20 \
  --verbose

# Batch cloud detection with resume support
reconcli cloudcli \
  --domains-file target_domains.txt \
  --s3-enum \
  --resume \
  --output-format json \
  --output-dir cloud_results \
  --verbose

# Resume interrupted scan
reconcli cloudcli --domains-file target_domains.txt --resume

# Check scan status and clear old states
reconcli cloudcli --show-resume
reconcli cloudcli --clear-resume
```

### Complete VHOST Discovery Workflow
```bash
# Discover virtual hosts with notifications
reconcli vhostcli \
  --domain target.com \
  --ip-list ip_ranges.txt \
  --wordlist vhost_wordlist.txt \
  --engine ffuf \
  --proxy http://127.0.0.1:8080 \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --output-dir vhost_results \
  --verbose
```

### Comprehensive Takeover Assessment
```bash
# Run takeover detection with full reporting
reconcli takeover \
  --input discovered_subdomains.txt \
  --tool subzy \
  --output-dir takeover_results \
  --json \
  --markdown \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --discord-webhook "https://discord.com/api/webhooks/..." \
  --resume \
  --verbose
```

### 🔗 CNAME Analysis and Subdomain Takeover Detection
```bash
# Basic CNAME analysis with provider identification
reconcli cnamecli \
  --domains subdomains.txt \
  --provider-tags \
  --verbose

# Full vulnerability scan with takeover detection
reconcli cnamecli \
  --domains targets.txt \
  --check \
  --takeover-check \
  --provider-tags \
  --json \
  --markdown \
  --verbose

# Filter only potential takeover candidates
reconcli cnamecli \
  --domains large_list.txt \
  --takeover-check \
  --status-filter potential_takeover \
  --json \
  --verbose

# Filter dead domains (don't resolve at all)
reconcli cnamecli \
  --domains subdomains.txt \
  --check \
  --status-filter dead \
  --markdown \
  --verbose

# High-performance concurrent scan
reconcli cnamecli \
  --domains large_list.txt \
  --takeover-check \
  --threads 20 \
  --timeout 10 \
  --json \
  --output-dir cname_results \
  --verbose

# Resume interrupted vulnerability scan
reconcli cnamecli \
  --domains targets.txt \
  --takeover-check \
  --resume \
  --verbose

# Check resume status and clear state
reconcli cnamecli --show-resume
reconcli cnamecli --clear-resume
```

**Status Types:**
- `no_cname`: Domain has no CNAME record (direct A/AAAA)
- `resolves_ok`: CNAME exists and resolves properly
- `not_resolving`: CNAME exists but doesn't resolve 
- `potential_takeover`: CNAME points to vulnerable service and doesn't resolve
- `dead`: Domain doesn't resolve at all (no DNS records)
- `error`: Analysis failed due to technical issues

## 📊 Project Stats

![GitHub repo size](https://img.shields.io/github/repo-size/jarek-bir/Reconcli)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/jarek-bir/Reconcli)
![Lines of code](https://img.shields.io/tokei/lines/github/jarek-bir/Reconcli)

## 🛡️ Security & Bug Bounty

ReconCLI is designed with bug bounty hunters and security researchers in mind:

- **Professional Output**: Clean JSON/Markdown reports for documentation
- **Stealth Mode**: Proxy support and configurable timeouts
- **Resume Capability**: Continue long-running scans without losing progress
- **Notification Integration**: Real-time alerts for critical findings
- **Modular Design**: Use only the modules you need

## 🚀 Roadmap

- [ ] Enhanced cloud provider detection with machine learning classification
- [ ] Extended S3 enumeration with security assessment capabilities
- [ ] Notification system integration for cloudcli with email and Slack support
- [ ] DNS zone walking improvements
- [ ] Enhanced JavaScript analysis with modern frameworks
- [ ] Web application fingerprinting module
- [ ] API endpoint discovery automation
- [ ] Integration with popular bug bounty platforms
- [ ] Docker containerization
- [ ] Web-based dashboard interface

## 📚 Additional Resources

- **Documentation**: [GitHub Wiki](https://github.com/jarek-bir/Reconcli/wiki)
- **Examples**: [Usage Examples](https://github.com/jarek-bir/Reconcli/tree/main/examples)
- **Changelog**: [Release Notes](https://github.com/jarek-bir/Reconcli/releases)
- **Security Policy**: [Security.md](https://github.com/jarek-bir/Reconcli/blob/main/SECURITY.md)

## Contributing

We welcome contributions to ReconCLI! Here's how you can help:

### 🐛 Reporting Issues
- Use the [GitHub issue tracker](https://github.com/jarek-bir/Reconcli/issues)
- Provide detailed information about the bug
- Include steps to reproduce the issue

### 🔧 Development Process
1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes with proper commit messages
4. Add tests if applicable
5. Run the existing tests to ensure nothing breaks
6. Submit a pull request with a clear description

### 📦 Repository Structure
```
reconcli/
├── main.py              # Main CLI entry point
├── vhostcli.py         # Virtual host discovery
├── takeovercli.py      # Subdomain takeover detection  
├── jscli.py            # JavaScript analysis
├── urlcli.py           # URL processing and discovery
├── utils/              # Shared utilities
│   ├── notifications.py # Slack/Discord notifications
│   ├── resume.py       # Resume functionality
│   └── loaders.py      # Data loading utilities
└── flows/              # YAML configuration templates
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jarek-bir/Reconcli/blob/main/LICENSE) file for details.

## 📈 Changelog

### Latest Changes (v3.0.0)

- ✅ **NEW: portcli.py** - Advanced port scanning and service enumeration
  - **Multi-Scanner Support**: naabu, rustscan, and nmap with unified interface
  - **Smart Target Handling**: Single IPs, CIDR ranges, and batch processing from files
  - **Resume Functionality**: Continue interrupted scans with built-in state management
  - **🏷️ Comprehensive Tagging System**: 60+ intelligent service tags across 13 categories
    - **Service Categories**: web, database, remote, mail, dns, ftp, monitoring, cloud, mgmt, voip, game, iot, messaging
    - **Environment Detection**: prod, dev, staging based on port patterns and service analysis
    - **Protocol Tags**: tcp, udp, ssl, http, https, encrypted for security assessment
    - **Technology Stacks**: jenkins, k8s-api, docker, prometheus, grafana, elk-stack, redis, postgres, mysql
    - **Cloud Providers**: aws, gcp, azure, digitalocean, cloudflare with automatic detection
  - **🔍 Advanced Service Recognition**: Automatic detection of 20+ technology stacks
    - **CI/CD Platforms**: Jenkins, GitLab, GitHub Enterprise, TeamCity, Bamboo
    - **Container Orchestration**: Kubernetes API, Docker services, container registries
    - **Monitoring Stack**: ELK (Elasticsearch, Logstash, Kibana), Prometheus+Grafana, Nagios
    - **Database Systems**: Redis, PostgreSQL, MySQL, MongoDB with cluster detection
    - **Version Control**: Git services, SVN, automated code repository identification
  - **☁️ Cloud & CDN Intelligence**: 
    - ASN-based cloud provider detection for AWS, GCP, Azure, DigitalOcean
    - CDN IP range identification and filtering (Cloudflare, AWS CloudFront, etc.)
    - Cloud service endpoint recognition and tagging
  - **🎯 Advanced Filtering System**:
    - `--filter-tags`: Include only specific service categories (e.g., prod,web,database)
    - `--exclude-tags`: Exclude noise like dev environments or CDN services
    - `--filter-services`: Target specific technologies (e.g., jenkins,k8s-api,elk-stack)
    - `--web-only`: Focus on web application ports for bug bounty hunting
  - **📊 Professional Reporting**:
    - **JSON Output**: Structured data with tags, detected services, cloud info, and statistics
    - **Enhanced Markdown**: Rich reports with service recognition, tag distribution, and visual formatting
    - **Statistical Analysis**: Port distribution by tags, success rates, and scanning performance metrics
  - **⚡ Performance & Reliability**:
    - Concurrent scanning with configurable threading and timeouts
    - Progress tracking for large batch scans with ETA calculations
    - Robust error handling with automatic retries and detailed logging
    - Resume capability for interrupted scans preserving state and progress

- ✅ **NEW: ipscli.py** - Advanced IP intelligence and reconnaissance module
  - **Multi-Source Enrichment**: ipinfo.io integration with geolocation, ASN, and organization data
  - **🏷️ Intelligent IP Tagging System**: Comprehensive classification with 20+ tag categories
    - **Geographic Tags**: country-based classification and region tagging
    - **Infrastructure Tags**: cloud, cdn, hosting, isp, government, education detection
    - **Service Tags**: web-server, mail-server, database, api, vpn automatic identification
    - **Security Tags**: honeypot detection heuristics and privacy service identification
  - **☁️ Cloud & CDN Intelligence**: 
    - Multi-provider cloud detection (AWS, GCP, Azure, DigitalOcean) via IP ranges and ASN
    - CDN identification and filtering (Cloudflare, AWS CloudFront, etc.)
    - Cloud service endpoint recognition with provider-specific tagging
  - **🔍 Advanced Discovery Integration**:
    - **Uncover Integration**: Automated ASN detection with multi-engine support (Shodan, Censys, FOFA)
    - **CIDR Expansion**: Safe expansion of network ranges with size limits
    - **Multi-Format Input**: Support for subdomain resolution output and raw IP lists
  - **🎯 Advanced Filtering & Analysis**:
    - `--filter-country`: Geographic filtering by country codes
    - `--filter-cloud`: Cloud provider filtering (aws,gcp,azure,digitalocean)
    - `--filter-asn`: ASN pattern matching and organization filtering
    - `--filter-tags`/`--exclude-tags`: Tag-based inclusion/exclusion filtering
    - `--honeypot`: Enhanced honeypot detection with behavioral analysis
  - **🔌 Integrated Port Scanning**:
    - Multi-scanner support (rustscan, nmap, masscan, simple socket-based)
    - Service detection and port-based tagging integration
    - Custom port lists and focused scanning capabilities
  - **📊 Professional Intelligence Reporting**:
    - **Comprehensive Markdown Reports**: Geographic distribution, cloud analysis, service statistics
    - **Structured JSON Output**: Complete enrichment data with tags, cloud info, and scan results
    - **Statistical Analysis**: ASN distribution, country analysis, tag frequency, and security insights
  - **⚡ Enterprise-Grade Features**:
    - Resume functionality for large-scale IP analysis campaigns
    - Concurrent processing with configurable threading and timeouts
    - Proxy support for corporate environments and operational security
    - Error handling with detailed logging and batch processing reliability

- ✅ **NEW: vhostcheckcli.py** - Advanced virtual host discovery and validation
  - Individual VHOST testing with comprehensive response analysis
  - **Batch Processing**: Multiple IPs from file with progress tracking and statistics
  - Technology detection for Nginx, Apache, IIS, WordPress, Drupal, and more
  - Multiple output formats (JSON, CSV, TXT) with detailed results and batch formats
  - Proxy support for testing through tools like Burp Suite
  - SSL/TLS options with insecure certificate handling
  - Comprehensive error handling for timeouts and connection issues
  - Success rate calculation and summary reporting for batch operations

- ✅ **NEW: cloudcli.py** - Comprehensive cloud provider detection and S3 bucket enumeration
  - 60+ cloud providers detection (AWS, Azure, Google Cloud, Cloudflare, DigitalOcean, etc.)
  - Multi-source detection: ASN, CNAME, PTR, HTTP headers, SSL certificates
  - S3 bucket enumeration with 73+ naming patterns and multi-region support
  - Batch processing with resume functionality for large domain lists
  - Rate limiting and threading controls for optimal performance
  - Professional reporting in JSON, TXT, and CSV formats

- ✅ **NEW: cnamecli.py** - CNAME analysis and subdomain takeover detection
  - Basic CNAME analysis with provider identification
  - Vulnerability scan with subdomain takeover detection
  - High-performance concurrent scanning
  - Resume support for interrupted scans
  - Professional reporting in JSON and Markdown formats

- ✅ **Enhanced resume system** - Advanced scan management
  - `--resume` - Continue interrupted scans seamlessly
  - `--clear-resume` - Clear all previous resume states
  - `--show-resume` - Display status of previous scans
  - Intermediate saves every 10 domains for large batch operations
  - Graceful interruption handling with Ctrl+C support

- ✅ **NEW: subdocli.py** - Enhanced subdomain enumeration with 11 integrated tools
  - Passive tools: Subfinder, Findomain, Assetfinder, Amass, Chaos, RapidDNS, crt.sh, BufferOver
  - Active tools: Gobuster, FFuf, DNSRecon
  - Multi-threaded DNS resolution and HTTP/HTTPS service probing
  - Advanced statistics and comprehensive reporting

- ✅ **NEW: whoisfreakscli.py** - Professional WHOIS intelligence gathering
  - WhoisFreaks API integration with bulk domain processing
  - Risk assessment and domain expiration monitoring
  - Professional reporting with threat intelligence insights

- ✅ **NEW: urlsorter.py** - Advanced URL processing and categorization
  - Smart pattern recognition for technology stacks and sensitive files
  - Multiple input sources (files, stdin) with resume support
  - Advanced filtering and deduplication capabilities

- ✅ **ENHANCED: urlcli.py** - Comprehensive URL discovery and analysis
  - Advanced Katana integration (depth, JS crawling, headless mode, tech detection)
  - Configurable timeouts for all external tools (GAU, Katana, Gospider, Waybackurls)
  - YAML flow support with predefined configuration templates
  - Enhanced error handling and professional reporting

- ✅ **Enhanced vhostcli.py** with robust resume, error handling, and notifications
- ✅ **Comprehensive notification system** supporting Slack and Discord webhooks
- ✅ **Improved takeovercli.py** with resume system and enhanced error handling
- ✅ **Fixed jscli.py** import paths for package compatibility
- ✅ **Added utils/notifications.py** with full-featured notification support
- ✅ **Professional documentation** with comprehensive usage examples
- ✅ **YAML flow configurations** for urlcli with predefined templates
- ✅ **MIT License** and enhanced README with all new features

## 🆘 Support & Community

### 💬 Getting Help
- **Issues**: [GitHub Issues](https://github.com/jarek-bir/Reconcli/issues)
- **Discussions**
- **Security**: Please report security issues privately

### 🌟 Show Your Support
If ReconCLI helps you in your security research or bug bounty hunting, consider:
- ⭐ Starring the repository on GitHub
- 🐛 Reporting bugs and suggesting features
- 🔧 Contributing code improvements
- 📖 Improving documentation

### 🏆 Contributors
Special thanks to all contributors who help make ReconCLI better!

---

**Made with ❤️ for the security community**

🔗 **Repository**: [https://github.com/jarek-bir/Reconcli](https://github.com/jarek-bir/Reconcli)
