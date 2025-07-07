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

### 🛡️ Advanced Vulnerability Scanning (`vulncli`)
- **🤖 AI-Powered Analysis**: Intelligent template selection and false positive reduction
- **⚡ Multiple Engines**: Nuclei and Jaeles scanner integration with unified interface
- **🔍 Smart Pattern Matching**: Custom GF patterns for targeted vulnerability discovery
- **📊 Risk Assessment**: AI-powered confidence scoring and vulnerability classification
- **🎯 Advanced Filtering**: Template selection by severity, tags, technology stacks
- **📈 Executive Reporting**: AI-generated summaries and detailed technical reports
- **🔄 Resume Support**: Continue interrupted scans with state management
- **⚙️ High Performance**: Concurrent scanning with progress tracking and rate limiting
- **🔔 Real-time Notifications**: Slack/Discord integration for critical findings
- **📋 Professional Output**: JSON, Markdown, CSV, and XML reports with metrics

#### 🤖 AI-Powered Features (Planned)
- **Smart Template Selection**: AI analyzes targets to suggest optimal Nuclei templates
- **False Positive Reduction**: Machine learning filters to reduce noise and improve accuracy
- **Vulnerability Classification**: Automatic categorization with OWASP Top 10 mapping
- **Executive Summaries**: AI-generated executive reports for management and stakeholders
- **Risk Scoring**: Intelligent risk assessment based on context and impact analysis

#### 🎯 Advanced CLI Options
```bash
# Basic vulnerability scan with smart defaults
reconcli vulncli --input urls.txt --output-dir results

# AI-powered scan with template optimization
reconcli vulncli --input targets.txt --ai-template-selection \
  --ai-false-positive-filter --confidence-threshold 0.8

# Advanced Nuclei scan with custom templates and severity filtering
reconcli vulncli --input urls.txt --engine nuclei \
  --templates custom-templates/ --severity critical,high \
  --exclude-tags dos,intrusive --concurrency 50

# Jaeles scan with specific signatures
reconcli vulncli --input targets.txt --engine jaeles \
  --jaeles-signatures "~/jaeles-signatures/cves/" \
  --jaeles-timeout 30 --parallel-jobs 10

# Combined scan with GF pattern pre-filtering
reconcli vulncli --input urls.txt --gf-patterns sqli,xss,rce \
  --engine nuclei --ai-classify --executive-summary

# Resume interrupted scan with notifications
reconcli vulncli --input large_targets.txt --resume \
  --slack-webhook "https://hooks.slack.com/..." \
  --discord-webhook "https://discord.com/api/webhooks/..." \
  --verbose --output-format json
```

### 🔍 Advanced Directory Brute Force (`dirbcli`)
- **🛠️ Multi-Tool Support**: FFuf, Feroxbuster, Gobuster, and Dirsearch integration
- **🧠 Smart Technology Detection**: Automatically detects web technologies and recommends wordlists
- **📊 Intelligent Categorization**: Risk-based classification of findings (admin panels, config files, backups)
- **🎯 Advanced Filtering**: Status codes, response sizes, regex patterns, and smart calibration
- **🔄 Enhanced Resume Support**: Continue interrupted scans with state management and validation
- **⚡ High Performance**: Concurrent scanning with customizable threads and rate limiting
- **🔔 Real-time Notifications**: Slack/Discord integration for critical findings
- **📋 Professional Reports**: JSON and Markdown reports with security recommendations
- **🔐 Security Assessment**: Automated risk scoring and actionable security advice
- **🎨 Technology-Specific**: WordPress, PHP, Apache, Nginx specialized scanning patterns
- **🗑️ Smart Cleanup**: Automatic cleanup of temporary files while preserving results

#### 🎯 Advanced CLI Options
```bash
# Basic directory brute force with technology detection
reconcli dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --tech-detect

# Smart scanning with AI-powered wordlist selection
reconcli dirbcli --url https://example.com --wordlist common.txt \
  --tech-detect --smart-wordlist --verbose

# Professional scanning with comprehensive reporting
reconcli dirbcli --url https://example.com --wordlist big.txt \
  --tool ffuf --threads 50 --rate-limit 10 \
  --include-ext php,html,txt,js,css,json \
  --filter-status 200,301,302,403 --auto-calibrate \
  --json-report --markdown-report --verbose

# Recursive scanning with feroxbuster
reconcli dirbcli --url https://example.com --wordlist /path/to/wordlist.txt \
  --tool feroxbuster --recursive --max-depth 3 \
  --slack-webhook "https://hooks.slack.com/..." --verbose

# Advanced filtering and customization
reconcli dirbcli --url https://example.com --wordlist /path/to/wordlist.txt \
  --custom-headers "Authorization: Bearer token123" \
  --proxy http://127.0.0.1:8080 --filter-size 100-50000 \
  --exclude-length 1234,5678 --match-regex "admin|config|backup"

# Resume management and cleanup
reconcli dirbcli --show-resume                    # Show previous scan status
reconcli dirbcli --clear-resume                   # Clear previous scan state
reconcli dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --resume --cleanup
```

### 🛡️ SQL Injection Vulnerability Scanner (`vulnsqlicli`)

- **🔍 Multi-Tool Support**: SQLMap, Ghauri, and GF (grep for fun) integration
- **⚡ Advanced Detection**: Comprehensive SQL injection vulnerability assessment
- **🎯 Smart Pattern Matching**: GF patterns for SQL injection indicators
- **🧪 Manual Testing**: Basic payload testing for quick detection
- **📊 Risk Classification**: Critical, High, Medium vulnerability categorization
- **🔧 Advanced Options**: Proxy, Tor, custom headers, tamper scripts support
- **📋 Professional Reports**: JSON, YAML, and Markdown reports with recommendations
- **🔔 Notifications**: Slack/Discord webhook integration for alerts
- **🗄️ Database Enumeration**: Full DBMS exploration capabilities
- **⚙️ Batch Processing**: Multiple URLs testing from file input

#### 🎯 Advanced SQL Injection Testing

```bash
# Basic SQL injection testing
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --basic-test

# Comprehensive testing with SQLMap
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --level 3 --risk 2

# Fast detection with Ghauri
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --ghauri --batch

# Pattern matching with GF
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --gf

# Full enumeration after finding vulnerability
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap \
  --dbs --tables --columns --current-user --passwords --privileges

# Test multiple URLs with all tools
reconcli vulnsqlicli --urls-file urls.txt --tool all \
  --json-report --markdown-report --verbose

# Advanced testing with proxy and tamper scripts
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap \
  --proxy http://127.0.0.1:8080 --tamper space2comment,charencode \
  --level 5 --risk 3 --random-agent

# Steganographic testing with Tor
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap \
  --tor --check-tor --random-agent --level 3 \
  --slack-webhook "https://hooks.slack.com/..." --verbose
```

### ☁️ Cloud Provider Detection & S3 Enumeration (`cloudcli`)

- **🌐 Multi-Cloud Support**: AWS, Azure, GCP detection
- **🔍 S3 Bucket Enumeration**: Advanced S3 bucket discovery
- **🎯 Permission Testing**: Bucket access and permission analysis
- **📊 Comprehensive Reports**: JSON and Markdown output formats
- **🔔 Notifications**: Slack/Discord webhook integration
- **⚡ High Performance**: Concurrent scanning with rate limiting

```bash
# Basic cloud enumeration
reconcli cloudcli --target example.com --all-clouds

# S3 bucket enumeration with custom wordlist
reconcli cloudcli --target example.com --s3-enum --wordlist buckets.txt

# Advanced scanning with notifications
reconcli cloudcli --target example.com --all-clouds --verbose \
  --slack-webhook "https://hooks.slack.com/..." \
  --json-report --markdown-report
```

## 🔧 Installation

### Requirements
- Python 3.8+
- pip package manager
- Required external tools (automatically checked)

### Quick Installation
```bash
# Clone repository
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .

# Verify installation
reconcli --help
```

### External Tools
ReconCLI integrates with various external tools. The toolkit will automatically check for tool availability and guide you through installation:

```bash
# Check tool availability
reconcli vulnsqlicli --check-tools
reconcli dirbcli --check-tools
reconcli vulncli --check-tools
```

## 🚀 Usage

### Basic Usage
```bash
# Show all available modules
reconcli --help

# Get help for specific module
reconcli vulnsqlicli --help
reconcli dirbcli --help
reconcli vhostcli --help
```

### Advanced Examples
```bash
# Multi-module reconnaissance workflow
reconcli dns --domain example.com --output-dir /tmp/recon
reconcli vhostcli --domain example.com --ip-list ips.txt --wordlist common.txt
reconcli vulnsqlicli --urls-file urls.txt --tool all --json-report

# Comprehensive web application security assessment
reconcli dirbcli --url https://example.com --tech-detect --smart-wordlist
reconcli vulnsqlicli --url https://example.com --sqlmap --level 3 --risk 2
reconcli vulncli --input targets.txt --engine nuclei --ai-classify
```

## 📊 Output Formats

ReconCLI supports multiple output formats for comprehensive reporting:

- **JSON**: Machine-readable format for automation
- **YAML**: Human-readable structured data
- **Markdown**: Professional reports with recommendations
- **CSV**: Data analysis and spreadsheet integration

## 🔔 Notifications

All modules support webhook notifications for real-time alerts:

```bash
# Slack notifications
--slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Discord notifications
--discord-webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

## 🛡️ Security Features

- **Resume Support**: Continue interrupted scans
- **Rate Limiting**: Respectful scanning practices
- **Proxy Support**: HTTP/HTTPS proxy integration
- **Tor Support**: Anonymous scanning capabilities
- **Custom Headers**: Advanced request customization
- **SSL/TLS Verification**: Secure communication options

## 🧪 Testing

Run the test suite to verify functionality:

```bash
# Run all tests
python -m pytest tests/

# Run specific module tests
python -m pytest tests/test_vulnsqlicli.py -v

# Check tool availability
python -m reconcli.vulnsqlicli --check-tools
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
```bash
# Clone repository
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings for all functions
- Include comprehensive error handling

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Roadmap

- [ ] AI-powered vulnerability analysis
- [ ] Machine learning-based pattern recognition
- [ ] Enhanced cloud provider support
- [ ] Advanced reporting dashboard
- [ ] Integration with popular security tools
- [ ] Mobile application security testing
- [ ] API security assessment improvements

## 🙏 Acknowledgments

- All the amazing open-source security tools that make this possible
- The security research community for continuous innovation
- Contributors and testers who help improve the toolkit

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/jarek-bir/Reconcli/issues)
- **Documentation**: [Visit our Wiki](https://github.com/jarek-bir/Reconcli/wiki)
- **Community**: [Join our Discord](https://discord.gg/reconcli)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any systems.

**🔒 Security**: Report security vulnerabilities responsibly through our security policy.