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

## 👥 Authors

**Jarek + AI + Copilot = cyber-squad z przyszłości** 🚀🤖

*A collaborative project combining human expertise, artificial intelligence, and GitHub Copilot to create cutting-edge cybersecurity tools.*

## 👥 Authors

**🚀 Cyber-Squad z Przyszłości**
- **Jarek** 🧑‍💻 - Lead Developer & Security Researcher
- **AI Assistant** 🤖 - Code Architecture & Advanced Features  
- **GitHub Copilot** ⚡ - Code Generation & Optimization

*Collaboration between human expertise and AI innovation to create cutting-edge security tools.*

## 🚀 Quick Start

```bash
# Install from GitHub
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli
pip install -e .

# Verify installation
reconcli --help

# Configure AI providers for advanced features (optional)
export OPENAI_API_KEY='your-openai-api-key'
export ANTHROPIC_API_KEY='your-anthropic-api-key'  
export GOOGLE_API_KEY='your-google-api-key'

# Test AI-powered features
reconcli aicli --prompt "Hello, AI assistant!" --persona trainer
```

## ✨ Features

### 🧠 **AI-Powered Reconnaissance Assistant (`aicli`)**
- **🎭 Multi-Persona AI System**: RedTeam, BugBounty, Pentester, Trainer, OSINT personas
- **🔬 Advanced Payload Mutation Engine**: XSS, SQLi, SSRF mutations with WAF bypasses  
- **🎯 AI-Powered Vulnerability Scanner**: Comprehensive security assessment with ReconCLI integration
- **⚔️ Multi-Stage Attack Flows**: SSRF→XSS→LFI chains with MITRE ATT&CK mapping
- **📊 Professional Reports**: Executive summaries, compliance mapping, remediation guidance
- **💬 Interactive Chat Mode**: Persistent sessions, advanced prompt templates
- **🔗 ReconCLI Integration**: Enhanced context from DNScli, HTTPcli, URLcli outputs

```bash
# AI-powered vulnerability scanning with ReconCLI integration
reconcli aicli --vuln-scan urlcli_output.json --scan-type comprehensive --persona pentester --integration

# Advanced payload mutations for WAF bypass
reconcli aicli --payload xss --context html --mutate --mutations 20 --persona bugbounty

# Multi-stage attack flow generation
reconcli aicli --attack-flow ssrf,xss,lfi --technique gopher --persona redteam

# Interactive AI assistance for reconnaissance
reconcli aicli --interactive --persona trainer --save-chat learning_session
```

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
reconcli vhostcheckcli --ip 192.168.1.100 --domain example.com --vhost admin

# Multiple IPs from file with progress tracking
reconcli vhostcheckcli --input ips.txt --domain example.com --vhost admin --verbose

# HTTPS with proxy and verbose output
reconcli vhostcheckcli --ip 192.168.1.100:8443 --domain example.com --vhost api \
  --https --proxy http://127.0.0.1:8080 --verbose

# Batch processing with results saving
reconcli vhostcheckcli --input target_ips.txt --domain example.com --vhost store \
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
reconcli urlsortcli --input urls.txt --verbose

# Process URLs from stdin with advanced patterns
cat urls.txt | reconcli urlsortcli --stdin --advanced-patterns \
  --remove-duplicates --markdown --verbose

# Resume interrupted processing
reconcli urlsortcli --input large_urls.txt --resume --verbose
```

### 🕷️ **Advanced Web Crawler Suite (`crawlercli`)**

- **Multi-Engine Support**: Waymore, GoSpider, XnLinkFinder, Crawley, Crawlergo integration
- **Intelligent Profiles**: Quick, Comprehensive, Stealth, Aggressive crawling modes
- **Parallel Execution**: Concurrent tool execution with thread management
- **Smart Filtering**: Extension-based filtering and subdomain inclusion controls
- **Data Extraction**: API endpoints, emails, phone numbers, social media, sensitive files
- **Professional Sessions**: Session management with resume capability and progress tracking
- **Advanced Features**: JavaScript execution, form extraction, Wayback Machine integration
- **Output Formats**: TXT, JSON, CSV, XML with comprehensive summary reports
- **Enterprise Features**: Proxy support, custom headers, cookies, notifications

```bash
# Quick domain crawl
reconcli crawlercli --domain example.com --profile quick

# Comprehensive crawl with API focus
reconcli crawlercli --domain target.com --profile comprehensive \
  --api-endpoints --forms --parallel --max-pages 1000

# Stealth crawl with proxy
reconcli crawlercli --domain target.com --profile stealth \
  --proxy http://127.0.0.1:8080 --delay 2.0

# Multi-domain crawl from file
reconcli crawlercli --input domains.txt --profile aggressive \
  --parallel --threads 20 --screenshot

# Advanced extraction with notifications
reconcli crawlercli --domain example.com --emails --phone-numbers \
  --sensitive-files --social-media --notifications "https://hooks.slack.com/..." \
  --output-format json --verbose

# Dry-run mode for testing
reconcli crawlercli --domain example.com --dry-run --verbose
```

### 🔍 WHOIS Intelligence (`whoisfreaks`)
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
reconcli takeovercli --input subdomains.txt

# With resume and notifications
reconcli takeovercli --input subdomains.txt --resume \
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

### � **Advanced Reconnaissance Pipeline (`oneshot`)**

- **Comprehensive Pipeline**: Automated end-to-end reconnaissance workflows
- **Multiple Profiles**: Quick, Standard, Deep, Stealth, and Custom reconnaissance modes
- **AI Integration**: OpenAI, Anthropic, and Google AI for intelligent analysis and recommendations
- **Parallel Execution**: Concurrent tool execution with advanced resource management
- **Session Management**: Resume functionality with persistent state and progress tracking
- **Professional Reporting**: Executive summaries, technical reports, and AI-generated insights
- **Enterprise Features**: Notifications, resource monitoring, error handling, and detailed statistics
- **Flexible Output**: JSON, Markdown, and AI-enhanced reporting formats

```bash
# Quick reconnaissance scan
reconcli oneshotcli --domain example.com --profile quick

# Deep reconnaissance with AI analysis
reconcli oneshotcli --domain target.com --profile deep \
  --ai-provider openai --ai-analysis --parallel

# Stealth reconnaissance with custom settings
reconcli oneshotcli --domain target.com --profile stealth \
  --proxy http://127.0.0.1:8080 --delay 2.0 --threads 5

# Enterprise reconnaissance with notifications
reconcli oneshotcli --domain example.com --profile standard \
  --notifications "https://hooks.slack.com/..." \
  --resource-monitoring --ai-provider anthropic

# Resume interrupted reconnaissance
reconcli oneshotcli --domain target.com --resume --verbose

# Dry-run mode for pipeline testing
reconcli oneshotcli --domain example.com --dry-run --verbose
```

### �🛡️ Advanced Vulnerability Scanning (`vulncli`)
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

### �️ **WAF Detection & Bypass Testing (`wafdetectcli`)**
- **🔍 Multi-Tool Detection**: wafw00f, WhatWaf, GoTestWAF, and Nmap integration
- **🧪 Advanced Payload Testing**: 25+ WAF signatures with 5 payload categories (XSS, SQLi, LFI, RCE, Generic)
- **📊 Interactive HTML Reports**: Modern CSS Grid layouts with JavaScript filtering and collapsible sections
- **🎯 Comprehensive Analysis**: Header analysis, security fingerprinting, and risk assessment
- **⚡ Multi-Target Support**: Bulk scanning with resume functionality and progress tracking
- **🎨 Professional UI**: Executive summary dashboard with color-coded risk levels and tool result cards
- **🔧 Enterprise Features**: Proxy support, custom timeouts, notification integration, and detailed statistics

#### 🛡️ WAF Detection Methods
- **Signature-based**: 25+ enterprise WAF signatures (Cloudflare, Akamai, AWS WAF, F5, Imperva, etc.)
- **Payload-based**: Custom bypass testing with advanced evasion techniques
- **Header analysis**: Deep HTTP header inspection for security indicators
- **Network-level**: Nmap scripts for firewall detection
- **Tool integration**: GoTestWAF for comprehensive bypass score analysis

#### 🎯 Advanced CLI Options
```bash
# Basic WAF detection with all tools
reconcli wafdetectcli -t example.com --all-tools --output-html

# Advanced bypass testing with payload mutations
reconcli wafdetectcli -t target.com --test-bypass --max-payloads 5 \
  --header-analysis --output-html --verbose

# Multi-target scanning with custom settings
reconcli wafdetectcli -i targets.txt --use-gotestwaf --use-nmap \
  --timeout 30 --output-json --output-markdown

# Enterprise analysis with notifications
reconcli wafdetectcli -t example.com --all-tools --test-bypass \
  --header-analysis --output-html --proxy http://127.0.0.1:8080 \
  --verbose --timeout 20

# Resume interrupted WAF analysis
reconcli wafdetectcli -i large_targets.txt --resume --all-tools \
  --test-bypass --max-payloads 3 --output-html --verbose
```

#### 📊 Interactive HTML Reports
- **Executive Dashboard**: Summary statistics with detection rates and risk metrics
- **Tool Result Cards**: Visual representation of each detection method's findings
- **Payload Testing Tables**: Detailed bypass attempt results with success indicators
- **Filtering & Search**: Real-time filtering by target, WAF type, or tool results
- **Risk Assessment**: Color-coded risk levels based on bypass success rates
- **Responsive Design**: Mobile-friendly interface with collapsible sections

### 📝 **Enhanced Markdown Reports (`mdreport`)**
- **🎨 Emoji Control**: `--emoji-off` flag for professional, emoji-free reports
- **🏢 Enterprise Templates**: Clean formatting suitable for corporate environments
- **📋 Multiple Formats**: Support for executive summaries and technical documentation
- **🔧 Template Customization**: Flexible report generation with configurable sections
- **📊 Data Integration**: Seamless integration with all ReconCLI modules

```bash
# Generate professional reports without emojis
reconcli mdreport --input scan_results.json --emoji-off --template executive

# Corporate-friendly vulnerability reports
reconcli mdreport --input vuln_scan.json --emoji-off --format corporate \
  --sections "summary,findings,recommendations"

# Clean technical documentation
reconcli mdreport --input recon_data.json --emoji-off --style technical \
  --exclude-metadata --professional-formatting
```

### �🔥 **Advanced WAF Bypass Examples**

```bash
# Modern SPA XSS with advanced obfuscation
reconcli aicli --payload xss --context "react,vue,angular" --mutate --mutations 30 \
  --technique "unicode,dom-events,template-injection" --persona redteam

# SQL injection with WAF evasion for cloud databases
reconcli aicli --payload sqli --context "aws-rds,azure-sql,gcp-sql" --mutate --mutations 25 \
  --technique "encoding,comment-variants,union-bypass" --persona bugbounty

# SSRF for cloud metadata extraction
reconcli aicli --payload ssrf --context "aws,gcp,azure,kubernetes" --mutate --mutations 20 \
  --technique "gopher,metadata,ipv6,dns-rebinding" --persona pentester
```

#### 🎯 **Real-World Attack Chains**

```bash
# E-commerce platform exploitation chain
reconcli aicli --attack-flow "ssrf,xss,sqli" --target-type "ecommerce" \
  --technique "payment-bypass" --persona redteam

# SaaS application privilege escalation
reconcli aicli --attack-flow "idor,xss,csrf" --target-type "saas" \
  --technique "tenant-isolation-bypass" --persona pentester

# API gateway exploitation
reconcli aicli --attack-flow "ssrf,jwt-abuse,graphql-injection" --target-type "api-gateway" \
  --technique "microservices-lateral-movement" --persona bugbounty
```

#### 🧠 **AI-Powered Research Assistance**

```bash
# Zero-day research for emerging technologies
reconcli aicli --research-query "Web3 smart contract vulnerabilities" --depth "comprehensive" \
  --persona researcher --save-chat "web3-research-2025"

# Threat modeling for fintech applications
reconcli aicli --threat-model "payment-processor" --compliance "pci-dss" \
  --attack-vectors "api,mobile,web" --persona architect

# Advanced persistent threat simulation
reconcli aicli --apt-simulation --target-industry "healthcare" \
  --attack-duration "long-term" --persona redteam
```

#### 🏭 **Industry-Specific Security Testing**

```bash
# Healthcare HIPAA compliance testing
reconcli aicli --industry-scan "healthcare" --compliance "hipaa" \
  --focus "patient-data,medical-devices" --persona healthcare-security

# Financial services PCI DSS assessment
reconcli aicli --industry-scan "fintech" --compliance "pci-dss" \
  --focus "payment-processing,card-data" --persona financial-security

# Government security assessment
reconcli aicli --industry-scan "government" --compliance "fisma" \
  --classification "confidential" --persona government-security

# Critical infrastructure testing
reconcli aicli --industry-scan "critical-infrastructure" --focus "scada,ics" \
  --threat-model "nation-state" --persona ot-security
```

#### 🌐 **Cloud-Native Security Testing**

```bash
# Kubernetes security assessment
reconcli aicli --cloud-native-scan "kubernetes" --components "api-server,etcd,kubelet" \
  --compliance "cis-benchmark" --persona cloud-security

# Serverless security testing
reconcli aicli --serverless-scan "aws-lambda,azure-functions" \
  --focus "function-isolation,secrets-management" --persona cloud-security

# Container security assessment
reconcli aicli --container-scan "docker,podman" --focus "escape,privilege-escalation" \
  --persona container-security

# Multi-cloud security posture
reconcli aicli --multi-cloud-scan "aws,azure,gcp" --compliance "cis,nist" \
  --assessment-type "comprehensive" --persona cloud-architect
```

#### 🔬 **Advanced Research and Development**

```bash
# AI/ML security research
reconcli aicli --ai-security-research --model-types "llm,computer-vision" \
  --attacks "adversarial,poisoning,extraction" --persona ai-researcher

# Web3 security research
reconcli aicli --web3-research --protocols "ethereum,polygon,solana" \
  --focus "smart-contracts,defi,nft" --persona web3-security

# IoT security assessment
reconcli aicli --iot-security --protocols "mqtt,coap,zigbee" \
  --focus "firmware,communication,device-management" --persona iot-security
```

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

#### For Web Crawling (`crawlercli`)
- **Waymore**: `pip install waymore`
- **GoSpider**: `go install github.com/jaeles-project/gospider@latest`
- **XnLinkFinder**: `git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git && cd xnLinkFinder && pip install -r requirements.txt`
- **Crawley**: `go install github.com/s0rg/crawley/cmd/crawley@latest`
- **Crawlergo**: Download from [GitHub releases](https://github.com/Qianlitp/crawlergo/releases)
- **Chrome/Chromium**: Required for Crawlergo JavaScript execution

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

#### For WAF Detection & Bypass Testing (`wafdetectcli`)
- **wafw00f**: `pip install wafw00f`
- **WhatWaf**: `pip install whatwaf`
- **GoTestWAF**: Download from [GitHub releases](https://github.com/wallarm/gotestwaf/releases)
- **Nmap**: Install from [nmap.org](https://nmap.org/download.html) (for WAF detection scripts)
- **httpx**: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

### API Keys

#### WhoisFreaks API (for `whoisfreaks`)
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
├── permutcli.py           # Advanced permutation generation (NEW)
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
├── wafdetectcli.py        # WAF detection & bypass testing (NEW)
├── mdreport.py            # Enhanced markdown reporting with emoji control (ENHANCED)
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
reconcli takeovercli --input large_subdomain_list.txt --resume

# If interrupted, resume with same command
reconcli takeovercli --input large_subdomain_list.txt --resume

# Check resume status
reconcli takeovercli --show-resume

# Clear resume state
reconcli takeovercli --clear-resume
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
reconcli takeovercli --input subdomains.txt --json

# Markdown output
reconcli takeovercli --input subdomains.txt --markdown

# Both formats
reconcli takeovercli --input subdomains.txt --json --markdown
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

# Using flow configuration
reconcli urlcli --domain target.com --flow flows/url_katana_advanced.yaml
```

### Smart URL Processing
```bash
# Process and categorize large URL lists
reconcli urlsortcli \
  --input massive_urls.txt \
  --advanced-patterns \
  --remove-duplicates \
  --remove-query-params \
  --markdown \
  --resume \
  --verbose

# Real-time URL processing from stdin
cat urls.txt | reconcli urlsortcli --stdin --advanced-patterns --verbose
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
reconcli tldrcli -d example --categories popular,country --verbose

# Advanced comprehensive TLD scan across all 2,672+ TLDs
reconcli tldrcli -d mycompany --categories all --http-check \
  --filter-active --save-json --verbose

# Cryptocurrency and blockchain focused reconnaissance
reconcli tldrcli -d cryptobrand --categories crypto_blockchain,emerging_tech \
  --http-check --filter-active --save-markdown

# Security research with typosquatting and specialized TLDs
reconcli tldrcli -d target --categories specialized,geographic \
  --exclude-wildcards --whois-check --verbose

# Custom TLD list with industry-specific focus
reconcli tldrcli -d brand --categories business,industry_specific \
  --http-check --filter-active --slack-webhook "https://hooks.slack.com/..."

# Maximum coverage scan for comprehensive domain discovery
reconcli tldrcli -d enterprise --categories all --threads 100 \
  --http-check --whois-check --exclude-wildcards \
  --save-json --save-markdown --verbose
```

### 🔄 Advanced Permutation Generation (`permutcli`)
- **16 Specialized Tools**: Internal engine, gotator, goaltdns, dnstwist, dnsgen, urlcrazy, shuffledns, dmut, s3scanner, alterx, kr (kitrunner), sublist3r, amass, subfinder, assetfinder, findomain
- **Multi-Type Permutations**: Subdomains, paths, buckets, parameters, and API endpoints
- **Advanced S3 Bucket Generator**: 300+ permutation patterns with AWS URL formats, custom suffixes, and deduplication
- **TLD Injection Mode**: Focus on TLD variations with custom lists and exclusions
- **Smart Case Mutations**: Automatic case-based variations (Dev, DEV, dev) for keywords and targets
- **Advanced CLI Options**: Prefix/suffix-only modes, keyword exclusions, result filtering, chunked output
- **DNS Resolver Updates**: Automatic download of latest resolver lists from Trickest and public sources
- **Professional Output**: JSON/TXT formats with chunking, filtering, and comprehensive metadata

#### 🎯 Multi-Engine Permutation Support

**DNS Tools:**
- **dnstwist**: Domain variation and typosquatting detection
- **dnsgen**: Advanced subdomain generation with custom wordlists
- **shuffledns**: High-performance DNS bruteforcing with resolver rotation
- **dmut**: Comprehensive mutation-based subdomain discovery
- **alterx**: Fast and flexible subdomain permutation
- **sublist3r, amass, subfinder, assetfinder, findomain**: Passive enumeration integration

**URL & Path Tools:**
- **urlcrazy**: URL typosquatting and permutation analysis
- **gotator**: Advanced subdomain permutation with depth control
- **goaltdns**: ALT-DNS style permutation generation

**Cloud & API Tools:**
- **s3scanner**: S3 bucket discovery with advanced naming patterns
- **kr (kitrunner)**: API endpoint discovery and testing

**Internal Engine:**
- **Advanced Built-in Generator**: Custom patterns, TLD support, case mutations

#### 🪣 Advanced S3 Bucket Permutation Engine

**Comprehensive Pattern Generation:**
- **300+ Unique Patterns**: Brand combinations, suffix variations, year integration
- **AWS URL Formats**: Complete S3 URL patterns (`.s3.amazonaws.com`, regional endpoints)
- **Multi-Style Separators**: Dashes, dots, underscores for maximum coverage
- **Business Patterns**: Company structures, departments, environments
- **Cloud Provider Variations**: AWS, GCP, Azure specific naming conventions
- **Perfect Deduplication**: Ordered set approach preserving generation quality

```bash
# Basic S3 bucket permutation
reconcli permutcli --input brands.txt --output s3_buckets.txt --tool s3scanner \
  --permutation-type buckets --verbose

# Advanced S3 bucket generation with custom keywords
reconcli permutcli --input companies.txt --output advanced_buckets.txt \
  --tool s3scanner --keywords "dev,staging,prod,backup,logs,cdn" --verbose

# S3 bucket discovery with chunked output
reconcli permutcli --input targets.txt --output s3_discovery.txt \
  --tool s3scanner --chunk 1000 --max-results 5000 --uniq --verbose
```

#### 🌐 TLD Injection Mode

**Advanced TLD Management:**
- **2,672+ TLD Support**: Complete TLD coverage with custom list support
- **www Prefix Integration**: Automatic www prefix generation
- **Custom Suffix/Prefix Injection**: Advanced pattern injection before TLDs
- **TLD Exclusions**: Filter out unwanted TLDs (gov, edu, mil)
- **Dry-run Mode**: Preview generation counts without execution

```bash
# Basic TLD injection mode
reconcli permutcli --input brands.txt --output tld_variants.txt \
  --mode tldinject --verbose

# Advanced TLD injection with custom lists and filtering
reconcli permutcli --input companies.txt --output tld_advanced.txt \
  --mode tldinject --tld-list custom_tlds.txt \
  --inject-suffix "-cdn,-backup" --exclude-tlds "gov,edu,mil" \
  --www-prefix --dry-run --verbose

# TLD injection with chunked output
reconcli permutcli --input targets.txt --output tld_chunked.txt \
  --mode tldinject --chunk 500 --max-results 2000 --verbose
```

#### 🔤 Advanced Mutation & Filtering Options

**Case Mutations:**
- **Automatic Case Variations**: Generate Dev, DEV, dev, Development variants
- **Smart Detection**: Only apply to alphabetic keywords and targets
- **Deduplication**: Automatic removal of case-based duplicates

**Advanced Filtering:**
- **Keyword Exclusions**: Remove unwanted keywords from generation
- **Pattern Filtering**: Keep only matching patterns with regex support
- **Result Exclusions**: Remove specific patterns from final output
- **Prefix/Suffix Only**: Generate only prefix or suffix-based permutations

**Output Management:**
- **Chunked Output**: Split large results into manageable files
- **Format Options**: JSON and TXT output with comprehensive metadata
- **Result Limits**: Control maximum output size for performance
- **Duplicate Removal**: Advanced deduplication across all tools

```bash
# Case mutation with filtering
reconcli permutcli --input targets.txt --output mutations.txt \
  --tool internal --mutate-case --exclude-keywords "test,old,backup" \
  --filter "api,admin,dev" --verbose

# Prefix-only subdomain generation
reconcli permutcli --input domains.txt --output prefix_subs.txt \
  --tool internal --permutation-type subdomains --prefix-only \
  --keywords "api,admin,dev,staging" --verbose

# Advanced filtering with chunked output
reconcli permutcli --input companies.txt --output filtered_results.txt \
  --tool gotator --exclude "temp,old,test" --max-results 10000 \
  --chunk 1000 --uniq --verbose
```

#### 🛠️ Tool-Specific Advanced Options

**Internal Engine:**
- **Custom Patterns**: Load pattern templates from files
- **TLD Integration**: Include common TLD variations
- **Advanced Mode**: Complex pattern generation with numbers and separators
- **Prefix/Suffix Control**: Granular control over permutation direction

**External Tools:**
- **Threading Control**: Configurable concurrency for supported tools
- **Timeout Management**: Per-tool timeout configuration
- **Depth Control**: Permutation depth for tools like gotator
- **Resolution Options**: DNS resolution for enumeration tools

**S3Scanner Integration:**
- **Cloud Provider Selection**: AWS, GCP, Azure, or all providers
- **Custom Suffixes**: Business-specific suffix patterns
- **Year Integration**: Current year and custom year support
- **Advanced Patterns**: 10+ categories of bucket naming conventions

```bash
# Internal engine with advanced patterns
reconcli permutcli --input targets.txt --output internal_advanced.txt \
  --tool internal --advanced --mutate-case --include-tlds \
  --keywords "api,admin,dev,staging,prod,test,demo" \
  --exclude-keywords "old,legacy" --max-results 50000 \
  --chunk 5000 --format json --verbose

# Gotator with depth control
reconcli permutcli --input subdomains.txt --output gotator_deep.txt \
  --tool gotator --depth 3 --threads 20 --timeout 120 --verbose

# DMut with custom threading
reconcli permutcli --input domains.txt --output dmut_results.txt \
  --tool dmut --threads 50 --keywords "dev,api,admin" --verbose

# Multi-tool S3 discovery workflow
reconcli permutcli --input brands.txt --output s3_comprehensive.txt \
  --tool s3scanner --cloud-provider all --advanced \
  --keywords "backup,logs,assets,cdn,data" --max-results 20000 \
  --chunk 2000 --format json --verbose
```

#### 🔌 DNS Resolver Management

**Automatic Resolver Updates:**
- **Trickest Integration**: Download latest public resolver lists
- **Custom Resolver Support**: Use organization-specific DNS servers
- **Multi-Source Updates**: Aggregate from multiple resolver sources
- **Performance Optimization**: Ensure optimal DNS resolution for tools

```bash
# Update DNS resolvers for shuffledns and other tools
reconcli permutcli --update-resolvers --verbose

# Use updated resolvers in permutation generation
reconcli permutcli --input targets.txt --output shuffled_results.txt \
  --tool shuffledns --threads 100 --resolve --verbose
```

#### 🎯 Professional Workflow Examples

```bash
# Comprehensive subdomain discovery workflow
reconcli permutcli --input target_domains.txt --output comprehensive_subs.txt \
  --tool internal --advanced --mutate-case --include-tlds \
  --keywords "api,admin,dev,staging,prod,test,demo" \
  --exclude-keywords "old,legacy" --max-results 50000 \
  --chunk 5000 --format json --verbose

# S3 bucket hunting for bug bounty
reconcli permutcli --input company_names.txt --output s3_hunt.txt \
  --tool s3scanner --permutation-type buckets \
  --keywords "backup,logs,assets,data,cdn,static" \
  --inject-suffix "-backup,-logs,-data" --cloud-provider aws \
  --max-results 10000 --uniq --verbose

# API endpoint discovery workflow
reconcli permutcli --input api_targets.txt --output api_endpoints.txt \
  --tool kr --permutation-type api --api-endpoints \
  --keywords "v1,v2,api,rest,graphql" --timeout 180 --verbose

# TLD variation discovery for typosquatting research
reconcli permutcli --input brand_list.txt --output tld_research.txt \
  --mode tldinject --inject-suffix "-shop,-store,-online" \
  --exclude-tlds "gov,edu,mil" --chunk 1000 --dry-run --verbose

# Path permutation for web application testing
reconcli permutcli --input base_paths.txt --output path_permutations.txt \
  --tool internal --permutation-type paths \
  --keywords "admin,api,backup,config,test" \
  --advanced --max-results 25000 --verbose

# Multi-engine DNS discovery campaign
reconcli permutcli --input root_domains.txt --output dns_campaign.txt \
  --tool shuffledns --keywords "api,admin,dev,staging,prod" \
  --threads 200 --resolve --max-results 100000 \
  --chunk 10000 --format json --verbose
```

#### 🔄 **Automated Security Workflows**

```bash
# Continuous bug bounty automation
reconcli aicli --continuous-hunting --platforms "hackerone,bugcrowd" \
  --target-categories "fintech,saas,ecommerce" --persona bugbounty

# Red team campaign automation
reconcli aicli --red-team-automation --duration "2-weeks" \
  --techniques "phishing,lateral-movement,persistence" --persona redteam

# Compliance testing automation
reconcli aicli --compliance-automation --frameworks "owasp,pci-dss,gdpr" \
  --reporting "executive,technical" --persona auditor
```

#### 🎓 **Educational and Training Examples**

```bash
# Interactive security training
reconcli aicli --training-mode "hands-on" --topic "web-application-security" \
  --difficulty "intermediate" --persona trainer

# Capture-the-flag assistance
reconcli aicli --ctf-assistance --category "web,crypto,pwn" \
  --hint-level "minimal" --persona trainer

# Security certification preparation
reconcli aicli --cert-prep "oscp,cissp,ceh" --study-plan --practice-labs --persona trainer
```# Test GPG commit
