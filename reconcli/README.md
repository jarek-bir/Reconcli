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

# Test new advanced data analysis features
reconcli csvtkcli analyze example_data.csv
reconcli gitcli init --remote https://github.com/user/recon-project.git

# Quick security analysis workflow
echo "admin.example.com,192.168.1.10,subdocli" > test.csv
reconcli csvtkcli security-report test.csv --target-domain example.com
```

## 🚀 Latest Updates

### �️ **WhoisFreaksCLI Database Integration** (New!)
- **Database Storage**: Store WHOIS findings in ReconCLI database with target classification
- **Single Domain Support**: Analyze individual domains without creating input files
- **Enhanced CLI**: Improved command structure with `lookup` subcommand
- **Target Tracking**: Associate WHOIS data with specific bug bounty programs and targets
- **Risk Correlation**: Link WHOIS findings with other reconnaissance data

```bash
# Single domain with database storage
reconcli whoisfreakscli lookup --domain example.com --store-db \
  --target-domain example.com --program hackerone-program --verbose

# Bulk analysis with database integration
reconcli whoisfreakscli lookup --input domains.txt --store-db \
  --target-domain example.com --program bugcrowd-program --risk-analysis
```

### �📸 **VhostCLI Screenshot Functionality** (New!)
- **Automated Screenshots**: Capture screenshots of discovered virtual hosts
- **Dual Tool Support**: Gowitness and Aquatone integration 
- **Advanced Options**: Full-page screenshots, custom timeouts and thread control
- **Seamless Integration**: Works with all VhostCLI engines (ffuf, httpx, gobuster, vhostfinder)

```bash
# Screenshots with Gowitness (supports full-page)
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --screenshot --screenshot-tool gowitness --fullpage

# Screenshots with Aquatone (HTML reports)
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --screenshot --screenshot-tool aquatone --screenshot-timeout 30
```

**Requirements**: Install screenshot tools
```bash
# Install gowitness
go install github.com/sensepost/gowitness@latest

# Install aquatone  
go install github.com/michenriksen/aquatone@latest
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
- **Engines**: FFuf, HTTPx, Gobuster, and VhostFinder support
- **Flexible Input**: Single IP or IP list
- **Output Formats**: JSON and Markdown reports
- **Proxy Support**: HTTP/HTTPS proxy configuration
- **Notifications**: Slack/Discord webhook integration
- **Verbose Mode**: Detailed progress tracking
- **📸 Screenshot Capture**: Automated screenshots of discovered virtual hosts
- **Screenshot Tools**: Gowitness and Aquatone integration
- **Advanced Options**: Full-page screenshots, custom timeouts and threads

```bash
# Basic VHOST discovery
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt

# With screenshots using gowitness
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --screenshot --screenshot-tool gowitness --fullpage

# With aquatone for HTML reports
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --screenshot --screenshot-tool aquatone --screenshot-timeout 30

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
  --katana-headless --katana-tech-detect --katana-form-fill --verbose

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
- **Database Integration**: Store findings in ReconCLI database with target classification
- **Single Domain Support**: Analyze individual domains without input files
- **Professional Reports**: Comprehensive JSON and Markdown output
- **Resume & Notifications**: Progress tracking and alert integration

```bash
# Single domain analysis
reconcli whoisfreakscli lookup --domain example.com --verbose

# Single domain with database storage
reconcli whoisfreakscli lookup --domain example.com --store-db \
  --target-domain example.com --program hackerone-program --verbose

# Bulk analysis with risk assessment
reconcli whoisfreakscli lookup --input domains.txt --risk-analysis \
  --expire-check 30 --save-json --save-markdown --verbose

# Bulk analysis with database storage
reconcli whoisfreakscli lookup --input domains.txt --store-db \
  --target-domain example.com --program bugcrowd-program \
  --risk-analysis --expire-check 90 --verbose

# With notifications for high-risk domains
reconcli whoisfreakscli lookup --input domains.txt --risk-analysis \
  --slack-webhook "https://hooks.slack.com/..." --verbose

# Resume interrupted scans
reconcli whoisfreakscli lookup --input large_domains.txt --resume --verbose

# Show previous scan status
reconcli whoisfreakscli lookup --show-resume --output-dir output_whoisfreaks

# Clear previous resume state
reconcli whoisfreakscli lookup --clear-resume --output-dir output_whoisfreaks
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
- **🔧 7 Analysis Engines**: Native Python engine plus 6 external tools (JSLuice, JSLeak, SubJS, Cariddi, GetJS, Mantra)
- **🔑 Advanced Secret Detection**: API keys, tokens, AWS credentials, GitHub tokens, private keys, and custom patterns
- **🎯 Endpoint Discovery**: URL patterns, API endpoints, and hidden paths extraction
- **🧠 AI-Powered Analysis**: Intelligent analysis of discovered secrets and endpoints with risk assessment
- **💾 Database Integration**: Store findings in ReconCLI database with target classification
- **⚡ High Performance**: Multi-threaded concurrent processing with configurable concurrency
- **🔄 Resume Support**: Continue interrupted large-scale scans with state management
- **💾 Raw File Preservation**: Save original JavaScript files for manual analysis
- **🔁 Advanced Retry Logic**: Configurable retry attempts with exponential backoff
- **⏱️ Rate Limiting**: Customizable delays between requests to avoid rate limiting
- **🔀 Proxy Support**: HTTP/HTTPS proxy integration for stealth scanning
- **📊 Professional Reports**: JSON and Markdown output with comprehensive statistics
- **🎯 Smart Filtering**: Filter results by findings to focus on actionable data

#### 🔧 Supported Engines

**Native Engine (Recommended)**
- Pure Python implementation with advanced regex patterns
- High reliability and performance for production use
- Comprehensive secret detection with 10+ pattern types
- Advanced endpoint extraction with smart filtering
- Full concurrency support with thread-safe statistics

**External Engines**
- **JSLuice**: BishopFox's JavaScript analysis tool for URLs and secrets
- **JSLeak**: Advanced JavaScript secrets scanner
- **SubJS**: JavaScript file discovery and enumeration
- **Cariddi**: Comprehensive JavaScript crawler and analyzer  
- **GetJS**: JavaScript file discovery from domains and URLs
- **Mantra**: JavaScript analysis with detailed pattern matching

#### 🔑 Secret Detection Patterns

**Automatically detects:**
- **API Keys**: General API key patterns across platforms
- **AWS Credentials**: Access keys, secret keys, and session tokens
- **GitHub Tokens**: Personal access tokens and app tokens
- **Slack Tokens**: Bot, user, and workspace tokens
- **Private Keys**: RSA and other private key formats
- **Bearer Tokens**: Authorization header tokens
- **Database Credentials**: Connection strings and passwords
- **Custom Secrets**: Generic secret and auth patterns

#### 🎯 Advanced Features

**AI Integration**
- Intelligent analysis of discovered secrets and endpoints
- Risk level classification and prioritization
- Security assessment with actionable recommendations
- Attack vector identification based on findings

**Database Storage**
- Target-based organization with program classification
- Historical tracking of JavaScript findings
- Integration with other ReconCLI tools for comprehensive analysis
- Searchable findings database for large engagements

**Performance Optimization**
- Configurable concurrency (1-100 threads)
- Smart retry logic with exponential backoff
- Rate limiting to respect target infrastructure
- Memory-efficient processing for large datasets

#### 🎯 Advanced CLI Options

```bash
# Basic JavaScript analysis with native engine
reconcli jscli --input js_urls.txt --verbose

# High-performance scan with custom concurrency
reconcli jscli --input js_urls.txt --engine native \
  --concurrency 50 --timeout 30 --retry 5 --delay 0.5

# Multi-engine comparison scan
reconcli jscli --input js_urls.txt --engine jsluice --verbose
reconcli jscli --input js_urls.txt --engine native --verbose

# AI-powered analysis with database storage
reconcli jscli --input js_urls.txt --ai-mode \
  --ai-model gpt-4 --store-db --target-domain example.com \
  --program "Bug Bounty Program" --verbose

# Production-ready scan with all features
reconcli jscli --input large_js_list.txt --engine native \
  --concurrency 20 --timeout 30 --retry 3 --delay 1.0 \
  --save-raw --only-with-findings --json --markdown \
  --ai-mode --store-db --verbose

# Stealth scanning through proxy
reconcli jscli --input js_urls.txt --proxy http://127.0.0.1:8080 \
  --verify-ssl false --delay 2.0 --concurrency 5 --verbose

# Resume interrupted large scan
reconcli jscli --input massive_js_list.txt --resume \
  --engine native --concurrency 30 --verbose

# External engine testing and comparison
reconcli jscli --input test_urls.txt --engine getjs --verbose
reconcli jscli --input test_urls.txt --engine mantra --verbose

# Real-world bug bounty scanning
reconcli jscli --input shopify_js_links.txt --engine native \
  --concurrency 25 --timeout 20 --retry 3 \
  --ai-mode --store-db --target-domain shopify.com \
  --program "Shopify Bug Bounty" --json --markdown \
  --save-raw --only-with-findings --verbose
```

#### 📊 Engine Performance Comparison

**Production Testing Results (15,582 JS URLs from Shopify)**

| Engine | URLs Processed | Endpoints Found | Success Rate | Recommended Use |
|--------|---------------|-----------------|--------------|-----------------|
| Native | 200/200 | 9,406 | 100% | ✅ Production Ready |
| JSLuice | 200/200 | 0 | 50% | Development/Testing |
| GetJS | Available | 0 | 25% | File Discovery |
| Mantra | Available | 0 | 25% | Specialized Analysis |

**Recommendations:**
- **Production Use**: Native engine for reliability and comprehensive results
- **Development**: External engines for specialized workflows and comparison
- **Large Scale**: Native engine with high concurrency (20-50 threads)
- **Stealth**: Native engine with proxy and rate limiting

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

# Stealth reconnaissance with proxy
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

### � **Open Redirect Vulnerability Scanner (`openredirectcli`)**
- **🧠 AI-Powered Analysis**: Intelligent payload generation and vulnerability detection
- **🚀 External Tool Integration**: OpenRedirex, kxss, waybackurls, GAU, unfurl, httpx support
- **🎯 Advanced Detection Methods**: Header redirects, JavaScript redirects, meta refresh analysis
- **🔍 Smart URL Discovery**: Historical URL fetching with parameter-based filtering
- **📊 Comprehensive Reporting**: JSON, Markdown, CSV, Burp Suite compatible outputs
- **⚡ Resume Functionality**: Continue interrupted scans with state management
- **🔔 Real-time Notifications**: Slack and Discord webhook integration for critical findings
- **🛡️ Multiple Payload Types**: Default, advanced, and AI-generated payloads with encoding options

#### 🎯 Key Features
- **AI-Enhanced Testing**: Context-aware payload generation based on URL structure analysis
- **Multi-Method Detection**: Header analysis, JavaScript redirect detection, meta refresh parsing
- **External Tool Integration**: Seamless integration with popular security tools
- **Database Storage**: ReconCLI database integration with program classification
- **Severity Assessment**: AI-powered risk evaluation with confidence scoring
- **Professional Reports**: Detailed Markdown reports with remediation guidance

#### 🔄 Advanced CLI Options
```bash
# Basic open redirect testing
reconcli openredirectcli -i urls.txt --verbose

# AI-powered testing with advanced payloads
reconcli openredirectcli -i urls.txt --ai-mode --advanced-payloads \
  --ai-model "gpt-4" --ai-confidence 0.8 --verbose

# Complete security assessment with external tools
reconcli openredirectcli -i urls.txt --ai-mode --use-openredirex \
  --use-kxss --use-waybackurls --use-gau --filter-params \
  --check-javascript --check-meta-refresh --markdown --store-db

# Bug bounty workflow with notifications
reconcli openredirectcli -i scope_urls.txt --ai-mode --use-waybackurls \
  --use-httpx --store-db --program "hackerone-target" \
  --target-domain example.com --severity medium --markdown \
  --slack-webhook "https://hooks.slack.com/..." --verbose

# Custom payload testing with encoding
reconcli openredirectcli -i urls.txt --payloads custom_payloads.txt \
  --payload-encoding double --keyword "FUZZ" --advanced-payloads \
  --proxy http://127.0.0.1:8080 --save-responses --verbose

# URL discovery and testing pipeline
reconcli openredirectcli -i domains.txt --use-waybackurls --use-gau \
  --use-httpx --httpx-flags "-mc 200,301,302,303,307,308" \
  --use-gf --gf-pattern "redirect" --filter-params --ai-mode \
  --resume --threads 100 --verbose
```

#### 🧠 AI-Powered Capabilities
- **Smart Payload Generation**: Context-aware payloads based on URL structure and parameters
- **Intelligent Response Analysis**: AI detection of hidden redirect mechanisms and patterns
- **Dynamic Severity Assessment**: Context-based risk evaluation considering business impact
- **Actionable Insights**: Comprehensive vulnerability analysis with remediation priorities

#### 📊 Output Formats & Integration
- **JSON Reports**: Structured data with AI insights and severity breakdowns
- **Markdown Reports**: Professional documentation with AI-generated recommendations
- **Burp Suite Export**: Compatible format for manual verification
- **Nuclei Integration**: Export findings for automated verification workflows
- **Database Storage**: Persistent storage with program and target classification

## 📋 Complete Module List

### 🔧 **Core Infrastructure & Development Tools**
- **📊 csvtkcli** - Advanced CSV data analysis and security reporting
- **🔧 gitcli** - Git operations and repository management for reconnaissance data
- **🗄️ dbcli** - Database management for reconnaissance data storage

### 🔍 **Discovery & Enumeration**
- **🌐 subdocli** - Enhanced subdomain enumeration using multiple sources
- **🔗 urlcli** - URL discovery and analysis with advanced filtering
- **🕷️ crawlercli** - Advanced web crawler suite with multi-engine support
- **🎯 vhostcli** - Virtual host discovery with screenshot capabilities
- **✅ vhostcheckcli** - Advanced virtual host discovery and validation
- **📡 dnscli** - DNS resolution and analysis
- **🌍 ipscli** - IP reconnaissance and geolocation analysis
- **⚡ portcli** - Port scanning and service enumeration with tagging
- **🔍 zonewalkcli** - DNS zone walking and enumeration

### 🛡️ **Security Testing & Analysis**
- **🧠 aicli** - AI-powered reconnaissance assistant with multi-persona system
- **🔐 vulncli** - Vulnerability scanning with Jaeles and Nuclei
- **💉 vulnsqlicli** - SQL injection vulnerability scanner
- **🔍 cnamecli** - CNAME record analysis and takeover detection
- **🛡️ wafdetectcli** - WAF detection, testing and bypass analysis
- **↗️ openredirectcli** - Advanced open redirect vulnerability scanner with AI
- **🔄 takeovercli** - Subdomain takeover vulnerability detection

### 🔍 **Intelligence & Analysis**
- **🌐 whoisfreakscli** - WHOIS intelligence and domain analysis
- **☁️ cloudcli** - Cloud provider detection and S3 enumeration
- **🔄 permutcli** - Advanced permutation generation for domains and paths
- **🔍 jscli** - JavaScript file discovery and analysis with multi-engine support

### 📊 **Utilities & Management**
- **🏷️ taggercli** - Advanced subdomain tagging and classification
- **📝 mdreportcli** - Enhanced markdown reports with templates and security analysis
- **🔗 urlsortcli** - URL sorting and organization with advanced patterns
- **📝 makewordlistcli** - Advanced wordlist generator with intelligence and mutations
- **🌐 httpcli** - HTTP client for web application testing

### 📋 Recent Updates

### v2.2.0 - Advanced Data Analysis & Version Control (Latest!)
- ✅ **📊 CSVTKCLI**: Advanced CSV data analysis with security-focused reporting
  - Automatic risk categorization (HIGH/MEDIUM/LOW security levels)
  - Professional security reports with executive summaries
  - Advanced search and filtering with regex support
  - Multi-dataset combination and statistical analysis
  - Integration with database exports and reconnaissance workflows

- ✅ **🔧 GitCLI**: Professional git operations for reconnaissance data management
  - Security-focused repository initialization with comprehensive .gitignore
  - Automated backup system with tagging and timestamps
  - Team collaboration tools designed for security professionals
  - Resume-safe operations excluding sensitive data and temporary files
  - Professional repository templates and workflow automation

- ✅ **Enhanced Integration**: Seamless workflow integration
  - Database → Export → CSVTK Analysis → Git Commit workflows
  - Alternative entry points for problematic dependency isolation
  - Comprehensive documentation with security best practices
  - Production-ready tools for professional reconnaissance teams

```bash
# Complete workflow example
reconcli dbcli export --table subdomains --analysis
reconcli csvtkcli security-report output/exports/subdomains_export.csv
reconcli gitcli add reports/ --exclude-output
reconcli gitcli commit "Add security analysis findings" --push
reconcli gitcli backup --tag milestone-$(date +%Y%m%d)
```

### v2.1.0 - WhoisFreaksCLI Database Integration
- ✅ **Database Storage**: Full integration with ReconCLI database system
- ✅ **Single Domain Support**: Analyze individual domains without file creation
- ✅ **Enhanced CLI Structure**: Improved command organization with subcommands
- ✅ **Target Classification**: Associate WHOIS findings with bug bounty programs
- ✅ **Risk Correlation**: Link WHOIS intelligence with other reconnaissance data
- ✅ **Professional Workflows**: Enhanced examples for security professionals

### Database Schema Updates
- New `whois_findings` table for storing WHOIS intelligence
- Enhanced target tracking with program classification
- Risk analysis data integration
- Timestamp tracking for temporal analysis

### Usage Examples
```bash
# Store WHOIS findings in database
reconcli whoisfreakscli lookup --domain example.com --store-db \
  --target-domain example.com --program hackerone-program

# Bulk analysis with database integration
reconcli whoisfreakscli lookup --input domains.txt --store-db \
  --target-domain example.com --program bug-bounty-2024 --risk-analysis
```

---

*ReconCLI - Empowering security professionals with modular reconnaissance capabilities*

# Test GPG commit
