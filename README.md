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

**🚀 Cyber-Squad from Future**
- **Jarek** 🧑‍💻 - Lead Developer & Security Researcher
- **AI Assistant** 🤖 - Code Architecture & Advanced Features
- **GitHub Copilot** ⚡ - Code Generation & Optimization

*Collaboration between human expertise and AI innovation to create cutting-edge security tools.*

## 🚀 Latest Updates

### ⚡ **Performance Cache System - Massive Speed Improvements** (EXPANDED!)
- **🎯 Smart Caching**: Intelligent cache system now covers ALL major modules including security tools
- **💨 99% Performance Boost**: Cache hits return results instantly, eliminating repeated scans
- **🔗 SHA256 Cache Keys**: Secure, collision-resistant cache key generation based on targets and options
- **⏰ Automatic Expiry**: Configurable cache expiration (24 hours default) with cleanup management
- **📊 Cache Statistics**: Detailed statistics showing cache hit/miss ratios and storage information
- **🗂️ Module-Specific**: Separate cache systems optimized for each reconnaissance type
- **🔧 Full CLI Control**: Enable/disable caching, clear cache, adjust expiration, view statistics

**🔥 Performance Results:**
- **DNS Resolution**: 45.2s → 0.01s (4,520x faster)
- **HTTP Analysis**: 2.03s → 0.02s (101x faster)  
- **Port Scanning**: 15.8s → 0.05s (316x faster)
- **Subdomain Enum**: 108s → 0.1s (1,080x faster)
- **🆕 Secret Discovery**: 10-120s → Near-instant (10-120x faster)
- **🆕 Directory Brute Force**: 30-300s → Near-instant (20-150x faster)
- **🆕 GraphQL Security**: 20-180s → Near-instant (30-200x faster)
- **🆕 SQL Injection Testing**: 25-400s → Near-instant (15-300x faster)
- **🆕 XSS Testing (XSpear)**: 60-300s → Near-instant (25-100x faster)

```bash
# Enable caching for any module (DNS, HTTP, Port, Subdomain, Security Tools)
reconcli dnscli --input domains.txt --cache --verbose
reconcli httpcli --input urls.txt --cache --security-scan --verbose
reconcli portcli --input targets.txt --cache --scanner nmap --verbose
reconcli subdocli --domain example.com --cache --tools "amass,subfinder" --verbose

# NEW: Security tools with cache support
reconcli secretscli --target https://github.com/org/repo --cache --tools all --verbose
reconcli dirbcli --url https://example.com --cache --tool feroxbuster --wordlist big.txt --verbose  
reconcli graphqlcli --domain example.com --cache --engine all --threat-matrix --verbose
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --tool all --ai --verbose

# Cache management commands
reconcli secretscli --cache-stats              # View cache statistics
reconcli dirbcli --clear-cache                 # Clear all cached results
reconcli graphqlcli --cache-dir custom_cache   # Custom cache directory
reconcli vulnsqlicli --cache-max-age 8         # Set cache expiry (8 hours)

# Performance comparison (cache miss vs hit)
reconcli secretscli --target large_repo --cache --tools all --verbose  # First run: 120s
reconcli secretscli --target large_repo --cache --tools all --verbose  # Second run: instant ⚡
```

### 🚀 **July 23, 2025 - Advanced AI Attack Features** (JUST ADDED!)

- **🔗 AI Attack Chain Prediction**: Advanced reconnaissance data analysis to predict possible attack chains and exploitation paths
- **💥 Automated Exploitation Engine**: AI-guided automated exploitation attempts with persona-specific strategies and safety controls  
- **🎯 Persona-Driven Analysis**: Tailored attack predictions and exploitation strategies for BugBounty, Pentester, RedTeam personas
- **📊 Structured Attack Intelligence**: JSON output with attack probabilities, complexity analysis, and step-by-step exploitation guides
- **🛡️ Reconnaissance Integration**: Seamless integration with all ReconCLI modules for comprehensive attack surface analysis
- **⚡ English Language Support**: Full English interface for international security professionals and researchers

```bash
# NEW: AI-powered attack chain prediction based on reconnaissance data
reconcli aicli --chain-predict --persona bugbounty --verbose

# NEW: Automated exploitation attempts with AI-guided strategies  
reconcli aicli --auto-exploit --persona pentester --verbose

# Combined workflow: predict attack chains then attempt automated exploitation
reconcli aicli --chain-predict --auto-exploit --persona redteam --cache --verbose

# Attack prediction for specific persona with detailed analysis
reconcli aicli --chain-predict --persona bugbounty --verbose
# Output: attack_chains_[timestamp].json with structured attack intelligence

# Automated exploitation with safety controls and comprehensive reporting
reconcli aicli --auto-exploit --persona pentester --verbose  
# Output: auto_exploit_results_[timestamp].json with attempt details and recommendations
```

### 🚀 **July 22, 2025 - Cross-Module Cache & AI Enhancements**
- **🛡️ XSSCli v2.0**: Professional XSS testing framework with KNOXSS API integration and Brute Logic lab testing
- **🔄 OpenRedirectCli Enhanced**: AI-powered payload generation with 20x-80x cache speed improvements
- **🔧 PermutCli Upgraded**: AI-enhanced permutation analysis with 50x-200x cache performance gains
- **🔗 URLCli Enhanced**: Intelligent caching with 90% performance improvements and AI-powered URL security analysis
- **🔍 ShodanCLI Upgraded**: Advanced cache management with geographic intelligence and AI vulnerability assessment
- **🤖 Unified AI Architecture**: Multi-provider support (OpenAI, Anthropic, Gemini) across all enhanced modules
- **⚡ Intelligent Caching**: SHA256-based cache keys with automatic expiry and performance tracking
- **📊 Performance Metrics**: Real-time cache statistics and vulnerability discovery rates

```bash
# XSSCli professional testing with KNOXSS and AI
export KNOXSS_API_KEY="your_key"
 reconcli xsscli knoxnl --input urls.txt --cache --ai --ai-provider anthropic

# OpenRedirectCli with AI-enhanced testing and caching
reconcli openredirectcli -i urls.txt --cache --ai-mode --ai-provider openai --advanced-payloads

# PermutCli with AI context and intelligent caching
reconcli permutcli --domain example.com --cache --ai --ai-context "fintech app" --tool gotator

# URLCli with intelligent caching and AI security analysis
reconcli urlcli --domain example.com --cache --ai-detailed --katana --verbose

# ShodanCLI with advanced caching and AI vulnerability assessment
reconcli shodancli --query "mongodb" --ai --cache --country US --format rich

# Cache performance monitoring across modules
reconcli xsscli test-input --cache-stats
reconcli urlcli --cache-stats
reconcli shodancli --cache-stats  
reconcli permutcli --cache-stats
```

### 🧠 **VulnSQLiCLI - Enterprise AI-Enhanced SQL Injection Scanner** (NEW!)
- **🤖 AI-Powered Analysis**: Advanced vulnerability assessment with risk scoring, attack vector analysis, and executive summaries
- **🎯 Custom Payloads**: Load custom SQL injection payloads from external files for targeted testing
- **🔧 Tool Integration**: Support for custom arguments for SQLMap (`--sqlmap-args`) and Ghauri (`--ghauri-args`)
- **🗄️ Database Storage**: Complete SQLite integration with 4-table schema for persistent result storage
- **⚡ Concurrent Processing**: Multi-threaded scanning with configurable concurrency levels
- **🔄 Retry Mechanisms**: Exponential backoff retry system for reliable network operations
- **🧪 Dry-Run Mode**: Simulate scans without executing actual tests for planning and validation
- **📊 Risk Assessment**: AI-driven risk scoring with CRITICAL/HIGH/MEDIUM/LOW classifications
- **🎯 Attack Vectors**: Detailed analysis of potential attack vectors and exploitation methods
- **📋 Executive Reports**: Business-ready summaries with actionable recommendations

```bash
# AI-enhanced SQL injection testing with custom payloads
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" --ai --payloads custom_sqli.txt --basic-test --verbose

# Enterprise-grade assessment with database storage
reconcli vulnsqlicli --urls-file targets.txt --ai --store-db results.db --concurrency 5 --retry 3 --json-report

# Advanced SQLMap integration with custom arguments
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" --sqlmap --sqlmap-args "--level 5 --risk 3 --tamper space2comment" --ai

# Dry-run mode for scan planning
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" --dry-run --ai --payloads advanced_payloads.txt --verbose

# Full security assessment with AI analysis
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" --tool all --ai --store-db assessment.db --markdown-report
```

### 🌐 **CDNCli - Advanced CDN Fingerprinting & Cloud Storage Discovery** (NEW!)
- **🔍 CDN Detection**: Multi-method CDN fingerprinting for Cloudflare, Akamai, AWS CloudFront, Fastly, MaxCDN
- **☁️ Cloud Storage Discovery**: Comprehensive AWS S3, Google Cloud, Azure Blob, Alibaba Cloud hunting with CloudHunter integration
- **🔄 Resume Functionality**: Advanced state persistence with secure pickle management for long-running scans
- **🧠 AI Analysis**: Risk assessment with attack vector identification and security recommendations
- **🌐 Threat Intelligence**: Shodan and FOFA API integration for comprehensive reconnaissance
- **🔧 Tool Integration**: CDNCheck, Subfinder, DNSX, Nuclei, Metabigor support with safe subprocess execution
- **🎯 Bypass Methods**: Active and passive CDN bypass techniques with direct IP discovery
- **🔐 Security Features**: Input validation, command injection prevention, secure state management

```bash
# Enterprise CDN fingerprinting with cloud storage discovery
reconcli cdncli --domain example.com --passive-all --cloudhunter --ai --shodan --fofa --store-db

# Resume functionality for long-running assessments
reconcli cdncli --domain example.com --passive-all --nuclei --resume --verbose

# Active bypass testing with comprehensive analysis
reconcli cdncli --domain example.com --bypass-all --cloudhunter --ai --format rich --save results.json
```

### 🚀 **JSCli - Advanced JavaScript Analysis with SourceMapper Integration** (NEW!)
- **🗺️ SourceMapper Integration**: Complete integration with denandz/sourcemapper for source map analysis
- **🔍 Enhanced Secret Detection**: 21+ patterns including JWT, Firebase, Stripe, PayPal, Twilio, SendGrid
- **📱 Framework Detection**: Automatic detection of React, Vue, Angular, jQuery, Lodash, Webpack
- **🌐 DOM Analysis**: Detect DOM manipulation patterns (innerHTML, eval, addEventListener)
- **✨ Code Beautification**: Automatic beautification of minified JavaScript using jsbeautifier
- **📦 Webpack Analysis**: Advanced Webpack bundle analysis and module extraction
- **🔧 External Tool Integration**: Support for JSLuice, JSLeak, SubJS, Cariddi, GetJS, Mantra
- **💬 Comment Extraction**: Extract and analyze JavaScript comments for sensitive information
- **⚠️ Sensitive Function Detection**: Identify dangerous functions like eval, innerHTML, crypto usage
- **📊 File Deduplication**: Hash generation for duplicate file detection

```bash
# Basic JavaScript analysis with framework detection
reconcli jscli -i js_urls.txt -o js_results --framework-detection --dom-analysis --verbose

# Enhanced analysis with SourceMapper integration
reconcli jscli -i js_urls.txt -o js_results --engine sourcemapper --source-maps --beautify --json --markdown

# Advanced security analysis with all features
reconcli jscli -i js_urls.txt -o js_results --framework-detection --dom-analysis --sensitive-functions --extract-comments --webpack-analysis --hash-files

# Custom secret detection with external patterns
reconcli jscli -i js_urls.txt -o js_results --secret-detection --custom-patterns my_patterns.txt --url-extraction api --min-file-size 1000

# Multiple analysis engines for comprehensive coverage
reconcli jscli -i js_urls.txt -o js_results --engine jsluice --timeout 30 --concurrency 5 --retry 3 --verbose

# Enterprise workflow with AI analysis and database storage
reconcli jscli -i js_urls.txt -o js_results --ai-mode --store-db --framework-detection --source-maps --beautify --json --markdown --verbose
```

### �🔥 **APICLI - SJ (Swagger Jacker) Integration** (NEW!)
- **🎯 Complete SJ Tool Integration**: Full BishopFox Swagger Jacker functionality integrated into APICLI
- **🔍 Swagger/OpenAPI Discovery**: Brute force discovery of 600+ Swagger definition file patterns
- **📋 Endpoint Extraction**: Extract and analyze all API endpoints from Swagger/OpenAPI files
- **🚀 Automated Testing**: Comprehensive automated testing of all discovered endpoints
- **🛠️ Command Generation**: Generate curl and sqlmap commands for manual testing
- **🔐 JavaScript Secret Scanning**: 20+ patterns for AWS keys, GitHub tokens, JWT, API keys, private keys
- **💾 Database Storage**: Complete SQLite integration with 3-table schema for result persistence
- **⚡ Rate Limiting**: Configurable requests per second for responsible scanning

```bash
# Swagger/OpenAPI discovery and brute force
reconcli apicli --url https://api.example.com --swagger-brute --store-db discovery.db --verbose

# Extract endpoints from Swagger files
reconcli apicli --url https://api.example.com --swagger-endpoints --swagger-url https://api.example.com/swagger.json

# Automated endpoint testing (SJ automate mode)
reconcli apicli --url https://api.example.com --swagger-parse --store-db results.db --rate-limit 10

# Generate testing commands
reconcli apicli --url https://api.example.com --swagger-prepare curl --swagger-file api.json
reconcli apicli --url https://api.example.com --swagger-prepare sqlmap --swagger-url https://api.example.com/openapi.yaml

# JavaScript secret scanning
reconcli apicli --url https://api.example.com --secret-scan --store-db secrets.db --verbose

# Complete security assessment with SJ integration
reconcli apicli --url https://api.example.com --security-test --secret-scan --swagger-brute --store-db full_scan.db --json-report --markdown-report
```

### ℹ️ **WhoisFreaksCLI Database Integration** (New!)

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

**Jarek + AI + Copilot = cyber-squad from future** 🚀🤖

*A collaborative project combining human expertise, artificial intelligence, and GitHub Copilot to create cutting-edge cybersecurity tools.*

## 👥 Authors

**🚀 Cyber-Squad from Future**
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

## 🔧 Quick Reference - Core Modules

### 🤖 SubdoCLI - Advanced Subdomain Enumeration
The most comprehensive subdomain enumeration tool with 12 integrated tools + BBOT integration:

```bash
# All 12 tools with selective execution
reconcli subdocli --domain example.com --tools "amass,subfinder,crtsh_alternative" --verbose

# BBOT integration for advanced passive reconnaissance  
reconcli subdocli --domain example.com --bbot-integration --bbot-targets targets.txt --verbose

# Mass subdomain discovery with database storage
reconcli subdocli --domain-list domains.txt --store-db --json --markdown --threads 10
```

### � PortCLI - Multi-Scanner Port Discovery & AI Analysis
Professional port scanning framework with 5 integrated scanners and intelligent service detection:

```bash
# Single domain scanning
reconcli portcli --domain example.com --top-ports 1000 --ai

# Fast parallel scanning with Rush + AI analysis
reconcli portcli --input targets.txt --scanner rush --rush-base-scanner naabu \
  --rush-jobs 20 --ai --cache --json

# Domain with rush scanner  
reconcli portcli --domain target.com --scanner rush --rush-base-scanner nmap --ai

# High-speed enterprise scanning
reconcli portcli --cidr 192.168.0.0/16 --scanner rush --rush-base-scanner masscan \
  --top-ports 1000 --masscan-rate 5000 --exclude-cdn --store-db

# Bug bounty web service discovery
reconcli portcli --input subdomains.txt --only-web --filter-tags prod \
  --exclude-tags dev --ai --markdown

# Service pattern detection and analysis
reconcli portcli --input infrastructure.txt --filter-services "kubernetes-cluster,database-server" \
  --ai --cache --json --verbose
```

### �🚀 JSCli - Advanced JavaScript Analysis & SourceMapper Integration
Enhanced JavaScript analysis with multiple engines and advanced security features:

```bash
# Framework detection and DOM analysis
reconcli jscli -i js_urls.txt -o js_results --framework-detection --dom-analysis --verbose

# SourceMapper integration for source map analysis
reconcli jscli -i js_urls.txt -o js_results --engine sourcemapper --source-maps --beautify --json

# Advanced security analysis with all features
reconcli jscli -i js_urls.txt -o js_results --framework-detection --sensitive-functions --extract-comments --webpack-analysis

# External tool integration (JSLuice, JSLeak, SubJS, Cariddi)
reconcli jscli -i js_urls.txt -o js_results --engine jsluice --timeout 30 --concurrency 5 --verbose

# Enterprise workflow with AI analysis
reconcli jscli -i js_urls.txt -o js_results --ai-mode --store-db --custom-patterns patterns.txt --json --markdown
```

### 🌐 CDNCli - Advanced CDN Fingerprinting & Cloud Storage Discovery

Enterprise-grade CDN detection and cloud storage discovery tool with AI analysis, resume functionality, and threat intelligence integration:

```bash
# Basic CDN detection and fingerprinting
reconcli cdncli --domain example.com --check-cdn --verbose

# Full passive reconnaissance with cloud storage discovery
reconcli cdncli --domain example.com --passive-all --cloudhunter --ai --verbose

# Active bypass attempts with nuclei scanning
reconcli cdncli --domain example.com --bypass-active --nuclei --store-db --program "bug-bounty-2024"

# Cloud storage hunting with custom wordlist
reconcli cdncli --domain example.com --cloudhunter --permutations-file custom.txt \
  --services aws,azure,google,alibaba --write-test --verbose

# Multi-engine analysis with threat intelligence
reconcli cdncli --domain example.com --subfinder --dnsx --shodan --fofa --ai \
  --format rich --store-db --program "enterprise-assessment"

# Resume functionality for long-running scans
reconcli cdncli --domain example.com --passive-all --cloudhunter --nuclei --resume

# Enterprise workflow with comprehensive analysis
reconcli cdncli --domain example.com --passive-all --bypass-all --cloudhunter \
  --nuclei --ai --shodan --fofa --store-db --format json --save results.json
```

🔑 **Key Features**:

- **🔍 CDN Detection**: Cloudflare, Akamai, AWS CloudFront, Fastly, MaxCDN identification
- **☁️ Cloud Storage Discovery**: AWS S3, Google Cloud, Azure Blob, Alibaba Cloud hunting
- **🔄 Resume Functionality**: Pause and resume long-running scans with state persistence
- **🧠 AI Analysis**: Risk assessment, attack vector identification, security recommendations
- **🌐 Threat Intelligence**: Shodan and FOFA API integration for comprehensive reconnaissance
- **🔧 Tool Integration**: CDNCheck, Subfinder, DNSX, Nuclei, Metabigor support
- **🎯 Bypass Methods**: Active and passive CDN bypass techniques
- **📊 Multiple Formats**: Rich console output, JSON, table formats with database storage

🔐 **Security Features**:

- Input validation and command injection prevention
- Secure pickle state management with file path validation
- Resume state encryption and size limits
- Proxy support (HTTP, Tor, Burp Suite integration)

📚 **Advanced Options**:

```bash
# Resume operations
reconcli cdncli --domain example.com --resume-stats              # Show statistics
reconcli cdncli --domain example.com --resume-clear             # Clear resume state

# Proxy configurations
reconcli cdncli --domain example.com --tor --passive-all        # Use Tor proxy
reconcli cdncli --domain example.com --burp --bypass-active     # Use Burp Suite proxy
reconcli cdncli --domain example.com --proxy http://127.0.0.1:8080 --cloudhunter

# CloudHunter specific options
reconcli cdncli --domain example.com --cloudhunter --base-only --open-only --crawl-deep 3
```

### 🤖 AI-Powered Analysis
```bash
# AI vulnerability scanning
reconcli aicli --vuln-scan data.json --persona pentester --verbose

# Interactive AI assistant
reconcli aicli --interactive --persona trainer
```

### 🔐 Secret Discovery
```bash
# Git repository secret scanning
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --verbose
```

### 🌐 API Security Testing
```bash
# Swagger discovery and testing
reconcli apicli --url https://api.example.com --swagger-brute --store-db --verbose
```

### 📊 Data Analysis
```bash
# Advanced CSV analysis
reconcli csvtkcli analyze data.csv --security-report --verbose
```

### 🚀 JavaScript Security Analysis
```bash
# Complete JavaScript security assessment workflow
echo "https://cdn.jquery.com/jquery.min.js" > js_targets.txt
echo "https://unpkg.com/react@18/umd/react.production.min.js" >> js_targets.txt

# Basic framework and security analysis
reconcli jscli -i js_targets.txt -o js_analysis --framework-detection --dom-analysis --verbose

# Advanced SourceMapper analysis for source maps
reconcli jscli -i js_targets.txt -o js_analysis --engine sourcemapper --source-maps --beautify --json

# Enterprise security workflow with custom patterns
echo "api_token=([a-zA-Z0-9]{32})" > custom_patterns.txt
reconcli jscli -i js_targets.txt -o js_analysis --custom-patterns custom_patterns.txt --sensitive-functions --webpack-analysis --hash-files

# External tool integration for comprehensive analysis
reconcli jscli -i js_targets.txt -o js_analysis --engine jsluice --concurrency 10 --timeout 30 --json --markdown

# AI-powered analysis with database storage
reconcli jscli -i js_targets.txt -o js_analysis --ai-mode --store-db --target-domain example.com --program "security-audit" --verbose
```

### 🔍 PortCLI - Advanced Port Scanning & Service Discovery ⭐ (ENHANCED!)

Professional multi-scanner port scanning framework with AI analysis, parallel execution, and intelligent service detection:

```bash
# Basic port scanning with automatic tagging
reconcli portcli --ip 192.168.1.100 --scanner naabu --verbose

# Advanced parallel scanning with Rush
reconcli portcli --input targets.txt --scanner rush --rush-base-scanner nmap --rush-jobs 20 --ai

# High-speed masscan with AI analysis
reconcli portcli --input scope.txt --scanner rush --rush-base-scanner masscan \
  --rush-jobs 15 --masscan-rate 5000 --ai --cache --json

# Comprehensive enterprise scanning
reconcli portcli --cidr 192.168.0.0/16 --scanner rush --rush-base-scanner naabu \
  --top-ports 1000 --exclude-cdn --filter-tags "web,database" --store-db

# Bug bounty focused scanning
reconcli portcli --input subdomains.txt --only-web --filter-tags prod \
  --exclude-tags dev --ai --cache --json --markdown
```

🔑 **Key Features**:

- **🚀 Multi-Scanner Support**: naabu, rustscan, nmap, masscan, rush (5 scanners)
- **⚡ Parallel Execution**: Rush-powered parallel scanning with configurable job limits  
- **🧠 AI Analysis**: Intelligent service analysis with security recommendations
- **🏷️ Smart Tagging**: Automatic port categorization (web, database, cloud, dev, prod)
- **☁️ Cloud Detection**: AWS, Azure, GCP, DigitalOcean infrastructure identification
- **💾 Intelligent Caching**: SHA256-based cache system for instant result retrieval
- **🎯 Advanced Filtering**: Filter by tags, services, cloud providers
- **📊 Rich Reports**: JSON, Markdown, database storage with professional formatting

🔐 **Security Intelligence**:

- **Service Pattern Detection**: Web stacks, Kubernetes clusters, database servers
- **Attack Surface Analysis**: Development vs production service identification  
- **CDN Bypass Insights**: Automatic CDN detection and exclusion capabilities
- **Vulnerability Context**: Port-specific security recommendations and next steps

⚙️ **Advanced Options**:

```bash
# Rush parallel scanning options
--rush-jobs INTEGER              # Parallel jobs count (default: 12)
--rush-timeout INTEGER           # Job timeout in seconds
--rush-retries INTEGER           # Maximum retries per job
--rush-base-scanner [nmap|naabu|rustscan|masscan]  # Base scanner selection

# AI-powered analysis
--ai --ai-provider openai        # AI analysis with specific provider
--ai-cache --ai-context "pentest" # Cache AI results with custom context

# Intelligent filtering and tagging
--filter-tags "web,prod"         # Show only web production services
--exclude-tags "dev,staging"     # Exclude development services
--filter-services "web-stack,kubernetes-cluster"  # Filter by detected service patterns

# Performance and caching
--cache --cache-max-age 24       # Enable 24-hour result caching
--masscan-rate 5000              # High-speed masscan configuration
```

📊 **Professional Reporting**:

```bash
# Generate comprehensive reports
reconcli portcli --input enterprise_scope.txt --scanner rush \
  --rush-base-scanner nmap --rush-jobs 25 --top-ports 1000 \
  --ai --cache --json --markdown --store-db \
  --target-domain company.com --program "Security-Assessment-2025"

# Service-focused analysis
reconcli portcli --input targets.txt --filter-services "database-server,jenkins-server" \
  --exclude-cdn --ai --markdown
```

🎯 **Use Cases**:

- **Bug Bounty**: Fast web service discovery with intelligent filtering
- **Penetration Testing**: Comprehensive infrastructure mapping with AI insights
- **Red Team**: Parallel reconnaissance with stealth scanning options
- **Blue Team**: Asset discovery and service inventory management
- **DevOps**: Infrastructure monitoring and service validation

```

### 💡 Real-World Security Testing Workflows

### 🎯 Bug Bounty Hunter Workflow

```bash
# Step 1: Subdomain enumeration
reconcli subdocli --domain target.com --tools "amass,subfinder,crtsh_alternative" --store-db --json

# Step 2: Port scanning and service discovery
reconcli portcli --input subdomains.txt --scanner rush --rush-base-scanner naabu \
  --only-web --filter-tags prod --exclude-cdn --ai --cache --json

# Step 3: HTTP analysis with screenshots
reconcli httpcli --input subdomains.txt --security-scan --screenshot --store-db --export-vulnerabilities

# Step 4: JavaScript security analysis
reconcli jscli -i js_urls.txt -o js_analysis --framework-detection --sensitive-functions --ai-mode --store-db

# Step 5: API discovery and testing
reconcli apicli --url https://api.target.com --swagger-brute --security-test --store-db

# Step 6: Secret scanning in repositories
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --store-db
```

### 🏢 Enterprise Security Assessment

```bash
# Comprehensive domain analysis
reconcli subdocli --domain-list corporate_domains.txt --bbot-integration --store-db assessment.db --threads 20

# Network infrastructure scanning
reconcli portcli --input corporate_networks.txt --scanner rush --rush-base-scanner masscan \
  --rush-jobs 25 --top-ports 1000 --ai --cache --store-db assessment.db

# Infrastructure analysis with Shodan
reconcli shodancli --query "org:\"Target Corp\"" --ai --store-db assessment.db --verbose

# Web application security testing
reconcli httpcli --input corporate_apps.txt --security-scan --nuclei --benchmark --store-db assessment.db

# JavaScript security audit
reconcli jscli -i corporate_js.txt -o js_audit --engine sourcemapper --ai-mode --store-db assessment.db --custom-patterns corp_patterns.txt

# API security assessment
reconcli apicli --urls-file api_endpoints.txt --swagger-brute --security-test --store-db assessment.db

# Generate comprehensive report
reconcli csvtkcli generate-report assessment.db --security-focus --executive-summary
```

## 🚀 Latest Updates

### 🔍 **ShodanCLI - AI-Enhanced Network Intelligence** (NEW!)
- **🧠 AI-Powered Analysis**: Comprehensive vulnerability analysis with geographical insights
- **🌍 Geographic Intelligence**: Country-based risk assessment and threat landscape analysis
- **🎯 Vulnerability Assessment**: Automated detection of critical security misconfigurations
- **⚡ Intelligent Caching**: SHA256-based cache system for massive performance improvements
- **📊 Rich Reporting**: Beautiful terminal output with Rich library integration
- **💾 Database Storage**: SQLite integration for persistent result storage
- **🔧 Cache Management**: Configurable cache directories, expiration (default 24h), and detailed statistics
- **🔧 Module Usage**: Run as `reconcli shodancli` for improved module compatibility

```bash
# Basic Shodan search with AI analysis and caching
reconcli shodancli --query "apache" --ai --cache --store-db --verbose

# Advanced search with geographic filtering and cache
reconcli shodancli --query "nginx" --country US --ai --cache --limit 100 --jsonout

# Vulnerability-focused analysis with intelligent caching
reconcli shodancli --query "port:443 ssl" --ai --cache --store-db results.db --verbose

# Cache management and performance monitoring
reconcli shodancli --cache-stats
reconcli shodancli --clear-cache
reconcli shodancli --cache-dir /tmp/shodan_cache --cache-max-age 48
```

### 🛡️ **XSSCli - Professional XSS Testing Framework** (MAJOR UPDATE!)
- **🚀 KNOXSS API Integration**: Professional-grade XSS detection with knoxnl wrapper
- **⚔️ XSpear Engine Integration**: Advanced Ruby-based XSS scanner with WAF bypass capabilities
- **🎯 Brute Logic Lab Testing**: Specialized testing environment with 120+ payloads
- **👻 Blind XSS Support**: Out-of-band testing with callback URL integration (XSpear)
- **🧠 Advanced AI Analysis**: Multi-provider support (OpenAI, Anthropic, Gemini) with contextual insights
- **🛡️ Multi-Engine Architecture**: Manual, XSpear, Dalfox, kxss engines with comparison capabilities
- **⚡ Intelligent Caching**: 25x-100x speed improvements with SHA256-based cache keys
- **🔧 16 Specialized Commands**: Comprehensive testing suite with professional tool integrations
- **🕵️ Tor Proxy Support**: Anonymous testing with full proxy integration
- **📊 Performance Metrics**: Real-time cache statistics and vulnerability success rates
- **💾 Enterprise Storage**: ReconCLI database integration with comprehensive result management

```bash
# XSpear advanced XSS scanning with AI and caching
reconcli xsscli test-input --input targets.txt --engine xspear --cache --ai

# XSpear with blind XSS testing
reconcli xsscli xspear --url "https://target.com/search.php" \
  --blind-url "https://callback.com/xss" --threads 5 --ai

# Multi-engine comparison (manual, XSpear, Dalfox, kxss)
reconcli xsscli test-input --input targets.txt --engine all --cache --ai

# Professional KNOXSS testing with AI and caching
export KNOXSS_API_KEY="your_key"
reconcli xsscli knoxnl --input urls.txt --cache --ai --ai-provider anthropic

# Brute Logic lab testing (120 vulnerabilities found)
reconcli xsscli brutelogic-test --cache --ai --verbose

# XSpear-specific AI analysis
reconcli xsscli xspear --url "https://target.com" --ai --ai-provider openai

# Cache management and performance monitoring
reconcli xsscli test-input --cache-stats
reconcli xsscli test-input --clear-cache
```

### 🌐 **HTTPCli - Enhanced HTTP/HTTPS Analysis with Performance Cache** (NEW!)
- **⚡ Smart Caching System**: 101x performance improvement with intelligent HTTP response caching
- **🛡️ Advanced Security Analysis**: Comprehensive security header scoring with A+ to F grades
- **🔍 WAF & CDN Detection**: Identify Cloudflare, Akamai, AWS WAF, F5, Imperva, and 9+ solutions
- **🎯 CORS Vulnerability Testing**: Detailed CORS misconfiguration analysis with risk assessment
- **📸 Visual Analysis**: Screenshot capture with Selenium integration for visual verification
- **⚡ Performance Benchmarking**: HTTP/2 support detection, compression testing, response time analysis
- **🔧 Technology Stack Detection**: Server, CMS, framework identification with enhanced fingerprinting
- **🚨 Vulnerability Export**: Export only vulnerable URLs with security misconfigurations
- **📊 Rich Reporting**: JSON, CSV, HTML, Markdown reports with charts and statistics
- **🌐 Single Domain Scanning**: Direct domain scanning without file creation using `--domain` option

**🎯 Cache Features:**
- `--cache`: Enable caching for massive speed improvements (2.03s → 0.02s)
- `--cache-dir`: Custom cache directory (default: http_cache)
- `--cache-max-age`: Cache expiration in seconds (default: 86400 = 24 hours)
- `--clear-cache`: Clear all cached HTTP responses
- `--cache-stats`: View cache statistics and performance metrics

```bash
# Single domain scanning (NEW!)
reconcli httpcli --domain example.com --security-scan --tech-detection
reconcli httpcli --domain pyszne.pl --security-scan --check-waf --check-cors --cache

# Comprehensive security assessment with caching
reconcli httpcli --input targets.txt --security-scan --check-waf --check-cors \
  --tech-detection --screenshot --benchmark --cache --export-vulnerabilities --verbose

# Bug bounty workflow with custom headers and cache
reconcli httpcli --input subdomains.txt --nuclei --custom-headers '{"X-Bug-Hunter":"true"}' \
  --store-db --program "hackerone" --generate-report --cache --verbose

# Performance and compression analysis with cache management
reconcli httpcli --input sites.txt --benchmark --check-compression --ssl-analysis \
  --threads 20 --rate-limit 10/s --cache --cache-max-age 3600 --jsonout --markdown --verbose

# Single domain advanced analysis (NEW!)
reconcli httpcli --domain target.com --nuclei --benchmark --screenshot --export-vulnerabilities

# Cache management commands
reconcli httpcli --cache-stats  # View cache performance statistics
reconcli httpcli --clear-cache  # Clear all cached responses

# Performance comparison (cache miss vs hit)
reconcli httpcli --input 100_urls.txt --security-scan --cache --verbose  # First run: ~2.03s
reconcli httpcli --input 100_urls.txt --security-scan --cache --verbose  # Cache hit: ~0.02s ⚡
```

### 🔐 **SecretsCLI - Advanced Secret Discovery** (NEW!)
- **🌐 Git Repository Support**: Automatic Git URL detection with TruffleHog git mode
- **🔍 Multi-Tool Integration**: TruffleHog, Gitleaks, JSubFinder, Cariddi support
- **🎯 Advanced Filtering**: Keyword filtering, confidence thresholds, entropy analysis
- **📊 Professional Reports**: JSON, Markdown, CSV, TXT export formats
- **⚡ Enterprise Features**: Resume functionality, proxy support, custom headers
- **🛡️ Smart Detection**: Custom patterns, wordlists, and file extension filtering

```bash
# Scan Git repository for secrets
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --verbose

# Advanced secret scanning with filtering
reconcli secretscli --input domains.txt --tool gitleaks \
  --filter-keywords "api,key,secret" --min-confidence 0.7 \
  --export json,markdown --store-db --verbose

# Enterprise assessment with custom patterns
reconcli secretscli --input /path/to/source --tool gitleaks \
  --wordlist custom_patterns.txt --entropy-threshold 5.0 \
  --proxy http://127.0.0.1:8080 --resume --verbose
```

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

### 💉 **VulnSQLiCLI - Enterprise AI SQL Injection Scanner** (ENHANCED!)
- **🤖 AI-Powered Analysis**: Comprehensive vulnerability assessment with risk scoring and executive summaries
- **🗄️ Database Storage**: SQLite integration with 4-table schema for persistent result storage
- **⚡ Concurrent Processing**: Multi-threaded scanning with configurable concurrency levels
- **🔄 Retry Mechanisms**: Exponential backoff retry system for reliable network operations
- **🎯 Custom Payloads**: Load external payload files for targeted testing
- **🔧 Tool Integration**: Custom arguments support for SQLMap and Ghauri
- **🧪 Dry-Run Mode**: Simulate scans without executing actual tests
- **💾 Intelligent Caching**: 15-300x performance improvement with cache hits
- **📊 Cache Management**: Full cache control with statistics and TTL management

```bash
# AI-enhanced SQL injection testing with caching and custom payloads
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --ai --payloads custom_sqli.txt --basic-test --cache --verbose

# Enterprise assessment with database storage, concurrency, and caching
reconcli vulnsqlicli --urls-file targets.txt --ai --store-db results.db \
  --concurrency 5 --retry 3 --cache --json-report --markdown-report

# Advanced SQLMap integration with custom arguments and caching
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --sqlmap --sqlmap-args "--level 5 --risk 3 --tamper space2comment" --ai --cache

# Ghauri testing with custom arguments, database storage, and cache
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --ghauri --ghauri-args "--threads 15 --level 4 --batch" \
  --store-db vuln_results.db --ai --cache --verbose

# Dry-run mode for scan planning with cache management
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --dry-run --ai --payloads advanced_payloads.txt --cache --verbose

# Complete security assessment with all tools, AI, and caching
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --tool all --ai --store-db assessment.db --retry 3 --cache \
  --sqlmap-args "--level 4 --risk 2" --ghauri-args "--level 3" \
  --markdown-report --json-report --verbose

# Cache management commands
reconcli vulnsqlicli --cache-stats                       # View cache statistics
reconcli vulnsqlicli --clear-cache                      # Clear all cached results
reconcli vulnsqlicli --cache-dir /tmp/vulnsql_cache     # Custom cache directory
reconcli vulnsqlicli --cache-max-age 8                  # 8-hour cache expiry
```

**⚡ Cache Performance:**
- **First Run**: 25-400 seconds (depending on tools and complexity)
- **Cache Hit**: Near-instant results (0.1-0.5 seconds)  
- **Performance Gain**: 15-300x faster for repeated SQL injection assessments
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --dry-run --ai --payloads advanced_payloads.txt --concurrency 3 --verbose

# Complete security assessment with all tools and AI
reconcli vulnsqlicli --url "https://target.com/page.php?id=1" \
  --tool all --ai --store-db assessment.db --retry 3 \
  --sqlmap-args "--level 4 --risk 2" --ghauri-args "--level 3" \
  --markdown-report --json-report --verbose
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

### ⚡ **Performance Cache System** 🚀

All ReconCLI modules now feature an intelligent caching system that dramatically improves performance:

- **🎯 DNS Resolution Cache**: 4,520x faster with 99.98% performance improvement
- **🌐 HTTP Analysis Cache**: 101x faster with 99.01% performance improvement  
- **🔍 Port Scanning Cache**: 316x faster with 99.68% performance improvement
- **🎪 Subdomain Enumeration Cache**: 1,080x faster with 99.91% performance improvement

**Key Features:**
- **SHA256-based Keys**: Secure, deterministic cache identification
- **JSON Storage**: Human-readable cache files with metadata
- **Automatic Expiry**: Configurable TTL with smart invalidation
- **Module-Specific**: Optimized for each reconnaissance task
- **CLI Integration**: Unified cache controls across all modules

```bash
# Enable cache for all operations (24h default TTL)
reconcli dnscli --domain example.com --cache

# Custom cache directory and TTL
reconcli httpcli --url-list urls.txt --cache --cache-dir /tmp/recon_cache --cache-max-age 12

# View cache statistics
reconcli portcli --host 192.168.1.1 --cache-stats

# Clear cache when needed
reconcli subdocli --domain example.com --clear-cache
```

📖 **For complete cache documentation**: See [CACHE_SYSTEM_GUIDE.md](reconcli/CACHE_SYSTEM_GUIDE.md)

### 🧠 **AI-Powered Reconnaissance Assistant (`aicli`)**

- **🎭 Multi-Persona AI System**: RedTeam, BugBounty, Pentester, Trainer, OSINT personas
- **🔬 Advanced Payload Mutation Engine**: XSS, SQLi, SSRF mutations with WAF bypasses
- **🎯 AI-Powered Vulnerability Scanner**: Comprehensive security assessment with ReconCLI integration
- **⚔️ Multi-Stage Attack Flows**: SSRF→XSS→LFI chains with MITRE ATT&CK mapping
- **� Attack Chain Prediction**: AI-powered analysis predicting possible attack chains based on reconnaissance data
- **💥 Auto-Exploitation Engine**: Automated exploitation attempts with persona-specific strategies
- **�📊 Professional Reports**: Executive summaries, compliance mapping, remediation guidance
- **💬 Interactive Chat Mode**: Persistent sessions, advanced prompt templates
- **🔗 ReconCLI Integration**: Enhanced context from DNScli, HTTPcli, URLcli outputs

```bash
# AI-powered vulnerability scanning with ReconCLI integration
reconcli aicli --vuln-scan urlcli_output.json --scan-type comprehensive --persona pentester --integration

# Advanced payload mutations for WAF bypass
reconcli aicli --payload xss --context html --mutate --mutations 20 --persona bugbounty

# Multi-stage attack flow generation
reconcli aicli --attack-flow ssrf,xss,lfi --technique gopher --persona redteam

# NEW: Attack chain prediction based on reconnaissance data
reconcli aicli --chain-predict --persona bugbounty --verbose

# NEW: Automated exploitation attempts with AI guidance
reconcli aicli --auto-exploit --persona pentester --verbose

# Combined attack prediction and exploitation workflow
reconcli aicli --chain-predict --auto-exploit --persona redteam --cache --verbose

# Interactive AI assistance for reconnaissance
reconcli aicli --interactive --persona trainer --save-chat learning_session
```

### 🔐 **API Security Testing (`apicli`) - SJ Integration**
- **🎯 Complete SJ Tool Integration**: Full BishopFox Swagger Jacker functionality integrated
- **🔍 Swagger/OpenAPI Discovery**: Brute force discovery with 600+ file patterns
- **📋 Endpoint Extraction**: Parse and analyze all API endpoints from Swagger/OpenAPI files
- **🚀 Automated Testing**: Comprehensive automated testing of discovered endpoints
- **🛠️ Command Generation**: Generate curl and sqlmap commands for manual testing
- **🔐 JavaScript Secret Scanning**: 20+ patterns for AWS keys, GitHub tokens, JWT, API keys
- **💾 Database Storage**: Complete SQLite integration with 3-table schema
- **⚡ Rate Limiting**: Configurable requests per second for responsible scanning
- **🔧 Security Testing**: Authentication bypass, CORS, injection vulnerabilities
- **📊 Professional Reports**: JSON, YAML, and Markdown output formats

```bash
# SJ Swagger/OpenAPI discovery and brute force
reconcli apicli --url https://api.example.com --swagger-brute --store-db discovery.db --verbose

# Extract endpoints from Swagger files
reconcli apicli --url https://api.example.com --swagger-endpoints \
  --swagger-url https://api.example.com/swagger.json

# Automated endpoint testing (SJ automate mode)
reconcli apicli --url https://api.example.com --swagger-parse \
  --store-db results.db --rate-limit 10

# Generate testing commands
reconcli apicli --url https://api.example.com --swagger-prepare curl \
  --swagger-file api.json
reconcli apicli --url https://api.example.com --swagger-prepare sqlmap \
  --swagger-url https://api.example.com/openapi.yaml

# JavaScript secret scanning
reconcli apicli --url https://api.example.com --secret-scan \
  --store-db secrets.db --verbose

# Complete security assessment with SJ integration
reconcli apicli --url https://api.example.com --security-test \
  --secret-scan --swagger-brute --store-db full_scan.db \
  --json-report --markdown-report

# Traditional API security testing
reconcli apicli --url https://api.example.com --discover \
  --security-test --auth-bypass --cors-test --injection-test \
  --rate-limit-test --parameter-pollution --store-db security.db
```

**SJ Integration Features:**
- **🔍 Brute Force Mode**: `--swagger-brute` - Discover Swagger/OpenAPI files
- **📋 Endpoints Mode**: `--swagger-endpoints` - Extract endpoint information
- **🚀 Automate Mode**: `--swagger-parse` - Automated endpoint testing
- **🛠️ Prepare Mode**: `--swagger-prepare {curl,sqlmap}` - Generate commands
- **🔐 Secret Scanning**: `--secret-scan` - JavaScript files analysis
- **💾 Database Storage**: `--store-db path.db` - Store all results

### � **Directory Brute Force (`dirbcli`)** (NEW!)

Advanced directory and file discovery with intelligent caching, multi-tool support, and comprehensive analysis features.

**🔧 Multi-Tool Support:**
- **ffuf**: Fast web fuzzer with advanced filtering
- **feroxbuster**: Rust-based recursive directory scanner  
- **gobuster**: Go-based directory and file brute forcer
- **dirsearch**: Python-based advanced web path scanner
- **dirb**: Classic directory brute force tool
- **wfuzz**: Web application fuzzer
- **dirmap**: Information gathering tool
- **dirhunt**: Advanced directory scanner

**✨ Smart Features:**
- **🎯 Intelligent Caching**: 20-150x performance improvement with cache hits
- **🔍 Smart Filtering**: Advanced status code, size, and regex filtering
- **📊 Response Analysis**: Technology detection and response analysis
- **🔄 Recursive Scanning**: Deep directory structure discovery
- **🛡️ Stealth Options**: Custom user agents and request throttling

```bash
# Basic directory discovery with caching
reconcli dirbcli --url https://example.com --cache --tool feroxbuster --wordlist common.txt --verbose

# Advanced multi-tool scanning with smart filtering
reconcli dirbcli --url https://example.com --tool ffuf --wordlist big.txt \
  --smart-filter --response-analysis --cache --verbose

# Recursive scanning with technology detection
reconcli dirbcli --url https://example.com --tool feroxbuster --wordlist raft-large.txt \
  --recursive --depth 3 --tech-detect --cache --store-db

# Enterprise assessment with comprehensive reporting
reconcli dirbcli --url https://example.com --tool gobuster \
  --wordlist /usr/share/dirb/wordlists/common.txt --cache --json-report --markdown-report

# Stealth scanning with custom settings
reconcli dirbcli --url https://example.com --tool ffuf --wordlist wordlist.txt \
  --user-agent "Mozilla/5.0..." --delay 1000 --threads 5 --cache --verbose

# Cache management and performance optimization
reconcli dirbcli --cache-stats                           # View cache statistics
reconcli dirbcli --clear-cache                          # Clear cached results  
reconcli dirbcli --cache-dir /tmp/dirb_cache             # Custom cache directory
reconcli dirbcli --cache-max-age 6                      # 6-hour cache expiry
```

**🎯 Cache Performance:**
- **First Run**: 30-300 seconds (depending on wordlist size)
- **Cache Hit**: Near-instant results (0.1-0.5 seconds)
- **Performance Gain**: 20-150x faster for repeated scans

### �🔮 **GraphQL Security Assessment (`graphqlcli`)** (NEW!)

Advanced GraphQL reconnaissance and security testing with multiple engines and comprehensive vulnerability assessment.

**🛡️ Multi-Engine Support:**
- **GraphW00F**: GraphQL fingerprinting and engine detection
- **GraphQL-Cop**: 12+ security vulnerability tests
- **GraphQLMap**: Interactive testing simulation
- **GQL**: Python client with introspection analysis
- **GQL-CLI**: Schema downloading and query execution

```bash
# Complete GraphQL security assessment with caching
reconcli graphqlcli --domain api.example.com --endpoint /graphql --engine all \
  --threat-matrix --batch-queries --sqli-test --nosqli-test --cache --report

# Schema download and analysis with cache
reconcli graphqlcli --domain api.example.com --engine gql-cli --print-schema \
  --schema-file schema.graphql --cache --verbose

# GraphW00F fingerprinting with caching for repeated scans
reconcli graphqlcli --domain api.example.com --engine graphw00f \
  --fingerprint --detect-engines --cache --report

# Threat matrix assessment with custom cache settings
reconcli graphqlcli --domain api.example.com --engine gql \
  --threat-matrix --batch-queries --sqli-test --cache --cache-max-age 12 --csv-output

# Interactive GraphQL testing with cache management
reconcli graphqlcli --domain api.example.com --engine gql-cli \
  --interactive-gql --gql-variables "code:PL,name:Poland" --cache

# Cache management commands
reconcli graphqlcli --cache-stats                        # View cache statistics
reconcli graphqlcli --clear-cache                       # Clear all cached results
reconcli graphqlcli --cache-dir /tmp/graphql_cache      # Custom cache directory
```

**⚡ Performance Caching:**
- **🎯 Intelligent Caching**: 30-200x performance improvement with cache hits
- **🔧 Engine-Specific Cache**: Separate cache for each GraphQL engine
- **🕒 TTL Management**: Configurable cache expiration (24 hours default)
- **📊 Cache Statistics**: Monitor cache performance and hit rates
- **First Run**: 20-180 seconds (depending on engine and tests)
- **Cache Hit**: Near-instant results (0.1-0.5 seconds)
```

**🔍 Security Tests:**
- **Introspection Detection**: Check if schema introspection is enabled
- **DoS Testing**: Deep recursion, field duplication, alias overload
- **Injection Testing**: SQL and NoSQL injection attempts
- **Batch Query Testing**: Test query batching capabilities
- **Engine Fingerprinting**: Detect Apollo, Hasura, GraphQL implementations

**📊 Output Formats:**
- **JSON**: Detailed technical results with vulnerability data
- **CSV**: Spreadsheet-compatible format for analysis
- **Markdown**: Executive security reports with recommendations
- **Session State**: Resume functionality for large assessments

**⚡ Advanced Features:**
- **Multiple Engines**: Run all 5 engines simultaneously
- **Threat Matrix**: Based on GraphQL security research
- **Manual Fallbacks**: When external tools unavailable
- **Schema Analysis**: Parse types, queries, mutations
- **Transport Support**: HTTP, WebSocket, and proxy configurations

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

### 🛠️ Port Scanning (`portcli`) - Now with Performance Cache!
- **⚡ Smart Caching System**: 316x performance improvement with intelligent scan result caching
- **Multiple Scanners**: naabu, rustscan, and nmap support with unified interface
- **Flexible Input**: Single IPs, CIDR ranges, or batch processing from files
- **Resume Functionality**: Continue interrupted scans with built-in state management
- **🏷️ Automatic Tagging System**: Smart service categorization and filtering
- **🔍 Service Recognition**: Automatic detection of technology stacks and services
- **☁️ Cloud & CDN Detection**: Identify cloud providers and CDN IP ranges
- **🎯 Advanced Filtering**: Filter by tags, services, or exclude specific categories
- **📊 Professional Reports**: JSON and enhanced Markdown output with comprehensive analysis
- **⚡ Performance Optimized**: Concurrent scanning with progress tracking

**🎯 Cache Features:**
- `--cache`: Enable caching for massive speed improvements (15.8s → 0.05s)
- `--cache-dir`: Custom cache directory (default: port_cache)
- `--cache-max-age`: Cache expiration in seconds (default: 86400 = 24 hours)
- `--clear-cache`: Clear all cached port scan results
- `--cache-stats`: View cache statistics and performance metrics

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
# Basic single IP scan with automatic tagging and caching
reconcli portcli --ip 192.168.1.100 --cache --verbose

# Scan CIDR showing only production web services with cache
reconcli portcli --cidr 192.168.1.0/24 --filter-tags prod,web --top-ports 1000 --cache --verbose

# Find Jenkins and Kubernetes services only with cache management
reconcli portcli --input targets.txt --filter-services jenkins,k8s-api --cache --cache-max-age 7200 --verbose

# Database services scan with detailed service detection and caching
reconcli portcli --input targets.txt --filter-tags database --scanner nmap \
  --nmap-flags "-sV -sC" --cache --json --markdown

# Cache management commands
reconcli portcli --cache-stats  # View cache performance statistics
reconcli portcli --clear-cache  # Clear all cached scan results

# Cloud infrastructure scan excluding CDN noise with cache
reconcli portcli --cidr 10.0.0.0/16 --exclude-tags cdn --filter-tags cloud,mgmt --cache --verbose

# Development environment discovery with caching
reconcli portcli --input internal_ips.txt --filter-tags dev,staging \
  --exclude-tags prod --cache --verbose

# Comprehensive infrastructure assessment with cache
reconcli portcli \
  --input infrastructure.txt \
  --scanner nmap \
  --nmap-flags "-sV -sC -O" \
  --cache \
  --json \
  --markdown \
  --verbose

# Production web services discovery with cache
reconcli portcli \
  --cidr 10.0.0.0/8 \
  --filter-tags prod,web \
  --exclude-tags dev,staging \
  --top-ports 1000 \
  --cache \
  --json

# Security assessment focusing on management interfaces with cache
reconcli portcli \
  --input targets.txt \
  --filter-tags mgmt,remote \
  --filter-services jenkins,k8s-api \
  --scanner nmap \
  --nmap-flags "-sV --script vuln" \
  --cache \
  --markdown

# Performance comparison (cache miss vs hit)
reconcli portcli --input targets.txt --scanner nmap --cache --verbose  # First run: ~15.8s
reconcli portcli --input targets.txt --scanner nmap --cache --verbose  # Cache hit: ~0.05s ⚡

# Database and messaging service discovery with cache
reconcli portcli \
  --cidr 172.16.0.0/12 \
  --filter-tags database,messaging \
  --exclude-tags dev \
  --cache \
  --verbose

# Cloud infrastructure analysis with cache
reconcli portcli \
  --input cloud_ips.txt \
  --filter-tags cloud,ssl \
  --exclude-tags cdn \
  --cache \
  --json \
  --markdown

# Development environment assessment with cache
reconcli portcli \
  --input dev_network.txt \
  --filter-tags dev,staging \
  --filter-services jenkins,gitlab \
  --web-only \
  --cache \
  --verbose
```

### 🤖 Enhanced Subdomain Enumeration (`subdocli`) - Now with BBOT Integration and Performance Cache!

**🔥 Latest Updates:**
- **⚡ Smart Caching System**: 1,080x performance improvement with intelligent subdomain result caching
- **🎯 Selective Tool Execution**: `--tools` option for running specific tools (e.g., 'amass,subfinder,crtsh')
- **🛡️ Enhanced Security**: Improved input validation and error handling (bandit security tested)
- **⚡ Optimized Performance**: Improved timeout handling and process management
- **🧹 Clean Configuration**: Consolidated duplicate options for better UX

**Core Features:**
- **🤖 BBOT Integration**: Bighuge BLS OSINT Tool with 53+ advanced subdomain enumeration modules
- **� 12 Traditional Tools**: subfinder, findomain, assetfinder, chaos, amass, sublist3r, wayback, otx, hackertarget, rapiddns, certspotter, crtsh_alternative
- **🎯 Selective Execution**: Choose specific tools with `--tools` parameter
- **�🔍 Superior Discovery**: anubisdb, crt.sh, chaos, hackertarget, certspotter, dnsdumpster, and 47+ more sources
- **⚡ Advanced Features**: Certificate transparency monitoring, DNS bruteforcing, intelligent mutations
- **☁️ Cloud Enumeration**: GitHub code search, cloud resource discovery, postman workspace enumeration
- **🧠 Smart Processing**: Multi-threaded IP resolution, HTTP/HTTPS service detection with title extraction
- **📊 Advanced Analytics**: Resume support, tool performance statistics, comprehensive reporting
- **💾 Export Formats**: CSV, JSON, TXT export for analysis and reporting
- **�️ Database Integration**: Complete SQLite storage with ReconCLI ecosystem integration

**🎯 Cache Features:**
- `--cache`: Enable caching for massive speed improvements (108s → 0.1s)
- `--cache-dir`: Custom cache directory (default: subdomain_cache)
- `--cache-max-age`: Cache expiration in seconds (default: 86400 = 24 hours)
- `--clear-cache`: Clear all cached subdomain results
- `--cache-stats`: View cache statistics and performance metrics

```bash
# Selective tool execution with caching - run specific tools only
reconcli subdocli --domain example.com --tools "amass,subfinder,crtsh_alternative" --cache --verbose

# Single tool execution with cache
reconcli subdocli --domain example.com --tools amass --cache --verbose

# BBOT-powered subdomain enumeration with caching (53+ modules)
reconcli subdocli --domain example.com --bbot --cache --verbose

# BBOT intensive mode with aggressive bruteforcing and cache
reconcli subdocli --domain example.com --bbot-intensive --cache --verbose

# Full scan with BBOT + traditional tools + HTTP probing + CSV export + cache
reconcli subdocli --domain example.com --bbot --resolve --probe-http \
  --all-tools --markdown --store-db --export csv --show-stats --cache --verbose

# Traditional tools only (no BBOT) with resolution, HTTP probing, and cache
reconcli subdocli --domain example.com --passive-only --resolve --probe-http --cache --verbose

# Active enumeration tools only with cache
reconcli subdocli --domain example.com --active-only --cache --verbose

# Cache management commands
reconcli subdocli --cache-stats  # View cache performance statistics
reconcli subdocli --clear-cache  # Clear all cached results

# JSON export for programmatic analysis with cache
reconcli subdocli --domain example.com --bbot-intensive --export json --cache --verbose

# TXT export for human-readable reports with cache
reconcli subdocli --domain example.com --bbot --export txt --cache --verbose

# Resume BBOT-powered scan with cache
reconcli subdocli --domain example.com --bbot --resume --cache --verbose

# Custom Amass configuration with cache
reconcli subdocli --domain example.com --amass-config /path/to/amass.ini --cache --verbose

# Performance comparison (cache miss vs hit)
reconcli subdocli --domain example.com --tools "hackertarget,wayback" --cache --verbose  # First run: ~108s
reconcli subdocli --domain example.com --tools "hackertarget,wayback" --cache --verbose  # Cache hit: ~0.1s ⚡
```

# Single tool execution
reconcli subdocli --domain example.com --tools amass --verbose

# BBOT-powered subdomain enumeration (53+ modules)
reconcli subdocli --domain example.com --bbot --verbose

# BBOT intensive mode with aggressive bruteforcing
reconcli subdocli --domain example.com --bbot-intensive --verbose

# Full scan with BBOT + traditional tools + HTTP probing + CSV export
reconcli subdocli --domain example.com --bbot --resolve --probe-http \
  --all-tools --markdown --store-db --export csv --show-stats --verbose

# Traditional tools only (no BBOT) with resolution and HTTP probing
reconcli subdocli --domain example.com --passive-only --resolve --probe-http --verbose

# Active enumeration tools only
reconcli subdocli --domain example.com --active-only --verbose

# JSON export for programmatic analysis and API integration
reconcli subdocli --domain example.com --bbot-intensive --export json --verbose

# TXT export for human-readable reports
reconcli subdocli --domain example.com --bbot --export txt --verbose

# Resume BBOT-powered scan
reconcli subdocli --domain example.com --bbot --resume --verbose

# Custom Amass configuration
reconcli subdocli --domain example.com --amass-config /path/to/amass.ini --verbose
```

**📚 Complete Documentation**: See `reconcli/SUBDOCLI_GUIDE.md` for comprehensive usage guide, examples, and best practices.

### 🌐 DNS Resolution & Analysis (`dnscli`) - Now with Performance Cache!
- **⚡ Smart Caching System**: 4,520x performance improvement with intelligent cache management
- **Enhanced DNS Resolution**: Multi-threaded IP resolution with PTR record tagging
- **Subdomain Bruteforcing**: Custom wordlist support for subdomain discovery
- **Custom DNS Resolvers**: Use custom resolver lists for improved performance
- **WHOIS Integration**: Enrich DNS results with WHOIS data from WhoisFreaks
- **Advanced Filtering**: Tag-based filtering and unresolved exclusion
- **Resume Support**: Continue interrupted DNS scans
- **Professional Reports**: JSON and Markdown output with detailed statistics
- **Notification Support**: Real-time alerts via Slack/Discord webhooks

**🎯 Cache Features:**
- `--cache`: Enable caching for massive speed improvements (45.2s → 0.01s)
- `--cache-dir`: Custom cache directory (default: dns_cache)
- `--cache-max-age`: Cache expiration in seconds (default: 86400 = 24 hours)
- `--clear-cache`: Clear all cached DNS results
- `--cache-stats`: View cache statistics and performance metrics

```bash
# Basic DNS resolution with caching enabled
reconcli dnscli --input subdomains.txt --cache --verbose

# Advanced DNS with custom resolvers and cache management
reconcli dnscli --input subdomains.txt --resolvers custom_resolvers.txt \
  --wordlists bruteforce_wordlist.txt --threads 100 --cache --cache-max-age 7200 --verbose

# DNS resolution with WHOIS enrichment and caching
reconcli dnscli --input subdomains.txt --whois-file whois_results.json \
  --save-json --save-markdown --cache --verbose

# Cache management commands
reconcli dnscli --cache-stats  # View cache performance statistics
reconcli dnscli --clear-cache  # Clear all cached results

# Resume interrupted DNS scan with notifications and caching
reconcli dnscli --input large_subdomain_list.txt --resume --cache \
  --slack-webhook "https://hooks.slack.com/..." \
  --exclude-unresolved --filter-tags "CDN,Cloud" --verbose

# Quick resolution-only mode with cache
reconcli dnscli --input subdomains.txt --resolve-only --cache \
  --threads 200 --timeout 3 --retries 1 --verbose

# Performance comparison (cache miss vs hit)
reconcli dnscli --input 1000_domains.txt --cache --verbose  # First run: ~45s
reconcli dnscli --input 1000_domains.txt --cache --verbose  # Cache hit: ~0.01s ⚡
```

### 🔗 URL Discovery & Analysis (`urlcli`)
- **Multiple Tools**: GAU, Katana, Gospider, Waybackurls integration
- **Advanced Katana Options**: Depth control, JS crawling, headless mode, form filling, tech detection
- **⚡ Intelligent Caching**: SHA256-based cache system with 90% performance improvements
- **🧠 AI-Powered Analysis**: Security-focused URL analysis with threat categorization
- **Configurable Timeouts**: Per-tool timeout settings
- **YAML Flow Support**: Predefined configuration templates
- **Comprehensive Filtering**: URL deduplication and pattern matching
- **Professional Reporting**: Detailed analysis with statistics
- **💾 Cache Management**: Configurable cache directories, expiration, and statistics

```bash
# Basic URL discovery with caching and AI
reconcli urlcli --domain example.com --cache --ai --verbose

# Advanced Katana crawling with intelligent caching
reconcli urlcli --domain example.com --katana-depth 3 --katana-js-crawl \
  --katana-headless --katana-tech-detect --cache --ai-detailed --verbose

# Cache management and statistics
reconcli urlcli --cache-stats
reconcli urlcli --clear-cache

# Using flow configuration with AI analysis
reconcli urlcli --domain example.com --flow flows/url_katana_advanced.yaml --cache --ai
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

### 🔄 **Open Redirect Vulnerability Scanner (`openredirectcli`)** (ENHANCED!)
- **🧠 AI-Powered Analysis**: Multi-provider AI support (OpenAI, Anthropic, Gemini) with intelligent payload generation
- **⚡ OpenRedirectCacheManager**: 20x-80x speed improvements with intelligent caching system
- **🚀 External Tool Integration**: OpenRedirex, kxss, waybackurls, GAU, unfurl, httpx support
- **🎯 Advanced Detection Methods**: Header redirects, JavaScript redirects, meta refresh analysis with pattern recognition
- **🔍 Smart URL Discovery**: Historical URL fetching with parameter-based filtering and AI optimization
- **📊 Comprehensive Reporting**: JSON, Markdown, CSV, Burp Suite compatible outputs with AI insights
- **⚡ Resume Functionality**: Continue interrupted scans with state management and cache integration
- **🔔 Real-time Notifications**: Slack and Discord webhook integration for critical findings
- **🛡️ Advanced Payload Engine**: AI-generated payloads with encoding options and confidence scoring

#### 🎯 Key Features
- **AI-Enhanced Testing**: Context-aware payload generation with multi-provider analysis
- **Intelligent Caching**: SHA256-based cache keys for instant repeated testing
- **Multi-Method Detection**: Header analysis, JavaScript redirect detection, meta refresh parsing
- **External Tool Integration**: Seamless integration with popular security tools and caching
- **Database Storage**: ReconCLI database integration with program classification
- **Performance Metrics**: Real-time cache hit rates and vulnerability discovery statistics
- **Professional Reports**: Detailed Markdown reports with AI-powered remediation guidance

#### 🔄 Advanced CLI Options
```bash
# Basic open redirect testing with AI and caching
reconcli openredirectcli -i urls.txt --cache --ai-mode --verbose

# AI-powered testing with advanced caching and specific provider
reconcli openredirectcli -i urls.txt --cache --ai-mode --ai-provider anthropic \
  --ai-model claude-3-opus --advanced-payloads --verbose

# Complete security assessment with external tools and caching
reconcli openredirectcli -i urls.txt --cache --ai-mode --use-openredirex \
  --use-kxss --use-waybackurls --use-gau --filter-params \
  --check-javascript --check-meta-refresh --markdown --store-db

# Cache management and performance monitoring
reconcli openredirectcli --cache-stats
reconcli openredirectcli --clear-cache

# Bug bounty workflow with AI, caching, and notifications
reconcli openredirectcli -i scope_urls.txt --cache --ai-mode --use-waybackurls \
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

### � **Subdomain Permutation Generator (`permutcli`)** (ENHANCED!)
- **🧠 AI-Enhanced Permutation Analysis**: Multi-provider AI support (OpenAI, Anthropic, Google, Local) with context-aware generation
- **⚡ PermutCacheManager**: 50x-200x speed improvements with intelligent caching system
- **🔧 15+ Tool Integration**: gotator, goaltdns, dnstwist, dnsgen, urlcrazy, shuffledns, dmut, s3scanner, alterx, and more
- **🎯 Smart Keyword Suggestion**: AI-powered keyword generation based on target analysis
- **🌐 Multiple Permutation Types**: Subdomains, paths, buckets, parameters, and API endpoints
- **📊 Advanced Analysis**: Pattern recognition, success rate tracking, and intelligent filtering
- **💾 Cross-Tool Deduplication**: SHA256-based result deduplication across multiple tools
- **🔍 Context-Aware Generation**: Domain-specific insights with technology stack correlation

#### 🎯 Key Features
- **AI-Enhanced Analysis**: Context-aware permutation generation with multi-provider support
- **Intelligent Caching**: SHA256-based cache keys for instant repeated permutation generation
- **Multi-Tool Integration**: Seamless integration with 15+ permutation and discovery tools
- **Performance Optimization**: Massive speed improvements through intelligent caching
- **Database Storage**: ReconCLI database integration with comprehensive result management
- **Advanced Filtering**: AI-powered result filtering and success rate optimization

#### 🔄 Advanced CLI Options
```bash
# AI-enhanced subdomain permutation with caching
reconcli permutcli -i seeds.txt --cache --ai --ai-provider openai --verbose

# Multi-tool permutation with AI context
reconcli permutcli --domain example.com --tool gotator --cache --ai \
  --ai-context "fintech application" --resolve --store-db

# Advanced permutation generation with custom wordlists
reconcli permutcli -i domains.txt --cache --ai --tool goaltdns \
  --wordlist custom.txt --permutation-type subdomains --verbose

# Cache management and performance monitoring
reconcli permutcli --cache-stats
reconcli permutcli --clear-cache

# Comprehensive permutation workflow with AI and database storage
reconcli permutcli --domain target.com --cache --ai --resolve \
  --store-db --target-domain target.com --output-format detailed
```

### �🔐 **Secret Discovery & Analysis (`secretscli`)**
- **🔍 Multi-Tool Integration**: TruffleHog, Gitleaks, JSubFinder, Cariddi, Semgrep, and more
- **🌐 Git Repository Support**: Automatic detection of Git URLs with proper scanning modes
- **🛡️ Semgrep SAST Integration**: Static Application Security Testing with p/secrets ruleset
- **🎯 Advanced Filtering**: Keyword filtering, confidence thresholds, and entropy-based detection
- **📊 Comprehensive Export**: JSON, Markdown, CSV, and TXT report formats
- **⚡ Resume Functionality**: Continue interrupted scans with state management
- **🔧 Enterprise Features**: Proxy support, custom headers, rate limiting, and depth control
- **🛡️ Smart Detection**: Entropy threshold analysis and custom pattern matching

```bash
# Scan Git repository for secrets
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --verbose

# Comprehensive secret discovery with jsubfinder
reconcli secretscli --input domains.txt --tool jsubfinder \
  --export json,markdown --min-confidence 0.7 --verbose

# Advanced filtering and analysis
reconcli secretscli --input target.com --tool trufflehog --filter-keywords "api,key,secret" \
  --exclude-keywords "test,demo" --entropy-threshold 5.0 --verbose

# Enterprise security assessment with trufflehog
reconcli secretscli --input targets.txt --tool trufflehog \
  --config-file security.json --proxy http://127.0.0.1:8080 \
  --export json,csv --store-db --resume --verbose

# Custom pattern scanning with wordlist
reconcli secretscli --input /path/to/files --tool gitleaks \
  --wordlist custom_patterns.txt --extensions js,py,php \
  --exclude-paths "test/,node_modules/" --depth 10 --verbose

# Semgrep static analysis for secrets (NEW!)
reconcli secretscli --input /path/to/source --tool semgrep --verbose

# Semgrep SAST analysis for secrets
reconcli secretscli --input project_files/ --tool semgrep \
  --export json,markdown --store-db --verbose
```

#### 📚 Documentation

- **[Complete SecretsCLI Guide](reconcli/SECRETSCLI_GUIDE.md)** - Comprehensive documentation with examples
- **[Quick Reference](reconcli/SECRETSCLI_QUICK_REFERENCE.md)** - Command reference and troubleshooting

### � **Code Security Analysis (`codeseccli`)** (NEW!)

- **🛡️ Semgrep SAST Integration**: Static Application Security Testing with p/secrets rulesets
- **🔍 Multi-Tool Support**: Semgrep, Bandit, and Safety security analysis tools
- **🎯 Severity Filtering**: Configurable severity levels (INFO, WARNING, ERROR)
- **📊 Multiple Export Formats**: JSON, SARIF, text, and Markdown reports
- **💾 Database Integration**: Store findings in ReconCLI database with target classification
- **🚀 Advanced Configuration**: Custom rulesets, include/exclude patterns, timeout control
- **⚡ Performance Optimized**: Concurrent analysis with progress tracking

```bash
# Basic code security analysis with Semgrep
reconcli codeseccli --input /path/to/code --tool semgrep --verbose

# Comprehensive security scan with all tools
reconcli codeseccli --input project/ --tool all \
  --severity ERROR --export json,markdown --store-db --verbose

# Custom ruleset analysis
reconcli codeseccli --input src/ --tool semgrep --config custom-rules.yaml \
  --include "*.py,*.js" --exclude "test/" --verbose

# Enterprise security assessment
reconcli codeseccli --input /app/source --tool semgrep \
  --severity WARNING --export sarif,json --store-db \
  --target-domain example.com --program "Security Assessment" --verbose

# Quick security check with database storage
reconcli codeseccli --input . --tool semgrep --store-db \
  --export json --verbose
```

#### 🛡️ Semgrep Integration Features

- **🔧 Static Analysis**: Comprehensive code security analysis using Semgrep SAST
- **📋 Security Rulesets**: Built-in p/secrets ruleset for detecting hardcoded secrets
- **🚫 Git-ignore Bypass**: Scan all files including those ignored by git (--no-git-ignore)
- **🎯 Smart Filtering**: Automatic exclusion of common non-security paths
- **📈 Professional Reports**: Detailed JSON output with vulnerability metadata
- **⚡ Enterprise Ready**: Database integration for tracking findings across projects

#### 📚 CodeSecCLI Documentation

- **[Complete DoctorCLI Guide](reconcli/DOCTORCLI_GUIDE.md)** - Comprehensive environment diagnostic documentation
- **[Quick Reference](reconcli/DOCTORCLI_QUICK_REFERENCE.md)** - Command reference and troubleshooting guide

### 🩺 **DoctorCLI - Environment Diagnostic Tool** (NEW!)
- **🔧 Comprehensive Environment Checking**: Verify 35+ security tools installation and configuration
- **🐍 Python Package Validation**: Check essential packages for reconnaissance workflows
- **📁 Directory Structure Analysis**: Ensure proper workspace organization and permissions
- **🌐 Network Connectivity Testing**: Test connectivity to common reconnaissance targets
- **🛤️ Programming Environment Paths**: Verify Go, Python, Ruby, Node.js, and other language installations
- **⚙️ Configuration File Management**: Create and validate tool configuration files
- **🔒 Security & Permissions Audit**: Check file permissions and system security settings
- **🩹 Automated Fixes**: Repair common issues with dry-run mode for safe testing
- **📊 Professional Reports**: Generate JSON, Markdown, and HTML diagnostic reports

```bash
# Complete environment diagnostic
reconcli doctorcli --all --fix --verbose

# Check specific components
reconcli doctorcli --tools --python --env --structure --verbose

# Dry-run mode - check without making changes
reconcli doctorcli --all --dry-run --verbose

# Check programming environments and paths
reconcli doctorcli --paths --system --network --verbose

# Security and permissions audit
reconcli doctorcli --permissions --configs --strict --verbose

# Generate comprehensive report
reconcli doctorcli --all --export html --output-dir reports/ --verbose

# Check optional tools and advanced features
reconcli doctorcli --optional --configs --permissions --fix --verbose

# Quick system overview
reconcli doctorcli --system --network --paths --quiet

# Fix common issues automatically
reconcli doctorcli --structure --configs --env --fix --verbose
```

#### 🔍 Diagnostic Features
- **Tool Installation**: Verify 35+ reconnaissance tools (amass, httpx, nuclei, subfinder, etc.)
- **Optional Tools**: Check advanced tools (wafw00f, subzy, kxss, openredirex, etc.)
- **Environment Variables**: Validate API keys and secrets configuration
- **Directory Structure**: Ensure proper output/, wordlists/, configs/ organization
- **Network Testing**: Test connectivity to GitHub, Shodan, CRT.sh, Archive.org
- **Programming Paths**: Check Go, Python, Ruby, Perl, Node.js installations
- **Configuration Files**: Create default configs for nuclei, httpx, amass
- **Security Audit**: File permissions, executable verification, hash checking

#### 📊 Report Formats
- **JSON Reports**: Structured data with detailed diagnostic information
- **Markdown Reports**: Human-readable documentation with fix suggestions
- **HTML Reports**: Interactive dashboard with color-coded status indicators
- **Terminal Output**: Real-time feedback with progress indicators and fix suggestions

#### 🩹 Automated Fixes
- **Missing Directories**: Create required output and configuration directories
- **Configuration Files**: Generate default tool configurations
- **Environment Setup**: Create sample .env_secrets with API key templates
- **Permissions**: Fix file and directory permissions for security tools
- **Dry-run Mode**: Preview all changes before applying them

## 📋 Complete Module List

### 🔧 **Core Infrastructure & Development Tools**
- **📊 csvtkcli** - Advanced CSV data analysis and security reporting
- **🔧 gitcli** - Git operations and repository management for reconnaissance data
- **🗄️ dbcli** - Database management for reconnaissance data storage
- **🩺 doctorcli** - Environment diagnostic tool with automated fixes and comprehensive reporting

### 🔍 **Discovery & Enumeration**
- **🌐 subdocli** - 🤖 Enhanced subdomain enumeration with BBOT integration (53+ modules for superior discovery)
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
- **💉 vulnsqlicli** - Enterprise AI-enhanced SQL injection scanner with custom payloads, concurrent processing, database storage, and advanced risk assessment
- **�️ xsscli** - AI-enhanced XSS testing with Tor proxy support for anonymous vulnerability assessment
- **�🔍 cnamecli** - CNAME record analysis and takeover detection
- **🛡️ wafdetectcli** - WAF detection, testing and bypass analysis
- **↗️ openredirectcli** - Advanced open redirect vulnerability scanner with AI
- **🔄 takeovercli** - Subdomain takeover vulnerability detection
- **🔐 secretscli** - Multi-tool secret discovery and analysis
- **🔐 codeseccli** - Code security analysis with Semgrep SAST integration
- **🔐 apicli** - API security testing with Swagger/OpenAPI support

### 🔍 **Intelligence & Analysis**
- **🌐 whoisfreakscli** - WHOIS intelligence and domain analysis
- **🔍 shodancli** - AI-enhanced network intelligence with geographic analysis and vulnerability assessment
- **☁️ cloudcli** - Cloud provider detection and S3 enumeration
- **🔄 permutcli** - Advanced permutation generation for domains and paths
- **🔍 jscli** - JavaScript file discovery and analysis with multi-engine support

### 📊 **Utilities & Management**
- **🏷️ taggercli** - Advanced subdomain tagging and classification
- **📝 mdreportcli** - Enhanced markdown reports with templates and security analysis
- **🔗 urlsortcli** - URL sorting and organization with advanced patterns
- **📝 makewordlistcli** - Advanced wordlist generator with intelligence and mutations
- **🌐 httpcli** - Advanced HTTP/HTTPS analysis with security assessment, WAF detection, technology fingerprinting, CORS testing, performance benchmarking, and vulnerability export

---

## 📚 Documentation

### 📖 **Complete Guides**
- **[CACHE_SYSTEM_GUIDE.md](reconcli/CACHE_SYSTEM_GUIDE.md)** - Comprehensive cache system documentation with performance benchmarks and usage examples
- **[AI_GUIDE.md](reconcli/AI_GUIDE.md)** - Complete AI features documentation with persona system and vulnerability scanning
- **[BBOT_INTEGRATION_GUIDE.md](reconcli/BBOT_INTEGRATION_GUIDE.md)** - BBOT integration for enhanced subdomain enumeration

### 🔧 **Module-Specific Documentation**
- **[SUBDOCLI_GUIDE.md](reconcli/SUBDOCLI_GUIDE.md)** - Advanced subdomain enumeration with 12 tools + BBOT
- **[SECRETSCLI_GUIDE.md](reconcli/SECRETSCLI_GUIDE.md)** - Multi-tool secret discovery and analysis
- **[DOCTORCLI_GUIDE.md](reconcli/DOCTORCLI_GUIDE.md)** - Environment diagnostics and automated fixes
- **[GRAPHQLCLI_ENHANCED_GUIDE.md](reconcli/GRAPHQLCLI_ENHANCED_GUIDE.md)** - GraphQL security testing
- **[HTTPCLI_DOCUMENTATION.md](HTTPCLI_DOCUMENTATION.md)** - Comprehensive HTTP/HTTPS analysis with security assessment and domain scanning
- **[HTTPCLI_TUTORIAL.md](HTTPCLI_TUTORIAL.md)** - HTTPCli quick start guide and practical examples
- **[PORTCLI_DOCUMENTATION.md](PORTCLI_DOCUMENTATION.md)** - Advanced port scanning with domain support and AI analysis

### ⚡ **Quick References**
- **[DOCTORCLI_QUICK_REFERENCE.md](reconcli/DOCTORCLI_QUICK_REFERENCE.md)** - DoctorCLI command quick reference
- **[SECRETSCLI_QUICK_REFERENCE.md](reconcli/SECRETSCLI_QUICK_REFERENCE.md)** - SecretsCLI command quick reference
- **[SUBDOCLI_QUICK_REFERENCE.md](reconcli/SUBDOCLI_QUICK_REFERENCE.md)** - SubdoCLI command quick reference

---

*ReconCLI - Empowering security professionals with modular reconnaissance capabilities*
# Test hook disable
