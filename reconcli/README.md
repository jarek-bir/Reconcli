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
├── vhostcheck.py          # VHOST verification utilities
├── utils/
│   ├── __init__.py
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

### Latest Changes (v2.0.0)

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
- **Discussions**: [GitHub Discussions](https://github.com/jarek-bir/Reconcli/discussions)
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
