# ReconCLI - Modular Reconnaissance Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/releases)
[![GitHub stars](https://img.shields.io/github/stars/jarek-bir/Reconcli.svg)](https://github.com/jarek-bir/Reconcli/stargazers)

A comprehensive, modular reconnaissance toolkit designed for security professionals and bug bounty hunters.

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

### 🚨 Subdomain Takeover Detection (`takeover`)
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

### 🌐 Additional Modules
- **DNS Enumeration** (`dns`): Comprehensive DNS discovery
- **HTTP Analysis** (`httpcli`): Web application assessment
- **IP Analysis** (`ipscli`): Network reconnaissance
- **URL Processing** (`urlcli`): URL manipulation and analysis
- **Zone Walking** (`zonewalkcli`): DNS zone transfer testing

## Installation

```bash
# Clone repository
git clone <your-repo-url>
cd reconcli

# Install package
pip install -e .

# Verify installation
reconcli --help
```

## Dependencies

### Required Tools
- **FFuf**: `go install github.com/ffuf/ffuf/v2@latest`
- **Subzy**: Install from GitHub releases
- **HTTPx**: `pip install httpx`

### Python Dependencies
- click
- httpx
- requests
- pathlib

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
├── vhostcli.py            # Virtual host discovery
├── takeovercli.py         # Subdomain takeover detection
├── jscli.py               # JavaScript analysis
├── dnscli.py              # DNS enumeration
├── httpcli.py             # HTTP analysis
├── ipscli.py              # IP reconnaissance
├── urlcli.py              # URL processing
├── zonewalkcli.py         # DNS zone walking
├── vhostcheck.py          # VHOST verification utilities
├── utils/
│   ├── __init__.py
│   ├── notifications.py   # Notification system
│   ├── resume.py          # Resume functionality
│   ├── loaders.py         # Data loading utilities
│   └── mdexport.py        # Markdown export utilities
├── flows/                 # Workflow definitions
└── wordlists/            # Default wordlists
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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Your License Here]

## Changelog

### Latest Changes
- ✅ Added comprehensive notification system (Slack/Discord)
- ✅ Enhanced vhostcli with verbose mode and progress tracking
- ✅ Improved takeovercli with resume system and professional output
- ✅ Fixed import paths for package compatibility
- ✅ Added error handling and timeout management
- ✅ Created professional documentation and examples

## Support

For questions, issues, or feature requests, please create an issue in the GitHub repository.
