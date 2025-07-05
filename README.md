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
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli

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

### Latest Changes (v1.0.0)
- ✅ **Enhanced urlcli.py** with robust resume, error handling, and notifications
- ✅ **Comprehensive notification system** supporting Slack and Discord webhooks
- ✅ **Enhanced vhostcli.py** with verbose mode, progress tracking, and professional output
- ✅ **Improved takeovercli.py** with resume system and enhanced error handling
- ✅ **Fixed jscli.py** import paths for package compatibility
- ✅ **Added utils/notifications.py** with full-featured notification support
- ✅ **Professional documentation** with usage examples and badges
- ✅ **MIT License** and comprehensive README

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
