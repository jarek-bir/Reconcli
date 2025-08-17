# 🎯 VHostHunter - Standalone Virtual Host Discovery Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/badge/release-v1.0.0-green.svg)]()

**Professional virtual host discovery and security assessment tool for bug bounty hunters and security researchers.**

## 🔥 Features

### 🎯 **Multi-Engine Discovery**
- **FFUF** - Fast web fuzzer (default, high performance)
- **Gobuster** - Reliable directory/vhost bruteforcer  
- **HTTPx** - Python-based HTTP toolkit
- **VhostFinder** - Specialized vhost discovery engine

### 🚀 **Enhanced Capabilities**
- **Port Scanning Integration** - Pre-discovery with naabu, nmap, masscan, JFScan
- **Nuclei Vulnerability Scanning** - Post-discovery security assessment
- **Screenshot Automation** - Visual evidence collection with Gowitness/Aquatone
- **AI-Powered Analysis** - Intelligent result interpretation
- **Database Storage** - Organized bug bounty data management

### ⚡ **Advanced Features**
- **Smart Caching** - Avoid repeated scans, 99% performance boost
- **Resume Capability** - Continue interrupted scans
- **Professional Reporting** - JSON, CSV, Markdown outputs
- **Notification Support** - Slack/Discord webhooks
- **Rate Limiting** - Respect target infrastructure
- **Proxy Support** - Burp Suite integration

## 🚀 Quick Start

### Installation
```bash
# Install dependencies
./install_dependencies.sh

# Verify installation
./check_dependencies.sh
```

### Basic Usage
```bash
# Simple vhost discovery
./vhosthunter --domain example.com --ip 192.168.1.100 --wordlist wordlists/common.txt

# Enhanced discovery with port scanning
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner jfscan \
    --verbose

# Full security assessment
./vhosthunter --domain example.com --ip 192.168.1.100 \
    --wordlist wordlists/comprehensive.txt \
    --port-scan --port-scanner jfscan \
    --nuclei-scan --nuclei-severity medium,high,critical \
    --screenshot --ai-mode \
    --store-db --program "Bug Bounty Program" \
    --verbose
```

### Automation Script
```bash
# Use the automated hunter
./hunt.sh example.com 192.168.1.100
```

## 📊 Performance

- **Multi-threaded scanning** for maximum speed
- **Smart caching system** - 99% performance improvement on repeated scans
- **Intelligent rate limiting** - Respect target infrastructure
- **Resume capability** - Never lose progress

## 🎯 Bug Bounty Integration

Perfect for bug bounty hunting:
- **Professional reporting** for HackerOne, Bugcrowd submissions
- **Evidence collection** with automated screenshots
- **Database integration** for program organization
- **AI analysis** for finding interesting patterns
- **Webhook notifications** for real-time alerts

## 📁 Project Structure

```
VHostHunter/
├── vhosthunter                 # Main executable
├── hunt.sh                     # Automation script
├── install_dependencies.sh     # Dependency installer
├── check_dependencies.sh       # Dependency checker
├── wordlists/                  # Wordlist collection
│   ├── common.txt             # Basic wordlist
│   ├── comprehensive.txt      # Extended wordlist
│   └── specialized/           # Target-specific wordlists
├── modules/                    # Core modules
│   ├── scanner.py             # Main scanning logic
│   ├── engines/               # Discovery engines
│   ├── analyzers/             # Result analyzers
│   └── reporters/             # Report generators
├── configs/                    # Configuration files
├── docs/                      # Documentation
└── examples/                  # Usage examples
```

## 🔧 Requirements

- Python 3.8+
- Go 1.19+ (for Go-based tools)
- Git (for tool installation)

### Core Tools
- ffuf
- gobuster
- nuclei
- naabu/nmap/masscan (port scanners)
- gowitness/aquatone (screenshots)

## 📖 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Examples](docs/EXAMPLES.md)
- [Configuration](docs/CONFIGURATION.md)
- [API Reference](docs/API.md)
- [Bug Bounty Workflows](docs/BUG_BOUNTY.md)

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🎯 Author

**Jarek** - Security Researcher & Bug Bounty Hunter
- GitHub: [@jarek-bir](https://github.com/jarek-bir)

---

**Made with ❤️ for the bug bounty community**
