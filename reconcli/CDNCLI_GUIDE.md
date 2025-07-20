# 🌐 CDNCli - Advanced CDN Fingerprinting & Cloud Storage Discovery

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation & Requirements](#installation--requirements)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Advanced Usage](#advanced-usage)
- [Resume Functionality](#resume-functionality)
- [Security Features](#security-features)
- [API Integration](#api-integration)
- [Output Formats](#output-formats)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## 📖 Overview

CDNCli is an enterprise-grade CDN fingerprinting and cloud storage discovery tool that provides comprehensive reconnaissance capabilities. It combines multiple detection methods, AI analysis, and threat intelligence to identify CDN providers, discover cloud storage buckets, and assess potential security risks.

### 🎯 Key Capabilities
- **Multi-method CDN detection** using headers, DNS, and dedicated tools
- **Cloud storage discovery** across AWS, Google Cloud, Azure, and Alibaba Cloud
- **AI-powered risk assessment** with attack vector analysis
- **Resume functionality** for long-running scans
- **Threat intelligence integration** via Shodan and FOFA APIs
- **Security-first design** with input validation and secure state management

## 🚀 Features

### 🔍 CDN Detection
- **Header Analysis**: Identifies CDN signatures in HTTP headers
- **CDNCheck Integration**: Uses projectdiscovery/cdncheck for accurate detection
- **DNS Analysis**: Examines CNAME records and IP ranges
- **Supported CDNs**: Cloudflare, Akamai, AWS CloudFront, Fastly, MaxCDN

### ☁️ Cloud Storage Discovery
- **CloudHunter Integration**: Comprehensive bucket hunting
- **Multi-cloud Support**: AWS S3, Google Cloud Storage, Azure Blob, Alibaba Cloud
- **Access Testing**: Checks bucket accessibility and permissions
- **Custom Wordlists**: Support for custom permutation files

### 🧠 AI Analysis
- **Risk Assessment**: Automated risk scoring (Critical/High/Medium/Low)
- **Attack Vector Identification**: Potential exploitation methods
- **Security Recommendations**: Actionable remediation steps
- **Executive Summaries**: Business-ready reporting

### 🔄 Resume Functionality
- **State Persistence**: Secure pickle-based state management
- **Step Tracking**: Granular progress tracking
- **Statistics**: Detailed session statistics
- **Recovery**: Automatic recovery from interruptions

### 🌐 Threat Intelligence
- **Shodan Integration**: Network intelligence gathering
- **FOFA Integration**: Global asset discovery
- **Enriched Results**: Enhanced context for discovered assets

## 🛠 Installation & Requirements

### Prerequisites
```bash
# Core requirements
pip install click requests rich

# Optional external tools (recommended)
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/j3ssie/metabigor@latest

# CloudHunter (cloud storage discovery)
git clone https://github.com/belane/CloudHunter.git
cd CloudHunter && chmod +x cloudhunter && sudo mv cloudhunter /usr/local/bin/
```

### API Keys (Optional)
```bash
# Shodan API
export SHODAN_API_KEY="your-shodan-api-key"

# FOFA API
export FOFA_EMAIL="your-fofa-email"
export FOFA_KEY="your-fofa-key"

# AI Providers (for enhanced analysis)
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
```

## 🚀 Quick Start

### Basic CDN Detection
```bash
# Simple CDN detection
reconcli cdncli --domain example.com --check-cdn

# Verbose CDN detection with multiple methods
reconcli cdncli --domain example.com --check-cdn --cdncheck --verbose
```

### Cloud Storage Discovery
```bash
# Basic cloud storage hunting
reconcli cdncli --domain example.com --cloudhunter

# Advanced cloud storage discovery
reconcli cdncli --domain example.com --cloudhunter \
  --services aws,google,azure --write-test --open-only
```

### Comprehensive Analysis
```bash
# Full passive reconnaissance
reconcli cdncli --domain example.com --passive-all --ai

# Complete security assessment
reconcli cdncli --domain example.com --passive-all --bypass-all \
  --cloudhunter --nuclei --ai --shodan --fofa
```

## 📖 Command Reference

### Core Options
| Option | Description | Example |
|--------|-------------|---------|
| `--domain` | Target domain (required) | `--domain example.com` |
| `--check-cdn` | Perform CDN detection | `--check-cdn` |
| `--passive-all` | Run all passive reconnaissance | `--passive-all` |
| `--cloudhunter` | Enable cloud storage discovery | `--cloudhunter` |
| `--ai` | Enable AI-powered analysis | `--ai` |
| `--verbose` | Verbose output | `--verbose` |

### Tool Integration
| Option | Description | Tool Required |
|--------|-------------|---------------|
| `--cdncheck` | Use CDNCheck for detection | cdncheck |
| `--subfinder` | Subdomain enumeration | subfinder |
| `--dnsx` | DNS resolution | dnsx |
| `--nuclei` | Vulnerability scanning | nuclei |
| `--metabigor` | Additional reconnaissance | metabigor |

### Cloud Storage Options
| Option | Description | Default |
|--------|-------------|---------|
| `--services` | Target cloud services | aws,google,azure,alibaba |
| `--permutations-file` | Custom wordlist | Built-in |
| `--write-test` | Test write permissions | Disabled |
| `--base-only` | Check base domain only | Disabled |
| `--open-only` | Show only accessible buckets | Disabled |
| `--crawl-deep` | Crawl depth level | 1 |

### Intelligence APIs
| Option | Description | Requirements |
|--------|-------------|--------------|
| `--shodan` | Query Shodan API | SHODAN_API_KEY |
| `--fofa` | Query FOFA API | FOFA_EMAIL, FOFA_KEY |

### Bypass Options
| Option | Description |
|--------|-------------|
| `--bypass-passive` | Passive bypass methods |
| `--bypass-active` | Active bypass methods |
| `--bypass-all` | All bypass methods |

### Output & Storage
| Option | Description | Example |
|--------|-------------|---------|
| `--format` | Output format | rich, json, table |
| `--save` | Save results to file | `--save results.json` |
| `--store-db` | Store in database | `--store-db` |
| `--program` | Program name for DB | `--program "bug-bounty"` |

### Resume Options
| Option | Description |
|--------|-------------|
| `--resume` | Resume previous session |
| `--resume-stats` | Show session statistics |
| `--resume-clear` | Clear resume state |

### Proxy Options
| Option | Description | Example |
|--------|-------------|---------|
| `--proxy` | HTTP/HTTPS proxy | `--proxy http://127.0.0.1:8080` |
| `--tor` | Use Tor proxy | `--tor` |
| `--burp` | Use Burp Suite proxy | `--burp` |

## 🔄 Resume Functionality

### How It Works
CDNCli implements a sophisticated resume system that allows you to pause and continue long-running scans:

```bash
# Start a comprehensive scan
reconcli cdncli --domain example.com --passive-all --cloudhunter --nuclei

# If interrupted, resume with:
reconcli cdncli --domain example.com --resume

# Check session statistics
reconcli cdncli --domain example.com --resume-stats

# Clear resume state
reconcli cdncli --domain example.com --resume-clear
```

### Resume Features
- **Step-by-step tracking**: Each analysis phase is tracked individually
- **Secure state management**: Resume files are validated and size-limited
- **Statistics tracking**: Detailed metrics about scan progress
- **Error recovery**: Graceful handling of interruptions

### Resume File Security
- Files stored only in controlled output directory
- 100MB size limit to prevent memory exhaustion
- Path validation to prevent directory traversal
- Secure pickle serialization with validation

## 🔐 Security Features

### Input Validation
```python
# Domain validation regex
^[a-zA-Z0-9.-]+$

# Blocked characters
; & | ` $ ( ) { } [ ] < >

# Length limits
Domain: 253 characters max
```

### Command Injection Prevention
- All subprocess calls use validated arguments
- Shell execution explicitly disabled
- Suspicious character detection
- Domain format validation

### Secure State Management
- Resume files path validation
- File size limits (100MB)
- Controlled directory access only
- Secure pickle with validation

## 🌐 API Integration

### Shodan Configuration
```bash
# Set API key
export SHODAN_API_KEY="your-api-key"

# Install Shodan library
pip install shodan

# Use in CDNCli
reconcli cdncli --domain example.com --shodan --verbose
```

### FOFA Configuration
```bash
# Set credentials
export FOFA_EMAIL="your-email@example.com"
export FOFA_KEY="your-fofa-key"

# Use in CDNCli
reconcli cdncli --domain example.com --fofa --verbose
```

### API Features
- **Rate limiting**: Automatic rate limiting compliance
- **Error handling**: Graceful API failure handling
- **Result enrichment**: Enhanced context for discovered assets
- **Caching**: API results cached in resume state

## 📊 Output Formats

### Rich Console Output (Default)
```bash
reconcli cdncli --domain example.com --format rich
```
- Color-coded results
- Progress bars and spinners
- Formatted tables and panels
- Real-time status updates

### JSON Output
```bash
reconcli cdncli --domain example.com --format json --save results.json
```
- Machine-readable format
- Complete result set
- Structured data for automation
- API-friendly format

### Table Output
```bash
reconcli cdncli --domain example.com --format table
```
- Tabular display
- Summary statistics
- Clean, readable format
- Perfect for reporting

### Database Storage
```bash
reconcli cdncli --domain example.com --store-db --program "assessment-2024"
```
- SQLite database storage
- Program-based organization
- Historical tracking
- Query capabilities

## 💡 Best Practices

### Performance Optimization
```bash
# Use appropriate thread counts
reconcli cdncli --domain example.com --threads 20

# Combine compatible options
reconcli cdncli --domain example.com --passive-all --cloudhunter

# Use resume for long scans
reconcli cdncli --domain example.com --nuclei --resume
```

### Security Considerations
```bash
# Use proxy for anonymity
reconcli cdncli --domain example.com --tor --passive-all

# Store results securely
reconcli cdncli --domain example.com --store-db --save encrypted_results.json

# Validate all inputs
reconcli cdncli --domain "example.com" --verbose  # Use quotes for safety
```

### Workflow Integration
```bash
# Bug bounty workflow
reconcli cdncli --domain target.com --passive-all --cloudhunter \
  --program "bugcrowd-target" --store-db --format json

# Red team assessment
reconcli cdncli --domain target.com --bypass-all --nuclei \
  --proxy http://teamserver:8080 --verbose

# Blue team monitoring
reconcli cdncli --domain company.com --shodan --fofa \
  --ai --format rich --save monitoring_report.json
```

## 🔧 Troubleshooting

### Common Issues

#### Binary Not Found
```bash
# Error: cdncheck not found
# Solution: Install required tools
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
```

#### API Key Issues
```bash
# Error: SHODAN_API_KEY not set
# Solution: Set environment variable
export SHODAN_API_KEY="your-api-key"
```

#### Resume File Corruption
```bash
# Error: Failed to load resume state
# Solution: Clear resume state
reconcli cdncli --domain example.com --resume-clear
```

#### Permission Denied
```bash
# Error: Permission denied writing results
# Solution: Check output directory permissions
chmod 755 cdncli_output/
```

### Debug Mode
```bash
# Enable verbose output for debugging
reconcli cdncli --domain example.com --verbose

# Check individual tools
cdncheck -i example.com
subfinder -d example.com
```

## 📚 Examples

### Basic Examples

#### Simple CDN Detection
```bash
reconcli cdncli --domain example.com --check-cdn
```

#### Cloud Storage Discovery
```bash
reconcli cdncli --domain example.com --cloudhunter --services aws,google
```

### Intermediate Examples

#### Passive Reconnaissance
```bash
reconcli cdncli --domain example.com --passive-all --ai --verbose
```

#### Resume Long Scan
```bash
# Start scan
reconcli cdncli --domain example.com --nuclei --cloudhunter

# Resume if interrupted
reconcli cdncli --domain example.com --resume
```

### Advanced Examples

#### Enterprise Assessment
```bash
reconcli cdncli --domain enterprise.com \
  --passive-all --bypass-all --cloudhunter \
  --nuclei --ai --shodan --fofa \
  --store-db --program "enterprise-2024" \
  --format json --save comprehensive_report.json \
  --verbose
```

#### Bug Bounty Workflow
```bash
reconcli cdncli --domain target.com \
  --passive-all --cloudhunter \
  --permutations-file custom_words.txt \
  --services aws,google,azure \
  --write-test --open-only \
  --ai --store-db --program "bugcrowd-target" \
  --format rich --save bb_results.json
```

#### Red Team Operation
```bash
reconcli cdncli --domain victim.com \
  --bypass-all --nuclei \
  --tor --verbose \
  --format json --save redteam_intel.json
```

#### Continuous Monitoring
```bash
#!/bin/bash
# Monitor script
reconcli cdncli --domain company.com \
  --shodan --fofa --ai \
  --store-db --program "monitoring-$(date +%Y%m)" \
  --format json --save "monitor_$(date +%Y%m%d).json"
```

### CloudHunter Specific Examples

#### Comprehensive Cloud Discovery
```bash
reconcli cdncli --domain example.com \
  --cloudhunter \
  --services aws,google,azure,alibaba \
  --permutations-file enterprise_words.txt \
  --crawl-deep 3 \
  --write-test \
  --threads 50 \
  --verbose
```

#### Quick Open Bucket Check
```bash
reconcli cdncli --domain example.com \
  --cloudhunter \
  --base-only \
  --open-only \
  --services aws \
  --threads 20
```

### AI Analysis Examples

#### Risk Assessment
```bash
reconcli cdncli --domain example.com \
  --passive-all --cloudhunter --ai \
  --format rich
```

#### Security Recommendations
```bash
reconcli cdncli --domain example.com \
  --bypass-all --nuclei --ai \
  --format json --save security_assessment.json
```

## 🎯 Use Cases

### Bug Bounty Hunting
- Discover hidden cloud storage buckets
- Identify CDN bypass opportunities
- Find exposed development resources
- Map attack surface comprehensively

### Red Team Operations
- Gather intelligence on target infrastructure
- Identify potential entry points
- Discover misconfigured cloud resources
- Plan bypass strategies

### Blue Team Monitoring
- Monitor organizational attack surface
- Identify exposed cloud resources
- Track CDN configuration changes
- Assess security posture

### Penetration Testing
- Comprehensive reconnaissance phase
- Infrastructure mapping
- Vulnerability identification
- Attack vector analysis

## 🤝 Contributing

CDNCli is part of the ReconCLI project. Contributions are welcome!

### Development Setup
```bash
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli
pip install -e .
```

### Testing
```bash
# Run security tests
bandit -r reconcli/cdncli.py

# Test functionality
python -m reconcli cdncli --help
```

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🙏 Acknowledgments

- **CloudHunter** by belane for cloud storage discovery
- **ProjectDiscovery** team for excellent tools
- **Security research community** for methodologies and techniques
- **AI providers** for advanced analysis capabilities

---

*CDNCli - Enterprise-grade CDN fingerprinting and cloud storage discovery*
