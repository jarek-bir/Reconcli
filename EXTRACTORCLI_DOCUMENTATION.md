# 🧲 ExtractorCLI v2.0 - Complete Documentation

## 📋 Table of Contents
- [Overview](#overview)
- [Installation & Setup](#installation--setup)
- [Quick Start Guide](#quick-start-guide)
- [Extraction Categories](#extraction-categories)
- [Advanced Features](#advanced-features)
- [Real-World Examples](#real-world-examples)
- [Performance & Optimization](#performance--optimization)
- [Security Features](#security-features)
- [Integration with Other Tools](#integration-with-other-tools)

---

## 🌟 Overview

**ExtractorCLI v2.0** is a powerful data extraction and security analysis tool designed for security professionals, bug bounty hunters, and developers. It can extract over **15 different types of data** from files, directories, URLs, and live content with **enhanced secret detection** capabilities covering **20+ secret types**.

### 🎯 Key Features
- **15+ Extraction Categories**: URLs, emails, secrets, crypto addresses, social media, PII data, and more
- **Enhanced Secret Detection**: 20+ secret types including AWS keys, OpenAI tokens, Discord tokens, etc.
- **ANSI Code Cleaning**: Processes colored terminal output and log files
- **AI-Powered Analysis**: Intelligent scoring and categorization
- **XSS-Vibes Integration**: Vulnerability scanning and endpoint discovery
- **Real-time Monitoring**: Live file monitoring capabilities
- **Multiple Output Formats**: JSON, JSONL, CSV, XML, tagged formats

---

## 🚀 Installation & Setup

### Prerequisites
```bash
# Required for basic functionality
pip install click requests

# Optional: For XSS integration (install xss-vibes separately)
# Optional: For enhanced file type detection
pip install python-magic
```

### Basic Usage
```bash
# Extract from a single file
reconcli extractorcli data.txt

# Extract specific types
reconcli extractorcli data.txt --types "secret,url,email"

# Process multiple files
reconcli extractorcli directory/ --recursive --types "secret,api"
```

---

## 🔍 Extraction Categories

### 🌐 Core Web Data
| Category | Description | Example Output |
|----------|-------------|----------------|
| `url` | HTTP/HTTPS URLs and endpoints | `https://api.example.com/v1/users` |
| `email` | Email addresses | `admin@example.com` |
| `domain` | Domain names | `example.com` |
| `subdomain` | Subdomains (requires --target-domain) | `api.example.com` |
| `ip` | IP addresses (IPv4/IPv6) | `192.168.1.1` |
| `form` | HTML forms and inputs | `<form action="/login">` |

### 🔐 Enhanced Security Data
| Category | Description | Secret Types Detected |
|----------|-------------|----------------------|
| `secret` | **20+ secret types** | AWS keys, GitHub tokens, OpenAI keys, Stripe keys, Discord tokens, Telegram bots, PayPal clients, Mailgun keys, Twilio SIDs, SendGrid keys, Anthropic keys, Google API keys, Azure keys, Docker tokens, Heroku keys, Cloudflare tokens, private keys, SSH keys, database URLs, connection strings, environment variables |
| `auth` | Authentication endpoints | `/login`, `/oauth`, `/jwt` |
| `api` | API endpoints | `/api/v1`, `/rest/`, `/graphql` |
| `swagger` | API documentation | `/swagger`, `/docs`, `/openapi` |

### 💰 Financial & Personal Data
| Category | Description | Example Output |
|----------|-------------|----------------|
| `crypto` | Cryptocurrency addresses | `BTC:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` |
| `pii` | Personal Identifiable Information | `CC:4532-1234-5678-9012` |
| `phone` | Phone numbers | `+1-555-123-4567` |

### 📱 Social Media & Communication
| Category | Description | Example Output |
|----------|-------------|----------------|
| `social` | Social media profiles | `TWITTER:@username`, `DISCORD:discord.gg/invite` |

### 📋 Technical Documentation
| Category | Description | Example Output |
|----------|-------------|----------------|
| `api_docs` | API documentation titles | `OpenAPI Specification`, `GraphQL Playground` |
| `tech_stack` | Technology stacks | `Nginx:1.18.0`, `Python:3.8` |
| `js` | JavaScript variables | `apiKey=abc123` |
| `comment` | HTML/JS comments | `<!-- Admin panel -->` |

---

## ⚡ Advanced Features

### 🤖 AI-Powered Analysis
```bash
# Enable AI scoring for intelligent categorization
reconcli extractorcli data.txt --ai-score --score-threshold 5

# Tagged output with metadata
reconcli extractorcli logs/ --recursive --tagged --ai-score
```

### 🔄 Real-time Processing
```bash
# Live monitoring mode
reconcli extractorcli --live-mode --watch-dir /var/log --types "secret,pii"

# URL fetching with concurrent processing
reconcli extractorcli urls.txt --fetch-urls --threads 20 --timeout 10
```

### 🔧 Custom Patterns
```bash
# Use custom regex patterns
reconcli extractorcli data.txt --custom-patterns patterns.json

# Export built-in patterns for customization
reconcli extractorcli --export-patterns my_patterns.json
```

### 📊 Data Merging & Deduplication
```bash
# Merge with existing data
reconcli extractorcli new_data.txt --merge-with old_results.json --dedup

# Advanced deduplication strategies
reconcli extractorcli data.txt --dedup-by "url,domain" --dedup-strategy "merge"
```

---

## 🌟 Real-World Examples

### 🔍 Bug Bounty Reconnaissance
```bash
# Comprehensive security scan
reconcli extractorcli target_scope.txt --types "secret,auth,api,crypto,pii" \
  --ai-score --tagged --sensitivity paranoid --output security_findings.json

# API documentation analysis
reconcli extractorcli swagger_endpoints.txt --types "api_docs,tech_stack,api" \
  --fetch-urls --deep-js --verbose

# Social media intelligence gathering
reconcli extractorcli social_data.txt --types "social,phone,email" \
  --json --ai-score --output osint_findings.json
```

### 🔐 Security Auditing
```bash
# Source code secret scanning
reconcli extractorcli /path/to/source --recursive \
  --types secret --sensitivity paranoid \
  --exclude-patterns "*.min.js,*.gz,node_modules/*" \
  --tagged --output secrets_audit.json

# Log file analysis for sensitive data
reconcli extractorcli /var/log --recursive \
  --types "secret,pii,crypto" --live-mode \
  --filter-regex "error|warn|critical"

# Configuration file analysis
find /etc -name "*.conf" -o -name "*.cfg" | \
  xargs reconcli extractorcli --types "secret,auth,database" --tagged
```

### 📈 Threat Intelligence
```bash
# Cryptocurrency tracking from leaked data
reconcli extractorcli darkweb_dumps/ --recursive \
  --types "crypto,email,social" --ai-score \
  --whitelist-domains "target1.com,target2.com"

# API discovery and enumeration
reconcli extractorcli target_urls.txt --fetch-urls \
  --types "api,swagger,auth" --xss-discover \
  --target-domain target.com --verbose
```

### 🔄 Pipeline Integration
```bash
# Integration with other ReconCLI modules
reconcli subdocli --domain target.com --bounty-mode --export json | \
  reconcli extractorcli --types "api,auth,secret" --fetch-urls

# Continuous monitoring pipeline
tail -f application.log | reconcli extractorcli --types "secret,pii,crypto" --tagged

# Batch processing with statistics
find . -name "*.log" -exec reconcli extractorcli {} --types secret \
  --benchmark --stats --output-dir results/ \;
```

---

## 🎛️ Performance & Optimization

### ⚡ Speed Optimization
```bash
# High-performance scanning
reconcli extractorcli large_dataset/ --recursive \
  --threads 50 --timeout 5 --max-size 10 \
  --exclude-patterns "*.zip,*.tar.gz,*.img"

# Smart file type detection
reconcli extractorcli mixed_files/ --recursive --smart-detect \
  --file-patterns "*.txt,*.log,*.json,*.html"

# Benchmarking mode
reconcli extractorcli data.txt --benchmark --stats --verbose
```

### 💾 Memory Management
```bash
# Large file processing
reconcli extractorcli huge_file.txt --max-length 1024 --min-length 10 \
  --limit 1000 --encoding utf-8

# Streaming processing for huge datasets
cat massive_dataset.txt | reconcli extractorcli --types "url,secret" \
  --dedup --sort-results
```

---

## 🛡️ Security Features

### 🔒 Secret Detection Sensitivity
```bash
# Paranoid level detection (maximum coverage)
reconcli extractorcli code/ --recursive --types secret \
  --sensitivity paranoid --score-threshold 3

# Medium sensitivity (balanced performance/coverage)
reconcli extractorcli logs/ --types secret --sensitivity medium

# Low sensitivity (high-confidence matches only)
reconcli extractorcli data.txt --types secret --sensitivity low
```

### 🚨 PII Data Protection
```bash
# PII data discovery with masking
reconcli extractorcli customer_data.txt --types pii \
  --tagged --ai-score --output-dir secure_results/

# Credit card and SSN detection
reconcli extractorcli financial_data/ --recursive --types pii \
  --filter-regex "payment|billing|customer"
```

### 🔍 Vulnerability Integration
```bash
# XSS-Vibes integration for endpoint discovery
reconcli extractorcli urls.txt --xss-discover --target-domain target.com \
  --xss-threads 10 --xss-depth 3

# Combined extraction and vulnerability scanning
reconcli extractorcli endpoints.txt --fetch-urls --types api \
  --xss-scan --xss-timeout 10 --verbose
```

---

## 🔗 Integration with Other Tools

### 🌐 Web Application Testing
```bash
# Burp Suite integration
reconcli extractorcli burp_history.xml --types "api,auth,secret" \
  --fetch-urls --deep-js --tagged

# OWASP ZAP integration  
reconcli extractorcli zap_report.json --types "url,form,auth" \
  --json --ai-score
```

### 📊 SIEM Integration
```bash
# Splunk-friendly output
reconcli extractorcli logs/ --recursive --types "secret,pii" \
  --to-jsonl --tagged --output splunk_feed.jsonl

# ELK Stack integration
reconcli extractorcli application.log --types "error,auth,secret" \
  --json --tagged | jq '.[] | select(.score > 5)'
```

### 🔄 CI/CD Pipeline Integration
```bash
# Git pre-commit hook
reconcli extractorcli . --recursive --types secret \
  --sensitivity high --quiet --exit-code

# Docker container scanning
docker run -v $(pwd):/workspace app_image | \
  reconcli extractorcli --types "secret,crypto,pii" --tagged
```

---

## 📚 Output Formats & Examples

### 📄 JSON Output
```json
{
  "secret": [
    {"value": "AWS_KEY:AKIAIOSFODNN7EXAMPLE", "score": 9},
    {"value": "GITHUB_TOKEN:ghp_1234567890abcdef", "score": 8}
  ],
  "crypto": [
    {"value": "BTC:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "score": 7}
  ]
}
```

### 📋 Tagged Output
```
# ExtractorCLI Results - 2025-08-17 15:30:45
# Processed: swagger_endpoints.txt
# Types: api_docs,tech_stack

## API_DOCS (164 found):
[Score:  8] OpenAPI Specification
[Score:  7] GraphQL Playground
[Score:  6] Swagger UI

## TECH_STACK (372 found):
[Score:  5] Nginx:1.18.0
[Score:  4] Python:3.8
[Score:  3] React
```

### 📊 JSONL Output
```jsonl
{"type": "secret", "value": "AWS_KEY:AKIAIOSFODNN7EXAMPLE", "score": 9}
{"type": "crypto", "value": "BTC:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "score": 7}
{"type": "social", "value": "TWITTER:@username", "score": 4}
```

---

## 🐛 Troubleshooting

### Common Issues
1. **Large Files**: Use `--max-size` and `--timeout` for large file processing
2. **Encoding Issues**: Specify `--encoding utf-8` or appropriate encoding
3. **Performance**: Reduce `--threads` if experiencing memory issues
4. **False Positives**: Adjust `--sensitivity` and use `--score-threshold`

### Debug Mode
```bash
# Enable verbose debugging
reconcli extractorcli data.txt --debug --verbose --stats
```

---

## 🔄 Version History

### v2.0 (Current)
- ✅ Enhanced secret detection (20+ types)
- ✅ Cryptocurrency address extraction
- ✅ Social media profile detection
- ✅ PII data extraction
- ✅ ANSI code cleaning
- ✅ Live monitoring mode
- ✅ Custom pattern support
- ✅ XSS-Vibes integration

### v1.0
- Basic URL, email, API extraction
- Simple secret detection
- JSON/CSV output formats

---

## 📧 Support & Contributing

For issues, feature requests, or contributions:
- **GitHub**: [jarek-bir/Reconcli](https://github.com/jarek-bir/Reconcli)
- **Issues**: Report bugs and request features
- **Pull Requests**: Contributions welcome

---

*Last updated: August 17, 2025*
