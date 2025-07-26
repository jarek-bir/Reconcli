# 🌐 HTTPCli - Advanced HTTP/HTTPS Analysis Documentation

**HTTPCli** is a powerful HTTP/HTTPS service analysis module within ReconCLI, designed for comprehensive web reconnaissance, security testing, and vulnerability assessment.

## 📋 Table of Contents

- [Features](#-features)
- [Installation & Dependencies](#-installation--dependencies)
- [Basic Usage](#-basic-usage)
- [Advanced Features](#-advanced-features)
- [Command Line Options](#-command-line-options)
- [Security Analysis](#-security-analysis)
- [Caching System](#-caching-system)
- [Export Formats](#-export-formats)
- [Database Integration](#-database-integration)
- [Examples](#-examples)
- [Bug Bounty Workflows](#-bug-bounty-workflows)

## 🚀 Features

### Core Analysis Features
- **🔍 Single Domain Scanning**: Direct domain scanning without file creation using `--domain`
- **📂 Batch Processing**: Process multiple URLs from file input with `--input`
- **🛡️ Security Header Analysis**: Comprehensive security header scoring (A+ to F grades)
- **🔍 WAF & CDN Detection**: Identify 15+ WAF/CDN solutions (Cloudflare, Akamai, AWS, etc.)
- **🎯 CORS Vulnerability Testing**: Detailed CORS misconfiguration analysis with risk assessment
- **🔧 Technology Stack Detection**: Server, CMS, framework identification with enhanced fingerprinting
- **📸 Visual Analysis**: Screenshot capture with Selenium integration
- **⚡ Performance Benchmarking**: Response time analysis with multiple runs

### Advanced Security Features
- **🚨 Nuclei Integration**: Vulnerability scanning with custom template support
- **🌐 HTTP/2 Support Detection**: Modern protocol support verification
- **📊 Compression Testing**: Gzip/Brotli compression analysis with efficiency metrics
- **🔐 SSL/TLS Analysis**: Certificate validation and configuration assessment
- **📈 Response Time Benchmarking**: Multi-sample performance measurement
- **🎭 Custom Headers**: Custom header injection for advanced testing
- **🔄 Proxy Support**: Full proxy integration for testing through tools

### Cache & Performance
- **⚡ Smart Caching System**: 101x performance improvement (2.03s → 0.02s)
- **🗂️ SHA256 Cache Keys**: Secure cache identification based on URL + options
- **⏰ Configurable Expiry**: Custom cache expiration (default: 24 hours)
- **📊 Cache Statistics**: Detailed performance metrics and hit/miss ratios
- **🧹 Cache Management**: Clear cache, view stats, cleanup expired entries

## 🔧 Installation & Dependencies

### Required Dependencies
```bash
pip install requests httpx beautifulsoup4 rich click mmh3
```

### Optional Dependencies
```bash
# For screenshot capture
pip install selenium

# For Nuclei integration
# Install Nuclei: https://github.com/projectdiscovery/nuclei

# For Wappalyzer integration  
npm install -g wappalyzer-cli
```

## 🎯 Basic Usage

### Single Domain Scanning
```bash
# Basic domain scan
reconcli httpcli --domain example.com

# Security analysis on single domain
reconcli httpcli --domain target.com --security-scan

# Technology detection on domain
reconcli httpcli --domain site.com --tech-detection
```

### Batch Processing from File
```bash
# Basic batch scanning
reconcli httpcli --input urls.txt

# Advanced batch analysis
reconcli httpcli --input subdomains.txt --security-scan --tech-detection
```

## 🔬 Advanced Features

### Comprehensive Security Assessment
```bash
# Full security scan with all features
reconcli httpcli --domain target.com --security-scan --check-waf --check-cors \
  --tech-detection --nuclei --benchmark --screenshot

# WAF and CDN detection
reconcli httpcli --domain example.com --check-waf --tech-detection

# CORS vulnerability testing
reconcli httpcli --domain api.target.com --check-cors --security-scan
```

### Performance Analysis
```bash
# Response time benchmarking
reconcli httpcli --domain target.com --benchmark --check-compression

# HTTP/2 and compression testing
reconcli httpcli --domain site.com --check-compression --ssl-analysis

# Custom performance testing
reconcli httpcli --domain example.com --benchmark --threads 20 --rate-limit 10/s
```

### Technology Detection
```bash
# Enhanced technology fingerprinting
reconcli httpcli --domain target.com --tech-detection --wappalyzer

# Custom headers for detection bypass
reconcli httpcli --domain site.com --tech-detection \
  --custom-headers '{"User-Agent":"Custom-Scanner","X-Test":"true"}'
```

## 📊 Command Line Options

### Input Options
| Option | Description | Example |
|--------|-------------|---------|
| `--domain` | Single domain to scan | `--domain example.com` |
| `--input` / `-i` | File with URLs/hostnames | `--input urls.txt` |

### Analysis Options
| Option | Description | Default |
|--------|-------------|---------|
| `--security-scan` | Comprehensive security header analysis | False |
| `--check-waf` | WAF and security solution detection | False |
| `--check-cors` | CORS configuration analysis | False |
| `--tech-detection` | Technology stack fingerprinting | False |
| `--nuclei` | Run Nuclei vulnerability scanner | False |
| `--screenshot` | Capture page screenshots | False |
| `--benchmark` | Response time benchmarking | False |
| `--check-compression` | Test compression support | False |
| `--ssl-analysis` | SSL/TLS certificate analysis | False |

### Performance Options
| Option | Description | Default |
|--------|-------------|---------|
| `--threads` | Concurrent processing threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `--retries` | Number of retries for failed requests | 2 |
| `--rate-limit` | Rate limit (e.g., 10/s, 100/m) | None |
| `--fastmode` | HEAD-only mode (no full GET) | False |

### Cache Options
| Option | Description | Default |
|--------|-------------|---------|
| `--cache` | Enable HTTP response caching | False |
| `--cache-dir` | Custom cache directory | `~/.reconcli/http_cache` |
| `--cache-max-age` | Cache expiration in hours | 24 |
| `--clear-cache` | Clear all cached responses | False |
| `--cache-stats` | Show cache statistics | False |

### Export Options
| Option | Description | Default |
|--------|-------------|---------|
| `--jsonout` | Export JSON and CSV results | False |
| `--markdown` | Generate Markdown report | False |
| `--headers` | Export HTTP headers | False |
| `--headers-format` | Header format (text/json/csv/table) | text |
| `--export-vulnerabilities` | Export only vulnerable URLs | False |
| `--generate-report` | Generate comprehensive HTML report | False |

### Filtering Options
| Option | Description | Example |
|--------|-------------|---------|
| `--export-tag` | Export URLs by tag | `--export-tag cors-wildcard` |
| `--export-status` | Export URLs by status code | `--export-status 200` |
| `--header-filter` | Filter specific headers | `--header-filter "Server,X-Powered-By"` |

## 🛡️ Security Analysis

### Security Header Scoring
HTTPCli provides comprehensive security header analysis with letter grades:

**Grading System:**
- **A+** (90-100%): Excellent security posture with all critical headers
- **A** (80-89%): Good security with most headers present
- **B** (70-79%): Moderate security, some improvements needed
- **C** (60-69%): Basic security, several headers missing
- **D** (50-59%): Poor security, many critical headers missing
- **F** (0-49%): Very poor security, minimal protection

**Analyzed Headers:**
- `X-Frame-Options` - Clickjacking protection
- `Content-Security-Policy` - XSS and injection protection
- `Strict-Transport-Security` - HTTPS enforcement
- `X-Content-Type-Options` - MIME sniffing protection
- `Referrer-Policy` - Referrer information control
- `Permissions-Policy` - Feature policy control
- `Access-Control-Allow-Origin` - CORS configuration

### CORS Vulnerability Detection
```bash
# Test for CORS misconfigurations
reconcli httpcli --domain api.target.com --check-cors

# Advanced CORS testing with multiple origins
reconcli httpcli --input api_endpoints.txt --check-cors --export-vulnerabilities
```

**CORS Risk Levels:**
- **High**: Wildcard origins with credentials, arbitrary origin reflection
- **Medium**: Null origin acceptance, credentials with specific origins
- **Low**: Proper origin validation and restricted methods

### WAF and CDN Detection
HTTPCli detects 15+ WAF and CDN solutions:

**Supported WAFs:**
- Cloudflare, Akamai, AWS WAF, Azure WAF
- Imperva (Incapsula), F5 BIG-IP, Barracuda
- Fortinet FortiWeb, Sucuri, Wordfence

**Supported CDNs:**
- Cloudflare, Akamai, Fastly, AWS CloudFront
- Azure CDN, Google Cloud CDN, MaxCDN, KeyCDN

## ⚡ Caching System

### Cache Performance
The intelligent caching system provides massive performance improvements:

```bash
# Enable caching for huge speed boost
reconcli httpcli --domain target.com --security-scan --cache

# First run (cache miss): ~2.03s
# Subsequent runs (cache hit): ~0.02s (101x faster!)
```

### Cache Management
```bash
# View cache statistics
reconcli httpcli --cache-stats

# Clear all cached responses
reconcli httpcli --clear-cache

# Custom cache configuration
reconcli httpcli --domain example.com --cache --cache-dir /tmp/http_cache --cache-max-age 12
```

### Cache Key Generation
- **SHA256-based**: Secure cache key generation
- **Request-aware**: Includes URL, method, and relevant headers
- **Option-sensitive**: Different options create different cache entries
- **Collision-resistant**: Virtually no chance of cache key conflicts

## 📤 Export Formats

### JSON Export
```bash
# Export comprehensive JSON data
reconcli httpcli --domain target.com --security-scan --jsonout

# Generates: http_results.json, http_results.csv
```

### Headers Export
```bash
# Export headers in various formats
reconcli httpcli --domain example.com --headers --headers-format json
reconcli httpcli --input urls.txt --headers --headers-format csv
reconcli httpcli --domain site.com --headers --headers-format table --header-filter "Server,X-Powered-By"
```

### Vulnerability Export
```bash
# Export only vulnerable targets
reconcli httpcli --input targets.txt --security-scan --export-vulnerabilities

# Generates: vulnerabilities.json, vulnerable_urls.txt
```

### Report Generation
```bash
# Generate comprehensive HTML report
reconcli httpcli --input subdomains.txt --security-scan --generate-report --markdown
```

## 🗄️ Database Integration

### Store Results in Database
```bash
# Store results with target classification
reconcli httpcli --domain target.com --security-scan --store-db --program "bug-bounty"

# Batch storage with program context
reconcli httpcli --input corporate_sites.txt --security-scan --store-db \
  --target-domain "company.com" --program "corporate-assessment"
```

## 📚 Examples

### Basic Reconnaissance
```bash
# Quick domain check
reconcli httpcli --domain example.com

# Technology stack identification
reconcli httpcli --domain target.com --tech-detection --verbose
```

### Security Assessment
```bash
# Comprehensive security scan
reconcli httpcli --domain target.com --security-scan --check-waf --check-cors

# Security scan with visual verification
reconcli httpcli --domain site.com --security-scan --screenshot --nuclei
```

### Performance Testing
```bash
# Response time analysis
reconcli httpcli --domain target.com --benchmark --check-compression

# Load testing with rate limiting
reconcli httpcli --input urls.txt --benchmark --threads 50 --rate-limit 20/s
```

### Batch Analysis
```bash
# Scan multiple subdomains
reconcli httpcli --input subdomains.txt --security-scan --tech-detection --cache

# Corporate assessment
reconcli httpcli --input corporate_assets.txt --security-scan --nuclei \
  --export-vulnerabilities --store-db --program "corporate-2024"
```

## 🎯 Bug Bounty Workflows

### Standard Bug Bounty Scan
```bash
# Comprehensive bug bounty analysis
reconcli httpcli --domain target.com --security-scan --check-waf --check-cors \
  --nuclei --screenshot --tech-detection --export-vulnerabilities \
  --store-db --program "hackerone-target" --cache --verbose
```

### API Security Testing
```bash
# API endpoint analysis
reconcli httpcli --input api_endpoints.txt --check-cors --custom-headers \
  '{"Authorization":"Bearer token","X-API-Key":"test"}' \
  --export-vulnerabilities --jsonout
```

### Large Scale Assessment
```bash
# Process hundreds of targets efficiently
reconcli httpcli --input large_scope.txt --security-scan --cache \
  --threads 20 --rate-limit 15/s --export-vulnerabilities \
  --generate-report --store-db --program "big-program"
```

### Visual Verification Workflow
```bash
# Screenshot interesting findings
reconcli httpcli --input interesting_urls.txt --screenshot --security-scan \
  --tech-detection --markdown --verbose
```

## 🔧 Advanced Configuration

### Custom Headers
```bash
# Bug bounty headers
reconcli httpcli --domain target.com --custom-headers \
  '{"X-Bug-Hunter":"researcher","User-Agent":"Mozilla/5.0 Custom Scanner"}'

# API testing headers
reconcli httpcli --input api_urls.txt --custom-headers \
  '{"Authorization":"Bearer test","Content-Type":"application/json"}'
```

### Proxy Configuration
```bash
# Use Burp Suite proxy
reconcli httpcli --domain target.com --proxy http://127.0.0.1:8080 --security-scan

# Use SOCKS proxy
reconcli httpcli --input urls.txt --proxy socks5://127.0.0.1:1080
```

### Nuclei Integration
```bash
# Use custom Nuclei templates
reconcli httpcli --domain target.com --nuclei --nuclei-templates /path/to/custom/

# Nuclei with filtering
reconcli httpcli --input targets.txt --nuclei --export-vulnerabilities
```

## 📊 Performance Metrics

### Cache Performance Examples
```bash
# Performance comparison
reconcli httpcli --input 100_urls.txt --security-scan --verbose
# Without cache: ~203s (2.03s per URL)

reconcli httpcli --input 100_urls.txt --security-scan --cache --verbose  
# First run: ~203s (building cache)
# Second run: ~2s (0.02s per URL) - 101x faster!
```

### Throughput Optimization
```bash
# Maximum throughput configuration
reconcli httpcli --input large_list.txt --threads 50 --rate-limit 30/s \
  --timeout 5 --retries 1 --cache --verbose
```

## 🚨 Error Handling

### Retry Configuration
```bash
# Custom retry settings
reconcli httpcli --domain unstable-site.com --retries 5 --timeout 15
```

### Verbose Debugging
```bash
# Debug mode for troubleshooting
reconcli httpcli --domain problematic-site.com --verbose
```

## 📝 Notes

- **Cache Persistence**: Cache survives between tool runs for consistent performance
- **Thread Safety**: All operations are thread-safe for concurrent processing
- **Memory Efficiency**: Streaming responses and smart memory management
- **Error Recovery**: Robust error handling with detailed error reporting
- **Rate Limiting**: Respectful scanning with configurable rate limits
- **Security**: No sensitive data stored in cache, only response metadata

## 🔗 Integration

HTTPCli integrates seamlessly with other ReconCLI modules:
- Use results from `dnscli` subdomain enumeration
- Feed outputs to `vulnsqlicli` for SQL injection testing
- Combine with `portcli` for complete service analysis
- Store all findings in unified ReconCLI database

---

**📖 For more examples and advanced usage, see the main ReconCLI documentation and tutorial files.**
