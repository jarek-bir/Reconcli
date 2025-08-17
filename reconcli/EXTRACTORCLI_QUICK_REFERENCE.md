# 🧲 ExtractorCLI v2.0 - Quick Reference Guide

## 🚀 Quick Start Commands

### Basic Extraction
```bash
# Extract from file
python ectractorcli.py file.html

# Extract specific types only
python ectractorcli.py file.html --types url,email,api

# Extract with output file
python ectractorcli.py file.html --output results.txt
```

### Input Options
```bash
# Different input methods
python ectractorcli.py file.html                    # Positional argument
python ectractorcli.py --input-file file.html       # Named parameter
python ectractorcli.py --input-url https://example.com  # Single URL
python ectractorcli.py --input-list urls.txt        # URL list file

# Process from stdin
echo "https://example.com" | python ectractorcli.py
cat data.txt | python ectractorcli.py
```

### Output Formats
```bash
# JSON format
python ectractorcli.py file.html --json --output results.json

# CSV format
python ectractorcli.py file.html --csv --output results.csv

# Tagged format with categories
python ectractorcli.py file.html --tagged --output results.txt

# JSONL format (JSON Lines)
python ectractorcli.py file.html --to-jsonl --output results.jsonl
```

## 📊 Extraction Types

### Available Types
```
url,email,form,auth,api,swagger,ip,domain,subdomain,secret,js,comment,hash,base64
```

### Common Combinations
```bash
# Security-focused extraction
python ectractorcli.py file.html --types secret,auth,api,url

# Network reconnaissance
python ectractorcli.py file.html --types domain,subdomain,ip,url --target-domain example.com

# Web application analysis
python ectractorcli.py file.html --types form,auth,api,js --deep-js

# General content extraction
python ectractorcli.py file.html --types url,email,domain
```

## 🔧 Advanced Features

### URL Fetching & Processing
```bash
# Fetch URLs and extract from their content
python ectractorcli.py urls.txt --fetch-urls --threads 20

# Deep JavaScript analysis
python ectractorcli.py file.html --deep-js --extract-inline

# Recursive directory scanning
python ectractorcli.py /path/to/dir --recursive --smart-detect
```

### Filtering & Processing
```bash
# Filter with regex
python ectractorcli.py file.html --filter-regex "admin|api"

# Exclude patterns
python ectractorcli.py file.html --exclude-regex "\.min\.|\.gz"

# Limit results
python ectractorcli.py file.html --limit 100

# Length filtering
python ectractorcli.py file.html --min-length 10 --max-length 200
```

### Deduplication & Merging
```bash
# Basic deduplication
python ectractorcli.py file.html --dedup

# Merge with existing file
python ectractorcli.py new.txt --merge-with old.txt --dedup

# Advanced deduplication
python ectractorcli.py file.html --dedup-by all --sort-results
```

## 🤖 AI & Scoring

### AI-Powered Analysis
```bash
# Apply AI scoring
python ectractorcli.py file.html --ai-score --tagged

# Filter by score threshold
python ectractorcli.py file.html --ai-score --score-threshold 5

# Sort by score
python ectractorcli.py file.html --ai-score --sort-by score
```

## 🔥 XSS-Vibes Integration

### Endpoint Discovery
```bash
# Discover XSS endpoints
python ectractorcli.py content.html --xss-discover --target-domain example.com

# Custom discovery depth
python ectractorcli.py content.html --xss-discover --xss-depth 3
```

### Vulnerability Scanning
```bash
# Scan URLs for XSS
python ectractorcli.py urls.txt --xss-scan --xss-threads 10

# Custom XSS payloads
python ectractorcli.py urls.txt --xss-scan --xss-payloads custom.txt

# Combined discovery and scanning
python ectractorcli.py content.html --xss-discover --xss-scan --target-domain example.com
```

## 🌐 Network & Security Options

### HTTP Configuration
```bash
# Custom headers and cookies
python ectractorcli.py urls.txt --fetch-urls --headers '{"Authorization": "Bearer token"}'

# Proxy support
python ectractorcli.py urls.txt --fetch-urls --proxy http://proxy:8080

# SSL options
python ectractorcli.py urls.txt --fetch-urls --insecure  # Disable SSL verification
python ectractorcli.py urls.txt --fetch-urls --verify-ssl  # Enable SSL verification
```

### Rate Limiting & Timeouts
```bash
# Configure timeouts and retries
python ectractorcli.py urls.txt --fetch-urls --timeout 30 --retry-count 3

# Control request rate
python ectractorcli.py urls.txt --fetch-urls --threads 5 --retry-delay 2
```

## 📝 File Processing

### Directory Scanning
```bash
# Recursive with patterns
python ectractorcli.py /path/to/dir --recursive --file-patterns "*.html,*.js"

# Exclude certain files
python ectractorcli.py /path/to/dir --recursive --exclude-patterns "*.min.*,*.gz"

# Smart file detection
python ectractorcli.py /path/to/dir --recursive --smart-detect
```

### Encoding & Size Limits
```bash
# Custom encoding
python ectractorcli.py file.txt --encoding utf-16

# File size limits
python ectractorcli.py urls.txt --fetch-urls --max-size 10  # 10MB limit
```

## 🎯 Common Use Cases

### Security Assessment
```bash
# Comprehensive security scan
python ectractorcli.py target_app/ \
  --recursive \
  --types secret,auth,api,url \
  --deep-js \
  --ai-score \
  --score-threshold 3 \
  --output security_findings.json \
  --json
```

### Subdomain Enumeration
```bash
# Extract subdomains for target domain
python ectractorcli.py recon_data.txt \
  --target-domain example.com \
  --types subdomain,domain,url \
  --dedup \
  --sort-results \
  --output subdomains.txt
```

### API Discovery
```bash
# Find APIs and documentation
python ectractorcli.py app_content/ \
  --recursive \
  --types api,swagger,url \
  --filter-regex "api|v1|v2|docs|swagger" \
  --ai-score \
  --tagged \
  --output api_endpoints.txt
```

### XSS Testing Pipeline
```bash
# Complete XSS testing workflow
python ectractorcli.py target_content.html \
  --fetch-urls \
  --target-domain target.com \
  --xss-discover \
  --xss-scan \
  --xss-threads 15 \
  --verbose \
  --output xss_results.txt
```

### Large-Scale URL Processing
```bash
# Process large URL lists efficiently
python ectractorcli.py massive_urls.txt \
  --fetch-urls \
  --threads 25 \
  --timeout 15 \
  --dedup \
  --limit 1000 \
  --to-jsonl \
  --output processed_data.jsonl
```

## 🔍 Debugging & Monitoring

### Verbose Output
```bash
# Different verbosity levels
python ectractorcli.py file.html --quiet           # Minimal output
python ectractorcli.py file.html --verbose         # Detailed output
python ectractorcli.py file.html --debug          # Debug information
```

### Performance Monitoring
```bash
# Enable statistics and benchmarking
python ectractorcli.py file.html --stats --benchmark

# Monitor processing
python ectractorcli.py urls.txt --fetch-urls --verbose --threads 10
```

## 📋 Output Examples

### Plain Text Output
```
https://example.com/api/v1
https://example.com/admin
admin@example.com
api_key:abc123def456
```

### JSON Output
```json
{
  "url": ["https://example.com/api/v1", "https://example.com/admin"],
  "email": ["admin@example.com"],
  "secret": ["api_key:abc123def456"]
}
```

### Tagged Output with AI Scores
```
## URL (2 found):
[Score:  8] https://example.com/admin
[Score:  6] https://example.com/api/v1

## EMAIL (1 found):
[Score:  3] admin@example.com

## SECRET (1 found):
[Score: 15] api_key:abc123def456
```

## ⚡ Performance Tips

### Optimal Thread Configuration
```bash
# For local files
python ectractorcli.py dir/ --recursive --threads 4

# For URL fetching (adjust based on network)
python ectractorcli.py urls.txt --fetch-urls --threads 20

# For XSS scanning
python ectractorcli.py urls.txt --xss-scan --xss-threads 10
```

### Memory Management
```bash
# Large dataset processing
python ectractorcli.py huge_data.txt --to-jsonl --dedup --limit 10000

# Control resource usage
python ectractorcli.py data/ --recursive --max-size 5 --exclude-patterns "*.log,*.tmp"
```

## 🛡️ Security Best Practices

### Safe URL Fetching
```bash
# Secure configuration
python ectractorcli.py urls.txt \
  --fetch-urls \
  --verify-ssl \
  --timeout 30 \
  --max-size 5 \
  --user-agent "Security Scanner/1.0"
```

### Data Sanitization
```bash
# Filter sensitive patterns
python ectractorcli.py data.txt \
  --exclude-regex "password|secret|token" \
  --min-length 5 \
  --max-length 100
```

## 📞 Getting Help

### Built-in Help
```bash
python ectractorcli.py --help              # Full help
```

### Documentation
- **Full Documentation**: `EXTRACTORCLI_DOCUMENTATION.md`
- **XSS Integration**: `XSS_VIBES_ENHANCEMENT_GUIDE.md`
- **Module Overview**: Part of ReconCLI suite

---

*ExtractorCLI v2.0 - Advanced data extraction with security focus. Part of the ReconCLI reconnaissance toolkit.*
