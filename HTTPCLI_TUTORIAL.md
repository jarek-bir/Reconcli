# 🌐 HTTPCli Tutorial - Quick Start Guide

This tutorial will guide you through the essential features of HTTPCli, from basic domain scanning to advanced security assessment workflows.

## 🚀 Quick Start

### 1. Basic Domain Scanning
The simplest way to analyze a domain:

```bash
# Scan a single domain
reconcli httpcli --domain example.com

# Expected output:
# + https://example.com -> 200 | Example Domain
```

### 2. Security Analysis
Add security header analysis:

```bash
# Security scan with grading
reconcli httpcli --domain example.com --security-scan

# Expected output:
# + https://example.com -> 200 | Example Domain | Security: F
```

### 3. Technology Detection
Identify web technologies:

```bash
# Detect web stack
reconcli httpcli --domain target.com --tech-detection

# Shows: servers, frameworks, CMS, and more
```

## 🛡️ Security Assessment Workflow

### Step 1: Comprehensive Security Scan
```bash
# Full security assessment
reconcli httpcli --domain target.com --security-scan --check-waf --check-cors
```

**What this does:**
- Analyzes security headers (X-Frame-Options, CSP, HSTS, etc.)
- Detects WAF/CDN solutions (Cloudflare, Akamai, etc.)  
- Tests CORS configuration for vulnerabilities
- Provides security grade (A+ to F)

### Step 2: Vulnerability Scanning
```bash
# Add Nuclei vulnerability scanning
reconcli httpcli --domain target.com --security-scan --nuclei --export-vulnerabilities
```

**Features:**
- Runs Nuclei templates against the target
- Exports only vulnerable URLs to separate files
- Comprehensive vulnerability reporting

### Step 3: Visual Verification
```bash
# Capture screenshots for manual review
reconcli httpcli --domain target.com --security-scan --screenshot
```

**Requirements:**
- Install Selenium: `pip install selenium`
- Chrome/Chromium browser installed
- Screenshots saved to `httpcli_output/screenshots/`

## ⚡ Performance & Caching

### Cache System Demo
```bash
# First run (no cache)
time reconcli httpcli --domain example.com --security-scan
# Time: ~2.03s

# Enable caching
reconcli httpcli --domain example.com --security-scan --cache
# First run: ~2.03s (builds cache)
# Second run: ~0.02s (101x faster!)
```

### Cache Management
```bash
# View cache statistics
reconcli httpcli --cache-stats

# Clear cache when needed
reconcli httpcli --clear-cache

# Custom cache configuration
reconcli httpcli --domain target.com --cache --cache-dir /tmp/http_cache --cache-max-age 12
```

## 📊 Batch Processing

### Process Multiple Targets
```bash
# Create a file with URLs
echo "https://example.com
https://httpbin.org
https://google.com" > urls.txt

# Batch analysis
reconcli httpcli --input urls.txt --security-scan --tech-detection
```

### Advanced Batch Processing
```bash
# Large scale analysis with optimization
reconcli httpcli --input large_list.txt --security-scan --cache \
  --threads 20 --rate-limit 10/s --export-vulnerabilities --verbose
```

## 🎯 Bug Bounty Workflow

### Complete Bug Bounty Scan
```bash
# Comprehensive assessment for bug bounty
reconcli httpcli --domain target.com \
  --security-scan \
  --check-waf \
  --check-cors \
  --nuclei \
  --tech-detection \
  --screenshot \
  --benchmark \
  --export-vulnerabilities \
  --store-db \
  --program "hackerone-target" \
  --cache \
  --verbose
```

**What this includes:**
- Security header analysis with grading
- WAF/CDN detection for bypass strategies
- CORS vulnerability testing
- Nuclei vulnerability scanning
- Technology stack fingerprinting
- Visual screenshots for reporting
- Performance benchmarking
- Database storage for tracking
- Vulnerability-only export
- Caching for repeated testing

### API Security Testing
```bash
# Test API endpoints with custom headers
reconcli httpcli --input api_endpoints.txt \
  --check-cors \
  --custom-headers '{"Authorization":"Bearer test","X-API-Key":"testkey"}' \
  --export-vulnerabilities \
  --jsonout
```

## 📈 Performance Analysis

### Response Time Benchmarking
```bash
# Test site performance
reconcli httpcli --domain target.com --benchmark --check-compression

# Multiple samples for accuracy
reconcli httpcli --domain site.com --benchmark --verbose
```

**Output includes:**
- Minimum/Maximum/Average response times
- Compression support (Gzip, Brotli)
- HTTP/2 support detection
- Performance recommendations

### Load Testing
```bash
# Simulate higher load
reconcli httpcli --input urls.txt --benchmark --threads 50 --rate-limit 30/s
```

## 🔧 Advanced Features

### Custom Headers
```bash
# Bug bounty research headers
reconcli httpcli --domain target.com \
  --custom-headers '{"X-Bug-Hunter":"researcher","User-Agent":"CustomScanner/1.0"}' \
  --security-scan
```

### Proxy Integration
```bash
# Use with Burp Suite
reconcli httpcli --domain target.com --proxy http://127.0.0.1:8080 --security-scan

# SOCKS proxy
reconcli httpcli --domain target.com --proxy socks5://127.0.0.1:1080
```

### Technology Detection
```bash
# Enhanced technology fingerprinting
reconcli httpcli --domain target.com --tech-detection --wappalyzer

# Detect specific technologies
reconcli httpcli --input wordpress_sites.txt --tech-detection --verbose
```

## 📤 Export & Reporting

### JSON Export
```bash
# Export detailed JSON data
reconcli httpcli --domain target.com --security-scan --jsonout

# Generates:
# - http_results.json (complete data)
# - http_results.csv (tabular format)
```

### Markdown Reports
```bash
# Generate readable reports
reconcli httpcli --input corporate_sites.txt --security-scan --markdown

# Creates detailed markdown report with:
# - Security summaries
# - Technology breakdowns  
# - Detailed findings per URL
```

### Header Analysis
```bash
# Export HTTP headers in various formats
reconcli httpcli --domain target.com --headers --headers-format json
reconcli httpcli --input urls.txt --headers --headers-format csv
reconcli httpcli --domain site.com --headers --headers-format table \
  --header-filter "Server,X-Powered-By,X-Frame-Options"
```

### Vulnerability Exports
```bash
# Export only problematic URLs
reconcli httpcli --input large_scope.txt --security-scan --export-vulnerabilities

# Generates:
# - vulnerabilities.json (detailed findings)
# - vulnerable_urls.txt (simple URL list)
```

## 🗄️ Database Integration

### Store Results
```bash
# Store findings in database
reconcli httpcli --domain target.com --security-scan --store-db --program "assessment-2024"

# Batch storage with classification
reconcli httpcli --input corporate_assets.txt --security-scan \
  --store-db --target-domain "company.com" --program "corporate-pentest"
```

**Benefits:**
- Persistent storage across scans
- Historical tracking of changes
- Integration with other ReconCLI modules
- Program-based organization

## 🚨 Common Use Cases

### 1. Quick Security Check
```bash
# Fast security assessment
reconcli httpcli --domain target.com --security-scan --cache
```

### 2. Technology Reconnaissance
```bash
# Identify technology stack
reconcli httpcli --domain target.com --tech-detection --wappalyzer --verbose
```

### 3. CORS Vulnerability Testing
```bash
# Test API CORS configuration
reconcli httpcli --domain api.target.com --check-cors --export-vulnerabilities
```

### 4. WAF Bypass Research
```bash
# Identify WAF for bypass strategies
reconcli httpcli --domain target.com --check-waf --custom-headers '{"X-Originating-IP":"127.0.0.1"}'
```

### 5. Performance Monitoring
```bash
# Monitor site performance
reconcli httpcli --domain production-site.com --benchmark --check-compression --cache
```

### 6. Bulk Security Assessment
```bash
# Assess multiple subdomains
reconcli httpcli --input subdomains.txt --security-scan --nuclei \
  --export-vulnerabilities --cache --threads 15
```

## 🔍 Troubleshooting

### Debug Mode
```bash
# Enable verbose output for debugging
reconcli httpcli --domain problematic-site.com --verbose
```

### Timeout Issues
```bash
# Increase timeout for slow sites
reconcli httpcli --domain slow-site.com --timeout 30 --retries 3
```

### Rate Limiting
```bash
# Respect rate limits
reconcli httpcli --input urls.txt --rate-limit 5/s --verbose
```

### Proxy Issues
```bash
# Test proxy connectivity
reconcli httpcli --domain httpbin.org --proxy http://127.0.0.1:8080 --verbose
```

## 🎓 Learning Path

### Beginner
1. Start with `--domain` single domain scans
2. Add `--security-scan` for header analysis
3. Try `--tech-detection` for technology identification
4. Enable `--cache` for performance

### Intermediate  
1. Use `--input` for batch processing
2. Add `--nuclei` for vulnerability scanning
3. Try `--check-cors` and `--check-waf`
4. Experiment with `--custom-headers`

### Advanced
1. Combine all features for comprehensive assessment
2. Use `--store-db` for persistent tracking
3. Set up automated workflows with caching
4. Integrate with other ReconCLI modules

## 📚 Next Steps

After mastering HTTPCli basics:
1. **Combine with DNScli**: Use subdomain results as HTTPCli input
2. **Feed to VulnSQLiCli**: Test identified URLs for SQL injection
3. **Database Integration**: Store and correlate findings across modules
4. **Automation**: Create scripts for repeated assessments

---

**💡 Pro Tip**: Always enable caching (`--cache`) for repeated testing - it provides 100x+ speed improvements while ensuring consistent results!

**📖 For complete reference, see HTTPCLI_DOCUMENTATION.md**
