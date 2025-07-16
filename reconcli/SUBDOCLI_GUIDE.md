# 🤖 SubdoCLI - Advanced Subdomain Enumeration Guide

## 📖 Overview

SubdoCLI is ReconCLI's advanced subdomain enumeration module, featuring BBOT (Bighuge BLS OSINT Tool) integration with 53+ specialized modules for superior subdomain discovery. This tool combines traditional passive enumeration tools with cutting-edge BBOT technology for comprehensive subdomain reconnaissance.

## 🚀 Key Features

### 🤖 BBOT Integration
- **53+ Specialized Modules**: Advanced subdomain enumeration with industry-leading tools
- **Passive & Active Sources**: anubisdb, crt.sh, chaos, hackertarget, certspotter, dnsdumpster, and 47+ more
- **Certificate Transparency**: Real-time monitoring of certificate transparency logs
- **DNS Bruteforcing**: Intelligent subdomain bruteforcing with custom wordlists
- **Cloud Resource Discovery**: GitHub code search, postman workspace enumeration
- **Intelligent Mutations**: Advanced subdomain mutation and permutation techniques

### 🛠️ Traditional Tools Support
- **Subfinder**: Fast passive subdomain enumeration
- **Findomain**: Multi-source subdomain discovery
- **Assetfinder**: Simple and effective subdomain finder
- **Amass**: OWASP's comprehensive subdomain enumeration tool
- **Chaos**: Chaos dataset integration
- **RapidDNS**: Fast DNS-based discovery
- **crt.sh**: Certificate transparency log analysis
- **BufferOver**: DNS over HTTPS queries
- **Gobuster**: DNS brute-forcing (active mode)
- **FFuf**: Web fuzzer for subdomain discovery (active mode)
- **DNSRecon**: Comprehensive DNS reconnaissance (active mode)

### 🧠 Advanced Processing
- **Multi-threaded Resolution**: Concurrent IP address resolution with PTR records
- **HTTP/HTTPS Service Detection**: Automatic service discovery with title extraction
- **Resume Functionality**: Continue interrupted scans seamlessly
- **Tool Performance Analytics**: Detailed statistics and performance metrics

### 📊 Export & Reporting
- **CSV Export**: Structured data for spreadsheet analysis and data processing
- **JSON Export**: Programmatic analysis format with comprehensive metadata
- **TXT Export**: Human-readable reports with organized sections and statistics
- **Markdown Reports**: Professional documentation format
- **Database Integration**: Complete SQLite storage with ReconCLI ecosystem

## 🚀 Quick Start

### Basic Usage
```bash
# Simple subdomain enumeration (traditional passive tools)
reconcli subdocli --domain example.com --verbose

# Only traditional passive tools (no BBOT, no active)
reconcli subdocli --domain example.com --passive-only --verbose

# Only traditional active tools (no BBOT, no passive)
reconcli subdocli --domain example.com --active-only --verbose

# BBOT-powered enumeration (recommended)
reconcli subdocli --domain example.com --bbot --verbose

# Intensive BBOT mode with maximum coverage
reconcli subdocli --domain example.com --bbot-intensive --verbose
```

### Advanced Workflows
```bash
# Complete reconnaissance workflow
reconcli subdocli --domain example.com --bbot-intensive \
  --resolve --probe-http --markdown --export csv \
  --store-db --show-stats --verbose

# All tools + BBOT integration
reconcli subdocli --domain example.com --all-tools \
  --resolve --probe-http --export json --verbose

# Resume interrupted scan
reconcli subdocli --domain example.com --bbot --resume --verbose
```

## 📋 Command Line Options

### Core Options
```bash
--domain, -d          Target domain for subdomain enumeration (required)
--output-dir, -o      Directory to save results (default: output)
--verbose, -v         Enable verbose output
--timeout             Timeout for individual operations (default: 30s)
--threads             Number of threads for concurrent operations (default: 50)
```

### BBOT Integration
```bash
--bbot                Enable BBOT with 53+ passive modules
--bbot-intensive      Enable BBOT intensive mode with aggressive bruteforcing
```

### Tool Selection
```bash
--all-tools           Use all available tools (passive + active)
--active              Include active enumeration tools (bruteforcing)
```

### Processing Options
```bash
--resolve             Resolve subdomains to IP addresses
--probe-http          Probe HTTP/HTTPS services
--ignore-ssl-errors   Ignore SSL certificate errors when probing HTTPS
```

### Resume & State Management
```bash
--resume              Resume previous scan
--clear-resume        Clear previous resume state
```

### Export & Reporting
```bash
--export              Export results (csv|json|txt)
--markdown            Generate Markdown report
--show-stats          Show detailed statistics
```

### Database Integration
```bash
--store-db            Store results in ReconCLI database
--target-domain       Primary target domain for database storage
--program             Bug bounty program name for classification
```

## 🎯 Usage Examples

### 1. Basic BBOT Enumeration
```bash
# BBOT with passive sources
reconcli subdocli --domain example.com --bbot --verbose

# Output: Discovers subdomains using 53+ BBOT modules
# Results: Saved to output/example.com/
```

### 2. Intensive Reconnaissance
```bash
# Maximum coverage with all features
reconcli subdocli --domain target.com --bbot-intensive \
  --resolve --probe-http --all-tools \
  --export csv --markdown --store-db \
  --show-stats --verbose

# Features activated:
# ✅ BBOT intensive mode (53+ modules + aggressive bruteforcing)
# ✅ Traditional tools (subfinder, findomain, amass, etc.)
# ✅ Active enumeration (gobuster, ffuf, dnsrecon)
# ✅ IP resolution with PTR records
# ✅ HTTP/HTTPS service detection
# ✅ CSV export for analysis
# ✅ Markdown report generation
# ✅ Database storage
# ✅ Detailed statistics
```

### 3. Export Formats Showcase
```bash
# CSV export for spreadsheet analysis
reconcli subdocli --domain example.com --bbot --export csv --verbose

# JSON export for programmatic processing
reconcli subdocli --domain example.com --bbot --export json --verbose

# TXT export for human-readable reports
reconcli subdocli --domain example.com --bbot --export txt --verbose
```

### 4. Resume Functionality
```bash
# Start scan
reconcli subdocli --domain large-target.com --bbot-intensive --verbose

# Resume if interrupted
reconcli subdocli --domain large-target.com --bbot-intensive --resume --verbose

# Clear resume state
reconcli subdocli --domain large-target.com --clear-resume
```

### 5. Database Integration
```bash
# Store results for bug bounty program
reconcli subdocli --domain target.com --bbot \
  --store-db --program "HackerOne Program" \
  --target-domain target.com --verbose

# Results stored in ReconCLI database for:
# - Cross-module analysis
# - Historical tracking
# - Program organization
```

### 6. Traditional Tools Only

```bash
# Use only traditional passive tools (subfinder, findomain, amass, etc.)
reconcli subdocli --domain example.com --passive-only --export csv --verbose

# Use only traditional active tools (gobuster, ffuf, dnsrecon)
reconcli subdocli --domain example.com --active-only --resolve --verbose

# Compare traditional vs BBOT results
reconcli subdocli --domain example.com --passive-only --export txt --verbose
reconcli subdocli --domain example.com --bbot --export txt --verbose
```

## 🎯 Tool Selection Strategies

### Pure Traditional Approach
```bash
# Fast passive-only scan with traditional tools
reconcli subdocli --domain target.com --passive-only --timeout 60 --verbose

# Complete active enumeration with bruteforcing
reconcli subdocli --domain target.com --active-only --threads 20 --verbose
```

### Hybrid Approaches
```bash
# Traditional + BBOT passive
reconcli subdocli --domain target.com --bbot --verbose

# Everything enabled (maximum coverage)
reconcli subdocli --domain target.com --all-tools --bbot-intensive --verbose
```

## 📊 Output Formats

### CSV Export Format
```csv
subdomain,ip,ptr,resolved,http_status,https_status,http_title,https_title,http_active,https_active,discovery_tool
api.example.com,192.168.1.1,api.example.com,True,200,200,API Gateway,API Gateway,True,True,bbot_passive
admin.example.com,192.168.1.2,,True,403,403,Forbidden,Forbidden,True,True,subfinder
dev.example.com,,,False,,,,,False,False,bbot_passive
```

### JSON Export Structure
```json
{
  "metadata": {
    "domain": "example.com",
    "scan_time": "2025-07-15T23:00:00",
    "total_subdomains": 150,
    "reconcli_version": "2.0.0",
    "bbot_integration": true
  },
  "tool_statistics": {
    "bbot_passive": 45,
    "bbot_comprehensive": 32,
    "subfinder": 28,
    "findomain": 25
  },
  "subdomains": {
    "list": ["api.example.com", "admin.example.com", ...],
    "count": 150
  },
  "resolved_subdomains": {
    "count": 120,
    "data": [...]
  },
  "http_services": {
    "http_count": 45,
    "https_count": 78,
    "data": [...]
  },
  "statistics": {
    "resolution_rate": 80.0,
    "http_service_rate": 30.0,
    "https_service_rate": 52.0
  }
}
```

### TXT Export Format
```txt
# Subdomain Enumeration Report for example.com
# Scan Time: 2025-07-15T23:00:00
# Total Subdomains: 150
# Generated by ReconCLI SubdoCLI with BBOT Integration

# TOOL STATISTICS
# ================
# bbot_passive: 45 subdomains
# subfinder: 28 subdomains
# findomain: 25 subdomains

# ALL DISCOVERED SUBDOMAINS
# ==========================
api.example.com
admin.example.com
dev.example.com
...

# RESOLVED SUBDOMAINS WITH IP ADDRESSES
# ======================================
api.example.com -> 192.168.1.1 (PTR: api.example.com)
admin.example.com -> 192.168.1.2

# ACTIVE HTTP/HTTPS SERVICES
# ===========================
api.example.com -> HTTP(200) | HTTPS(200)
admin.example.com -> HTTP(403) | HTTPS(403)

# SCAN STATISTICS SUMMARY
# =======================
# Resolution Rate: 120/150 (80.0%)
# HTTP Services: 45/150 (30.0%)
# HTTPS Services: 78/150 (52.0%)
```

## 🔧 Advanced Configuration

### BBOT Configuration
SubdoCLI automatically configures BBOT with optimal settings:
- **Passive Mode**: 20+ passive sources for safe reconnaissance
- **Comprehensive Mode**: Combines passive and safe active modules
- **Intensive Mode**: Maximum coverage with aggressive bruteforcing
- **Kitchen Sink**: All available BBOT modules for complete discovery

### Tool Integration
```bash
# Traditional tools only (no BBOT)
reconcli subdocli --domain example.com --verbose

# BBOT + traditional tools
reconcli subdocli --domain example.com --bbot --all-tools --verbose

# Active enumeration (includes bruteforcing)
reconcli subdocli --domain example.com --active --verbose
```

### Performance Tuning
```bash
# High-performance scanning
reconcli subdocli --domain example.com --bbot \
  --threads 100 --timeout 60 --verbose

# Conservative scanning
reconcli subdocli --domain example.com --bbot \
  --threads 20 --timeout 15 --verbose
```

## 📈 Performance & Statistics

### Tool Performance Metrics
- **Discovery Rate**: Subdomains found per tool per minute
- **Accuracy**: Percentage of valid subdomains discovered
- **Coverage**: Unique sources and discovery methods
- **Resolution Success**: IP resolution success rate
- **Service Detection**: HTTP/HTTPS service discovery rate

### Expected Results
- **BBOT Passive**: 50-200 subdomains for typical domains
- **BBOT Intensive**: 100-500+ subdomains with bruteforcing
- **Traditional Tools**: 20-100 subdomains from public sources
- **Combined Mode**: 150-800+ subdomains maximum coverage

## 🎯 Best Practices

### 1. Start with BBOT Passive
```bash
# Safe, comprehensive passive enumeration
reconcli subdocli --domain target.com --bbot --verbose
```

### 2. Use Intensive Mode for Maximum Coverage
```bash
# When you need complete subdomain discovery
reconcli subdocli --domain target.com --bbot-intensive \
  --resolve --probe-http --export json --verbose
```

### 3. Always Export Results
```bash
# Export for analysis and documentation
reconcli subdocli --domain target.com --bbot \
  --export csv --markdown --store-db --verbose
```

### 4. Use Resume for Large Targets
```bash
# For domains with many subdomains
reconcli subdocli --domain large-target.com --bbot-intensive \
  --resume --verbose
```

### 5. Integrate with Database
```bash
# For program management and tracking
reconcli subdocli --domain target.com --bbot \
  --store-db --program "Bug Bounty Program" --verbose
```

## 🔍 Troubleshooting

### Common Issues

1. **BBOT Not Found**
   ```bash
   # Ensure BBOT is installed in virtual environment
   pip install bbot
   ```

2. **Timeout Issues**
   ```bash
   # Increase timeout for slow networks
   reconcli subdocli --domain example.com --timeout 60 --verbose
   ```

3. **Resume Not Working**
   ```bash
   # Clear resume state if corrupted
   reconcli subdocli --domain example.com --clear-resume
   ```

4. **Permission Errors**
   ```bash
   # Check output directory permissions
   mkdir -p output && chmod 755 output
   ```

## 🌟 Integration with Other Modules

SubdoCLI integrates seamlessly with other ReconCLI modules:

### DNS Resolution
```bash
# Use subdocli output with dnscli
reconcli subdocli --domain example.com --bbot --export txt
reconcli dnscli --input output/example.com/all.txt --verbose
```

### Port Scanning
```bash
# Use resolved IPs for port scanning
reconcli subdocli --domain example.com --bbot --resolve --export json
# Extract IPs and use with portcli
```

### HTTP Analysis
```bash
# Use HTTP services for further analysis
reconcli subdocli --domain example.com --bbot --probe-http --export csv
# Use active services for screenshot analysis, etc.
```

## 📚 Additional Resources

- **BBOT Documentation**: [https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)
- **ReconCLI Database**: See `reconcli/db/` for database integration
- **Export Features**: See `EXPORT_FEATURES_SUMMARY.md` for detailed export documentation
- **BBOT Integration**: See `BBOT_INTEGRATION_GUIDE.md` for advanced BBOT usage

## 🎉 Conclusion

SubdoCLI provides the most comprehensive subdomain enumeration capabilities available, combining the power of BBOT's 53+ modules with traditional tools and advanced processing features. Whether you're conducting passive reconnaissance or aggressive subdomain discovery, SubdoCLI delivers superior results with professional reporting and database integration.

**Start your subdomain enumeration journey:**
```bash
reconcli subdocli --domain your-target.com --bbot-intensive \
  --resolve --probe-http --export csv --store-db --verbose
```

🎯 **Happy Hunting!** 🚀
