# WHOISFREAKSCLI - Advanced WHOIS Intelligence for ReconCLI

## 🔍 Overview

WhoisFreaksCLI is a comprehensive WHOIS analysis and domain intelligence gathering module for ReconCLI. It leverages the WhoisFreaks API to provide detailed domain information, historical records, DNS analysis, and advanced reconnaissance capabilities with rate limiting, caching, and security-focused analysis.

## 🚀 Features

- **Comprehensive WHOIS Lookup**: Detailed domain registration information
- **Historical Analysis**: Domain history and changes over time
- **DNS Intelligence**: Advanced DNS record analysis and monitoring
- **Bulk Processing**: Efficient processing of multiple domains with rate limiting
- **Database Integration**: Automatic storage of findings in ReconCLI database
- **Security Analysis**: Risk assessment and security-focused categorization
- **Resume Capability**: Continue interrupted large-scale operations
- **Notifications**: Integration with notification systems for alerts
- **Export Formats**: JSON, CSV, and markdown reporting

## 🔧 Installation & Setup

### API Key Configuration
```bash
# Set WhoisFreaks API key
export WHOISFREAKS_API_KEY="your_api_key_here"

# Or create config file
mkdir -p ~/.reconcli
echo '{"whoisfreaks_api_key": "your_key"}' > ~/.reconcli/config.json
```

### Get WhoisFreaks API Key
1. Visit: https://whoisfreaks.com/
2. Register for an account
3. Generate API key from dashboard
4. Configure in ReconCLI

## 📋 Commands

### 🔍 lookup
Single domain WHOIS lookup with comprehensive analysis
```bash
python reconcli_csvtk.py whoisfreakscli lookup <domain> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli lookup tesla.com
python reconcli_csvtk.py whoisfreakscli lookup tesla.com --save-db --output tesla_whois.json
python reconcli_csvtk.py whoisfreakscli lookup tesla.com --analysis --export-csv
```

**Options:**
- `--save-db`: Store results in ReconCLI database
- `--output FILE`: Save results to JSON file
- `--analysis`: Show detailed security analysis
- `--export-csv`: Export to CSV format
- `--verbose`: Detailed output

### 🗂️ bulk
Bulk WHOIS analysis for multiple domains
```bash
python reconcli_csvtk.py whoisfreakscli bulk <domains_file> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --output-dir results/
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --threads 5 --rate-limit 10
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --resume --save-db
```

**Options:**
- `--output-dir DIR`: Output directory for results
- `--threads NUM`: Number of concurrent threads (default: 5)
- `--rate-limit NUM`: Requests per minute (default: 60)
- `--save-db`: Store all results in database
- `--resume`: Resume interrupted operation
- `--format FORMAT`: Output format (json/csv/both)

### 📊 analyze
Analyze domain patterns and security indicators
```bash
python reconcli_csvtk.py whoisfreakscli analyze <domains_file> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli analyze domains.txt --security-focus
python reconcli_csvtk.py whoisfreakscli analyze domains.txt --patterns suspicious.json
python reconcli_csvtk.py whoisfreakscli analyze domains.txt --export-findings
```

**Options:**
- `--security-focus`: Focus on security indicators
- `--patterns FILE`: Custom pattern file for analysis
- `--export-findings`: Export security findings
- `--risk-threshold LEVEL`: Risk threshold (low/medium/high)

### 🕒 history
Domain history and changes analysis
```bash
python reconcli_csvtk.py whoisfreakscli history <domain> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli history tesla.com --days 365
python reconcli_csvtk.py whoisfreakscli history tesla.com --changes-only
python reconcli_csvtk.py whoisfreakscli history tesla.com --export-timeline
```

**Options:**
- `--days NUM`: Number of days to look back
- `--changes-only`: Show only records with changes
- `--export-timeline`: Export timeline visualization

### 🌐 dns
Advanced DNS analysis and monitoring
```bash
python reconcli_csvtk.py whoisfreakscli dns <domain> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli dns tesla.com --all-records
python reconcli_csvtk.py whoisfreakscli dns tesla.com --monitor --interval 3600
python reconcli_csvtk.py whoisfreakscli dns tesla.com --security-scan
```

**Options:**
- `--all-records`: Fetch all DNS record types
- `--monitor`: Enable continuous monitoring
- `--interval SEC`: Monitoring interval in seconds
- `--security-scan`: Security-focused DNS analysis

### 📈 monitor
Continuous domain monitoring and alerting
```bash
python reconcli_csvtk.py whoisfreakscli monitor <domains_file> [options]

# Examples:
python reconcli_csvtk.py whoisfreakscli monitor important_domains.txt --interval 3600
python reconcli_csvtk.py whoisfreakscli monitor domains.txt --alert-webhook https://hooks.slack.com/...
python reconcli_csvtk.py whoisfreakscli monitor domains.txt --changes-only --save-db
```

**Options:**
- `--interval SEC`: Check interval in seconds (default: 3600)
- `--alert-webhook URL`: Webhook for alerts
- `--changes-only`: Alert only on changes
- `--save-db`: Store monitoring results

## 🎯 Usage Examples

### Basic Domain Intelligence
```bash
# Single domain lookup
python reconcli_csvtk.py whoisfreakscli lookup tesla.com --save-db --analysis

# Bulk domain analysis
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --threads 3 --rate-limit 30

# Export results to CSV
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --format csv --output-dir results/
```

### Security-Focused Analysis
```bash
# Security analysis of domain patterns
python reconcli_csvtk.py whoisfreakscli analyze suspicious_domains.txt --security-focus

# Monitor critical domains for changes
python reconcli_csvtk.py whoisfreakscli monitor critical_domains.txt --interval 1800 --changes-only

# Historical analysis for incident response
python reconcli_csvtk.py whoisfreakscli history compromised.com --days 90 --changes-only
```

### Large-Scale Operations
```bash
# Process large domain list with resume capability
python reconcli_csvtk.py whoisfreakscli bulk large_domains.txt \
  --threads 10 --rate-limit 100 --resume --save-db --output-dir bulk_results/

# Continuous monitoring with notifications
python reconcli_csvtk.py whoisfreakscli monitor enterprise_domains.txt \
  --interval 3600 --alert-webhook https://hooks.slack.com/services/... --save-db
```

### Integration with Database
```bash
# Export database findings for analysis
python reconcli_csvtk.py dbcli export --table whois_findings --format csv

# Analyze exported WHOIS data
python reconcli_csvtk.py csvtkcli analyze output/exports/whois_findings_export.csv

# Generate security report from WHOIS data
python reconcli_csvtk.py csvtkcli security-report output/exports/whois_findings_export.csv
```

## 🛡️ Security Analysis Features

### Risk Indicators
- **Suspicious Patterns**: Recently registered domains, frequent changes
- **Privacy Services**: Domains using privacy protection services
- **Suspicious Registrars**: Domains from high-risk registrars
- **Geographic Anomalies**: Unexpected geographic registration patterns
- **Short-lived Domains**: Domains with very recent registration

### Security Categories

#### 🚨 HIGH RISK
- Domains registered in last 30 days
- Multiple registrar changes
- Known malicious registrars
- Privacy service abuse patterns

#### 🟠 MEDIUM RISK
- Recently modified DNS records
- Suspicious geographic patterns
- Short registration periods
- Unusual technical contacts

#### 🔵 LOW RISK
- Established domains (>1 year)
- Stable registration patterns
- Reputable registrars
- Consistent contact information

## 📊 Output Formats

### JSON Output
```json
{
  "domain": "tesla.com",
  "whois_data": {
    "registrar": "MarkMonitor Inc.",
    "registration_date": "1992-11-04",
    "expiration_date": "2025-11-03",
    "name_servers": ["ns1.markmonitor.com", "ns2.markmonitor.com"],
    "status": ["clientDeleteProhibited", "clientTransferProhibited"]
  },
  "security_analysis": {
    "risk_level": "low",
    "indicators": [],
    "recommendations": ["Monitor for DNS changes", "Track renewal dates"]
  },
  "dns_records": {
    "A": ["104.109.12.83"],
    "MX": ["mx1.tesla.com", "mx2.tesla.com"],
    "TXT": ["v=spf1 include:_spf.tesla.com ~all"]
  }
}
```

### CSV Export Format
```csv
domain,registrar,registration_date,expiration_date,name_servers,status,risk_level,last_updated
tesla.com,MarkMonitor Inc.,1992-11-04,2025-11-03,"ns1.markmonitor.com;ns2.markmonitor.com",active,low,2025-07-12
```

### Security Report
```markdown
# WHOIS Security Analysis Report

**Analysis Date:** 2025-07-12
**Total Domains Analyzed:** 250

## Risk Summary
- 🚨 **HIGH RISK**: 12 domains (4.8%)
- 🟠 **MEDIUM RISK**: 45 domains (18%)
- 🔵 **LOW RISK**: 193 domains (77.2%)

## Key Findings
### High-Risk Domains
1. **suspicious-domain.com** - Registered 5 days ago
2. **fake-bank.org** - Multiple registrar changes
3. **phishing-site.net** - Privacy service abuse

### Recommendations
1. 🔍 **Immediate Investigation**: Review high-risk domains
2. 🛡️ **Monitoring**: Set up alerts for domain changes
3. 📊 **Regular Audits**: Schedule monthly WHOIS reviews
```

## 🔄 Integration Workflows

### Subdomain Discovery Integration
```bash
# Discover subdomains and analyze parent domain
python reconcli_csvtk.py subdocli tesla.com --output subdomains.txt
python reconcli_csvtk.py whoisfreakscli lookup tesla.com --save-db --analysis

# Bulk analyze discovered domains
python reconcli_csvtk.py whoisfreakscli bulk subdomains.txt --save-db --security-focus
```

### Database Export and Analysis
```bash
# Export WHOIS data from database
python reconcli_csvtk.py dbcli export --table whois_findings --analysis

# Advanced CSV analysis of WHOIS data
python reconcli_csvtk.py csvtkcli freq output/exports/whois_findings_export.csv -f registrar
python reconcli_csvtk.py csvtkcli search output/exports/whois_findings_export.csv -f registrar -p "suspicious"
```

### Automation and Monitoring
```bash
#!/bin/bash
# Automated domain intelligence workflow

# 1. Daily domain monitoring
python reconcli_csvtk.py whoisfreakscli monitor critical_domains.txt \
  --interval 86400 --save-db --changes-only

# 2. Weekly security analysis
python reconcli_csvtk.py whoisfreakscli analyze all_domains.txt \
  --security-focus --export-findings

# 3. Monthly comprehensive report
python reconcli_csvtk.py dbcli export --table whois_findings --format csv
python reconcli_csvtk.py csvtkcli security-report output/exports/whois_findings_export.csv
```

## ⚡ Performance Optimization

### Rate Limiting
- Default: 60 requests per minute
- Adjustable based on API plan
- Automatic backoff on rate limit errors
- Resume capability for large operations

### Caching
- Local caching of WHOIS results
- Configurable cache duration
- Cache invalidation options
- Reduced API calls for repeated queries

### Concurrent Processing
- Configurable thread pool size
- Optimal for bulk operations
- Respects rate limits
- Progress tracking with tqdm

## 🔧 Configuration

### Config File (~/.reconcli/config.json)
```json
{
  "whoisfreaks_api_key": "your_api_key",
  "whoisfreaks_rate_limit": 60,
  "whoisfreaks_cache_duration": 3600,
  "whoisfreaks_default_threads": 5,
  "notification_webhook": "https://hooks.slack.com/...",
  "database_auto_store": true
}
```

### Environment Variables
```bash
export WHOISFREAKS_API_KEY="your_api_key"
export WHOISFREAKS_RATE_LIMIT="60"
export WHOISFREAKS_CACHE_DURATION="3600"
export RECONCLI_DB_AUTO_STORE="true"
```

## 🚨 Troubleshooting

### Common Issues

**API Key Not Found**
```bash
# Set environment variable
export WHOISFREAKS_API_KEY="your_key"

# Or check config file
cat ~/.reconcli/config.json
```

**Rate Limit Exceeded**
```bash
# Reduce rate limit
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --rate-limit 30

# Use fewer threads
python reconcli_csvtk.py whoisfreakscli bulk domains.txt --threads 3
```

**Large File Processing**
```bash
# Use resume for large operations
python reconcli_csvtk.py whoisfreakscli bulk large_file.txt --resume

# Process in batches
split -l 1000 large_file.txt batch_
for file in batch_*; do
  python reconcli_csvtk.py whoisfreakscli bulk "$file" --save-db
done
```

## 📈 Best Practices

1. **API Management**: Monitor API usage and respect rate limits
2. **Data Storage**: Use database storage for persistent analysis
3. **Security Focus**: Regular security analysis of domain portfolios
4. **Monitoring**: Set up continuous monitoring for critical domains
5. **Automation**: Integrate into CI/CD pipelines for security checks
6. **Reporting**: Generate regular security reports for stakeholders

## 🔗 Related Tools

- **csvtkcli**: Analyze exported WHOIS data
- **dbcli**: Database operations and exports
- **subdocli**: Subdomain discovery for WHOIS analysis
- **dnscli**: DNS analysis integration

---

**Author**: ReconCLI Team
**Version**: 1.0
**Last Updated**: July 2025
**API Provider**: WhoisFreaks.com
