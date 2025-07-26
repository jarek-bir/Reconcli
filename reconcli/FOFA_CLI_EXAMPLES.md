# 🔍 FOFA CLI - Advanced Examples & Documentation

## 📋 Table of Contents

- [🎯 Basic Usage](#-basic-usage)
- [🧠 AI Query Enhancement](#-ai-query-enhancement)
- [🔗 Tool Chaining Workflows](#-tool-chaining-workflows)
- [🌐 Multi-Engine Search](#-multi-engine-search)
- [🎯 FX Rules for Cybersecurity](#-fx-rules-for-cybersecurity)
- [🔍 Advanced Search Techniques](#-advanced-search-techniques)
- [📊 Database & Analytics](#-database--analytics)
- [⚡ Performance Optimization](#-performance-optimization)
- [🔧 Configuration & Management](#-configuration--management)
- [💡 Real-World Use Cases](#-real-world-use-cases)

---

## 🎯 Basic Usage

### Simple FOFA Searches

```bash
# Basic search with different output formats
reconcli fofacli search --query "jenkins" --fetch-size 100
reconcli fofacli search --query "jenkins" --format json --output jenkins_results.json
reconcli fofacli search --query "jenkins" --format csv --output jenkins_results.csv

# Geographic filtering
reconcli fofacli search --query "mongodb" --exclude-country-cn --fetch-size 50
reconcli fofacli search --query "elasticsearch" --exclude --exclude-country-cn --fetch-size 100

# Enhanced information gathering
reconcli fofacli search --query "gitlab" --fetch-fullhost-info --fetch-titles-ofdomain --fetch-size 50

# Open results in browser for manual analysis
reconcli fofacli search --query "jenkins" --open-browser --fetch-size 30
```

### Target-Specific Searches

```bash
# Domain-specific reconnaissance
reconcli fofacli search --query "domain:example.com" --fetch-size 200 --format json

# IP range analysis
reconcli fofacli search --query "ip:192.168.1.0/24" --fetch-fullhost-info --fetch-size 100

# Technology stack discovery
reconcli fofacli search --query "title='GitLab' && country='US'" --fetch-size 50 --format json

# Certificate-based correlation
reconcli fofacli search --query "cert='DigiCert Inc'" --fetch-size 100 --exclude-country-cn
```

---

## 🧠 AI Query Enhancement

### Fuzzy Keyword Expansion

```bash
# Basic fuzzy enhancement
reconcli fofacli query-enhance --query "jenkins" --fuzzy
# Output: (title="jenkins" || title="Hudson" || body="jenkins" || body="Hudson")

# Technology-specific enhancement
reconcli fofacli query-enhance --query "wordpress" --fuzzy
# Output: (title="wordpress" || title="wp-admin" || body="wordpress" || body="wp-admin")

# Container technology enhancement
reconcli fofacli query-enhance --query "docker" --fuzzy
# Output: (title="docker" || title="container" || body="docker" || body="container")
```

### Smart Query Optimization

```bash
# Smart enhancement with context-aware filtering
reconcli fofacli query-enhance --query "jenkins" --smart
# Adds: login page filters, geographic filters, honeypot exclusion

# Combined fuzzy and smart enhancement
reconcli fofacli query-enhance --query "gitlab" --fuzzy --smart --explain
# Shows: original → fuzzy → smart transformation with explanations

# Get related query suggestions
reconcli fofacli query-enhance --query "jenkins" --suggestions
# Returns: Related technologies like GitLab, Jira, TeamCity, Bamboo
```

### AI-Enhanced Search Workflows

```bash
# Direct search with AI enhancement
reconcli fofacli search --query "jenkins" --fuzzy --smart-query --show-suggestions --fetch-size 50

# AI-enhanced search with database storage
reconcli fofacli search --query "wordpress" --fuzzy --smart-query --store-db --format json

# Advanced AI search with caching
reconcli fofacli advanced-search --query "mongodb" --ai --cache --store-db --format json --full-host --title
```

---

## 🔗 Tool Chaining Workflows

### Complete Reconnaissance Pipeline

```bash
# Full pipeline: FOFA → httpx → nuclei → uncover
reconcli fofacli chain \
  --query "title='Jenkins' && country='US'" \
  --fuzzy --smart-query \
  --fetch-size 50 \
  --httpx --httpx-opts "--title --tech-detect --status-code --content-length" \
  --nuclei --nuclei-opts "-t /home/user/nuclei-templates/http/exposed-panels/ -severity high,critical" \
  --uncover --uncover-opts "-e shodan,censys,fofa -l 100" \
  --output /tmp/jenkins_recon \
  --cache --store-db
```

### Targeted Vulnerability Discovery

```bash
# FOFA + nuclei for vulnerability scanning
reconcli fofacli chain \
  --query "apache" \
  --smart-query \
  --fetch-size 100 \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/vulnerabilities/ -severity critical" \
  --store-db --cache

# Technology-specific vulnerability hunting
reconcli fofacli chain \
  --query "nginx" \
  --fuzzy --smart-query \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/misconfiguration/" \
  --output /tmp/nginx_vulns \
  --store-db
```

### Web Service Discovery

```bash
# FOFA + httpx for web service enumeration
reconcli fofacli chain \
  --query "port:8080" \
  --fuzzy \
  --fetch-size 200 \
  --httpx --httpx-opts "--title --tech-detect --screenshot --status-code" \
  --cache --store-db

# SSL/TLS service discovery
reconcli fofacli chain \
  --query "ssl:true" \
  --smart-query \
  --httpx --httpx-opts "--title --tech-detect" \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/ssl/" \
  --store-db
```

---

## 🌐 Multi-Engine Search

### Cross-Platform Reconnaissance

```bash
# Multi-engine search across all platforms
reconcli fofacli uncover \
  --query "jenkins" \
  --engines "shodan,censys,fofa,quake,hunter,zoomeye,netlas,criminalip" \
  --limit 500 \
  --json \
  --output multi_engine_jenkins.json

# Targeted multi-engine search
reconcli fofacli uncover \
  --query "mongodb" \
  --engines "fofa,shodan,censys" \
  --limit 200 \
  --field "ip:port" \
  --timeout 60

# Geographic-specific multi-engine search
reconcli fofacli uncover \
  --query "elasticsearch country:US" \
  --engines "shodan,fofa" \
  --limit 100 \
  --json
```

### Chain Integration with Uncover

```bash
# FOFA + uncover for comprehensive coverage
reconcli fofacli chain \
  --query "wordpress" \
  --fuzzy --smart-query \
  --uncover --uncover-opts "-e fofa,shodan,censys -l 200" \
  --httpx --httpx-opts "--title --tech-detect" \
  --store-db --cache

# Multi-stage reconnaissance with uncover
reconcli fofacli chain \
  --query "docker" \
  --fuzzy \
  --fetch-size 50 \
  --uncover --uncover-opts "-e shodan,quake,hunter -l 150" \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/exposed-panels/" \
  --output /tmp/docker_recon
```

---

## 🎯 FX Rules for Cybersecurity

### Unauthorized Access Detection

```bash
# Database exposure detection
reconcli fofacli fx search "elastic-unauth" --fetch-size 100 --exclude-country-cn --format json
reconcli fofacli fx search "mongodb-unauth" --exclude --fetch-fullhost-info --store-db
reconcli fofacli fx search "redis-unauth" --format csv --output redis_exposed.csv

# Management interface exposure
reconcli fofacli fx search "jenkins-unauth" --fetch-size 50 --open-browser
reconcli fofacli fx search "grafana-unauth" --exclude-country-cn --store-db --format json
reconcli fofacli fx search "kibana-unauth" --exclude --fetch-titles-ofdomain
```

### IoT and Infrastructure Discovery

```bash
# IoT device discovery
reconcli fofacli fx search "webcam-exposed" --fetch-size 30 --fetch-titles-ofdomain --format json
reconcli fofacli fx search "printer-exposed" --exclude-country-cn --store-db
reconcli fofacli fx search "vnc-exposed" --exclude --format csv --output vnc_findings.csv

# Remote access services
reconcli fofacli fx search "rdp-exposed" --fetch-size 40 --exclude-country-cn --format json
reconcli fofacli fx search "ftp-anonymous" --exclude --store-db --fetch-fullhost-info
```

### Container and API Exposure

```bash
# Container technology exposure
reconcli fofacli fx search "docker-api" --fetch-size 50 --exclude-country-cn --format json
reconcli fofacli fx search "solr-admin" --exclude --fetch-fullhost-info --store-db

# Network services
reconcli fofacli fx search "smtp-open-relay" --fetch-size 30 --exclude-country-cn
reconcli fofacli fx search "zabbix-login" --exclude --format json --output zabbix_instances.json
```

### Custom FX Rule Analysis

```bash
# Show detailed rule information
reconcli fofacli fx show "elastic-unauth"
reconcli fofacli fx show "docker-api"
reconcli fofacli fx show "webcam-exposed"

# List all available FX rules
reconcli fofacli fx list

# Search for specific rule types
reconcli fofacli fx list | grep -i "unauth"
reconcli fofacli fx list | grep -i "exposed"
```

---

## 🔍 Advanced Search Techniques

### Certificate and Hash-Based Searches

```bash
# Certificate-based reconnaissance
reconcli fofacli hash-search --url-cert https://target.com --fetch-size 100 --format json --output cert_matches.json
reconcli fofacli hash-search --url-cert https://api.example.com --fetch-size 50 --exclude-country-cn

# Icon hash correlation
reconcli fofacli hash-search --url-to-icon-hash https://target.com/favicon.ico --format csv --output favicon_matches.csv
reconcli fofacli hash-search --icon-file-path /path/to/favicon.ico --fetch-size 50 --store-db

# SSL certificate hunting
reconcli fofacli search --query 'cert="Let's Encrypt"' --fetch-size 200 --format json
reconcli fofacli search --query 'cert.subject="*.example.com"' --fetch-fullhost-info --fetch-size 100
```

### Technology Stack Discovery

```bash
# Web technology identification
reconcli fofacli search --query 'server="nginx"' --fetch-size 100 --fetch-titles-ofdomain
reconcli fofacli search --query 'body="powered by WordPress"' --exclude-country-cn --format json

# Framework and CMS detection
reconcli fofacli search --query 'title="Drupal"' --fetch-fullhost-info --fetch-size 50
reconcli fofacli search --query 'body="React"' --exclude --format csv --output react_apps.csv

# Database technology hunting
reconcli fofacli search --query 'port="3306" && banner="mysql"' --fetch-size 50 --exclude-country-cn
reconcli fofacli search --query 'port="5432" && banner="postgresql"' --format json --store-db
```

### Port and Service Analysis

```bash
# Specific port analysis
reconcli fofacli search --query "port:8080" --fetch-size 200 --fetch-titles-ofdomain --format json
reconcli fofacli search --query "port:443" --exclude-country-cn --fetch-fullhost-info

# Service-specific searches
reconcli fofacli search --query 'service="http"' --fetch-size 150 --format csv
reconcli fofacli search --query 'protocol="https"' --exclude --store-db --fetch-titles-ofdomain

# Custom port ranges
reconcli fofacli search --query "port>=8000 && port<=9000" --fetch-size 100 --format json
```

---

## 📊 Database & Analytics

### Database Management

```bash
# View database statistics
reconcli fofacli db stats

# Search history analysis
reconcli fofacli db history --limit 20
reconcli fofacli db history --limit 50 | grep -i "jenkins"

# Export specific search results
reconcli fofacli db export 123 --output detailed_results.json --format json
reconcli fofacli db export 456 --output search_results.csv --format csv
```

### IP-Based Analysis

```bash
# Search by IP address in stored results
reconcli fofacli db search-ip 1.2.3.4
reconcli fofacli db search-ip 192.168.1.100

# IP range analysis from database
reconcli fofacli db search-ip 10.0.0.1
reconcli fofacli db search-ip 172.16.0.1
```

### Analytics and Reporting

```bash
# Advanced search with database storage
reconcli fofacli advanced-search \
  --query "mongodb" \
  --ai --cache --store-db \
  --format json \
  --full-host --title \
  --output advanced_mongodb_analysis.json

# Comprehensive reporting workflow
reconcli fofacli search --query "jenkins" --fuzzy --smart-query --store-db --format json
reconcli fofacli db export $(reconcli fofacli db history --limit 1 | grep -o '[0-9]\+') --output latest_jenkins_scan.json
```

---

## ⚡ Performance Optimization

### Cache Management

```bash
# View cache performance statistics
reconcli fofacli cache stats

# Clear expired cache entries
reconcli fofacli cache cleanup

# Clear all cache with confirmation
reconcli fofacli cache clear --confirm

# Custom cache configuration
reconcli fofacli --cache-ttl 7200 search --query "jenkins" --cache --verbose
```

### Performance Monitoring

```bash
# Performance comparison with cache
reconcli fofacli search --query "wordpress" --fuzzy --smart-query --cache --verbose  # First run
reconcli fofacli search --query "wordpress" --fuzzy --smart-query --cache --verbose  # Cache hit

# Batch processing optimization
reconcli fofacli search --query "nginx" --fetch-size 500 --cache --store-db --format json

# Cache-enabled chain operations
reconcli fofacli chain \
  --query "apache" \
  --fuzzy --smart-query \
  --httpx --nuclei \
  --cache --store-db \
  --output /tmp/cached_apache_scan
```

---

## 🔧 Configuration & Management

### API Configuration

```bash
# Configure FOFA API credentials
reconcli fofacli config

# View FOFA account information
reconcli fofacli userinfo

# Debug mode for troubleshooting
reconcli fofacli --debug search --query "test" --fetch-size 5
```

### Proxy and Network Configuration

```bash
# HTTP proxy configuration
reconcli fofacli --proxy http://127.0.0.1:8080 search --query "jenkins" --fetch-size 10

# SOCKS proxy support
reconcli fofacli --proxy socks5://127.0.0.1:1080 search --query "wordpress" --fetch-size 10

# Custom FOFA URL (for private instances)
reconcli fofacli --fofa-url https://private-fofa.company.com search --query "internal" --fetch-size 50
```

### Advanced Configuration

```bash
# Custom email and key override
reconcli fofacli --email custom@example.com --key custom-api-key search --query "test"

# Combined configuration options
reconcli fofacli \
  --proxy http://127.0.0.1:8080 \
  --debug \
  --fofa-url https://fofa.info \
  search --query "jenkins" --fetch-size 10 --verbose
```

---

## 💡 Real-World Use Cases

### Bug Bounty Reconnaissance

```bash
# Target discovery workflow
reconcli fofacli search --query "domain:target.com" --fuzzy --smart-query --store-db --format json
reconcli fofacli fx search "jenkins-unauth" --exclude-country-cn --fetch-size 50 --store-db
reconcli fofacli hash-search --url-cert https://target.com --fetch-size 100 --store-db

# Technology stack enumeration
reconcli fofacli chain \
  --query "domain:target.com" \
  --fuzzy --smart-query \
  --httpx --httpx-opts "--title --tech-detect --screenshot" \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/exposed-panels/" \
  --store-db --cache

# Multi-engine correlation
reconcli fofacli uncover \
  --query "ssl:target.com" \
  --engines "fofa,shodan,censys" \
  --limit 200 \
  --json --output target_correlation.json
```

### Enterprise Security Assessment

```bash
# Organization-wide reconnaissance
reconcli fofacli search --query 'org:"Target Corp"' --fetch-size 500 --store-db --format json
reconcli fofacli fx search "elastic-unauth" --exclude-country-cn --store-db
reconcli fofacli fx search "mongodb-unauth" --exclude --store-db

# Infrastructure analysis
reconcli fofacli chain \
  --query 'org:"Target Corp"' \
  --smart-query \
  --fetch-size 200 \
  --httpx --httpx-opts "--title --tech-detect" \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/vulnerabilities/ -severity high,critical" \
  --uncover --uncover-opts "-e shodan,censys -l 300" \
  --store-db --cache \
  --output /tmp/enterprise_assessment

# Compliance and reporting
reconcli fofacli db stats
reconcli fofacli db history --limit 50
reconcli fofacli db export $(reconcli fofacli db history --limit 1 | grep -o '[0-9]\+') --output enterprise_report.json
```

### Threat Intelligence Gathering

```bash
# Threat actor infrastructure tracking
reconcli fofacli hash-search --url-cert https://suspicious-domain.com --fetch-size 200 --store-db
reconcli fofacli search --query 'cert.subject="*.suspicious-domain.com"' --fetch-fullhost-info --store-db

# IoT botnet discovery
reconcli fofacli fx search "webcam-exposed" --exclude-country-cn --fetch-size 100 --store-db
reconcli fofacli fx search "vnc-exposed" --exclude --fetch-size 50 --store-db

# Infrastructure correlation
reconcli fofacli uncover \
  --query "ssl:suspicious-domain.com" \
  --engines "fofa,shodan,censys,quake" \
  --limit 500 \
  --json --output threat_infrastructure.json
```

### Red Team Operations

```bash
# Target enumeration
reconcli fofacli search --query "domain:target-company.com" --fuzzy --smart-query --store-db --cache
reconcli fofacli fx search "jenkins-unauth" --exclude-country-cn --store-db
reconcli fofacli fx search "docker-api" --exclude --store-db

# Attack surface mapping
reconcli fofacli chain \
  --query "domain:target-company.com" \
  --fuzzy --smart-query \
  --fetch-size 100 \
  --httpx --httpx-opts "--title --tech-detect" \
  --nuclei --nuclei-opts "-t /path/to/nuclei-templates/http/exposed-panels/ -severity high,critical" \
  --store-db --cache

# Infrastructure intelligence
reconcli fofacli uncover \
  --query "org:'Target Company'" \
  --engines "fofa,shodan,censys" \
  --limit 300 \
  --json --output redteam_intelligence.json
```

---

## 📚 Advanced Tips & Tricks

### Query Optimization

```bash
# Use fuzzy enhancement for better coverage
reconcli fofacli search --query "jenkins" --fuzzy --smart-query

# Combine multiple search strategies
reconcli fofacli search --query "docker" --fuzzy --exclude-country-cn --fetch-fullhost-info
reconcli fofacli fx search "docker-api" --exclude --store-db

# Geographic targeting
reconcli fofacli search --query "mongodb && country='US'" --fetch-size 100 --format json
```

### Automation and Scripting

```bash
# Automated daily scans
#!/bin/bash
DATE=$(date +%Y%m%d)
reconcli fofacli search --query "jenkins" --fuzzy --smart-query --store-db --format json --output "jenkins_scan_${DATE}.json"
reconcli fofacli fx search "elastic-unauth" --store-db --format json --output "elastic_scan_${DATE}.json"

# Multi-target automation
for target in target1.com target2.com target3.com; do
    reconcli fofacli search --query "domain:${target}" --fuzzy --smart-query --store-db --cache
done
```

### Integration with Other Tools

```bash
# Export for external analysis
reconcli fofacli search --query "jenkins" --format json --output jenkins_results.json
cat jenkins_results.json | jq -r '.[] | .ip + ":" + .port'

# Integration with nuclei
reconcli fofacli search --query "nginx" --format txt --output nginx_targets.txt
nuclei -l nginx_targets.txt -t /path/to/nuclei-templates/http/

# Integration with httpx
reconcli fofacli search --query "port:8080" --format txt --output web_targets.txt
httpx -l web_targets.txt -title -tech-detect -json -o httpx_results.json
```

---

This comprehensive guide covers all major FOFA CLI features and real-world usage scenarios. For additional help, use `reconcli fofacli --help` or consult the individual command help pages.
