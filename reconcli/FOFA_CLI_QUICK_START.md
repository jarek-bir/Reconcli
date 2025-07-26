# 🔍 FOFA CLI - Quick Start Guide

## 🚀 Installation & Setup

```bash
# Configure FOFA API credentials
reconcli fofacli config

# Test configuration
reconcli fofacli userinfo

# Check available commands
reconcli fofacli --help
```

## ⚡ Quick Examples

### Basic Searches

```bash
# Simple search
reconcli fofacli search --query "jenkins" --fetch-size 50

# Enhanced search with AI
reconcli fofacli search --query "jenkins" --fuzzy --smart-query --fetch-size 50

# Geographic filtering
reconcli fofacli search --query "mongodb" --exclude-country-cn --fetch-size 100
```

### Query Enhancement

```bash
# Get query suggestions
reconcli fofacli query-enhance --query "jenkins" --fuzzy --smart --suggestions

# Explain enhancements
reconcli fofacli query-enhance --query "wordpress" --fuzzy --smart --explain
```

### Multi-Tool Chaining

```bash
# FOFA + httpx + nuclei
reconcli fofacli chain --query "jenkins" --fuzzy --httpx --nuclei

# Complete pipeline
reconcli fofacli chain --query "wordpress" --fuzzy --smart-query \
  --httpx --nuclei --uncover --cache --store-db
```

### FX Rules (Cybersecurity Patterns)

```bash
# List all rules
reconcli fofacli fx list

# Search unauthorized access
reconcli fofacli fx search "elastic-unauth" --fetch-size 50
reconcli fofacli fx search "jenkins-unauth" --exclude-country-cn
```

### Multi-Engine Search

```bash
# Search across multiple platforms
reconcli fofacli uncover --query "jenkins" --engines "fofa,shodan,censys" --limit 200

# Export results
reconcli fofacli uncover --query "wordpress" --engines "fofa,shodan" --json --output results.json
```

## 🎯 Common Use Cases

### Bug Bounty

```bash
# Target discovery
reconcli fofacli search --query "domain:target.com" --fuzzy --smart-query --store-db

# Technology hunting
reconcli fofacli fx search "jenkins-unauth" --exclude-country-cn --store-db
reconcli fofacli hash-search --url-cert https://target.com --store-db
```

### Threat Intelligence

```bash
# Infrastructure correlation
reconcli fofacli hash-search --url-cert https://suspicious.com --fetch-size 200

# IoT botnet detection
reconcli fofacli fx search "webcam-exposed" --exclude-country-cn --fetch-size 100
```

### Red Team

```bash
# Attack surface mapping
reconcli fofacli chain --query "domain:target.com" --fuzzy --smart-query \
  --httpx --nuclei --store-db --cache
```

## 📊 Database & Analytics

```bash
# View statistics
reconcli fofacli db stats

# Search history
reconcli fofacli db history --limit 10

# Export results
reconcli fofacli db export 123 --output results.json
```

## ⚡ Performance

```bash
# Enable caching
reconcli fofacli search --query "jenkins" --cache

# Cache statistics
reconcli fofacli cache stats

# Clear cache
reconcli fofacli cache clear --confirm
```

## 🔧 Advanced Options

```bash
# Proxy support
reconcli fofacli --proxy http://127.0.0.1:8080 search --query "test"

# Debug mode
reconcli fofacli --debug search --query "test" --fetch-size 5

# Custom output formats
reconcli fofacli search --query "nginx" --format json --output nginx.json
reconcli fofacli search --query "apache" --format csv --output apache.csv
```

## 📖 Full Documentation

For comprehensive examples and advanced usage:
- **[FOFA_CLI_EXAMPLES.md](FOFA_CLI_EXAMPLES.md)** - Complete documentation with real-world scenarios
- **[README.md](README.md)** - Main project documentation

---

*Quick reference for FOFA CLI - The most advanced FOFA search tool with AI enhancement*
