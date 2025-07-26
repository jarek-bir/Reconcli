# FOFA CLI Module for ReconCLI

## Overview

The FOFA CLI module provides comprehensive integration with FOFA search engine for cyberspace mapping and reconnaissance. It offers advanced querying capabilities, hash-based searches, and FX syntax rules for efficient asset discovery.

## 🚀 Features

### Core Functionality
- **Advanced FOFA Queries**: Full support for FOFA search syntax
- **Icon Hash Search**: Calculate and search by favicon hashes
- **Certificate Hash Search**: SSL/TLS certificate-based searches
- **FX Syntax Rules**: Pre-built and custom query templates
- **Multiple Output Formats**: JSON, CSV, and TXT export
- **Browser Integration**: Open results directly in web browser

### Advanced Capabilities
- **Rich CLI Interface**: Beautiful terminal output with progress tracking
- **Concurrent Processing**: Fast, multi-threaded operations
- **Intelligent Caching**: Avoid redundant API calls
- **Debug Mode**: Detailed logging for troubleshooting
- **Configuration Management**: YAML-based configuration system

## 📋 Usage Examples

### Basic Search
```bash
# Search for Apache servers
reconcli fofacli search -q 'app="Apache"' -fs 100

# Exclude honeypots and China
reconcli fofacli search -q 'app="Apache"' -e -ec -fs 50

# Get full URLs with titles
reconcli fofacli search -q 'domain="example.com"' -ffi -fto
```

### Hash-Based Searches
```bash
# Icon hash from URL
reconcli fofacli hash-search --url-to-icon-hash https://example.com/favicon.ico

# Icon hash from local file
reconcli fofacli hash-search --icon-file-path favicon.ico

# Certificate hash from HTTPS site
reconcli fofacli hash-search --url-cert https://example.com
```

### FX Syntax Rules
```bash
# List available FX rules
reconcli fofacli fx list

# Search using FX rule
reconcli fofacli fx search google-reverse

# Show FX rule details
reconcli fofacli fx show jupyter-unauth
```

### Configuration
```bash
# Setup FOFA credentials
reconcli fofacli config

# Check user information
reconcli fofacli userinfo
```

## ⚙️ Configuration

### Initial Setup
1. Run `reconcli fofacli config` to create configuration file
2. Edit `~/.config/fofax/fofax.yaml` with your FOFA credentials:

```yaml
fofa-email: your-email@example.com
fofakey: your-fofa-api-key
fofa-url: https://fofa.info
proxy: null
debug: false
```

### Configuration File Locations
The module searches for configuration in this order:
1. `fofax.yaml` (current directory)
2. `~/.config/fofax/fofax.yaml` (user config)
3. `/etc/fofax.yaml` (system-wide config)

## 🔍 Search Options

### Filters
- `--exclude, -e`: Exclude honeypots
- `--exclude-country-cn, -ec`: Exclude China
- `--fetch-fullhost-info, -ffi`: Get full URLs with scheme
- `--fetch-titles-ofdomain, -fto`: Fetch website titles

### Output Options
- `--output, -o`: Output file path
- `--format, -f`: Output format (json/csv/txt)
- `--open-browser, --open`: Open results in browser

### Advanced Options
- `--fetch-size, -fs`: Maximum results (default: 100)
- `--debug`: Enable debug mode
- `--proxy, -p`: HTTP proxy configuration

## 📊 Output Formats

### Text Output (Default)
```
8.8.8.8:443
1.1.1.1:80
208.67.222.222:53
```

### JSON Output
```json
[
  {
    "protocol": "https",
    "ip": "8.8.8.8",
    "port": "443",
    "host": "dns.google",
    "title": "Google Public DNS"
  }
]
```

### CSV Output
```csv
protocol,ip,port,host,title
https,8.8.8.8,443,dns.google,Google Public DNS
```

## 🎯 FX Rules

### Built-in Rules
- **google-reverse**: Google reverse proxy servers
- **jupyter-unauth**: Jupyter Notebook unauthorized access
- **python-simplehttp**: Python SimpleHTTP servers

### Custom Rules
Create custom FX rules in `~/.config/fofax/fxrules/` directory:

```yaml
id: fx-custom-001
query: my-custom-search
rule_name: Custom Rule
rule_english: My Custom Search Rule
description: Description of the custom rule
author: Your Name
fofa_query: 'title="Custom App" && country="US"'
tag:
- custom
- webapp
source: internal
```

## 🔗 Integration with ReconCLI

### Piping Results
```bash
# Export FOFA results and analyze with other tools
reconcli fofacli search -q 'app="Apache"' -o apache_servers.txt
reconcli portcli -i apache_servers.txt -t 1000

# Chain with subdomain enumeration
reconcli subdocli -d example.com | reconcli fofacli search -q 'domain=example.com'
```

### Combined Workflows
```bash
# Complete reconnaissance workflow
reconcli subdocli -d target.com -o subdomains.txt
reconcli fofacli search -q 'domain="target.com"' -o fofa_results.json
reconcli vulncli -i fofa_results.json --all-tools
```

## 🛡️ Security Features

### Rate Limiting
- Respects FOFA API rate limits
- Configurable request delays
- Session management for optimal performance

### Privacy
- No sensitive data logging in normal mode
- Secure credential storage
- Optional proxy support for anonymity

## 🐛 Troubleshooting

### Common Issues

**Authentication Error**
```bash
# Verify credentials
reconcli fofacli userinfo

# Check configuration
reconcli fofacli config
```

**API Rate Limiting**
```bash
# Use smaller fetch sizes
reconcli fofacli search -q 'app="Apache"' -fs 50

# Add delays between requests
reconcli fofacli search -q 'app="Apache"' --debug
```

**Connection Issues**
```bash
# Test with proxy
reconcli fofacli search -q 'app="Apache"' --proxy http://127.0.0.1:8080

# Enable debug mode
reconcli fofacli search -q 'app="Apache"' --debug
```

## 📈 Performance Tips

1. **Use Specific Queries**: More specific queries return faster results
2. **Optimize Fetch Size**: Balance between speed and completeness
3. **Leverage FX Rules**: Use pre-built rules for common searches
4. **Enable Caching**: Avoid duplicate requests for better performance
5. **Use Filters**: Apply filters to reduce result processing time

## 🔮 Advanced Use Cases

### Red Team Operations
```bash
# Infrastructure enumeration
reconcli fofacli fx search redteam-info-gathering -o targets.json

# Technology stack analysis
reconcli fofacli search -q 'org="Target Corp"' -ffi -fto -o infrastructure.csv
```

### Bug Bounty Research
```bash
# Find specific technologies
reconcli fofacli search -q 'app="Jenkins" && country="US"' -e -fs 200

# Certificate transparency analysis
reconcli fofacli hash-search --url-cert https://target.com -o cert_matches.txt
```

### Threat Intelligence
```bash
# Monitor infrastructure changes
reconcli fofacli search -q 'cert.sha1="abc123..."' --debug -o monitoring.json

# Track technology adoption
reconcli fofacli search -q 'app="Vulnerable Software"' -o vulnerable_hosts.csv
```

The FOFA CLI module provides a powerful and flexible interface for cyberspace mapping and reconnaissance within the ReconCLI framework.
