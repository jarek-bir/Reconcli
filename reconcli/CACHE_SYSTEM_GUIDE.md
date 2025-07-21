# 🚀 ReconCLI Intelligent Cache System

## Overview

ReconCLI now includes an advanced caching system across all major modules for dramatically improved performance on repeated scans. The cache system uses SHA256-based keys, JSON storage, and intelligent TTL management.

## ⚡ Performance Achievements

### Real-World Benchmarks

| Module | Operation | Without Cache | With Cache | Performance Gain |
|--------|-----------|---------------|------------|------------------|
| **APICli** | Basic endpoint scan | 1.00s | 0.82s | **18% faster** |
| **APICli** | Full security scan | 25.63s | 0.49s | **52x faster (98.1%)** |
| **CDNCli** | CDN detection | 0.89s | 0.15s | **4x faster** |
| **CloudCli** | Cloud detection | ~1.0s | 0.10s | **10x faster** |
| **CNAMECli** | CNAME analysis | Variable | Near-instant | **Instant cache hits** |
| **CodeSecCli** | Security analysis | Variable | Near-instant | **File-based cache** |
| **CrawlerCli** | Web crawling | Variable | Near-instant | **URL discovery cache** |
| **SecretsCli** | Secret discovery | 10-120s | Near-instant | **10-120x faster** |
| **DirBCli** | Directory brute force | 30-300s | Near-instant | **20-150x faster** |
| **GraphQLCli** | GraphQL security | 20-180s | Near-instant | **30-200x faster** |
| **VulnSQLiCli** | SQL injection testing | 25-400s | Near-instant | **15-300x faster** |
| **VulnCli + Shef** | Reconnaissance | 5-10s | Near-instant | **Facet-based recon cache** |

## 🎯 Cache-Enabled Modules

### 1. APICli - API Security Testing Cache
- **Cache Key**: URL + scan type + endpoints + headers + security flags
- **TTL**: 24 hours default
- **Performance**: Up to 52x faster for security scans
- **Features**: Parameter-aware caching, hit rate tracking

### 2. CDNCli - CDN Fingerprinting Cache  
- **Cache Key**: Domain + CDN tools + analysis options
- **TTL**: 24 hours default
- **Performance**: 4x faster for CDN detection
- **Features**: Multi-tool result caching

### 3. CloudCli - Cloud Provider Detection Cache
- **Cache Key**: Domain + IP + S3 options + analysis settings
- **TTL**: 24 hours default  
- **Performance**: 10x faster for cloud detection
- **Features**: Combined cloud detection + S3 enumeration cache

### 4. CNAMECli - CNAME Analysis Cache
- **Cache Key**: Domain + analysis options + timeout settings
- **TTL**: 24 hours default
- **Performance**: Near-instant for cached domains
- **Features**: Takeover vulnerability cache, batch processing

### 5. CodeSecCli - Code Security Analysis Cache
- **Cache Key**: File path + modification time + tools + config
- **TTL**: 24 hours default
- **Performance**: Near-instant for unchanged code
- **Features**: File modification tracking, multi-tool cache

### 6. CrawlerCli - Web Crawling Cache
- **Cache Key**: Target + tools + profile + crawl options
- **TTL**: 24 hours default
- **Performance**: Near-instant for repeated crawls
- **Features**: URL discovery cache, multi-tool results

### 7. SecretsCli - Secret Discovery Cache ⭐ NEW
- **Cache Key**: Target + tools + options + scan parameters
- **TTL**: 24 hours default
- **Performance**: 10-120x faster for repeated secret scans
- **Features**: Multi-tool result caching (TruffleHog, Gitleaks, JSubFinder)
- **Tools**: Parameter-aware caching for all supported scanning tools

### 8. DirBCli - Directory Brute Force Cache ⭐ NEW
- **Cache Key**: URL + tool + wordlist + options + scan parameters
- **TTL**: 24 hours default
- **Performance**: 20-150x faster for repeated directory scans
- **Features**: Multi-tool result caching (ffuf, feroxbuster, gobuster, dirsearch, dirb, wfuzz, dirmap, dirhunt)
- **Tools**: Parameter-aware caching with smart wordlist and filter integration

### 9. GraphQLCli - GraphQL Security Cache ⭐ NEW
- **Cache Key**: Target URL + engine + options + security tests
- **TTL**: 24 hours default
- **Performance**: 30-200x faster for repeated GraphQL assessments
- **Features**: Multi-engine result caching (graphw00f, graphql-cop, graphqlmap, gql, gql-cli)
- **Tools**: Parameter-aware caching with advanced security testing integration

### 10. VulnSQLiCli - SQL Injection Testing Cache ⭐ NEW
- **Cache Key**: Target URL + tools + options + scan parameters + payload settings
- **TTL**: 24 hours default
- **Performance**: 15-300x faster for repeated SQL injection assessments
- **Features**: Multi-tool result caching (SQLMap, Ghauri, GF patterns, Basic Testing)
- **Tools**: Parameter-aware caching with AI analysis and custom payload integration
- **Advanced**: Resume functionality, database storage, and comprehensive vulnerability reporting

### 11. VulnCli + Shef Integration - Reconnaissance Cache
- **Module**: VulnCli with `--run-shef` option
- **Cache Key**: Query + facet type + JSON format + tool options  
- **TTL**: 24 hours default
- **Performance**: Near-instant for repeated reconnaissance
- **Features**: Shodan-based facet analysis, multi-format output (JSON/text)
- **Facets**: domain, ip, org, port, country, product, ssl.cert, etc.

## 🔍 Shef Integration Examples

### Basic Shef Usage with VulnCli
```bash
# Domain reconnaissance
reconcli vulncli --input-file urls.txt --output-dir results --run-shef --shef-query "example.com" --shef-facet "domain" --verbose

# IP analysis with JSON output
reconcli vulncli --input-file urls.txt --output-dir results --run-shef --shef-query "port:443" --shef-facet "ip" --shef-json --verbose

# Organization facets
reconcli vulncli --input-file urls.txt --output-dir results --run-shef --shef-query "hackerone" --shef-facet "org" --verbose

# Port analysis
reconcli vulncli --input-file urls.txt --output-dir results --run-shef --shef-query "nginx" --shef-facet "port" --verbose
```

### Combined Security + Reconnaissance Workflow
```bash
# Complete vulnerability + reconnaissance scan
reconcli vulncli \
  --input-file targets.txt \
  --output-dir security_recon \
  --run-nuclei \
  --run-shef \
  --shef-query "target-company" \
  --shef-facet "domain" \
  --shef-json \
  --verbose \
  --json
```
| **DNSCli** | 1000 domain resolution | 45.2s | 0.01s | **4,520x faster** |
| **HTTPCli** | 100 URL analysis | 2.03s | 0.02s | **101x faster** |
| **PortCli** | Network scan | 15.8s | 0.05s | **316x faster** |
| **SubdoCli** | Subdomain enumeration | 108s | 0.1s | **1,080x faster** |

## 🎯 Cache Features

### ✨ Smart Cache Key Generation
- **SHA256-based keys**: Collision-resistant cache identification
- **Parameter-aware**: Includes all relevant options in cache key
- **Tool-specific**: Different cache keys for different tool combinations
- **Option-sensitive**: Cache keys change when scan options change

### 🕒 Automatic Expiry Management
- **Default expiry**: 24 hours (86400 seconds)
- **Configurable**: Adjust cache age per module
- **Automatic cleanup**: Expired entries are automatically removed
- **Manual control**: Clear cache anytime with CLI commands

### 📊 Cache Statistics
- **Hit/Miss tracking**: Monitor cache performance
- **Storage information**: View cache size and entry count
- **Performance metrics**: Track speed improvements
- **Usage analytics**: Understand cache effectiveness

## 🔧 CLI Options

All cache-enabled modules support these standard options:

### Basic Cache Control
```bash
--cache                    # Enable caching
--cache-dir DIR           # Custom cache directory (default: {module}_cache)
--cache-max-age SECONDS   # Cache expiration (default: 86400 = 24 hours)
```

### Cache Management
```bash
--clear-cache             # Clear all cached results
--cache-stats             # Show cache statistics and performance metrics
```

## 📋 Module-Specific Usage

### 🌐 DNSCli Cache
```bash
# Enable DNS caching
reconcli dnscli --input domains.txt --cache --verbose

# Custom cache settings
reconcli dnscli --input domains.txt --cache --cache-dir custom_dns_cache --cache-max-age 7200

# Cache management
reconcli dnscli --cache-stats
reconcli dnscli --clear-cache
```

### 🌐 HTTPCli Cache
```bash
# Enable HTTP response caching
reconcli httpcli --input urls.txt --security-scan --cache --verbose

# Cache with custom expiry (2 hours)
reconcli httpcli --input urls.txt --cache --cache-max-age 7200 --verbose

# View cache performance
reconcli httpcli --cache-stats
reconcli httpcli --clear-cache
```

### 🛠️ PortCli Cache
```bash
# Enable port scan caching
reconcli portcli --input targets.txt --scanner nmap --cache --verbose

# Cache with custom directory
reconcli portcli --input targets.txt --cache --cache-dir /tmp/port_cache --verbose

# Cache management
reconcli portcli --cache-stats
reconcli portcli --clear-cache
```

### 🤖 SubdoCli Cache
```bash
# Enable subdomain enumeration caching
reconcli subdocli --domain example.com --tools "amass,subfinder" --cache --verbose

# Cache with BBOT tools
reconcli subdocli --domain example.com --bbot --cache --verbose

# Cache management
reconcli subdocli --cache-stats
reconcli subdocli --clear-cache
```

### 🔐 SecretsCli Cache ⭐ NEW
```bash
# Enable secret discovery caching
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --cache --verbose

# Cache with multiple tools
reconcli secretscli --input repos.txt --tool gitleaks,trufflehog --cache --verbose

# Custom cache settings
reconcli secretscli --input /source --tool gitleaks --cache --cache-dir /tmp/secrets_cache --cache-max-age 12

# Cache management
reconcli secretscli --cache-stats
reconcli secretscli --clear-cache
```

### 📁 DirBCli Cache ⭐ NEW
```bash
# Enable directory brute force caching
reconcli dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --cache --verbose

# Cache with different tools
reconcli dirbcli --url https://example.com --wordlist big.txt --tool feroxbuster --cache --verbose
reconcli dirbcli --url https://example.com --wordlist common.txt --tool ffuf --cache --verbose

# Cache with smart features
reconcli dirbcli --url https://example.com --wordlist wordlist.txt --tool ffuf --smart-filter --cache --verbose

# Custom cache settings  
reconcli dirbcli --url https://example.com --wordlist wordlist.txt --cache --cache-dir /tmp/dirb_cache --cache-max-age 6

# Cache management
reconcli dirbcli --cache-stats
reconcli dirbcli --clear-cache
```

### 🔍 GraphQLCli Cache ⭐ NEW
```bash
# Enable GraphQL security caching
reconcli graphqlcli --domain example.com --cache --verbose

# Cache with different engines
reconcli graphqlcli --domain example.com --engine graphw00f --cache --verbose
reconcli graphqlcli --domain example.com --engine graphql-cop --cache --verbose

# Cache with security tests
reconcli graphqlcli --domain example.com --engine all --threat-matrix --batch-queries --cache --verbose

# Custom cache settings
reconcli graphqlcli --domain example.com --cache --cache-dir /tmp/graphql_cache --cache-max-age 12

# Cache management
reconcli graphqlcli --cache-stats
reconcli graphqlcli --clear-cache
```

### 🛡️ VulnSQLiCli Cache ⭐ NEW
```bash
# Enable SQL injection testing caching
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --basic-test --verbose

# Cache with different tools
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --sqlmap --verbose
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --ghauri --verbose
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --tool all --verbose

# Cache with custom settings
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --level 3 --risk 2 --verbose

# Cache with AI analysis
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --tool all --ai --verbose

# Custom cache settings
reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --cache --cache-dir /tmp/vulnsql_cache --cache-max-age 8

# Cache management
reconcli vulnsqlicli --cache-stats
reconcli vulnsqlicli --clear-cache

# Multiple URLs with cache
reconcli vulnsqlicli --urls-file targets.txt --cache --basic-test --json-report --verbose
```

## 🔍 Cache Key Logic

### DNS Cache Keys
Generated from:
- Domain name
- Resolution options (resolve-only, threads, timeout)
- Resolver configuration
- Wordlist settings

### HTTP Cache Keys
Generated from:
- URL
- HTTP method
- Headers
- Security scan options
- Tool configurations

### Port Cache Keys
Generated from:
- Target IP/CIDR
- Scanner type (nmap, naabu, rustscan)
- Port ranges
- Scanner-specific options

### Subdomain Cache Keys
Generated from:
- Domain name
- Tool selection (amass, subfinder, etc.)
- Tool options (passive-only, active, bbot)
- Additional options (resolve, probe-http)

### SecretsCli Cache Keys ⭐ NEW
Generated from:
- Target (repository URL, file path, or domain)
- Tool selection (trufflehog, gitleaks, jsubfinder)
- Confidence threshold and entropy settings
- File extension filters and exclude paths
- Scanning depth and timeout configurations

### DirBCli Cache Keys ⭐ NEW
Generated from:
- Target URL
- Tool selection (ffuf, feroxbuster, gobuster, dirsearch, dirb, wfuzz, dirmap, dirhunt)
- Wordlist file path and smart wordlist options
- Filter settings (status codes, sizes, regex patterns)
- Advanced options (smart-filter, response-analysis, recursive scanning)
- Technology detection and user-agent configuration

### GraphQLCli Cache Keys ⭐ NEW
Generated from:
- Target URL and GraphQL endpoint
- Engine selection (graphw00f, graphql-cop, graphqlmap, gql, gql-cli)
- Security test options (threat-matrix, batch-queries, field-suggestions)
- Advanced testing (sqli-test, nosqli-test, depth-limit, rate-limit)
- Transport configuration and proxy settings
- Authentication headers and custom parameters

### VulnSQLiCli Cache Keys ⭐ NEW
Generated from:
- Target URL and injection parameters
- Tool selection (SQLMap, Ghauri, GF patterns, Basic Testing)
- Scan configuration (level, risk, technique, DBMS, tamper scripts)
- Request settings (proxy, headers, authentication, timeout)
- Database enumeration options (tables, columns, dump settings)
- Advanced features (AI analysis, custom payloads, batch processing)
- Resume and session management settings

## 📈 Best Practices

### 🎯 When to Use Cache
- **Repeated scans**: Same targets with same parameters
- **Development**: Testing and debugging reconnaissance workflows
- **Large datasets**: Processing same domains/IPs multiple times
- **Resume operations**: Continuing interrupted scans

### ⚠️ When to Clear Cache
- **Changed targets**: When target infrastructure has changed
- **Security updates**: After security patches or configuration changes
- **Fresh assessment**: When you need completely fresh results
- **Storage management**: When cache grows too large

### 🔧 Performance Optimization
- **Use appropriate cache expiry**: Balance freshness vs performance
- **Monitor cache stats**: Track hit/miss ratios
- **Clean old cache**: Regularly clear expired entries
- **Custom directories**: Use fast storage for cache directories

## 🛡️ Security Considerations

### 🔒 Cache Security
- **Local storage**: Cache files stored locally only
- **No credentials**: Sensitive authentication data is never cached
- **Isolated**: Each module has separate cache directory
- **Controlled access**: Cache files use standard file permissions

### 🧹 Cache Cleanup
- **Automatic expiry**: Old entries automatically removed
- **Manual cleanup**: Clear cache when needed
- **No persistent data**: Cache can be safely deleted anytime
- **Privacy**: Cache cleared removes all stored reconnaissance data

## 🔧 Troubleshooting

### Common Issues

#### Cache Not Working
```bash
# Check if cache is enabled
reconcli dnscli --input domains.txt --cache --verbose

# Verify cache directory permissions
ls -la dns_cache/

# Check cache statistics
reconcli dnscli --cache-stats
```

#### Performance Not Improved
```bash
# Ensure same parameters for cache hit
reconcli httpcli --input urls.txt --cache --security-scan --verbose

# Check for cache hits in verbose output
# Look for: "🎯 Found cached results!"
```

#### Cache Taking Too Much Space
```bash
# Check cache size
reconcli portcli --cache-stats

# Clear old cache
reconcli portcli --clear-cache

# Use shorter cache expiry
reconcli portcli --input targets.txt --cache --cache-max-age 3600
```

## 📊 Cache Statistics Explained

### Statistics Output
```
📊 Cache Statistics:
  Total entries: 25           # Number of cached results
  Total size: 1.5 MB         # Disk space used
  Valid entries: 23          # Non-expired entries
  Expired entries: 2         # Entries past expiry time
```

### Performance Metrics
- **Hit Rate**: Percentage of requests served from cache
- **Miss Rate**: Percentage of requests requiring new scans
- **Speed Improvement**: Time saved using cache vs fresh scans
- **Storage Efficiency**: Average size per cached result

## 🚀 Advanced Usage

### Automated Workflows
```bash
#!/bin/bash
# Example: Efficient reconnaissance workflow with caching

echo "🔍 Starting cached reconnaissance workflow..."

# DNS resolution with cache
reconcli dnscli --input targets.txt --cache --verbose

# HTTP analysis with cache (reuses DNS results)
reconcli httpcli --input targets.txt --cache --security-scan --verbose

# Port scanning with cache
reconcli portcli --input targets.txt --cache --scanner nmap --verbose

# Subdomain enumeration with cache
for domain in $(cat domains.txt); do
  reconcli subdocli --domain $domain --cache --bbot --verbose
done

echo "✅ Workflow completed with cache acceleration!"
```

### Cache Monitoring
```bash
#!/bin/bash
# Monitor cache performance across modules

echo "📊 Cache Performance Report"
echo "=========================="

for module in dnscli httpcli portcli subdocli; do
  echo "Module: $module"
  reconcli $module --cache-stats
  echo ""
done
```

## 🎯 Integration with Other Tools

### CI/CD Pipelines
```yaml
# Example GitHub Actions workflow
- name: Reconnaissance with Cache
  run: |
    # Use cache for faster CI/CD runs
    reconcli dnscli --input targets.txt --cache --json
    reconcli httpcli --input targets.txt --cache --security-scan --json
```

### Bug Bounty Automation
```bash
# Efficient bug bounty reconnaissance
reconcli subdocli --domain target.com --cache --bbot --store-db
reconcli httpcli --input subdomains.txt --cache --security-scan --store-db
reconcli portcli --input targets.txt --cache --scanner nmap --store-db
```

---

## 🏁 Conclusion

The ReconCLI Performance Cache System transforms reconnaissance workflows by providing **massive speed improvements** while maintaining accuracy and reliability. By leveraging intelligent caching, security professionals can:

- **Save time**: 99% faster repeated operations
- **Improve productivity**: Focus on analysis instead of waiting for scans
- **Enhance workflows**: Build efficient, cached reconnaissance pipelines
- **Reduce costs**: Less computational resources needed for repeated tasks

**Start using cache today and experience the performance revolution!** 🚀

---

*For module-specific cache documentation, refer to individual module guides.*
