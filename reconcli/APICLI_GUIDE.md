# 🔐 APICli - Advanced API Security Testing with Intelligent Cache

## 🎯 Overview

APICli is a comprehensive API security testing tool with intelligent caching system that provides **52x performance improvements** for security scans. It combines advanced vulnerability detection with powerful caching capabilities for efficient reconnaissance.

## ⚡ Performance Cache System

### 📊 **Performance Improvements:**
- **Basic endpoint scan**: 1.00s → 0.82s (18% faster)
- **Full security scan**: **25.63s → 0.49s (52x faster, 98.1% improvement!)**

### 🎯 **Cache Features:**
- **SHA256-based keys** for secure cache identification
- **JSON storage** with metadata and expiry
- **Intelligent invalidation** based on scan parameters
- **Performance tracking** with hit rate statistics
- **Automatic TTL management** (24h default)

## 🚀 Quick Start

### Basic Usage
```bash
# Simple API endpoint test
reconcli apicli --url https://api.example.com/v1/users

# Enable caching for performance
reconcli apicli --url https://api.example.com/v1/users --cache --verbose

# Comprehensive security test with cache
reconcli apicli --url https://api.example.com/v1/users --security-test --cache
```

### Cache Management
```bash
# Show cache statistics
reconcli apicli --cache-stats

# Custom cache directory and TTL
reconcli apicli --url https://api.example.com --cache --cache-dir /tmp/api_cache --cache-max-age 12

# Clear all cache
reconcli apicli --clear-cache
```

## 🔧 CLI Options

### Core Options
- `--url` - Target API URL or base URL
- `--endpoints-file` - File containing API endpoints (one per line)
- `--discover` - Auto-discover API endpoints
- `--verbose, -v` - Enable verbose output

### Security Testing
- `--security-test` - Perform comprehensive security testing
- `--method-test` - Test HTTP methods on endpoints
- `--auth-bypass` - Test authentication bypass techniques
- `--cors-test` - Test CORS configuration
- `--injection-test` - Test for injection vulnerabilities
- `--rate-limit-test` - Test rate limiting implementation
- `--parameter-pollution` - Test HTTP Parameter Pollution

### ⚡ Cache Options
- `--cache` - Enable intelligent caching for API results
- `--cache-dir` - Cache directory path (default: `api_cache`)
- `--cache-max-age` - Cache max age in hours (default: 24)
- `--cache-stats` - Show cache performance statistics
- `--clear-cache` - Clear all cached API data

### Swagger/OpenAPI Support
- `--swagger-parse` - Parse Swagger/OpenAPI definition files
- `--swagger-brute` - Brute force discover Swagger/OpenAPI files
- `--swagger-endpoints` - Extract endpoints from Swagger/OpenAPI files
- `--swagger-prepare` - Generate testing commands (curl/sqlmap)
- `--swagger-url` - Swagger/OpenAPI definition URL to parse
- `--swagger-file` - Local Swagger/OpenAPI definition file

### Advanced Options
- `--secret-scan` - Enable JavaScript secret scanning
- `--tech-detect` - Detect API technologies
- `--proxy` - Proxy URL (e.g., http://127.0.0.1:8080)
- `--custom-headers` - Custom headers (key:value,key2:value2)
- `--timeout` - Request timeout in seconds (default: 5)
- `--threads` - Number of concurrent threads (default: 10)

### Output Options
- `--output-dir` - Output directory (default: output/apicli)
- `--json-report` - Generate JSON report
- `--yaml-report` - Generate YAML report
- `--markdown-report` - Generate Markdown report
- `--store-db` - Store results in SQLite database

## 🎯 Security Tests

### Authentication Testing
```bash
# Test authentication bypass techniques
reconcli apicli --url https://api.example.com/admin --auth-bypass --cache

# Test with custom headers
reconcli apicli --url https://api.example.com --auth-bypass --custom-headers "X-API-Key:test123" --cache
```

### CORS Testing
```bash
# Test CORS configuration
reconcli apicli --url https://api.example.com --cors-test --cache

# Full security scan
reconcli apicli --url https://api.example.com --security-test --cache --verbose
```

### Injection Testing
```bash
# Test for injection vulnerabilities
reconcli apicli --url https://api.example.com --injection-test --cache

# Test with multiple endpoints
reconcli apicli --endpoints-file api_endpoints.txt --injection-test --cache
```

## 🕷️ Swagger/OpenAPI Integration

### Discovery
```bash
# Brute force discover Swagger files
reconcli apicli --url https://api.example.com --swagger-brute --cache

# Parse existing Swagger file
reconcli apicli --url https://api.example.com --swagger-url https://api.example.com/swagger.json --swagger-endpoints
```

### Testing
```bash
# Parse and test Swagger endpoints
reconcli apicli --swagger-file api.json --swagger-parse --security-test --cache

# Generate testing commands
reconcli apicli --swagger-url https://api.example.com/openapi.yaml --swagger-prepare curl
```

## 🔐 JavaScript Secret Scanning

### Secret Detection
```bash
# Enable JavaScript secret scanning
reconcli apicli --url https://example.com --secret-scan --cache --verbose

# Scan with database storage
reconcli apicli --url https://example.com --secret-scan --store-db secrets.db --cache
```

### Detected Secret Types
- **AWS Access Keys** (AKIA...)
- **GitHub Tokens** (ghp_...)
- **JWT Tokens** (eyJ...)
- **API Keys** (generic patterns)
- **Database URLs** (mongodb://, mysql://)
- **Private Keys** (-----BEGIN PRIVATE KEY-----)
- **Slack Tokens** (xoxb-)
- **Discord Webhooks**
- **Stripe Keys** (sk_live_, pk_test_)
- **Google API Keys** (AIza...)

## 📊 Performance Examples

### Real-World Performance Test
```bash
# Test with Petstore API (first run)
time reconcli apicli --url https://petstore3.swagger.io/api/v3/pet --security-test --cache
# Result: 25.63s (full security scan)

# Test with cache (second run)
time reconcli apicli --url https://petstore3.swagger.io/api/v3/pet --security-test --cache
# Result: 0.49s (52x faster!)
```

### Cache Statistics Example
```bash
reconcli apicli --cache-stats
```
Output:
```
📊 [CACHE] API Cache Statistics:
    Cache hits: 1
    Cache misses: 0
    Hit rate: 100.0%
    Total requests: 1
    Cache files: 3
    Cache size: 24352 bytes
    Cache directory: api_cache
```

## 🎯 Use Cases

### 1. API Security Assessment
```bash
# Comprehensive security assessment with caching
reconcli apicli --url https://api.example.com \
  --security-test \
  --secret-scan \
  --tech-detect \
  --cache \
  --json-report \
  --verbose
```

### 2. Swagger API Testing
```bash
# Test Swagger-based API with caching
reconcli apicli --url https://api.example.com \
  --swagger-brute \
  --swagger-endpoints \
  --security-test \
  --cache \
  --store-db api_results.db
```

### 3. Bulk Endpoint Testing
```bash
# Test multiple endpoints with caching
echo -e "https://api.example.com/users\nhttps://api.example.com/orders" > endpoints.txt
reconcli apicli --endpoints-file endpoints.txt --security-test --cache --markdown-report
```

### 4. CI/CD Integration
```bash
# Fast security check with cache for CI/CD
reconcli apicli --url $API_URL --security-test --cache --json-report --output-dir reports/
```

## 🔍 Advanced Features

### Technology Detection
APICli automatically detects:
- **REST APIs** (JSON, HAL+JSON)
- **GraphQL** (introspection, queries)
- **SOAP** (XML, WSDL)
- **gRPC** (protocol detection)
- **Frameworks**: FastAPI, Django, Flask, Express, Spring, ASP.NET

### Database Integration
```bash
# Store results in SQLite database
reconcli apicli --url https://api.example.com --security-test --store-db security.db --cache

# Database schema includes:
# - api_scans (general scan results)
# - secret_scans (JavaScript secrets)
# - js_analysis (JavaScript file analysis)
```

### Resume Functionality
```bash
# Resume interrupted scans
reconcli apicli --url https://api.example.com --security-test --resume --cache

# Show resume statistics
reconcli apicli --resume-stat

# Reset resume state
reconcli apicli --resume-reset
```

## 🛡️ Security Features

### Authentication Bypass Tests
- **Header injection** (X-Forwarded-For, X-Real-IP)
- **URL rewriting** (X-Rewrite-URL, X-Original-URL)
- **Role escalation** (X-User-ID, X-Role, X-Admin)
- **Basic auth bypasses**

### Injection Testing
- **SQL Injection** (MySQL, PostgreSQL, SQLite)
- **NoSQL Injection** (MongoDB queries)
- **XSS** (reflected, stored patterns)
- **Command Injection** (shell commands)
- **LDAP Injection**
- **XML Injection** (XXE patterns)

### CORS Testing
- **Origin validation**
- **Credentials handling**
- **Preflight requests**
- **Wildcard origins**

## 📈 Performance Best Practices

### Cache Optimization
```bash
# Use appropriate cache TTL
reconcli apicli --url https://api.example.com --cache --cache-max-age 6  # 6 hours

# Separate cache directories for different projects
reconcli apicli --url https://project1.api.com --cache --cache-dir cache/project1
reconcli apicli --url https://project2.api.com --cache --cache-dir cache/project2
```

### Efficient Scanning
```bash
# Use threading for multiple endpoints
reconcli apicli --endpoints-file large_list.txt --threads 20 --cache

# Enable only needed tests
reconcli apicli --url https://api.example.com --auth-bypass --cors-test --cache
```

## 🚨 Troubleshooting

### Common Issues

#### Cache Not Working
```bash
# Check cache directory permissions
ls -la api_cache/

# Verify cache stats
reconcli apicli --cache-stats

# Clear and rebuild cache
reconcli apicli --clear-cache
```

#### SSL/TLS Issues
```bash
# Disable SSL verification (not recommended for production)
reconcli apicli --url https://api.example.com --insecure --cache

# Use custom proxy
reconcli apicli --url https://api.example.com --proxy http://localhost:8080 --cache
```

#### Rate Limiting
```bash
# Adjust rate limiting
reconcli apicli --url https://api.example.com --rate-limit 5 --cache

# Add delays between requests
reconcli apicli --url https://api.example.com --delay 1.0 --cache
```

## 📋 Output Formats

### JSON Report
```json
{
  "summary": {
    "total_endpoints": 1,
    "vulnerable_endpoints": 1,
    "high_risk_issues": 18,
    "medium_risk_issues": 1
  },
  "detailed_results": [...],
  "recommendations": [...]
}
```

### Markdown Report
- Executive summary
- Vulnerability breakdown
- Risk assessments
- Remediation recommendations

### Database Storage
```sql
-- View scan results
SELECT * FROM api_scans WHERE risk_level = 'HIGH';

-- Secret analysis
SELECT * FROM secret_scans WHERE confidence_level > 0.8;

-- JavaScript analysis
SELECT * FROM js_analysis WHERE secrets_found > 0;
```

## 🔗 Integration Examples

### With Other Tools
```bash
# Chain with nuclei
reconcli apicli --url https://api.example.com --json-report --cache
nuclei -l api_results.json -t exposures/

# Chain with ffuf
reconcli apicli --url https://api.example.com --discover --cache
ffuf -u https://api.example.com/FUZZ -w endpoints.txt
```

### Webhook Notifications
```bash
# Slack notifications
reconcli apicli --url https://api.example.com --security-test --slack-webhook $SLACK_URL --cache

# Discord notifications
reconcli apicli --url https://api.example.com --security-test --discord-webhook $DISCORD_URL --cache
```

## 📚 References

- **Swagger Jacker Integration**: Full BishopFox SJ functionality
- **OWASP API Security**: Top 10 API risks coverage
- **Cache Architecture**: SHA256-based intelligent caching
- **Performance Optimization**: 52x improvement benchmarks

---

*APICli - Empowering API security testing with intelligent performance caching*
