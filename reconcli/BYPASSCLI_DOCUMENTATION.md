# BypassCLI - HTTP Status Code Bypass Module

## Overview

BypassCLI is a comprehensive HTTP status code bypass module that helps security researchers and penetration testers circumvent access controls like 403 Forbidden, 404 Not Found, and other restrictive status codes. The module integrates multiple bypass techniques including external tools and custom evasion methods.

## Features

- **Multiple Bypass Techniques**: Combines header manipulation, path traversal, HTTP method variation, and encoding techniques
- **External Tool Integration**: Seamless integration with `forbidden` and `bypass-url-parser` tools
- **Custom Evasion Methods**: Proprietary bypass techniques including Unicode normalization and case variations
- **Intelligent Caching**: Results caching to avoid redundant requests and improve performance
- **Comprehensive Output**: Multiple output formats (JSON, TXT, CSV) with detailed bypass information
- **AI-Powered Analysis**: Optional AI analysis of bypass results for enhanced insights

## Installation Requirements

### External Tools

1. **Forbidden Tool** (by ivan-sincek):
   ```bash
   # Clone and install forbidden
   git clone https://github.com/ivan-sincek/forbidden.git
   cd forbidden
   pip install -r requirements.txt
   ```

2. **Bypass URL Parser** (by laluka):
   ```bash
   # Clone and install bypass-url-parser
   git clone https://github.com/laluka/bypass-url-parser.git
   cd bypass-url-parser
   pip install -r requirements.txt
   ```

### Python Dependencies

```bash
pip install requests beautifulsoup4 urllib3
```

## Basic Usage

### Single URL Bypass Testing

```bash
# Test basic bypass techniques on a single URL
python reconcli.py bypasscli --url https://example.com/admin

# Test with external tools integration
python reconcli.py bypasscli --url https://example.com/admin --use-forbidden --use-bypass-parser

# Enable AI analysis of results
python reconcli.py bypasscli --url https://example.com/admin --ai
```

### Bulk URL Testing

```bash
# Test multiple URLs from file
python reconcli.py bypasscli --input urls.txt --use-forbidden

# Test URLs with custom headers
python reconcli.py bypasscli --input urls.txt --headers "X-Forwarded-For: 127.0.0.1" "X-Real-IP: localhost"

# Comprehensive bypass testing with all techniques
python reconcli.py bypasscli --input urls.txt --use-forbidden --use-bypass-parser --custom-bypasses --ai
```

### Advanced Configuration

```bash
# Specify custom output file
python reconcli.py bypasscli --url https://example.com/admin --output custom_bypass_results.json

# Set custom timeout and retries
python reconcli.py bypasscli --url https://example.com/admin --timeout 30 --retries 3

# Use custom User-Agent
python reconcli.py bypasscli --url https://example.com/admin --user-agent "Mozilla/5.0 Custom Scanner"

# Enable verbose output for debugging
python reconcli.py bypasscli --url https://example.com/admin --verbose
```

## Bypass Techniques

### 1. Header Manipulation

- **X-Forwarded-For**: Bypass IP-based restrictions
- **X-Real-IP**: Alternative IP spoofing
- **X-Originating-IP**: Additional IP header variation
- **Host Header Injection**: Bypass host-based filtering
- **Referer Manipulation**: Bypass referer-based access control

### 2. HTTP Method Variations

- **GET, POST, PUT, DELETE**: Standard method testing
- **HEAD, OPTIONS, PATCH**: Alternative HTTP methods
- **TRACE, CONNECT**: Less common method testing
- **Custom Methods**: X-HTTP-Method-Override headers

### 3. Path Manipulation

- **Directory Traversal**: `../`, `..%2f`, `..%252f`
- **URL Encoding**: Single and double encoding
- **Unicode Normalization**: UTF-8 bypass techniques
- **Case Variations**: Upper/lower case path testing
- **Null Byte Injection**: `%00` path termination

### 4. Protocol Manipulation

- **HTTP vs HTTPS**: Protocol switching
- **HTTP Version**: HTTP/1.0, HTTP/1.1, HTTP/2
- **Port Variations**: Default and non-standard ports

### 5. Custom Payload Techniques

- **Request Smuggling Payloads**: HTTP request smuggling attempts
- **Cache Poisoning**: Cache-based bypass attempts
- **JWT Manipulation**: Token-based bypass techniques

## External Tool Integration

### Forbidden Tool Features

The `forbidden` tool integration provides:
- Advanced header manipulation
- Comprehensive HTTP method testing
- Intelligent payload generation
- Rate limiting and stealth mode

### Bypass URL Parser Features

The `bypass-url-parser` tool integration provides:
- URL parsing and manipulation
- Encoding/decoding techniques
- Path normalization bypass
- Query parameter manipulation

## Output Formats

### JSON Output (Default)

```json
{
  "url": "https://example.com/admin",
  "timestamp": "2025-01-14T10:30:00Z",
  "bypasses_found": 3,
  "successful_bypasses": [
    {
      "technique": "header_manipulation",
      "method": "GET",
      "headers": {
        "X-Forwarded-For": "127.0.0.1"
      },
      "status_code": 200,
      "bypassed": true,
      "response_length": 1024
    }
  ]
}
```

### Text Output

```
[+] Bypass Found: Header Manipulation
    URL: https://example.com/admin
    Method: GET
    Headers: X-Forwarded-For: 127.0.0.1
    Status: 200 OK
    Response Length: 1024 bytes

[+] Bypass Found: Path Traversal
    URL: https://example.com/admin/../admin/
    Method: GET
    Status: 200 OK
    Response Length: 1024 bytes
```

## Caching System

BypassCLI implements intelligent caching to improve performance:

- **Result Caching**: Stores bypass results to avoid redundant testing
- **TTL Support**: Configurable cache expiration
- **Cache Validation**: Ensures cache integrity and freshness
- **Cache Location**: `~/reconcli_dnscli_full/bypass_cache/`

## AI Analysis Integration

When `--ai` flag is enabled, BypassCLI provides:

- **Technique Effectiveness Analysis**: AI assessment of bypass success probability
- **Payload Optimization**: AI-suggested payload improvements
- **Security Impact Assessment**: Analysis of bypass implications
- **Remediation Recommendations**: AI-generated fix suggestions

## Security Considerations

### Ethical Usage

- Only test systems you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target systems
- Follow responsible disclosure practices for discovered vulnerabilities

### Legal Compliance

- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Document testing activities for compliance purposes

## Troubleshooting

### Common Issues

1. **External Tools Not Found**:
   ```bash
   # Ensure tools are properly installed and in PATH
   which forbidden
   which bypass-url-parser
   ```

2. **Permission Denied Errors**:
   ```bash
   # Check file permissions
   chmod +x forbidden/forbidden.py
   chmod +x bypass-url-parser/bypass-url-parser.py
   ```

3. **Network Connectivity Issues**:
   ```bash
   # Test basic connectivity
   curl -I https://example.com/admin
   ```

### Debug Mode

Enable verbose output for detailed debugging:

```bash
python reconcli.py bypasscli --url https://example.com/admin --verbose
```

## Configuration

### Tool Paths Configuration

Create `config/bypasscli_config.json`:

```json
{
  "forbidden_path": "/path/to/forbidden/forbidden.py",
  "bypass_parser_path": "/path/to/bypass-url-parser/bypass-url-parser.py",
  "default_timeout": 30,
  "default_retries": 3,
  "cache_ttl": 3600
}
```

### Headers Configuration

Create custom header profiles in `config/bypass_headers.json`:

```json
{
  "profiles": {
    "cloud_bypass": [
      "X-Forwarded-For: 127.0.0.1",
      "X-Real-IP: 127.0.0.1",
      "X-Cluster-Client-IP: 127.0.0.1"
    ],
    "cdn_bypass": [
      "X-Forwarded-Host: localhost",
      "X-Host: localhost",
      "X-Forwarded-Server: localhost"
    ]
  }
}
```

## Examples

### Bug Bounty Workflow

```bash
# 1. Discover restricted endpoints
echo "https://target.com/admin" > restricted_urls.txt
echo "https://target.com/api/internal" >> restricted_urls.txt

# 2. Test comprehensive bypasses
python reconcli.py bypasscli --input restricted_urls.txt \
  --use-forbidden --use-bypass-parser --custom-bypasses \
  --ai --output bypass_results.json

# 3. Analyze results
cat bypass_results.json | jq '.successful_bypasses[]'

# 4. Generate report
python reconcli.py bypasscli --generate-report bypass_results.json
```

### Red Team Assessment

```bash
# Stealth bypass testing with custom User-Agent
python reconcli.py bypasscli --url https://target.com/admin \
  --user-agent "Mozilla/5.0 (compatible; GoogleBot/2.1)" \
  --timeout 60 --retries 1 \
  --headers "X-Forwarded-For: 8.8.8.8"

# Test specific bypass categories
python reconcli.py bypasscli --url https://target.com/admin \
  --techniques "header_manipulation,path_traversal" \
  --custom-bypasses
```

### Automated Security Testing

```bash
# Integration with CI/CD pipeline
python reconcli.py bypasscli --input urls.txt \
  --output results.json \
  --format json \
  --exit-on-success

# Parse results for automated reporting
if [ $? -eq 0 ]; then
  echo "Bypasses found - security review required"
  exit 1
fi
```

## Integration with Other ReconCLI Modules

### Chain with URLCli

```bash
# Discover URLs then test bypasses
python reconcli.py urlcli --domain target.com --output discovered_urls.txt
python reconcli.py bypasscli --input discovered_urls.txt --ai
```

### Chain with HTTPCli

```bash
# Analyze HTTP responses then test bypasses
python reconcli.py httpcli --domain target.com --output http_analysis.json
cat http_analysis.json | jq -r '.urls[]' | python reconcli.py bypasscli --input -
```

## API Reference

### Command Line Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `--url` | string | Single URL to test |
| `--input` | string | File containing URLs to test |
| `--output` | string | Output file path |
| `--format` | string | Output format (json, txt, csv) |
| `--use-forbidden` | flag | Enable forbidden tool integration |
| `--use-bypass-parser` | flag | Enable bypass-url-parser integration |
| `--custom-bypasses` | flag | Enable custom bypass techniques |
| `--techniques` | string | Comma-separated list of techniques |
| `--headers` | list | Custom headers to include |
| `--user-agent` | string | Custom User-Agent string |
| `--timeout` | int | Request timeout in seconds |
| `--retries` | int | Number of retry attempts |
| `--ai` | flag | Enable AI analysis |
| `--verbose` | flag | Enable verbose output |

### Return Codes

- `0`: No bypasses found
- `1`: Bypasses found
- `2`: Error occurred
- `3`: Configuration error

## Contributing

To contribute to BypassCLI development:

1. Fork the repository
2. Create a feature branch
3. Implement new bypass techniques
4. Add comprehensive tests
5. Update documentation
6. Submit a pull request

## License

BypassCLI is part of the ReconCLI framework and follows the same licensing terms.

## Credits

- **Forbidden Tool**: https://github.com/ivan-sincek/forbidden
- **Bypass URL Parser**: https://github.com/laluka/bypass-url-parser
- **ReconCLI Framework**: Core framework and integration
