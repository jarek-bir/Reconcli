# XSSCLI Advanced Guide

## Overview

XSSCLI is a comprehensive Cross-Site Scripting (XSS) testing module for ReconCLI that provides advanced vulnerability detection and analysis capabilities.

## Features

### Core Functionality

- **Multi-tool XSS scanning** - Integration with popular XSS testing tools
- **Custom payload management** - Store and organize custom XSS payloads  
- **WAF detection** - Identify Web Application Firewalls
- **URL discovery** - Gather URLs from multiple sources
- **Database tracking** - SQLite database for results management
- **Resume capabilities** - Pause and resume scanning sessions

### Supported Tools

- **Dalfox** - Fast XSS scanner
- **XSStrike** - Advanced XSS detection tool
- **kxss** - Fast XSS detection
- **Linkfinder** - Endpoint discovery in JavaScript
- **ParamSpider** - Parameter discovery
- **waybackurls** - Historical URL discovery
- **gau** - GetAllUrls tool
- **hakrawler** - Fast web crawler
- **gospider** - Fast web spider
- **katana** - Next-generation crawling framework
- **nuclei** - Vulnerability scanner

## Installation

### Prerequisites

```bash
pip install click httpx
```

### External Tools

```bash
# Go-based tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/kxss@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest

# Python tools
git clone https://github.com/s0md3v/XSStrike.git
```

## Usage Examples

### Basic Commands

#### Check Dependencies

```bash
python -m reconcli.xsscli check-deps
```

#### WAF Detection

```bash
python -m reconcli.xsscli detect-waf --url https://example.com
python -m reconcli.xsscli detect-waf --url https://example.com --output waf_results.txt
```

#### Manual XSS Testing

```bash
python -m reconcli.xsscli manual-test --url https://example.com --param search
python -m reconcli.xsscli manual-test --url https://example.com --payloads-file custom.txt
```

#### Custom Payload Management

```bash
# Add payload
python -m reconcli.xsscli add-payload --payload "<script>alert('test')</script>" --category "basic"

# List payloads  
python -m reconcli.xsscli list-payloads --category basic --active-only

# Add tagged payload
python -m reconcli.xsscli add-payload --payload "<img src=x onerror=alert(1)>" --tags "img,basic"
```

#### URL Discovery

```bash
python -m reconcli.xsscli gather-urls --domain example.com --output urls.txt
python -m reconcli.xsscli gather-urls --domain example.com --sources wayback,gau,hakrawler
```

#### Tool Integration

```bash
# Dalfox scanning
python -m reconcli.xsscli dalfox --target https://example.com --threads 50

# kxss scanning  
python -m reconcli.xsscli kxss --input urls.txt --output results.txt

# Parameter discovery
python -m reconcli.xsscli paramspider --domain example.com
```

#### Full Scanning Pipeline

```bash
python -m reconcli.xsscli full-scan --target example.com --threads 20 --output results/
```

### Advanced Features

#### Statistics and Reporting

```bash
# Show scanning statistics
python -m reconcli.xsscli stats

# Show recent results
python -m reconcli.xsscli show-results --limit 20 --vulnerable-only
```

#### Export Results

```bash
# Export to different formats
python -m reconcli.xsscli export --format json --output results.json
python -m reconcli.xsscli export --format csv --output results.csv
```

#### Database Management

```bash
# Clean up old results
python -m reconcli.xsscli cleanup

# Resume queue management
python -m reconcli.xsscli resume-stat
python -m reconcli.xsscli resume-add --url https://example.com
```

## Database Schema

### Results Table

Stores XSS testing results with fields:

- `url` - Target URL tested
- `param` - Parameter that was tested
- `payload` - XSS payload used
- `reflected` - Whether payload was reflected
- `vulnerable` - Confirmed vulnerability status
- `tool_used` - Tool that generated the result
- `severity` - Vulnerability severity level
- `confidence_score` - Confidence in the finding

### Custom Payloads Table

Manages custom XSS payloads:

- `payload` - The XSS payload
- `category` - Payload category
- `success_rate` - Historical success rate
- `times_used` - Usage statistics
- `tags` - Searchable tags

### WAF Detection Table

Tracks WAF detection results:

- `waf_type` - Type of WAF detected
- `detection_method` - How it was detected
- `confidence` - Detection confidence
- `bypass_payloads` - Potential bypass methods

## Payload Categories

- **basic** - Simple XSS payloads
- **dom** - DOM-based XSS payloads
- **reflected** - Reflected XSS payloads
- **stored** - Stored XSS payloads
- **blind** - Blind XSS payloads
- **waf_bypass** - WAF bypass techniques
- **csp_bypass** - CSP bypass payloads
- **polyglot** - Multi-context payloads
- **modern** - Modern JavaScript techniques

## Workflow Examples

### Complete Bug Bounty Workflow

```bash
# 1. Setup and dependency check
python -m reconcli.xsscli check-deps

# 2. Gather target URLs
python -m reconcli.xsscli gather-urls --domain target.com --output urls.txt

# 3. Detect WAF protection
python -m reconcli.xsscli detect-waf --url https://target.com

# 4. Run automated tools
python -m reconcli.xsscli full-scan --target target.com --output scan_results/

# 5. Manual testing with custom payloads
python -m reconcli.xsscli manual-test --url https://target.com/search --param q

# 6. Review results and statistics
python -m reconcli.xsscli stats
python -m reconcli.xsscli show-results --vulnerable-only

# 7. Export findings
python -m reconcli.xsscli export --format json --output final_results.json
```

### Custom Payload Development

```bash
# Add new payload variations
python -m reconcli.xsscli add-payload --payload "<svg onload=fetch('/log?'+btoa(document.cookie))>" --category "modern" --tags "svg,fetch,stealth"

# Test effectiveness
python -m reconcli.xsscli manual-test --url https://target.com --payloads-file modern_payloads.txt

# Review payload performance
python -m reconcli.xsscli list-payloads --category modern
```

## Configuration

### Environment Variables

```bash
export RECONCLI_XSS_DB=/custom/path/xss.db
export RECONCLI_XSS_THREADS=20
export RECONCLI_XSS_TIMEOUT=30
```

### Custom Configuration Files

Create `~/.reconcli/xss_config.json`:

```json
{
  "default_threads": 20,
  "request_timeout": 30,
  "default_delay": 1,
  "max_payload_length": 1000,
  "custom_headers": {
    "User-Agent": "XSSCLI/2.0"
  }
}
```

## Troubleshooting

### Common Issues

1. **Missing Tools Error**

```bash
# Check what's missing
python -m reconcli.xsscli check-deps

# Install missing Go tools
go install github.com/hahwul/dalfox/v2@latest
```

2. **Database Permission Issues**

```bash
# Check directory permissions
ls -la ~/.reconcli/
chmod 755 ~/.reconcli/
```

3. **Network Timeouts**

```bash
# Increase delay between requests
python -m reconcli.xsscli manual-test --url target.com --delay 3
```

### Debug Mode

```bash
# Enable verbose logging
export RECONCLI_DEBUG=1
python -m reconcli.xsscli [command]
```

## Best Practices

### Responsible Testing

- Only test applications you have permission to test
- Respect rate limits and avoid DoS conditions
- Use minimal payloads that demonstrate the vulnerability
- Report findings through appropriate channels

### Optimization Tips

- Use URL filtering to focus on vulnerable endpoints
- Customize payloads for specific technologies
- Monitor success rates to improve payload effectiveness
- Regular database cleanup to maintain performance

### Payload Development

- Start with simple payloads and increase complexity
- Test different encoding methods
- Consider context-specific payloads
- Document successful bypass techniques

## Integration

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# xss_scan.sh
python -m reconcli.xsscli gather-urls --domain $TARGET --output urls.txt
python -m reconcli.xsscli dalfox --target $TARGET --output results.json
python -m reconcli.xsscli export --format json --output final_report.json
```

### Custom Tool Integration

Add new tools by extending the module:

```python
@cli.command()
@click.option("--target", required=True)
def custom_tool(target):
    """Integration with custom XSS tool."""
    # Implementation here
    pass
```

## Performance Tuning

### Large Scale Scanning

```bash
# Optimize for large targets
python -m reconcli.xsscli full-scan --target bigsite.com --threads 50 --output results/

# Use resume functionality for interrupted scans
python -m reconcli.xsscli resume-stat
```

### Memory Management

```bash
# Clean up regularly during long scans
python -m reconcli.xsscli cleanup

# Monitor database size
du -sh ~/.reconcli/xsscli.db
```

## Contributing

To contribute new features:

1. Add tool to `BINARIES` list
2. Implement wrapper function
3. Add CLI command with proper options
4. Update documentation
5. Add test cases

Example tool integration:

```python
@cli.command()
@click.option("--input", required=True, help="Input URLs file")
def new_tool(input):
    """Integration with new XSS tool."""
    if not check_binary("newtool"):
        print("[!] newtool not found")
        return
    
    subprocess.run(["newtool", "--input", input])
```
