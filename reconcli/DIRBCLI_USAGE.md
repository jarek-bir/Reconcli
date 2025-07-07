# 🔍 DirBCLI - Advanced Directory Brute Force Scanner

Advanced directory brute force scanner with smart analysis capabilities, supporting multiple tools and providing comprehensive reporting.

## Features

### 🛠️ Multi-Tool Support
- **ffuf** - Fast web fuzzer (default, recommended)
- **feroxbuster** - Rust-based recursive scanner
- **gobuster** - Go-based directory/file brute forcer
- **dirsearch** - Python-based web path scanner

### 🧠 Smart Analysis
- **Technology Detection** - Automatically detects web technologies
- **Smart Wordlist Selection** - Recommends additional wordlists based on detected tech
- **Intelligent Categorization** - Categorizes findings by risk level
- **False Positive Reduction** - Advanced filtering to reduce noise

### 📊 Advanced Reporting
- **JSON Reports** - Machine-readable detailed reports
- **Markdown Reports** - Human-readable comprehensive reports
- **Security Recommendations** - Actionable security advice
- **Risk Assessment** - Categorizes findings by security impact

### 🔔 Notifications & Monitoring
- **Slack Integration** - Real-time notifications to Slack
- **Discord Integration** - Real-time notifications to Discord
- **Progress Tracking** - Live progress updates
- **High-Risk Alerts** - Automatic alerts for critical findings

## Usage Examples

### Basic Scanning
```bash
# Basic scan with ffuf
python3 main.py dirbcli --url https://example.com --wordlist /path/to/wordlist.txt

# Scan with technology detection
python3 main.py dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --tech-detect

# Verbose output with smart wordlist
python3 main.py dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --verbose --smart-wordlist --tech-detect
```

### Advanced Scanning
```bash
# Recursive scan with feroxbuster
python3 main.py dirbcli --url https://example.com --wordlist big.txt --tool feroxbuster --recursive --max-depth 2

# Scan with comprehensive reporting
python3 main.py dirbcli --url https://example.com --wordlist common.txt --json-report --markdown-report

# Scan with filtering and notifications
python3 main.py dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --filter-status 200,301,403 --slack-webhook https://hooks.slack.com/...
```

### Professional Scanning
```bash
# Full professional scan
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /usr/share/wordlists/dirb/big.txt \
    --tool ffuf \
    --threads 50 \
    --rate-limit 10 \
    --include-ext php,html,txt,js,css,json \
    --tech-detect \
    --smart-wordlist \
    --recursive \
    --max-depth 3 \
    --filter-status 200,301,302,403 \
    --auto-calibrate \
    --json-report \
    --markdown-report \
    --verbose \
    --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Command Line Options

### Required Options
- `--url` - Target URL (e.g., https://example.com)
- `--wordlist` - Path to wordlist file

### Tool Selection
- `--tool` - Choose scanner: ffuf, feroxbuster, gobuster, dirsearch (default: ffuf)

### Request Configuration
- `--proxy` - HTTP proxy (e.g., http://127.0.0.1:8080)
- `--user-agent` - Custom User-Agent string(s)
- `--custom-headers` - Custom headers (key:value,key2:value2)
- `--timeout` - Request timeout in seconds (default: 10)
- `--verify-ssl` - Verify SSL certificates
- `--delay` - Delay between requests (seconds)
- `--rate-limit` - Rate limit (requests per second)
- `--threads` - Number of concurrent threads (default: 25)

### Content Discovery
- `--include-ext` - File extensions to include (e.g., php,html,txt)
- `--recursive` - Enable recursive directory scanning
- `--max-depth` - Maximum recursion depth (default: 3)
- `--follow-redirects` - Follow HTTP redirects

### Filtering & Analysis
- `--filter-status` - Filter by status codes (e.g., 200,301,403)
- `--filter-size` - Filter by response size range (e.g., 100-1000)
- `--exclude-length` - Exclude responses with specific lengths
- `--include-length` - Include only responses with specific lengths
- `--match-regex` - Match responses with regex pattern
- `--auto-calibrate` - Auto-calibrate filtering (ffuf/feroxbuster)

### Smart Features
- `--tech-detect` - Detect web technologies before scanning
- `--smart-wordlist` - Use smart wordlist selection based on detected technology

### Output & Reporting
- `--output-dir` - Directory to save results (default: output/dirbcli)
- `--json-report` - Generate JSON report
- `--markdown-report` - Generate Markdown report
- `--verbose` - Enable verbose output
- `--resume` - Resume previous scan if possible

### Notifications
- `--slack-webhook` - Slack webhook URL for notifications
- `--discord-webhook` - Discord webhook URL for notifications

### User-Agent Management
- `--user-agent` - Custom User-Agent string(s) (can be used multiple times)
- `--user-agent-file` - Load User-Agents from file (one per line, # for comments)
- `--builtin-ua` - Use built-in User-Agent collection (25+ popular agents)
- `--random-ua` - Use random User-Agent from selected collection

## Output Structure

### Files Generated
```
output/dirbcli/
├── ffuf.json                    # Tool raw output
├── dirbcli_report.json         # Comprehensive JSON report
├── dirbcli_report.md           # Markdown report
└── feroxbuster.state           # Resume state (if applicable)
```

### Report Content
- **Scan Overview** - Target info, duration, statistics
- **Technology Detection** - Detected web technologies
- **Findings by Status Code** - HTTP response analysis
- **Security Categorization** - Risk-based categorization
- **Detailed Findings** - Complete results with metadata
- **Security Recommendations** - Actionable security advice

## Security Categories

### High Risk 🔴
- **Admin Panels** - Administrative interfaces
- **Config Files** - Configuration files
- **Backup Files** - Backup and archive files
- **Development Files** - Development/debug files

### Medium Risk 🟡
- **Sensitive Files** - Log files, databases
- **API Endpoints** - API interfaces
- **Server Info** - Server status pages

### Low Risk 🟢
- **Static Content** - CSS, JS, images
- **Common Directories** - Standard web directories

## Technology-Specific Features

### WordPress Detection
- Automatic detection of WordPress installations
- Specialized wordlists for wp-admin, wp-content, plugins
- Security recommendations for WordPress hardening

### PHP Applications
- Detection of PHP-based applications
- PHP-specific file extensions and directories
- Configuration file detection (.htaccess, php.ini)

### Framework Detection
- Support for popular frameworks (Laravel, Symfony, etc.)
- Framework-specific directory structures
- Custom security recommendations

## Integration Examples

### CI/CD Integration
```bash
#!/bin/bash
# CI/CD pipeline integration
python3 main.py dirbcli \
    --url $TARGET_URL \
    --wordlist /opt/wordlists/common.txt \
    --json-report \
    --slack-webhook $SLACK_WEBHOOK \
    --filter-status 200,301,403 \
    --timeout 30
```

### Automated Scanning
```bash
#!/bin/bash
# Automated scanning script
for domain in $(cat domains.txt); do
    python3 main.py dirbcli \
        --url "https://$domain" \
        --wordlist /usr/share/wordlists/dirb/big.txt \
        --output-dir "results/$domain" \
        --tech-detect \
        --smart-wordlist \
        --json-report \
        --verbose
done
```

## Requirements

### Tool Dependencies
- **ffuf** - `go install github.com/ffuf/ffuf@latest`
- **feroxbuster** - `cargo install feroxbuster`
- **gobuster** - `go install github.com/OJ/gobuster/v3@latest`
- **dirsearch** - `pip install dirsearch`

### Python Dependencies
- click
- requests
- pathlib
- urllib3

## Best Practices

### Performance Optimization
- Use appropriate thread counts (25-50 for most targets)
- Implement rate limiting to avoid overwhelming targets
- Use auto-calibration to reduce false positives
- Leverage smart wordlist selection for efficiency

### Security Considerations
- Always get proper authorization before scanning
- Respect robots.txt and website policies
- Use appropriate delays to avoid DoS conditions
- Implement proper error handling and logging

### Wordlist Management
- Use targeted wordlists for specific technologies
- Combine multiple wordlists for comprehensive coverage
- Create custom wordlists based on target analysis
- Regularly update wordlists with new patterns

## Troubleshooting

### Common Issues
1. **Tool not found** - Ensure required tools are installed and in PATH
2. **Permission denied** - Check file permissions and directory access
3. **Rate limiting** - Reduce thread count or increase delay
4. **SSL errors** - Use `--verify-ssl` flag or check certificate validity

### Debug Options
- Use `--verbose` for detailed output
- Check raw tool output files
- Verify target accessibility before scanning
- Review generated reports for analysis

## Advanced Configuration

### Custom Headers
```bash
# Custom headers for authentication
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --custom-headers "Authorization: Bearer token123,X-API-Key: secret456"
```

### Proxy Configuration
```bash
# Using proxy for scanning
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --proxy http://127.0.0.1:8080
```

### Multi-Stage Scanning
```bash
# Stage 1: Quick discovery
python3 main.py dirbcli --url https://example.com --wordlist quick.txt --tech-detect

# Stage 2: Technology-specific scan
python3 main.py dirbcli --url https://example.com --wordlist wordpress.txt --smart-wordlist

# Stage 3: Comprehensive scan
python3 main.py dirbcli --url https://example.com --wordlist big.txt --recursive --max-depth 3
```

### User-Agent Configuration
```bash
# Built-in User-Agent collection
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --builtin-ua

# Random User-Agent from built-in collection
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --builtin-ua \
    --random-ua

# User-Agents from file
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --user-agent-file user_agents.txt

# Random User-Agent from file
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --user-agent-file user_agents.txt \
    --random-ua

# Multiple custom User-Agents
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist /path/to/wordlist.txt \
    --user-agent "Mozilla/5.0 (Windows NT 10.0)" \
    --user-agent "Mozilla/5.0 (Macintosh; Intel)" \
    --user-agent "CustomBot/1.0"
```

## Contributing

This module is part of the ReconCLI project. For contributions, please follow the project's contribution guidelines and ensure all new features include appropriate tests and documentation.
