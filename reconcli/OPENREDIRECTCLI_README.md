# 🔄 OpenRedirectCLI - Advanced Open Redirect Vulnerability Scanner

## Overview

OpenRedirectCLI is a comprehensive tool for detecting open redirect vulnerabilities with advanced evasion techniques, AI-powered analysis, external tool integration, and detailed reporting capabilities.

## 🚀 Key Features

### Core Capabilities
- **Advanced Payload Generation**: Built-in and custom payload support with encoding options
- **AI-Powered Analysis**: Intelligent vulnerability detection and severity assessment
- **External Tool Integration**: OpenRedirex, kxss, waybackurls, GAU, unfurl, httpx support
- **Multiple Detection Methods**: Header redirects, JavaScript redirects, meta refresh
- **Comprehensive Reporting**: JSON, TXT, CSV, Markdown, Burp Suite formats
- **Database Integration**: ReconCLI database storage with program classification
- **Resume Functionality**: Continue interrupted scans
- **Real-time Notifications**: Slack and Discord webhook support

### AI Enhancements
- **Smart Payload Generation**: Context-aware payload creation based on URL analysis
- **Intelligent Response Analysis**: AI-powered detection of hidden redirect mechanisms
- **Dynamic Severity Assessment**: Context-based risk evaluation
- **Actionable Insights**: Comprehensive vulnerability analysis and remediation guidance

## 📦 Installation

```bash
# Install ReconCLI framework
git clone https://github.com/your-repo/reconcli
cd reconcli
pip install -r requirements.txt

# Optional: Install external tools for enhanced functionality
go install github.com/devanshbatham/OpenRedireX@latest
go install github.com/Emoe/kxss@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
```

## 🎯 Basic Usage

### Quick Start
```bash
# Basic open redirect testing
python -m reconcli.openredirectcli -i urls.txt --verbose

# AI-powered testing
python -m reconcli.openredirectcli -i urls.txt --ai-mode --verbose

# Complete assessment with external tools
python -m reconcli.openredirectcli -i urls.txt \
    --use-openredirex \
    --use-kxss \
    --use-waybackurls \
    --ai-mode \
    --store-db \
    --markdown \
    --verbose
```

### Input File Format
Create a `urls.txt` file with target URLs:
```
https://example.com/redirect?url=FUZZ
https://target.com/goto?next=FUZZ
https://site.com/login?returnUrl=FUZZ
https://app.com/auth?redirect_uri=FUZZ
```

## 🎛️ Advanced Usage Examples

### 🧠 AI-Powered Testing
```bash
# Enhanced AI analysis with custom model
python -m reconcli.openredirectcli -i urls.txt \
    --ai-mode \
    --ai-model "gpt-4" \
    --ai-confidence 0.8 \
    --advanced-payloads \
    --verbose

# AI with external tool integration
python -m reconcli.openredirectcli -i urls.txt \
    --ai-mode \
    --use-openredirex \
    --use-waybackurls \
    --check-javascript \
    --check-meta-refresh \
    --markdown
```

### 🔍 Bug Bounty Workflow
```bash
# Complete bug bounty assessment
python -m reconcli.openredirectcli -i scope_urls.txt \
    --ai-mode \
    --use-waybackurls \
    --use-gau \
    --use-httpx \
    --filter-params \
    --store-db \
    --program "hackerone-target" \
    --target-domain example.com \
    --severity medium \
    --markdown \
    --slack-webhook "https://hooks.slack.com/services/..." \
    --verbose
```

### 🛠️ Penetration Testing
```bash
# Comprehensive pentest with proxy
python -m reconcli.openredirectcli -i target_urls.txt \
    --use-openredirex \
    --use-kxss \
    --check-javascript \
    --check-meta-refresh \
    --save-responses \
    --proxy http://127.0.0.1:8080 \
    --custom-headers '{"X-Forwarded-For": "127.0.0.1"}' \
    --cookie "session=abc123" \
    --output-format json \
    --burp-suite \
    --verbose
```

### 🎯 Custom Payload Testing
```bash
# Custom payloads with encoding
python -m reconcli.openredirectcli -i urls.txt \
    --payloads custom_payloads.txt \
    --payload-encoding double \
    --keyword "FUZZ" \
    --advanced-payloads \
    --verbose

# Test specific status codes
python -m reconcli.openredirectcli -i urls.txt \
    --check-status-codes "301,302,303,307,308,200" \
    --follow-redirects \
    --max-redirects 10 \
    --verbose
```

### 📊 URL Discovery Pipeline
```bash
# Discover and test URLs automatically
python -m reconcli.openredirectcli -i domains.txt \
    --use-waybackurls \
    --use-gau \
    --use-httpx \
    --httpx-flags "-mc 200,301,302,303,307,308 -fc 404,403" \
    --use-gf \
    --gf-pattern "redirect" \
    --filter-params \
    --ai-mode \
    --store-db \
    --verbose
```

## 🔧 Configuration Options

### Core Settings
| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input` | File with URLs to test | Required |
| `--threads` | Number of concurrent threads | 50 |
| `--timeout` | Request timeout in seconds | 10 |
| `--delay` | Delay between requests | 0.0 |
| `--retries` | Number of retries for failed requests | 2 |

### AI Configuration
| Option | Description | Default |
|--------|-------------|---------|
| `--ai-mode` | Enable AI-powered analysis | False |
| `--ai-model` | AI model to use | gpt-3.5-turbo |
| `--ai-confidence` | Minimum confidence threshold | 0.7 |

### External Tools
| Option | Description | Tool Required |
|--------|-------------|---------------|
| `--use-openredirex` | Advanced redirect testing | OpenRedirex |
| `--use-kxss` | Reflected parameter detection | kxss |
| `--use-waybackurls` | Historical URL discovery | waybackurls |
| `--use-gau` | URL discovery | GAU |
| `--use-unfurl` | URL parsing and analysis | unfurl |
| `--use-httpx` | Fast HTTP probing | httpx |
| `--use-gf` | Pattern-based filtering | gf |
| `--use-qsreplace` | Parameter replacement | qsreplace |

### Output Options
| Option | Description |
|--------|-------------|
| `--output-format` | json, txt, csv, xml |
| `--markdown` | Generate Markdown report |
| `--burp-suite` | Burp Suite compatible output |
| `--nuclei-export` | Export for Nuclei verification |
| `--save-responses` | Save full HTTP responses |

### Database & Notifications
| Option | Description |
|--------|-------------|
| `--store-db` | Store in ReconCLI database |
| `--program` | Bug bounty program name |
| `--target-domain` | Primary target domain |
| `--slack-webhook` | Slack notification URL |
| `--discord-webhook` | Discord notification URL |

## 📊 Output Formats

### JSON Output
```json
{
  "scan_info": {
    "timestamp": "2025-07-12T15:30:00",
    "target_domain": "example.com",
    "total_findings": 5,
    "ai_mode": true,
    "ai_model": "gpt-3.5-turbo"
  },
  "findings": [
    {
      "timestamp": "2025-07-12T15:30:15",
      "original": "https://example.com/redirect?url=FUZZ",
      "test": "https://example.com/redirect?url=http://evil.com",
      "payload": "http://evil.com",
      "status": 302,
      "location": "http://evil.com",
      "severity": "critical",
      "method": "header_redirect",
      "external_redirect": true
    }
  ],
  "ai_insights": {
    "risk_assessment": "Critical external redirect vulnerabilities detected",
    "remediation_priorities": ["Implement whitelist validation", "..."],
    "business_impact": "High risk of phishing attacks"
  }
}
```

### Markdown Report
The tool generates comprehensive Markdown reports with:
- Executive summary
- AI-powered analysis (if enabled)
- Detailed findings with severity ratings
- Remediation recommendations
- Business impact assessment

## 🎯 Resume Functionality

```bash
# Check resume status
python -m reconcli.openredirectcli -i urls.txt --resume-stats

# Resume interrupted scan
python -m reconcli.openredirectcli -i urls.txt --resume

# Reset resume state
python -m reconcli.openredirectcli -i urls.txt --resume-reset
```

## 🔍 Detection Methods

### 1. Header-Based Redirects
- Analyzes HTTP Location headers
- Tests various status codes (301, 302, 303, 307, 308)
- Payload injection in redirect parameters

### 2. JavaScript Redirects
- Detects `window.location` assignments
- Identifies `location.href` modifications
- Finds `location.replace()` calls
- Discovers `window.open()` redirects

### 3. Meta Refresh Redirects
- Parses HTML meta refresh tags
- Extracts redirect URLs from content attribute
- Validates payload presence in destinations

### 4. AI-Enhanced Detection
- Context-aware payload generation
- Intelligent response analysis
- Hidden redirect mechanism discovery
- Confidence-based filtering

## 🛡️ Security Considerations

### Responsible Testing
- Only test applications you own or have permission to test
- Use appropriate delays to avoid overwhelming target servers
- Respect rate limits and terms of service
- Consider using proxy settings for controlled testing

### Payload Safety
- Default payloads use safe redirect destinations
- Custom payloads should avoid malicious content
- Test payloads in controlled environments first

## 🔧 Troubleshooting

### Common Issues

**Import Errors**
```bash
# Install missing dependencies
pip install -r requirements.txt
pip install click requests
```

**External Tool Not Found**
```bash
# Install missing tools
go install github.com/devanshbatham/OpenRedireX@latest
# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**AI Mode Issues**
```bash
# Check AI module availability
python -c "from reconcli.aicli import AIAnalyzer; print('AI available')"
```

**Database Storage Issues**
```bash
# Verify database module
python -c "from reconcli.db.operations import store_target; print('DB available')"
```

## 📈 Performance Tips

### Optimization
- Use `--threads` to adjust concurrency based on target capacity
- Set appropriate `--delay` to respect rate limits
- Use `--filter-params` to focus on relevant URLs
- Enable `--use-httpx` for faster URL validation

### Large Scale Testing
```bash
# High-performance configuration
python -m reconcli.openredirectcli -i large_urls.txt \
    --threads 100 \
    --delay 0.1 \
    --timeout 5 \
    --use-httpx \
    --filter-params \
    --severity medium \
    --resume
```

## 🎓 Learning Resources

### Understanding Open Redirects
- [OWASP Open Redirect Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/dom-based/open-redirection)

### Tool-Specific Documentation
- [OpenRedirex](https://github.com/devanshbatham/OpenRedireX)
- [kxss](https://github.com/Emoe/kxss)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [httpx](https://github.com/projectdiscovery/httpx)

## 🤝 Contributing

### Feature Requests
- Submit issues for new detection methods
- Suggest external tool integrations
- Propose AI enhancement ideas

### Bug Reports
- Include command used and error output
- Provide sample URLs if possible
- Specify environment details

## 📝 Changelog

### Latest Updates
- ✅ AI-powered payload generation and analysis
- ✅ Enhanced external tool integration
- ✅ Comprehensive reporting with insights
- ✅ Database storage with program classification
- ✅ Real-time notifications support
- ✅ Resume functionality for large scans
- ✅ Multiple output formats

## 📜 License

This tool is part of the ReconCLI framework and follows the same licensing terms.

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for ensuring they have proper permission before testing any applications.
