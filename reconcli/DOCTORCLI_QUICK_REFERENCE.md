# 🩺 DoctorCLI Quick Reference

Quick reference guide for ReconCLI's environment diagnostic tool.

## 🚀 Essential Commands

```bash
# Complete health check with fixes
reconcli doctorcli --all --fix --verbose

# Safe mode - check without changes
reconcli doctorcli --all --dry-run --verbose

# Quick system overview
reconcli doctorcli --system --network --paths --quiet
```

## 🎛️ Command Options

### Basic Options
| Option | Description |
|--------|-------------|
| `--all` | Run all diagnostic checks |
| `--fix` | Attempt to fix found issues |
| `--dry-run` | Check without making changes |
| `--verbose` | Detailed output |
| `--quiet` | Minimal output |

### Diagnostic Categories
| Option | What it checks |
|--------|----------------|
| `--tools` | Required reconnaissance tools (35+) |
| `--optional` | Optional/advanced tools |
| `--python` | Python packages |
| `--env` | API keys in .env_secrets |
| `--structure` | Directory organization |
| `--configs` | Configuration files |
| `--permissions` | File permissions |
| `--system` | System information |
| `--network` | Connectivity to targets |
| `--paths` | Programming environments |

### Advanced Options
| Option | Description |
|--------|-------------|
| `--strict` | Enable hash checking |
| `--export {json,markdown,html}` | Report format |
| `--output-dir DIR` | Report directory |

## 🔧 Common Use Cases

### Initial Setup
```bash
# Set up new environment
reconcli doctorcli --all --fix --verbose
```

### Quick Health Check
```bash
# Daily environment check
reconcli doctorcli --tools --network --quiet
```

### Before Reconnaissance
```bash
# Pre-flight check
reconcli doctorcli --tools --env --structure --fix --verbose
```

### Troubleshooting
```bash
# Diagnose issues
reconcli doctorcli --all --dry-run --verbose --export html
```

### CI/CD Integration
```bash
# Automated validation
reconcli doctorcli --all --quiet --export json --output-dir /tmp/
```

## 🔍 What Gets Checked

### Required Tools (35+)
- **Subdomain**: amass, subfinder, assetfinder, findomain
- **Web**: httpx, nuclei, dalfox, ffuf, gobuster
- **Secrets**: gitleaks, trufflehog, jsubfinder
- **Network**: nmap, masscan, naabu
- **Crawling**: hakrawler, gau, waybackurls, katana

### Optional Tools
- wafw00f, whatwaf, gotestwaf, subzy, tko-subs, openredirex, kxss

### Python Packages
- click, requests, beautifulsoup4, lxml, colorama, tqdm, pyyaml

### Environment Variables
- SHODAN_API_KEY, WHOISFREAKS_API_KEY, FOFA_EMAIL, FOFA_KEY

### Directories
- output/, wordlists/, configs/, workflows/, templates/

### Programming Environments
- Go, Python, Ruby, Perl, Node.js, NPM, Git, Curl, Wget

## 🩹 Auto-Fix Capabilities

| Issue | Fix |
|-------|-----|
| Missing directories | Creates required folders |
| Missing configs | Generates default configurations |
| No .env_secrets | Creates template with API key placeholders |
| Wrong permissions | Sets appropriate file/directory permissions |

## 📊 Report Formats

### JSON Report
```bash
reconcli doctorcli --all --export json --output-dir reports/
# Creates: reports/doctor_report.json
```

### Markdown Report
```bash
reconcli doctorcli --all --export markdown --output-dir reports/
# Creates: reports/doctor_report.md
```

### HTML Report
```bash
reconcli doctorcli --all --export html --output-dir reports/
# Creates: reports/doctor_report.html (interactive dashboard)
```

## ⚠️ Common Issues & Solutions

### Tools Not Found
```bash
# Check PATH and get install suggestions
reconcli doctorcli --tools --paths --fix --verbose
```

### Permission Errors
```bash
# Fix file permissions
reconcli doctorcli --permissions --fix --verbose
```

### Missing Configuration
```bash
# Create default configs
reconcli doctorcli --configs --structure --fix --verbose
```

### Network Issues
```bash
# Test connectivity
reconcli doctorcli --network --verbose
```

## 🎯 Best Practices

1. **Regular Checks**: Run weekly health checks
2. **Pre-Project**: Always check before starting reconnaissance
3. **Use Dry-Run**: Test fixes before applying
4. **Export Reports**: Keep diagnostic history
5. **CI/CD Integration**: Automate environment validation

## 🔗 Integration

### With Other Tools
```bash
# Environment check before reconnaissance
reconcli doctorcli --all --fix --quiet
reconcli subdocli --domain example.com

# Generate comprehensive reports
reconcli doctorcli --all --export markdown --output-dir reports/
reconcli mdreportcli --input reports/ --template comprehensive
```

### Database Storage
```bash
# Compatible with ReconCLI database
reconcli doctorcli --all --export json --output-dir output/
```

---

For detailed documentation, see [DOCTORCLI_GUIDE.md](DOCTORCLI_GUIDE.md) or run `reconcli doctorcli --help`.
