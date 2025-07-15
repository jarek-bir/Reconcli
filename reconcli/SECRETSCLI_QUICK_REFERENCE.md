# SecretsCLI Quick Reference

## 🚀 Basic Commands

```bash
# Scan Git repository
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog

# Scan local directory
reconcli secretscli --input /path/to/source --tool gitleaks

# Multi-tool scan
reconcli secretscli --input targets.txt --tool trufflehog,gitleaks,jsubfinder
```

## 🎯 Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--tool` | Specify scanning tool(s) | `--tool trufflehog,gitleaks` |
| `--verbose` | Enable detailed output | `--verbose` |
| `--export` | Export formats | `--export json,markdown` |
| `--filter-keywords` | Include keywords | `--filter-keywords "api,key,secret"` |
| `--exclude-keywords` | Exclude keywords | `--exclude-keywords "test,demo"` |
| `--min-confidence` | Confidence threshold | `--min-confidence 0.8` |
| `--entropy-threshold` | Entropy threshold | `--entropy-threshold 5.0` |
| `--resume` | Resume interrupted scan | `--resume` |
| `--proxy` | HTTP proxy | `--proxy http://127.0.0.1:8080` |

## 🔧 Supported Tools

- **trufflehog** - Git repository scanning with verification
- **gitleaks** - Source code secret detection
- **jsubfinder** - JavaScript secret discovery
- **cariddi** - Web crawler with secret patterns
- **mantra** - Additional secret scanning
- **shhgit** - Real-time GitHub monitoring

## 📊 Export Formats

- **json** - Structured data export
- **markdown** - Professional reports
- **csv** - Spreadsheet format
- **txt** - Plain text output

## 🎛️ Advanced Features

```bash
# Enterprise scanning with all features
reconcli secretscli --input repos.txt \
  --tool trufflehog,gitleaks \
  --filter-keywords "api,key,secret" \
  --min-confidence 0.7 \
  --export json,markdown \
  --store-db secrets.db \
  --resume --verbose

# Custom configuration
reconcli secretscli --input /source \
  --tool gitleaks \
  --config-file security.json \
  --wordlist patterns.txt \
  --extensions js,py,php \
  --exclude-paths test/,node_modules/ \
  --proxy http://proxy:8080
```

## 🚨 Security Scanning Workflow

1. **Discovery**: Use subdocli/urlcli to find targets
2. **Repository Search**: Use gitcli to find code repositories
3. **Secret Scanning**: Use secretscli to detect secrets
4. **Analysis**: Use csvtkcli for data analysis
5. **Reporting**: Use mdreportcli for professional reports

```bash
# Complete workflow
reconcli subdocli --domain target.com --output subdomains.txt
reconcli gitcli search --domain target.com --output repos.txt
reconcli secretscli --input repos.txt --tool trufflehog --store-db
reconcli csvtkcli security-report secrets_export.csv
reconcli mdreportcli generate --template security
```

## 📋 Troubleshooting

| Issue | Solution |
|-------|----------|
| Tool not found | Install with `go install` |
| Permission denied | Check file/repo permissions |
| Timeout errors | Increase `--timeout` value |
| Large memory usage | Reduce `--concurrency` |
| Empty results | Lower `--min-confidence` |

## 🔗 Related Tools

- **TruffleHog**: `go install github.com/trufflesecurity/trufflehog/v3@latest`
- **Gitleaks**: `go install github.com/gitleaks/gitleaks/v8@latest`
- **JSubFinder**: `go install github.com/ThreatUnkown/jsubfinder@latest`
- **Cariddi**: `go install github.com/edoardottt/cariddi/cmd/cariddi@latest`

---

*Quick reference for SecretsCLI - Advanced secret discovery tool*
