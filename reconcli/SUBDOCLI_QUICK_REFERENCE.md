# 📋 SubdoCLI Quick Reference Card

## 🚀 Basic Usage

```bash
d
git# Standard subdomain enumeration (traditional tools)
reconcli subdocli --domain example.com --verbose

# Traditional passive tools only (no BBOT, no active)
reconcli subdocli --domain example.com --passive-only --verbose

# Traditional active tools only (no BBOT, no passive)
reconcli subdocli --domain example.com --active-only --verbose

# BBOT-powered enumeration (recommended)
reconcli subdocli --domain example.com --bbot --verbose

# Intensive mode with maximum coverage
reconcli subdocli --domain example.com --bbot-intensive --verbose
```

## 📊 Export Formats

```bash
# CSV export for spreadsheet analysis
reconcli subdocli --domain example.com --bbot --export csv --verbose

# JSON export for programmatic processing
reconcli subdocli --domain example.com --bbot --export json --verbose

# TXT export for human-readable reports
reconcli subdocli --domain example.com --bbot --export txt --verbose
```

## 🔍 Advanced Analysis

```bash
# Full reconnaissance with all features
reconcli subdocli --domain example.com --bbot-intensive \
  --resolve --probe-http --all-tools \
  --export csv --markdown --store-db \
  --show-stats --verbose

# Resume interrupted scan
reconcli subdocli --domain example.com --bbot --resume --verbose
```

## 💾 Database Integration

```bash
# Store results in database with program tracking
reconcli subdocli --domain example.com --bbot \
  --store-db --program "Bug Bounty Program" --verbose
```

## 📚 Key Options

| Option | Description |
|--------|-------------|
| `--passive-only` | Use only traditional passive tools (no BBOT, no active) |
| `--active-only` | Use only traditional active tools (no BBOT, no passive) |
| `--bbot` | Enable BBOT with 53+ passive modules |
| `--bbot-intensive` | Aggressive mode with bruteforcing |
| `--resolve` | Resolve subdomains to IP addresses |
| `--probe-http` | Test HTTP/HTTPS services |
| `--export csv\|json\|txt` | Export results in specified format |
| `--all-tools` | Use all tools (passive + active + BBOT) |
| `--resume` | Continue interrupted scan |
| `--store-db` | Save to ReconCLI database |

## 🎯 Example Output

**TXT Export Sample:**
```txt
# Subdomain Enumeration Report for example.com
# Total Subdomains: 150
# BBOT Integration: 53+ modules

# ALL DISCOVERED SUBDOMAINS
api.example.com
admin.example.com
dev.example.com

# RESOLVED WITH IP ADDRESSES
api.example.com -> 192.168.1.100
admin.example.com -> 10.0.0.50

# ACTIVE HTTP/HTTPS SERVICES
api.example.com -> HTTP(200) | HTTPS(200)
admin.example.com -> HTTP(403) | HTTPS(403)

# STATISTICS
Resolution Rate: 80.0%
HTTP Services: 60.0%
HTTPS Services: 70.0%
```

📚 **Complete Documentation**: `reconcli/SUBDOCLI_GUIDE.md`
