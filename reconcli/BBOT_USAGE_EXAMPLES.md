# 🤖 BBOT SubdoCLI - Quick Usage Examples

## Standard BBOT Enumeration
```bash
# Enable BBOT with 53+ modules for superior subdomain discovery
reconcli subdocli --domain example.com --bbot --verbose
```

## Intensive BBOT Mode
```bash
# Maximum coverage with aggressive techniques and larger wordlists
reconcli subdocli --domain example.com --bbot-intensive --verbose
```

## Complete Bug Bounty Workflow
```bash
# Ultimate subdomain enumeration for bug bounty hunting
reconcli subdocli --domain target.com --bbot-intensive --resolve --probe-http \
  --all-tools --store-db --program "Bug Bounty Program" --markdown --show-stats
```

## OSINT Investigation
```bash
# Pure passive enumeration with maximum intelligence sources
reconcli subdocli --domain target.com --bbot --markdown --verbose
```

## Penetration Testing
```bash
# Comprehensive enumeration with active techniques
reconcli subdocli --domain client.com --bbot --active --all-tools \
  --resolve --probe-http --ignore-ssl-errors --timeout 120
```

## � Data Export & Analysis
```bash
# Export results to CSV for spreadsheet analysis
reconcli subdocli --domain target.com --bbot --resolve --probe-http --export csv

# Export to JSON for programmatic analysis
reconcli subdocli --domain target.com --bbot-intensive --export json

# Complete workflow with all export formats
reconcli subdocli --domain target.com --bbot-intensive --resolve --probe-http \
  --markdown --export json --store-db --show-stats
```

## �🚀 What Makes BBOT Special?

- **53+ Specialized Modules** vs 8 traditional tools
- **Certificate Transparency Monitoring** with 4 dedicated modules
- **GitHub Code Search** for discovering subdomains in repositories
- **Cloud Intelligence** for Azure, AWS, GCP resource discovery
- **Intelligent Mutations** with target-specific wordlist generation
- **Advanced APIs** from Shodan, VirusTotal, SecurityTrails, and 20+ more

## 📊 Expected Results

- **Traditional SubdoCLI**: 100-500 subdomains
- **BBOT Integration**: 300-2000+ subdomains (2-5x improvement)
- **Unique Discovery**: Finds subdomains other tools miss

---

**BBOT transforms ReconCLI SubdoCLI into one of the most powerful subdomain enumeration tools available! 🎯**
