# 🩺 DoctorCLI - Environment Diagnostic Tool

DoctorCLI is a comprehensive environment diagnostic tool for ReconCLI that verifies, validates, and fixes your reconnaissance environment to ensure optimal performance.

## 🚀 Quick Start

```bash
# Complete environment diagnostic with fixes
reconcli doctorcli --all --fix --verbose

# Dry-run mode - check everything without making changes
reconcli doctorcli --all --dry-run --verbose

# Quick system overview
reconcli doctorcli --system --network --paths --quiet
```

## 📋 Table of Contents

- [Installation Requirements](#installation-requirements)
- [Basic Usage](#basic-usage)
- [Command Line Options](#command-line-options)
- [Diagnostic Categories](#diagnostic-categories)
- [Report Formats](#report-formats)
- [Automated Fixes](#automated-fixes)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## 🔧 Installation Requirements

DoctorCLI is included with ReconCLI and requires no additional installation. However, it checks for the following components:

### Required Tools (35+)
- **Subdomain Enumeration**: amass, subfinder, assetfinder, findomain
- **Web Technologies**: httpx, nuclei, dalfox, ffuf, gobuster
- **Secret Discovery**: gitleaks, trufflehog, jsubfinder, shhgit
- **API & GraphQL**: uncover, graphw00f
- **Web Crawling**: hakrawler, gau, waybackurls, katana, gospider, cariddi
- **Vulnerability Assessment**: jaeles, gowitness, aquatone
- **Network & Port Scanning**: nmap, masscan, naabu
- **Additional Tools**: unfurl, anew, qsreplace

### Optional Tools
- wafw00f, whatwaf, gotestwaf, subzy, tko-subs, openredirex, kxss, mantra

### Python Packages
- click, requests, beautifulsoup4, lxml, colorama, tqdm, pyyaml, python-dotenv

## 🎯 Basic Usage

### Complete Environment Check
```bash
# Check everything and fix issues
reconcli doctorcli --all --fix --verbose

# Check everything in dry-run mode (no changes)
reconcli doctorcli --all --dry-run --verbose

# Quiet mode for automated scripts
reconcli doctorcli --all --fix --quiet
```

### Specific Component Checks
```bash
# Check only required tools
reconcli doctorcli --tools --verbose

# Check Python packages
reconcli doctorcli --python --verbose

# Check environment variables
reconcli doctorcli --env --verbose

# Check directory structure
reconcli doctorcli --structure --verbose
```

## 🎛️ Command Line Options

### Main Options
- `--all` - Run all diagnostic checks
- `--fix` - Attempt to fix found issues automatically
- `--dry-run` - Check everything but don't make any changes
- `--verbose` - Enable detailed output
- `--quiet` - Minimize output for scripts

### Diagnostic Categories
- `--tools` - Check required reconnaissance tools
- `--optional` - Check optional tools
- `--python` - Check Python packages
- `--env` - Check .env_secrets file
- `--structure` - Check directory structure
- `--configs` - Check configuration files
- `--permissions` - Check file permissions
- `--system` - Check system information
- `--network` - Test network connectivity
- `--paths` - Check programming environment paths

### Advanced Options
- `--strict` - Enable strict hash and alias checking
- `--export {json,markdown,html}` - Export format for reports
- `--output-dir DIR` - Output directory for reports (default: output)

## 🔍 Diagnostic Categories

### 1. Tool Installation Check (`--tools`)
Verifies installation of 35+ reconnaissance tools:

```bash
# Check all required tools
reconcli doctorcli --tools --verbose

# Check with installation suggestions
reconcli doctorcli --tools --fix --verbose
```

**Checked Tools:**
- Subdomain enumeration: amass, subfinder, assetfinder, findomain
- Web testing: httpx, nuclei, dalfox, ffuf, gobuster
- Secret discovery: gitleaks, trufflehog, jsubfinder
- Network scanning: nmap, masscan, naabu
- And 20+ more tools

### 2. Optional Tools Check (`--optional`)
Checks advanced/optional tools:

```bash
reconcli doctorcli --optional --verbose
```

**Optional Tools:**
- wafw00f, whatwaf, gotestwaf
- subzy, tko-subs
- openredirex, kxss, mantra

### 3. Python Packages (`--python`)
Validates essential Python packages:

```bash
reconcli doctorcli --python --fix --verbose
```

**Checked Packages:**
- click, requests, beautifulsoup4, lxml
- colorama, tqdm, pyyaml, python-dotenv

### 4. Environment Variables (`--env`)
Checks API keys and secrets configuration:

```bash
reconcli doctorcli --env --fix --verbose
```

**Checked Variables:**
- SHODAN_API_KEY
- WHOISFREAKS_API_KEY
- FOFA_EMAIL, FOFA_KEY

### 5. Directory Structure (`--structure`)
Ensures proper workspace organization:

```bash
reconcli doctorcli --structure --fix --verbose
```

**Required Directories:**
- output/, output/secrets/, output/vulns/, output/reports/
- workflows/, wordlists/, wordlists/subdomains/, wordlists/directories/
- configs/, templates/

### 6. Configuration Files (`--configs`)
Validates tool configuration files:

```bash
reconcli doctorcli --configs --fix --verbose
```

**Configuration Files:**
- configs/nuclei-config.yaml
- configs/httpx-config.yaml
- configs/amass-config.ini
- wordlists/subdomains/common.txt
- wordlists/directories/common.txt

### 7. File Permissions (`--permissions`)
Checks security-related file permissions:

```bash
reconcli doctorcli --permissions --fix --verbose
```

### 8. System Information (`--system`)
Displays system information:

```bash
reconcli doctorcli --system --verbose
```

**System Info:**
- Operating system and version
- Python version and architecture
- Hostname and processor info

### 9. Network Connectivity (`--network`)
Tests connectivity to reconnaissance targets:

```bash
reconcli doctorcli --network --verbose
```

**Tested Endpoints:**
- github.com
- api.shodan.io
- crt.sh
- web.archive.org
- api.whoisfreaks.com

### 10. Programming Environment Paths (`--paths`)
Checks programming language installations:

```bash
reconcli doctorcli --paths --verbose
```

**Checked Environments:**
- Go, Python 3, Python 2
- Ruby, Perl, Node.js, NPM
- Pip, Git, Curl, Wget

## 📊 Report Formats

### JSON Reports
Structured data for automation:

```bash
reconcli doctorcli --all --export json --output-dir reports/
```

### Markdown Reports
Human-readable documentation:

```bash
reconcli doctorcli --all --export markdown --output-dir reports/
```

### HTML Reports
Interactive dashboard with color-coded status:

```bash
reconcli doctorcli --all --export html --output-dir reports/
```

## 🩹 Automated Fixes

DoctorCLI can automatically fix common issues:

### Directory Creation
```bash
# Create missing directories
reconcli doctorcli --structure --fix --verbose
```

### Configuration File Generation
```bash
# Create default configuration files
reconcli doctorcli --configs --fix --verbose
```

### Environment File Setup
```bash
# Create sample .env_secrets file
reconcli doctorcli --env --fix --verbose
```

### Permission Fixes
```bash
# Fix file and directory permissions
reconcli doctorcli --permissions --fix --verbose
```

### Dry-Run Mode
Test fixes without applying them:

```bash
# Preview all fixes
reconcli doctorcli --all --dry-run --verbose
```

## 🔧 Advanced Usage

### Custom Output Directory
```bash
reconcli doctorcli --all --export html --output-dir /path/to/reports/
```

### Strict Mode
Enable hash verification and strict checking:

```bash
reconcli doctorcli --tools --strict --verbose
```

### Automated Scripts
For CI/CD or automated setups:

```bash
# Silent mode with JSON output
reconcli doctorcli --all --fix --quiet --export json --output-dir /tmp/
```

### Specific Tool Checks
```bash
# Check only networking tools
reconcli doctorcli --tools --network --verbose

# Check only Python environment
reconcli doctorcli --python --paths --verbose
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Tools Not Found
```bash
# Check PATH and install missing tools
reconcli doctorcli --tools --paths --verbose

# Get installation suggestions
reconcli doctorcli --tools --fix --verbose
```

#### 2. Permission Errors
```bash
# Fix permission issues
reconcli doctorcli --permissions --fix --verbose
```

#### 3. Missing Configuration
```bash
# Create default configurations
reconcli doctorcli --configs --structure --fix --verbose
```

#### 4. Network Connectivity Issues
```bash
# Test network connectivity
reconcli doctorcli --network --verbose
```

### Tool-Specific Issues

#### Amass Version Preference
DoctorCLI recognizes user preference for Amass v3.2:
```bash
# Special handling for Amass 3.2
reconcli doctorcli --tools --verbose
# ✅ amass OK (3.2 - preferred version)
```

#### Go Tools Installation
For missing Go tools, DoctorCLI provides installation commands:
```bash
reconcli doctorcli --tools --fix --verbose
# 💡 Install with: go install github.com/ffuf/ffuf@latest
```

### Environment Variables Setup
```bash
# Create and configure API keys
reconcli doctorcli --env --fix --verbose
# Edit .env_secrets file with your API keys
```

## 🎯 Best Practices

### Regular Health Checks
```bash
# Weekly environment check
reconcli doctorcli --all --verbose

# Quick daily check
reconcli doctorcli --tools --network --quiet
```

### Before Starting Projects
```bash
# Ensure environment is ready
reconcli doctorcli --all --fix --verbose
```

### After Tool Updates
```bash
# Verify tools after updates
reconcli doctorcli --tools --strict --verbose
```

### CI/CD Integration
```bash
# Automated environment validation
reconcli doctorcli --all --dry-run --export json --quiet
```

## 📚 Integration with ReconCLI

DoctorCLI is fully integrated with the ReconCLI ecosystem:

### Database Integration
Reports can be stored in ReconCLI database for tracking:
```bash
reconcli doctorcli --all --export json --output-dir output/
# JSON reports compatible with database import
```

### Workflow Integration
Use before starting reconnaissance workflows:
```bash
# Pre-flight check
reconcli doctorcli --all --fix --quiet

# Start reconnaissance
reconcli subdocli --domain example.com
```

### Report Integration
DoctorCLI reports integrate with other ReconCLI reports:
```bash
# Generate comprehensive environment report
reconcli doctorcli --all --export markdown --output-dir reports/
reconcli mdreportcli --input reports/ --template comprehensive
```

---

For more information, see the [ReconCLI Documentation](README.md) or run `reconcli doctorcli --help`.
