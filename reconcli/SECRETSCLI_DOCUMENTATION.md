# 📋 SecretsCLI Documentation Index

## 📚 Available Documentation

### 🎯 **Complete Guides**
- **[SecretsCLI Complete Guide](SECRETSCLI_GUIDE.md)** - Comprehensive documentation with installation, usage examples, and advanced features
- **[Quick Reference](SECRETSCLI_QUICK_REFERENCE.md)** - Command reference, common options, and troubleshooting

### 🔗 **Integration Guides**
- **[Main README](../README.md#-secret-discovery--analysis-secretscli)** - Overview and integration with ReconCLI ecosystem
- **[Advanced Features Guide](ADVANCED_FEATURES_GUIDE.md)** - Advanced ReconCLI features and workflows

## 🚀 Quick Start

```bash
# Install and verify
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli && pip install -e .
reconcli secretscli --help

# Basic Git repository scan
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --verbose

# Advanced enterprise scan
reconcli secretscli --input targets.txt --tool gitleaks,trufflehog \
  --export json,markdown --min-confidence 0.8 --store-db --resume
```

## 🔧 Tool Installation

### Required Tools
```bash
# TruffleHog
go install github.com/trufflesecurity/trufflehog/v3@latest

# Gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

# JSubFinder
go install github.com/ThreatUnkown/jsubfinder@latest

# Cariddi
go install github.com/edoardottt/cariddi/cmd/cariddi@latest
```

## 📊 Key Features Overview

| Feature | Description | Documentation |
|---------|-------------|---------------|
| **Multi-Tool Support** | TruffleHog, Gitleaks, JSubFinder, Cariddi | [Complete Guide](SECRETSCLI_GUIDE.md#-key-features) |
| **Git Repository Scanning** | Automatic URL detection and proper modes | [Complete Guide](SECRETSCLI_GUIDE.md#-intelligent-source-detection) |
| **Advanced Filtering** | Keywords, confidence, entropy analysis | [Complete Guide](SECRETSCLI_GUIDE.md#-advanced-filtering--analysis) |
| **Professional Reports** | JSON, Markdown, CSV, TXT exports | [Complete Guide](SECRETSCLI_GUIDE.md#-professional-reporting) |
| **Resume Functionality** | Continue interrupted scans | [Complete Guide](SECRETSCLI_GUIDE.md#-enterprise-features) |
| **Enterprise Features** | Proxy, headers, rate limiting | [Complete Guide](SECRETSCLI_GUIDE.md#-enterprise-features) |

## 🎯 Use Cases

### 🔍 **Security Assessment**
- Code repository secret discovery
- Pre-commit security scanning
- CI/CD pipeline integration
- Enterprise security audits

### 🔐 **Bug Bounty Hunting**
- Target reconnaissance
- Historical commit analysis
- JavaScript secret discovery
- API key enumeration

### 🏢 **Enterprise Security**
- Internal repository scanning
- Compliance verification
- Security policy enforcement
- Risk assessment workflows

## 📈 Documentation Status

| Document | Status | Last Updated | Lines |
|----------|---------|--------------|-------|
| Complete Guide | ✅ Complete | 2025-07-14 | 402 |
| Quick Reference | ✅ Complete | 2025-07-14 | 104 |
| Main README Integration | ✅ Complete | 2025-07-14 | Updated |
| Test Integration | ✅ Complete | 2025-07-14 | Working |

## 🔄 Related Tools in ReconCLI

- **subdocli** - Subdomain enumeration for target discovery
- **gitcli** - Git repository discovery and management
- **urlcli** - URL discovery and analysis
- **dbcli** - Database management for results storage
- **csvtkcli** - Data analysis and reporting
- **mdreportcli** - Professional report generation

## 🆘 Support & Troubleshooting

### Common Issues
1. **Tool not found** → Install tools with `go install` commands above
2. **Permission denied** → Check repository access and file permissions
3. **Empty results** → Lower confidence threshold or check tool installation
4. **Timeout errors** → Increase timeout value for large repositories

### Getting Help
- Check [Quick Reference](SECRETSCLI_QUICK_REFERENCE.md#-troubleshooting) for common solutions
- Review [Complete Guide](SECRETSCLI_GUIDE.md#-troubleshooting) for detailed troubleshooting
- Test with `reconcli secretscli --check-tools` (if implemented)

---

*SecretsCLI Documentation - Advanced secret discovery for security professionals*
