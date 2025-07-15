# SecretsCLI - Advanced Secret Discovery Tool

## 🔐 Overview

SecretsCLI is a comprehensive secret discovery and analysis tool integrated into the ReconCLI ecosystem. It provides advanced capabilities for detecting secrets, API keys, credentials, and sensitive information across multiple sources including Git repositories, local files, and web applications.

## 🎯 Key Features

### 🔍 **Multi-Tool Integration**
- **TruffleHog**: Git repository scanning with secret verification
- **Gitleaks**: Source code secret detection with entropy analysis
- **JSubFinder**: JavaScript secret discovery with subdomain enumeration
- **Cariddi**: Web crawler with secret pattern matching
- **Mantra**: Additional secret scanning capabilities
- **ShhGit**: Real-time GitHub secret monitoring

### 🌐 **Intelligent Source Detection**
- **Git Repositories**: Automatic detection of Git URLs with proper scanning modes
- **Local Filesystems**: Recursive directory scanning with depth control
- **Web Applications**: HTTP endpoint scanning and crawling
- **Mixed Sources**: Support for files containing multiple target types

### 🎯 **Advanced Filtering & Analysis**
- **Keyword Filtering**: Include/exclude patterns for targeted scanning
- **Confidence Thresholds**: Filter results based on detection confidence scores
- **Entropy Analysis**: Shannon entropy calculation for detecting high-entropy secrets
- **Custom Patterns**: Support for custom wordlists and secret patterns
- **File Extension Filtering**: Target specific file types for scanning
- **Path Exclusion**: Skip directories and files based on patterns

### 📊 **Professional Reporting**
- **Multiple Formats**: JSON, Markdown, CSV, and TXT exports
- **Structured Data**: Organized output with metadata and confidence scores
- **Executive Summaries**: High-level overview for management reporting
- **Technical Details**: Comprehensive findings for security teams

### ⚡ **Enterprise Features**
- **Resume Functionality**: Continue interrupted scans with state management
- **Rate Limiting**: Configurable request rates for responsible scanning
- **Proxy Support**: HTTP/HTTPS proxy integration for corporate environments
- **Custom Headers**: HTTP header customization for authenticated scanning
- **Concurrency Control**: Parallel processing with configurable thread limits
- **Timeout Management**: Per-scan timeout configuration

## 🚀 Installation & Setup

### Prerequisites
Ensure you have the required tools installed:

```bash
# Install TruffleHog
go install github.com/trufflesecurity/trufflehog/v3@latest

# Install Gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

# Install JSubFinder
go install github.com/ThreatUnkown/jsubfinder@latest

# Install Cariddi
go install github.com/edoardottt/cariddi/cmd/cariddi@latest
```

### Installation
```bash
# Install ReconCLI with SecretsCLI
git clone https://github.com/jarek-bir/Reconcli.git
cd Reconcli
pip install -e .

# Verify installation
reconcli secretscli --help
```

## 📖 Usage Examples

### Basic Usage

```bash
# Scan a single Git repository
reconcli secretscli --input "https://github.com/target/repo.git" --tool trufflehog --verbose

# Scan local directory
reconcli secretscli --input "/path/to/source" --tool gitleaks --verbose

# Scan from file list
reconcli secretscli --input domains.txt --tool trufflehog,gitleaks --verbose
```

### Advanced Filtering

```bash
# Filter by keywords and confidence
reconcli secretscli --input repo.git --tool trufflehog \
  --filter-keywords "api,key,secret,password" \
  --exclude-keywords "test,demo,example" \
  --min-confidence 0.8 --verbose

# Entropy-based detection
reconcli secretscli --input /source --tool gitleaks \
  --entropy-threshold 5.0 --min-confidence 0.7 --verbose

# File extension filtering
reconcli secretscli --input /webapp --tool gitleaks \
  --extensions "js,py,php,java" \
  --exclude-paths "node_modules/,test/,vendor/" --verbose
```

### Enterprise Security Assessment

```bash
# Comprehensive multi-tool scan with database storage
reconcli secretscli --input targets.txt \
  --tool trufflehog,gitleaks,jsubfinder \
  --export json,markdown,csv \
  --store-db secrets.db \
  --min-confidence 0.6 \
  --resume --verbose

# Corporate environment scanning with proxy
reconcli secretscli --input internal_repos.txt \
  --tool gitleaks \
  --proxy http://proxy.corp.com:8080 \
  --headers "Authorization: Bearer token123" \
  --rate-limit 10 \
  --timeout 60 --verbose

# Custom pattern matching with wordlists
reconcli secretscli --input /source \
  --tool gitleaks \
  --wordlist custom_patterns.txt \
  --config-file security_config.json \
  --depth 15 --verbose
```

### Git Repository Analysis

```bash
# Public repository scanning
reconcli secretscli --input "https://github.com/org/repo.git" \
  --tool trufflehog \
  --export json,markdown \
  --min-confidence 0.9 --verbose

# Bulk repository analysis
echo "https://github.com/org/repo1.git" > repos.txt
echo "https://github.com/org/repo2.git" >> repos.txt
reconcli secretscli --input repos.txt \
  --tool trufflehog \
  --concurrency 3 \
  --export json --verbose

# Historical commit analysis
reconcli secretscli --input "https://github.com/target/repo.git" \
  --tool trufflehog \
  --tool-flags "--since-commit abc123 --until-commit def456" \
  --verbose
```

### CI/CD Integration

```bash
# Pre-commit scanning
reconcli secretscli --input . \
  --tool gitleaks \
  --export json \
  --quiet \
  --min-confidence 0.9

# Build pipeline integration
reconcli secretscli --input /build/source \
  --tool gitleaks,trufflehog \
  --export json \
  --output /reports/secrets \
  --min-confidence 0.8 \
  --timeout 300
```

## 🎛️ Advanced Configuration

### Configuration File Example

```json
{
  "default_tools": ["gitleaks", "trufflehog"],
  "confidence_threshold": 0.7,
  "entropy_threshold": 4.5,
  "rate_limit": 50,
  "timeout": 30,
  "excluded_paths": [
    "node_modules/",
    "vendor/",
    "test/",
    "tests/",
    ".git/",
    "build/",
    "dist/"
  ],
  "included_extensions": [
    "js", "py", "php", "java", "go", "rb", "cs",
    "yml", "yaml", "json", "xml", "env", "config"
  ],
  "custom_patterns": [
    "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?([a-z0-9]{20,})['\"]?",
    "(?i)(secret[_-]?key|secretkey)\\s*[:=]\\s*['\"]?([a-z0-9]{20,})['\"]?",
    "(?i)(access[_-]?token|accesstoken)\\s*[:=]\\s*['\"]?([a-z0-9]{20,})['\"]?"
  ]
}
```

### Custom Wordlist Example

```text
# API Keys
api_key
apikey
api-key
secret_key
secretkey
secret-key
access_token
accesstoken
access-token

# Database Credentials
db_password
database_password
mysql_password
postgres_password
mongodb_password

# Cloud Provider Keys
aws_access_key_id
aws_secret_access_key
azure_client_secret
gcp_service_account_key

# Third-party Services
github_token
slack_webhook
discord_webhook
stripe_secret_key
twilio_auth_token
```

## 📊 Output Formats

### JSON Export
```json
{
  "scan_metadata": {
    "tool": "trufflehog",
    "target": "https://github.com/example/repo.git",
    "timestamp": "2025-07-14T11:15:55Z",
    "confidence_threshold": 0.7
  },
  "findings": [
    {
      "detector": "AWS",
      "verified": true,
      "raw": "AKIA...",
      "file": "src/config.js",
      "line": 15,
      "confidence": 0.95,
      "entropy": 5.2
    }
  ]
}
```

### Markdown Report
```markdown
# Secret Discovery Report

## Executive Summary
- **Total Secrets Found**: 5
- **Verified Secrets**: 3
- **High Confidence**: 4
- **Risk Level**: HIGH

## Findings by Tool
### TruffleHog Results
- AWS Access Key (Verified) - `src/config.js:15`
- GitHub Token (Unverified) - `docs/setup.md:42`

## Recommendations
1. Rotate all identified credentials immediately
2. Implement pre-commit hooks to prevent future leaks
3. Review access controls for affected services
```

## 🔧 Integration & Automation

### Database Integration
```bash
# Store results in ReconCLI database
reconcli secretscli --input repos.txt \
  --tool trufflehog \
  --store-db project.db \
  --target-domain example.com \
  --program "bug-bounty-2024"

# Query stored results
reconcli dbcli query "SELECT * FROM secret_findings WHERE verified = 1"
```

### Resume Functionality
```bash
# Start scan with resume capability
reconcli secretscli --input large_repo_list.txt \
  --tool trufflehog \
  --resume --verbose

# Check resume status
reconcli secretscli --resume-stat

# Clear resume state
reconcli secretscli --resume-clear
```

## 🛡️ Security Best Practices

### Responsible Disclosure
- Always obtain proper authorization before scanning
- Respect rate limits and server resources
- Follow responsible disclosure practices for findings
- Document and report findings through appropriate channels

### Operational Security
- Use proxy configurations in corporate environments
- Implement proper credential rotation procedures
- Maintain audit logs of scanning activities
- Secure storage of scan results and databases

### Performance Optimization
- Use appropriate concurrency levels for target systems
- Implement rate limiting for web-based scanning
- Utilize resume functionality for large-scale operations
- Monitor resource usage during extensive scans

## 🔄 Integration with Other Tools

### Workflow Integration
```bash
# Combined reconnaissance and secret discovery
reconcli subdocli --domain example.com --output subdomains.txt
reconcli gitcli search --domain example.com --output repos.txt
reconcli secretscli --input repos.txt --tool trufflehog --store-db

# Post-processing with other ReconCLI tools
reconcli secretscli --input repos.txt --tool gitleaks --export json
reconcli csvtkcli analyze secrets_export.csv --security-report
reconcli mdreportcli generate --template security --input findings/
```

### API Integration
SecretsCLI results can be integrated with external systems through JSON exports and database queries, enabling automation and integration with security platforms.

## 📈 Performance & Scalability

### Benchmarks
- **Small Repository** (< 100 files): 5-15 seconds
- **Medium Repository** (100-1000 files): 30-120 seconds
- **Large Repository** (> 1000 files): 2-10 minutes
- **Bulk Scanning** (10+ repositories): Hours (with resume support)

### Optimization Tips
- Use file extension filtering to reduce scan scope
- Implement path exclusions for irrelevant directories
- Utilize concurrency for multiple targets
- Enable resume functionality for large operations

## 🆘 Troubleshooting

### Common Issues
1. **Tool Not Found**: Ensure required tools are installed and in PATH
2. **Permission Denied**: Check file system permissions and Git access
3. **Timeout Errors**: Increase timeout values for large repositories
4. **Memory Issues**: Reduce concurrency or enable progressive scanning

### Debug Mode
```bash
# Enable verbose debugging
reconcli secretscli --input target --tool trufflehog --verbose --debug

# Check tool availability
reconcli secretscli --check-tools

# Validate configuration
reconcli secretscli --config-file config.json --validate
```

## 📚 Additional Resources

- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [ReconCLI Documentation](https://github.com/jarek-bir/Reconcli)
- [Secret Management Best Practices](https://owasp.org/www-project-secrets-management-cheat-sheet/)

---

*SecretsCLI - Advanced secret discovery for security professionals*
