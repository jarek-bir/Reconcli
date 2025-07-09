# Tagger CLI - Advanced Subdomain Tagging Tool

## 🏷️ Overview

The Tagger CLI is an intelligent subdomain classification and tagging system that automatically categorizes domains based on their purpose, infrastructure, and security relevance. It's designed to help security professionals quickly identify high-value targets and organize reconnaissance results.

## ✨ Features

### 🎯 Intelligent Auto-Tagging
- **Infrastructure**: CDN, Load Balancers, Proxies, Gateways
- **Services**: API, Mail, Database, Monitoring, File services
- **Security**: Admin panels, Authentication, VPN, Firewalls
- **Development**: Dev, Test, Staging, CI/CD environments
- **Cloud Detection**: AWS, GCP, Azure, DigitalOcean auto-detection
- **Risk Scoring**: Automatic risk assessment (0-10 scale)

### 🔧 Advanced Features
- **Custom Rules**: JSON-based custom tagging rules
- **Multiple Formats**: JSON, CSV, TXT, Markdown outputs
- **Filtering**: Filter by tags, risk scores, cloud providers
- **Statistics**: Comprehensive analysis and reporting
- **IP Intelligence**: Private/Public IP detection and cloud provider identification

## 🚀 Usage Examples

### Basic Tagging
```bash
# Basic domain tagging
reconcli tagger -i subs_resolved.txt -o tagged_domains.json

# With verbose output and statistics
reconcli tagger -i domains.txt -o results.json --stats --verbose
```

### Advanced Filtering
```bash
# Filter high-risk domains only
reconcli tagger -i domains.txt -o high_risk.json --min-risk 7

# Show only admin and API endpoints
reconcli tagger -i domains.txt -o admin_api.txt --filter-tags admin,api --format txt

# Internal domains only in markdown format
reconcli tagger -i domains.txt -o internal.md --internal-only --format markdown

# Cloud-hosted domains only
reconcli tagger -i domains.txt -o cloud.csv --cloud-only --format csv
```

### Custom Rules
```bash
# Use custom tagging rules
reconcli tagger -i domains.txt -o custom_tagged.json --rules custom_rules.json
```

### Sorting and Organization
```bash
# Sort by risk score (highest first)
reconcli tagger -i domains.txt -o by_risk.json --sort-by risk

# Sort by number of tags
reconcli tagger -i domains.txt -o by_tags.json --sort-by tags
```

## 📊 Output Formats

### JSON Format (Default)
```json
[
  {
    "domain": "admin.example.com",
    "ip": "93.184.216.36",
    "tags": ["external", "admin"],
    "risk_score": 5,
    "confidence_scores": {
      "admin": 0.85,
      "external": 0.95
    }
  }
]
```

### CSV Format
```csv
domain,ip,tags,risk_score
admin.example.com,93.184.216.36,"admin,external",5
api.example.com,93.184.216.35,"api,external",2
```

### Markdown Report
```markdown
# Domain Tagging Report

| Domain | IP | Tags | Risk Score |
|--------|----|----- |-----------|
| admin.example.com | 93.184.216.36 | admin, external | 5 |
| api.example.com | 93.184.216.35 | api, external | 2 |
```

## 🎯 Tag Categories

### Infrastructure Tags
- `cdn` - Content Delivery Network
- `load-balancer` - Load balancers and proxies
- `gateway` - API gateways and edge services

### Service Tags
- `api` - API endpoints
- `mail` - Mail services (SMTP, IMAP, webmail)
- `database` - Database services
- `monitoring` - Monitoring and metrics
- `files` - File services (FTP, uploads)
- `media` - Media and content services

### Security Tags
- `admin` - Administration panels
- `security` - Authentication and security services
- `vpn-access` - VPN and remote access
- `backup` - Backup services

### Development Tags
- `development` - Dev, test, staging environments
- `ci-cd` - Continuous integration/deployment
- `version-control` - Git and SVN services
- `container-orchestration` - Kubernetes, Docker

### Cloud Tags
- `cloud-aws` - Amazon Web Services
- `cloud-gcp` - Google Cloud Platform
- `cloud-azure` - Microsoft Azure
- `cloud-digitalocean` - DigitalOcean
- `cloud-cloudflare` - Cloudflare

### Network Tags
- `internal` - Private IP addresses
- `external` - Public IP addresses

## 🔧 Custom Rules Format

Create a JSON file with custom tagging rules:

```json
{
  "rule_name": {
    "patterns": ["regex_pattern1", "regex_pattern2"],
    "tag": "custom_tag",
    "confidence": 0.85
  },
  "jenkins_detection": {
    "patterns": ["jenkins", "ci\\.", "build"],
    "tag": "ci-cd",
    "confidence": 0.9
  },
  "kubernetes": {
    "patterns": ["k8s", "kubernetes", "kube"],
    "tag": "container-orchestration",
    "confidence": 0.9
  }
}
```

## 📈 Statistics Output

When using `--stats`, a statistics file is generated:

```json
{
  "total_domains": 16,
  "tag_distribution": {
    "internal": 9,
    "external": 7,
    "development": 3
  },
  "risk_distribution": {
    "low": 8,
    "medium": 8,
    "high": 0
  },
  "cloud_providers": {
    "aws": 3,
    "azure": 1
  },
  "top_tags": [
    ["internal", 9],
    ["external", 7],
    ["development", 3]
  ],
  "most_risky": [
    {
      "domain": "admin.example.com",
      "risk_score": 8,
      "tags": ["admin", "external"]
    }
  ]
}
```

## 🎯 Risk Scoring

Risk scores are calculated based on:
- **High Risk (7-10)**: Admin panels, databases, backup systems
- **Medium Risk (4-6)**: APIs, CI/CD, development environments
- **Low Risk (1-3)**: CDN, media, public-facing services

## 🔍 Integration Examples

### With Subdomain Enumeration
```bash
# Enumerate and tag in one workflow
reconcli subdocli -d example.com -o domains.txt
reconcli tagger -i domains.txt -o tagged.json --stats
```

### High-Value Target Identification
```bash
# Find high-risk internal services
reconcli tagger -i domains.txt -o critical.txt \\
  --internal-only --min-risk 6 --format txt
```

### Security Assessment Workflow
```bash
# Generate comprehensive security assessment
reconcli tagger -i all_domains.txt -o assessment.md \\
  --format markdown --stats --sort-by risk
```

## 🚀 Cyber-Squad z Przyszłości

**Created by the Cyber-Squad z Przyszłości team:**
- **Jarek** 🧑‍💻 - Lead Developer & Security Researcher  
- **AI Assistant** 🤖 - Algorithm Development & Intelligence
- **GitHub Copilot** ⚡ - Code Generation & Optimization

*Advanced reconnaissance tools where human expertise meets AI innovation.*
