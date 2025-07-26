# 🚀 PortCLI - Practical Tutorial

## Quick Start

### 1. Basic Scanning

```bash
# Single IP
reconcli portcli --ip 192.168.1.100

# Single domain
reconcli portcli --domain example.com

# Specific ports on domain
reconcli portcli --domain target.com --ports 80,443,8080,22

# Top 1000 ports
reconcli portcli --ip 192.168.1.100 --top-ports 1000
```

### 2. Rush - Parallel Scanning ⭐

```bash
# Basic Rush usage
reconcli portcli --input targets.txt --scanner rush --rush-jobs 10

# Rush with single domain
reconcli portcli --domain example.com --scanner rush --rush-base-scanner nmap

# Rush with Nmap
reconcli portcli --input targets.txt --scanner rush \
  --rush-base-scanner nmap --rush-jobs 20

# Rush with Masscan (fastest)
reconcli portcli --input targets.txt --scanner rush \
  --rush-base-scanner masscan --rush-jobs 15 --masscan-rate 5000
```

## Practical Scenarios

### 🎯 Bug Bounty

```bash
# 1. Fast subdomain scanning
reconcli portcli --input subdomains.txt --only-web --exclude-cdn --json

# 2. Focus on production services
reconcli portcli --input targets.txt --filter-tags "web,prod" --exclude-tags "dev,staging"

# 3. With AI analysis
reconcli portcli --input vip_targets.txt --scanner rush \
  --rush-base-scanner naabu --ai --cache --markdown
```

### 🏢 Penetration Testing

```bash
# 1. Internal network scanning
reconcli portcli --cidr 192.168.0.0/16 --scanner rush \
  --rush-base-scanner nmap --top-ports 1000

# 2. Infrastructure service discovery
reconcli portcli --input networks.txt \
  --filter-services "kubernetes-cluster,database-server,docker-host"

# 3. Comprehensive reporting
reconcli portcli --input scope.txt --scanner rush \
  --rush-base-scanner masscan --ai --store-db --json --markdown
```

### ⚡ Performance Tips

```bash
# Maximum performance
reconcli portcli --input large_scope.txt --scanner rush \
  --rush-base-scanner masscan --rush-jobs 50 \
  --masscan-rate 10000 --cache

# Cache for repeated tests
reconcli portcli --input targets.txt --cache --cache-max-age 24

# Resume interrupted scans
reconcli portcli --resume --verbose
```

## Filtering and Analysis

### Automatic Tags

```bash
# Web services only
reconcli portcli --input targets.txt --filter-tags web

# Exclude dev ports
reconcli portcli --input targets.txt --exclude-tags dev

# Complex filtering
reconcli portcli --input targets.txt \
  --filter-tags "web,database" --exclude-tags "dev,staging"
```

### Service Patterns

```bash
# Web applications (80+443)
reconcli portcli --input targets.txt --filter-services web-stack

# Kubernetes clusters
reconcli portcli --input targets.txt --filter-services kubernetes-cluster

# Database servers
reconcli portcli --input targets.txt --filter-services database-server
```

## AI Analysis 🤖

```bash
# Basic AI analysis
reconcli portcli --input targets.txt --ai

# With AI cache
reconcli portcli --input targets.txt --ai --ai-cache

# AI context
reconcli portcli --input targets.txt --ai --ai-context "pentest infrastructure"
```

## Output Formats

```bash
# JSON + Markdown
reconcli portcli --input targets.txt --json --markdown

# Database storage
reconcli portcli --input targets.txt --store-db \
  --target-domain company.com --program "Security-Assessment"

# Verbose for debugging
reconcli portcli --input targets.txt --verbose
```

## Troubleshooting

### Common Errors

```bash
# Missing scanner binary
[!] naabu binary not found in PATH
# Solution: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Masscan permissions
# Solution: sudo setcap cap_net_raw+ep /usr/bin/masscan

# Rush timeout
# Solution: --rush-timeout 120
```

### Performance Issues

```bash
# Large scans - use Rush
reconcli portcli --input large_scope.txt --scanner rush --rush-jobs 30

# Slow networks - increase timeout
reconcli portcli --input targets.txt --timeout 10000

# Repeated tests - enable cache
reconcli portcli --input targets.txt --cache
```

## Advanced Examples

### Enterprise Workflow

```bash
# Complete workflow
reconcli portcli --input corporate_networks.txt \
  --scanner rush \
  --rush-base-scanner nmap \
  --rush-jobs 25 \
  --top-ports 1000 \
  --ai \
  --cache \
  --store-db \
  --target-domain company.internal \
  --program "Internal-Assessment-2025" \
  --json \
  --markdown \
  --verbose
```

### Bug Bounty Automation

```bash
# Automated pipeline
reconcli portcli --input subdomains_live.txt \
  --scanner rush \
  --rush-base-scanner naabu \
  --only-web \
  --filter-tags prod \
  --exclude-cdn \
  --ai \
  --ai-cache \
  --cache \
  --json \
  --store-db \
  --target-domain target.com \
  --program "HackerOne-Target"
```

---

📚 **More documentation**: Check `PORTCLI_DOCUMENTATION.md` for complete documentation
