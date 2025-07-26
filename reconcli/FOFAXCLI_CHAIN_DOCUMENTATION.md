# FOFAX CLI - Tool Chaining Documentation

## Overview

FOFAX CLI v2.0 now supports advanced tool chaining capabilities, allowing you to seamlessly integrate FOFA search results with popular security tools like **httpx**, **nuclei**, and **kscan**. This enables powerful automated reconnaissance workflows.

## New Features

### 🔗 Tool Chaining
- **--chain**: Execute multi-tool reconnaissance pipelines
- **--httpx**: HTTP probing and technology detection
- **--nuclei**: Vulnerability scanning
- **--kscan**: Port scanning and fingerprinting (inspired by the original kscan tool)

### 🤖 AI Integration
- **--ai**: AI-powered query optimization using OpenAI GPT models
- Intelligent query suggestions and result analysis

### 📦 Cache Management
- **--cache**: Intelligent caching system with TTL support
- Reduces API calls and improves performance
- Cache statistics and cleanup commands

### 🗃️ Database Storage
- **--store-db**: Persistent SQLite storage for search results
- Search history tracking
- IP-based result lookups
- Export capabilities

### 📋 Extended FX Rules
- **20+ new cybersecurity-focused FX rules**
- Categories: unauthorized access, IoT devices, monitoring systems
- Rule search by keywords and tags

## Installation Requirements

```bash
# Core dependencies
pip install click requests rich PyYAML

# Optional AI features
pip install openai

# External tools for chaining
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# kscan (download from releases)
wget https://github.com/lcvvvv/kscan/releases/latest/download/kscan_linux_amd64.tar.gz
tar -xzf kscan_linux_amd64.tar.gz
sudo mv kscan /usr/local/bin/
```

## Usage Examples

### 1. Basic Tool Chaining

Chain FOFA search with httpx for HTTP probing:
```bash
# Search for Jenkins instances and probe them with httpx
reconcli fofacli chain -q 'app="Jenkins"' --httpx --fetch-size 50

# Chain with httpx and nuclei for vulnerability scanning
reconcli fofacli chain -q 'title="phpMyAdmin"' --httpx --nuclei --fetch-size 20

# Full reconnaissance pipeline with all tools
reconcli fofacli chain -q 'port="22"' --httpx --nuclei --kscan --fetch-size 100
```

### 2. Advanced Chain Options

```bash
# Chain with custom tool options
reconcli fofacli chain -q 'title="login"' \
  --httpx --httpx-opts "-rate-limit 10 -timeout 5" \
  --nuclei --nuclei-opts "-severity critical,high -exclude-tags dos" \
  --output /tmp/recon_results

# Chain with AI optimization and database storage
reconcli fofacli chain -q 'wordpress' \
  --ai --cache --store-db \
  --httpx --nuclei \
  --fetch-size 100
```

### 3. Individual Tool Usage

#### httpx Integration
```bash
# Use httpx with FOFA query
reconcli fofacli httpx -q 'title="Admin Panel"' --title --tech-detect --status-code

# Use httpx with existing targets file
reconcli fofacli httpx -t targets.txt --title --tech-detect --custom-opts "-rate-limit 20"
```

#### nuclei Integration
```bash
# Vulnerability scanning with FOFA results
reconcli fofacli nuclei -q 'app="WordPress"' --severity high,critical --tags wordpress

# Scan custom targets with specific templates
reconcli fofacli nuclei -t targets.txt --templates /path/to/templates --tags cve,xss
```

### 4. AI-Powered Features

```bash
# Enable AI features
reconcli fofacli ai --enable-ai --ai-model gpt-4

# Get AI-optimized query
reconcli fofacli ai --query "find vulnerable wordpress sites"

# Search with AI optimization
reconcli fofacli advanced-search -q "wordpress admin" --ai --fetch-size 50
```

### 5. Cache Management

```bash
# Configure cache
reconcli fofacli cache config --enable --ttl 7200  # 2 hours

# View cache statistics
reconcli fofacli cache stats

# Clear expired entries
reconcli fofacli cache cleanup

# Clear all cache
reconcli fofacli cache clear --confirm
```

### 6. Database Operations

```bash
# Enable database storage
reconcli fofacli db config --enable

# View database statistics
reconcli fofacli db stats

# View search history
reconcli fofacli db history --limit 20

# Search stored results by IP
reconcli fofacli db search-ip 192.168.1.100

# Export specific search results
reconcli fofacli db export 1 --output results.json --format json
```

### 7. Extended FX Rules

```bash
# List all FX rules (now 20+ rules)
reconcli fofacli fx list

# Search rules by tag
reconcli fofacli fx tag unauth        # Unauthorized access vulnerabilities
reconcli fofacli fx tag iot           # IoT devices
reconcli fofacli fx tag monitoring    # Monitoring systems

# Search rules by keyword
reconcli fofacli fx search-rules "database"

# Use FX rules in searches
reconcli fofacli fx search elastic-unauth --size 50
reconcli fofacli fx search webcam-exposed --size 20
```

## New FX Rules Categories

### Unauthorized Access (unauth)
- `elastic-unauth`: Elasticsearch databases
- `kibana-unauth`: Kibana dashboards  
- `mongodb-unauth`: MongoDB databases
- `redis-unauth`: Redis cache servers
- `docker-api`: Docker API endpoints
- `grafana-unauth`: Grafana monitoring
- `jenkins-unauth`: Jenkins CI/CD systems

### IoT Devices
- `webcam-exposed`: Network cameras
- `printer-exposed`: Network printers

### Remote Access
- `vnc-exposed`: VNC remote desktop
- `rdp-exposed`: RDP remote desktop
- `ftp-anonymous`: Anonymous FTP servers

### Web Applications
- `gitlab-exposed`: GitLab instances
- `wordpress-default`: WordPress sites
- `phpmyadmin-exposed`: phpMyAdmin panels

### Monitoring & Admin
- `zabbix-login`: Zabbix monitoring
- `nagios-exposed`: Nagios monitoring
- `solr-admin`: Apache Solr admin panels

## Workflow Examples

### 1. Complete Web Application Assessment

```bash
# Step 1: Find web applications
reconcli fofacli chain -q 'country="US" && (title="login" || title="admin")' \
  --httpx --nuclei \
  --httpx-opts "-title -tech-detect -status-code" \
  --nuclei-opts "-severity medium,high,critical -tags web,xss,sqli" \
  --fetch-size 200 \
  --ai --cache --store-db \
  --output /tmp/webapp_assessment

# Step 2: Analyze results
reconcli fofacli db history
reconcli fofacli cache stats
```

### 2. IoT Device Discovery

```bash
# Find exposed IoT devices
reconcli fofacli fx search webcam-exposed --size 100 | \
reconcli fofacli chain -q 'port="80" && title="Network Camera"' \
  --httpx --kscan \
  --output /tmp/iot_discovery
```

### 3. Infrastructure Monitoring

```bash
# Monitor for new exposures
reconcli fofacli chain -q 'title="Jenkins" && country="PL"' \
  --httpx --nuclei \
  --cache --store-db \
  --nuclei-opts "-severity critical -tags jenkins" \
  --fetch-size 50

# Check for changes
reconcli fofacli db history
reconcli fofacli cache stats
```

## Configuration

### Environment Variables
```bash
export FOFA_EMAIL="your-email@example.com"
export FOFA_KEY="your-fofa-api-key"
export OPENAI_API_KEY="your-openai-key"  # For AI features
```

### Configuration File (~/.config/fofax/fofax.yaml)
```yaml
fofa-email: "your-email@example.com"
fofakey: "your-fofa-api-key"
fofa-url: "https://fofa.info"
cache-enabled: true
cache-ttl: 3600
ai-enabled: true
ai-model: "gpt-3.5-turbo"
db-enabled: true
db-path: "~/.config/fofax/fofax.db"
```

## Integration with ReconCLI

```bash
# Use within ReconCLI ecosystem
reconcli fofacli chain -q 'org="Example Corp"' --httpx --nuclei
reconcli dnscli -d example.com
reconcli urlcli -u example.com
```

## Performance Tips

1. **Use caching** for repeated queries: `--cache`
2. **Enable database storage** for historical analysis: `--store-db`
3. **Optimize queries with AI**: `--ai`
4. **Limit fetch size** for faster results: `--fetch-size 50`
5. **Use rate limiting** with httpx: `--httpx-opts "-rate-limit 10"`

## Output Formats

- **TXT**: Simple text output
- **JSON**: Machine-readable format
- **CSV**: Spreadsheet compatible
- **Database**: SQLite storage for queries

## Security Considerations

1. **Rate Limiting**: Respect target servers with appropriate delays
2. **Authorization**: Only scan systems you own or have permission to test
3. **Data Storage**: Secure your database and cache files
4. **API Keys**: Protect your FOFA and OpenAI credentials

## Troubleshooting

### Common Issues

1. **Tool not found errors**: Ensure httpx, nuclei, kscan are in PATH
2. **API rate limits**: Use caching and reasonable fetch sizes
3. **Empty results**: Check FOFA query syntax and credentials
4. **nuclei timeout**: Increase timeout with `--nuclei-opts "-timeout 10"`

### Debug Mode

```bash
# Enable debug output
reconcli fofacli --debug chain -q "your-query" --httpx
```

This enhanced FOFAX CLI provides a comprehensive reconnaissance platform that integrates seamlessly with the broader ReconCLI ecosystem, offering powerful automation capabilities for cybersecurity professionals.
