# 🧲 ExtractorCLI - Advanced Data Extraction Module

## 📋 Overview

ExtractorCLI is a powerful data extraction module within ReconCLI that can extract URLs, emails, forms, authentication endpoints, API endpoints, IP addresses, domains, secrets, and more from various sources. It includes advanced features like XSS-Vibes integration, concurrent processing, intelligent deduplication, and AI-powered scoring.

## 🎯 Features

### 🔍 **Data Extraction Capabilities**
- **URLs**: Extract HTTP/HTTPS URLs from any text source
- **Emails**: Detect email addresses with comprehensive regex patterns
- **Forms**: Extract HTML forms and input elements
- **Authentication**: Find auth endpoints (login, oauth, jwt, etc.)
- **APIs**: Discover API endpoints (REST, GraphQL, versions)
- **Documentation**: Locate API documentation (Swagger, OpenAPI)
- **Network**: Extract IP addresses and domains
- **Subdomains**: Target-specific subdomain extraction
- **Secrets**: Detect API keys, tokens, passwords, JWT tokens
- **JavaScript**: Deep JS variable and function analysis
- **Comments**: Extract HTML/JS comments
- **Hashes**: Find MD5, SHA1, SHA256 hashes
- **Base64**: Detect base64 encoded strings

### 🚀 **Advanced Processing Features**
- **Concurrent Processing**: Multi-threaded URL fetching
- **Smart File Detection**: Auto-detect file types for optimal extraction
- **SSL/Security**: Configurable SSL verification and security options
- **Deduplication**: Intelligent duplicate removal with merge capabilities
- **AI Scoring**: Heuristic-based result prioritization
- **XSS Integration**: Built-in XSS-Vibes scanning capabilities

### 📊 **Output Formats**
- **Plain Text**: Simple line-by-line output
- **JSON**: Structured JSON with categorization
- **JSONL**: JSON Lines format for streaming
- **Tagged**: Categorized output with metadata
- **Scored**: AI-enhanced results with relevance scores

## 🛠️ Installation & Requirements

### Dependencies
```bash
pip install click requests pathlib urllib3
```

### Optional Dependencies for Enhanced Features
```bash
# For XSS scanning (requires xss-vibes installation)
pip install xss-vibes

# For advanced regex and pattern matching
pip install regex
```

## 📖 Usage Guide

### Basic Usage
```bash
# Extract from file
python ectractorcli.py input.html

# Extract from stdin
echo "https://example.com" | python ectractorcli.py

# Extract specific types
python ectractorcli.py input.txt --types url,email,api

# Extract with output file
python ectractorcli.py input.html --output results.txt
```

### Advanced Examples
```bash
# Comprehensive extraction with fetching
python ectractorcli.py urls.txt --fetch-urls --deep-js --dedup --ai-score

# Subdomain extraction for specific domain
python ectractorcli.py content.html --target-domain example.com --types subdomain

# Merge with existing data and deduplicate
python ectractorcli.py new_data.txt --merge-with old_data.txt --dedup-by url

# XSS scanning integration
python ectractorcli.py urls.txt --xss-scan --xss-threads 10 --verbose

# Directory scanning with smart detection
python ectractorcli.py /path/to/dir --recursive --smart-detect --tagged
```

## 🔧 Command Line Options

### Input/Output Options
| Option | Description | Example |
|--------|-------------|---------|
| `input` | Input file or directory path | `file.html` |
| `--input`, `-i` | Alternative input specification | `--input urls.txt` |
| `--output`, `-o` | Output file path | `--output results.txt` |
| `--types`, `-t` | Comma-separated extraction types | `--types url,email,api` |
| `--target-domain`, `-d` | Target domain for subdomain extraction | `--target-domain example.com` |

### Output Format Options
| Option | Description | Example |
|--------|-------------|---------|
| `--json` | Output as JSON format | `--json` |
| `--to-jsonl` | Export as JSONL (JSON Lines) | `--to-jsonl` |
| `--tagged` | Tag results by category | `--tagged` |
| `--ai-score` | Apply AI-based scoring | `--ai-score` |

### Processing Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--smart-detect` | Auto-detect file types | False | `--smart-detect` |
| `--recursive` | Scan directories recursively | False | `--recursive` |
| `--fetch-urls` | Fetch content from discovered URLs | False | `--fetch-urls` |
| `--threads` | Number of concurrent threads | 10 | `--threads 20` |
| `--timeout` | Request timeout in seconds | 10 | `--timeout 30` |
| `--max-size` | Maximum file size in MB | 5 | `--max-size 10` |

### Security Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--verify-ssl` | Verify SSL certificates | True | `--verify-ssl` |
| `--insecure` | Disable SSL verification | False | `--insecure` |
| `--user-agent` | Custom User-Agent string | ExtractorCLI/2.0 | `--user-agent "Custom Bot"` |
| `--follow-redirects` | Follow HTTP redirects | False | `--follow-redirects` |

### Content Processing Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--include-comments` | Include HTML/JS comments | False | `--include-comments` |
| `--deep-js` | Deep JavaScript analysis | False | `--deep-js` |

### Deduplication Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--dedup` | Remove duplicates | False | `--dedup` |
| `--merge-with` | Merge with existing file | None | `--merge-with old.txt` |
| `--dedup-by` | Deduplication strategy | url | `--dedup-by all` |
| `--sort-results` | Sort results alphabetically | False | `--sort-results` |
| `--unique-only` | Show only unique results | False | `--unique-only` |

### XSS Integration Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--xss-scan` | Run XSS-Vibes vulnerability scan | False | `--xss-scan` |
| `--xss-discover` | Use XSS-Vibes endpoint discovery | False | `--xss-discover` |
| `--xss-threads` | Threads for XSS scanning | 5 | `--xss-threads 10` |
| `--xss-timeout` | Timeout for XSS requests | 5 | `--xss-timeout 15` |

### Utility Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--verbose`, `-v` | Verbose output with details | False | `--verbose` |
| `--help` | Show help message | - | `--help` |

## 📝 Extraction Types Reference

### Available Types
```bash
--types url,email,form,auth,api,swagger,ip,domain,subdomain,secret,js,comment,hash,base64
```

| Type | Description | Example Output |
|------|-------------|----------------|
| `url` | HTTP/HTTPS URLs | `https://example.com/api/v1` |
| `email` | Email addresses | `admin@example.com` |
| `form` | HTML forms and inputs | `<form action="/login">` |
| `auth` | Authentication endpoints | `/auth/login`, `/oauth/token` |
| `api` | API endpoints | `/api/v1/users`, `/graphql` |
| `swagger` | API documentation | `/swagger-ui`, `/docs` |
| `ip` | IP addresses | `192.168.1.1` |
| `domain` | Domain names | `example.com` |
| `subdomain` | Subdomains (with --target-domain) | `api.example.com` |
| `secret` | API keys, tokens, secrets | `api_key:abc123` |
| `js` | JavaScript variables (with --deep-js) | `apiKey=secret123` |
| `comment` | HTML/JS comments (with --include-comments) | `<!-- Debug mode -->` |
| `hash` | Hash values (MD5, SHA) | `d41d8cd98f00b204e9800998ecf8427e` |
| `base64` | Base64 encoded strings | `SGVsbG8gV29ybGQ=` |

## 🔥 XSS-Vibes Integration

ExtractorCLI integrates with XSS-Vibes for advanced XSS vulnerability discovery and testing.

### Endpoint Discovery
```bash
# Discover XSS endpoints for a domain
python ectractorcli.py content.html --target-domain example.com --xss-discover --verbose
```

### Vulnerability Scanning
```bash
# Scan extracted URLs for XSS vulnerabilities
python ectractorcli.py urls.txt --xss-scan --xss-threads 10 --xss-timeout 15
```

### Combined Workflow
```bash
# Extract URLs, discover endpoints, and scan for XSS
echo "https://example.com" | python ectractorcli.py \
  --fetch-urls \
  --target-domain example.com \
  --xss-discover \
  --xss-scan \
  --verbose \
  --output comprehensive_results.txt
```

## 🧠 AI Scoring System

The AI scoring system assigns relevance scores to extracted data based on security importance.

### Scoring Criteria
- **URLs**: Higher scores for admin, API, auth endpoints
- **Secrets**: Highest scores for potential credentials
- **APIs**: Scored based on version indicators and documentation
- **General**: Bonus points for internal, private, management keywords

### Usage
```bash
# Apply AI scoring to results
python ectractorcli.py input.html --ai-score --tagged
```

## 🔄 Deduplication Strategies

### Basic Deduplication
```bash
# Remove duplicates from results
python ectractorcli.py input.txt --dedup
```

### Advanced Merging
```bash
# Merge with existing file and deduplicate
python ectractorcli.py new_urls.txt --merge-with existing_urls.txt --dedup-by url
```

### Deduplication Options
- `url`: Deduplicate URLs only
- `domain`: Deduplicate domains only
- `all`: Deduplicate all categories

## 📊 Output Examples

### Plain Text Output
```
https://example.com/api/v1
https://example.com/login
admin@example.com
192.168.1.1
```

### JSON Output
```json
{
  "url": [
    "https://example.com/api/v1",
    "https://example.com/login"
  ],
  "email": [
    "admin@example.com"
  ],
  "ip": [
    "192.168.1.1"
  ]
}
```

### Tagged Output
```
# ExtractorCLI Results - 2025-08-06 10:30:00
# Processed: input.html
# Types: url,email,ip

## URL (2 found):
https://example.com/api/v1
https://example.com/login

## EMAIL (1 found):
admin@example.com

## IP (1 found):
192.168.1.1
```

### JSONL Output
```json
{"type": "url", "value": "https://example.com/api/v1"}
{"type": "url", "value": "https://example.com/login"}
{"type": "email", "value": "admin@example.com"}
{"type": "ip", "value": "192.168.1.1"}
```

## ⚡ Performance Tips

### Optimizing Large Datasets
```bash
# Use appropriate thread count for your system
python ectractorcli.py large_dataset.txt --threads 20

# Limit file sizes to prevent memory issues
python ectractorcli.py directory/ --recursive --max-size 10

# Use deduplication to reduce output size
python ectractorcli.py input.txt --dedup --unique-only
```

### Memory Management
```bash
# Process large files with JSONL for streaming
python ectractorcli.py huge_file.html --to-jsonl --output results.jsonl

# Use specific types to reduce processing overhead
python ectractorcli.py input.txt --types url,api --dedup
```

## 🛡️ Security Considerations

### SSL/TLS Handling
```bash
# Default: SSL verification enabled
python ectractorcli.py urls.txt --fetch-urls

# Disable SSL verification (use with caution)
python ectractorcli.py urls.txt --fetch-urls --insecure
```

### Rate Limiting
```bash
# Adjust timeout to be respectful to target servers
python ectractorcli.py urls.txt --fetch-urls --timeout 30

# Use fewer threads for sensitive targets
python ectractorcli.py urls.txt --fetch-urls --threads 5
```

### User Agent Configuration
```bash
# Use custom User-Agent for identification
python ectractorcli.py urls.txt --fetch-urls --user-agent "MyBot/1.0"
```

## 🔧 Integration Examples

### Pipeline Integration
```bash
# Chain with other ReconCLI modules
python ectractorcli.py urls.txt --types api --json | python apicli.py --input -

# Export for external tools
python ectractorcli.py input.html --types url --output urls.txt
cat urls.txt | httpx -silent
```

### Automation Scripts
```bash
#!/bin/bash
# Automated extraction and XSS scanning pipeline

# Extract URLs and APIs
python ectractorcli.py target_content.html \
  --types url,api \
  --fetch-urls \
  --dedup \
  --output extracted_urls.txt

# Scan for XSS vulnerabilities
python ectractorcli.py extracted_urls.txt \
  --xss-scan \
  --xss-threads 15 \
  --verbose \
  --output xss_results.txt

echo "Pipeline completed! Check xss_results.txt for vulnerabilities."
```

## 🐛 Troubleshooting

### Common Issues

#### SSL Certificate Errors
```bash
# Problem: SSL verification fails
# Solution: Use --insecure flag or check certificate validity
python ectractorcli.py urls.txt --fetch-urls --insecure
```

#### Memory Issues with Large Files
```bash
# Problem: Out of memory with large files
# Solution: Use --max-size to limit file sizes
python ectractorcli.py large_dir/ --recursive --max-size 5
```

#### XSS-Vibes Not Found
```bash
# Problem: xss-vibes command not found
# Solution: Install xss-vibes or check PATH
pip install xss-vibes
# or ensure xss-vibes is in your PATH
```

#### Timeout Issues
```bash
# Problem: Requests timing out
# Solution: Increase timeout value
python ectractorcli.py urls.txt --fetch-urls --timeout 60
```

### Debug Mode
```bash
# Enable verbose output for debugging
python ectractorcli.py input.txt --verbose --fetch-urls
```

## 📚 Advanced Usage Patterns

### Multi-Stage Extraction
```bash
# Stage 1: Extract URLs from initial content
python ectractorcli.py initial.html --types url --output stage1_urls.txt

# Stage 2: Fetch content from URLs and extract more data
python ectractorcli.py stage1_urls.txt --fetch-urls --deep-js --output stage2_data.json --json

# Stage 3: Extract secrets and APIs from fetched content
python ectractorcli.py stage2_data.json --types secret,api --ai-score --tagged
```

### Domain-Focused Reconnaissance
```bash
# Extract subdomains for a specific target
python ectractorcli.py recon_data.txt \
  --target-domain target.com \
  --types subdomain,url,api \
  --dedup \
  --sort-results \
  --output target_recon.txt
```

### Security Assessment Workflow
```bash
# Comprehensive security-focused extraction
python ectractorcli.py application_source/ \
  --recursive \
  --types secret,auth,api,url \
  --smart-detect \
  --deep-js \
  --include-comments \
  --ai-score \
  --tagged \
  --output security_assessment.txt
```

## 🔗 Related Modules

ExtractorCLI integrates well with other ReconCLI modules:

- **HTTPCLI**: Process extracted URLs for HTTP analysis
- **APICLI**: Analyze extracted API endpoints
- **DNSCLI**: Resolve extracted domains and subdomains
- **SECRETSCLI**: Further analyze extracted secrets
- **XSS-Vibes**: Integrated XSS vulnerability testing

## 📈 Performance Metrics

### Typical Performance
- **Small files** (< 1MB): < 1 second
- **Medium files** (1-10MB): 1-5 seconds
- **Large files** (10-100MB): 5-30 seconds
- **URL fetching** (100 URLs): 10-60 seconds (depends on network)

### Optimization Guidelines
- Use `--threads` based on your system capabilities (default: 10)
- Set appropriate `--timeout` for network conditions (default: 10s)
- Use `--max-size` to prevent memory issues (default: 5MB)
- Apply `--dedup` for large datasets to reduce output size

## 🆕 Recent Updates

### Version 2.0 Features
- ✅ XSS-Vibes integration for vulnerability scanning
- ✅ AI-powered result scoring and prioritization
- ✅ Enhanced deduplication with merge capabilities
- ✅ Concurrent URL fetching with advanced error handling
- ✅ Smart file type detection for optimal extraction
- ✅ Comprehensive secret detection (AWS, GitHub, Slack, JWT)
- ✅ JSONL output format for streaming large datasets
- ✅ Deep JavaScript analysis with variable extraction

## 📞 Support & Contributing

### Getting Help
- 📧 **Issues**: Report bugs via GitHub Issues
- 💬 **Discussion**: Join the ReconCLI Discord community
- 📖 **Documentation**: Check the comprehensive guides

### Contributing
- Fork the repository and submit pull requests
- Follow the existing code style and patterns
- Add tests for new features
- Update documentation for any changes

---

*ExtractorCLI is part of the ReconCLI security reconnaissance suite. For more information about the full toolkit, visit the main ReconCLI documentation.*
