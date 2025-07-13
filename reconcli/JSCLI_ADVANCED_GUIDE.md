# 🔍 JSCli Advanced JavaScript Analysis Guide

## Overview
JSCli now supports multiple analysis engines and advanced features for comprehensive JavaScript reconnaissance.

## ✨ New Features Added

### 🛠️ Multiple Analysis Engines
- **Native Engine** - Built-in Python analysis (default)
- **JSLuice** - Advanced JS parsing and URL extraction
- **JSLeak** - Secrets detection in JavaScript files
- **SubJS** - JavaScript file discovery
- **Cariddi** - Comprehensive JavaScript analysis

### 🔧 Advanced Options
- `--engine [native|jsluice|jsleak|subjs|cariddi]` - Choose analysis engine
- `--store-db` - Store results in ReconCLI database
- `--ai-mode` - Enable AI-powered analysis of findings
- `--retry INTEGER` - Number of retries for failed requests (default: 3)
- `--delay FLOAT` - Delay between requests in seconds (default: 0.0)
- `--concurrency INTEGER` - Maximum concurrent requests (default: 10)

### 🧠 AI Analysis Features
- Security assessment of discovered secrets and endpoints
- Risk level classification
- Attack vector identification
- Priority recommendations for manual review

## 🚀 Usage Examples

### Basic Native Analysis
```bash
reconcli jscli --input js_urls.txt --output-dir js_results --json --markdown
```

### JSLuice Engine with Database Storage
```bash
reconcli jscli --input js_urls.txt --engine jsluice --store-db \
  --target-domain example.com --program "Bug Bounty Program"
```

### AI-Powered Analysis
```bash
reconcli jscli --input js_urls.txt --ai-mode --ai-model gpt-4 \
  --engine native --verbose
```

### High Concurrency with Retry Logic
```bash
reconcli jscli --input js_urls.txt --concurrency 20 --retry 5 \
  --delay 0.5 --timeout 30 --verbose
```

### JSLeak for Secrets Discovery
```bash
reconcli jscli --input js_urls.txt --engine jsleak \
  --only-with-findings --save-raw
```

### Cariddi Comprehensive Analysis
```bash
reconcli jscli --input js_urls.txt --engine cariddi \
  --store-db --ai-mode --verbose
```

### SubJS for JS File Discovery
```bash
reconcli jscli --input domain_list.txt --engine subjs \
  --json --markdown --proxy http://127.0.0.1:8080
```

## 🔧 Engine-Specific Features

### 🏠 Native Engine
- Built-in secret pattern matching
- Endpoint extraction with regex
- File extension tagging
- Custom retry logic and delay

### 🧪 JSLuice
- Advanced JavaScript parsing
- URL and endpoint extraction
- Secrets detection
- JSON structured output

### 🔓 JSLeak
- Specialized in secrets discovery
- API key detection
- Token identification
- Line-by-line analysis

### 📜 SubJS
- JavaScript file discovery
- Domain-based JS enumeration
- Simple and fast scanning

### 🚗 Cariddi
- Comprehensive JS analysis
- Endpoint and secret discovery
- Parameter extraction
- Multi-format output

## 📊 Output Structure

### Enhanced JSON Output
```json
{
  "scan_info": {
    "engine": "jsluice",
    "timestamp": "2025-07-12T10:30:00Z",
    "total_urls": 150,
    "results_found": 45,
    "concurrency": 10,
    "timeout": 20,
    "retries": 3,
    "delay": 0.5
  },
  "results": [
    {
      "url": "https://example.com/app.js",
      "endpoints": ["/api/users", "/admin/panel"],
      "secrets": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
      "tags": ["jwt", "api"],
      "source": "jsluice",
      "size": 45231,
      "status_code": 200
    }
  ],
  "ai_analysis": "...",
  "summary": {
    "total": 150,
    "with_findings": 45,
    "secrets": 23,
    "endpoints": 167
  }
}
```

### Enhanced Markdown Report
```markdown
# 🔍 JavaScript Analysis Results

**Generated:** 2025-07-12T10:30:00Z
**Engine:** jsluice
**Total URLs:** 150
**Results Found:** 45
**URLs with Findings:** 45
**Total Secrets:** 23
**Total Endpoints:** 167

---

## 📄 https://example.com/app.js

**Tags:** `jwt, api`
**Source:** `jsluice`
**Size:** `45231 bytes`

### 🔗 Endpoints
- `/api/users`
- `/admin/panel`

### 🔑 Secrets/Keys
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

---

## 🧠 AI Analysis

[Detailed AI analysis of findings]
```

## 🔧 Installation Requirements

### Core Requirements
```bash
# Python dependencies
pip install requests click

# ReconCLI installation
pip install -e .
```

### External Engines
```bash
# JSLuice
go install github.com/BishopFox/jsluice@latest

# JSLeak
go install github.com/channyein1337/jsleak@latest

# SubJS
go install github.com/lc/subjs@latest

# Cariddi
go install github.com/edoardottt/cariddi/cmd/cariddi@latest
```

## 🧠 AI Integration

### Supported Models
- GPT-3.5-turbo (default)
- GPT-4
- Claude models
- Custom API endpoints

### AI Analysis Features
- **Security Assessment** - Risk evaluation of discovered secrets
- **Pattern Recognition** - Identification of common vulnerability patterns
- **Attack Vector Analysis** - Potential exploitation methods
- **Prioritization** - Risk-based finding classification
- **Recommendations** - Next steps for manual analysis

## 💾 Database Integration

### Supported Storage
- Target information with program classification
- JS findings with metadata
- Source attribution and timestamps
- Aggregated statistics

### Database Schema
```sql
js_findings:
- url (text)
- secrets_count (integer)
- endpoints_count (integer)
- tags (text)
- source (text)
- timestamp (text)
```

## 🔧 Performance Optimization

### Concurrency Settings
- **Low Traffic**: `--concurrency 5 --delay 1.0`
- **Normal**: `--concurrency 10 --delay 0.5` (default)
- **Aggressive**: `--concurrency 20 --delay 0.1`
- **Maximum**: `--concurrency 50 --delay 0.0`

### Retry Logic
- **Conservative**: `--retry 1 --timeout 10`
- **Balanced**: `--retry 3 --timeout 20` (default)
- **Persistent**: `--retry 5 --timeout 30`

## 🛡️ Best Practices

### 1. Engine Selection
- **Native**: General purpose, custom patterns
- **JSLuice**: Modern JS frameworks, SPA analysis
- **JSLeak**: Secret-focused reconnaissance
- **SubJS**: Discovery phase, file enumeration
- **Cariddi**: Comprehensive analysis, parameter extraction

### 2. Performance Tuning
- Start with conservative settings
- Monitor target response times
- Adjust concurrency based on target capacity
- Use delays to avoid rate limiting

### 3. Output Management
- Always use `--json` for programmatic processing
- Enable `--markdown` for human-readable reports
- Use `--only-with-findings` to reduce noise
- Enable `--save-raw` for manual analysis

### 4. Integration Workflow
- Database storage for centralized results
- AI analysis for risk assessment
- Multiple engines for comprehensive coverage
- Resume functionality for large scans

## 🔍 Advanced Patterns

### Custom Secret Patterns
The native engine supports custom secret patterns in `SECRET_PATTERNS`:
- API keys and tokens
- AWS credentials
- GitHub tokens
- Private keys
- Custom application secrets

### Endpoint Extraction
Regex-based endpoint discovery:
- Path parameters
- API endpoints
- Admin panels
- File references
- Dynamic routes

## 📈 Monitoring and Debugging

### Verbose Output
```bash
reconcli jscli --input urls.txt --verbose --progress
```

### Resume Functionality
```bash
# Show previous scan status
reconcli jscli --show-resume --output-dir js_results

# Resume interrupted scan
reconcli jscli --input urls.txt --resume --output-dir js_results

# Clear resume state
reconcli jscli --clear-resume --output-dir js_results
```

## 🎯 Use Cases

### 1. Bug Bounty Reconnaissance
```bash
reconcli jscli --input target_js.txt --ai-mode --store-db \
  --target-domain target.com --program "Company Bug Bounty" \
  --engine jsluice --concurrency 15
```

### 2. Penetration Testing
```bash
reconcli jscli --input client_js.txt --engine native \
  --save-raw --only-with-findings --verbose \
  --retry 3 --delay 0.5
```

### 3. Security Assessment
```bash
reconcli jscli --input app_js.txt --ai-mode --ai-model gpt-4 \
  --engine cariddi --json --markdown \
  --store-db --verbose
```

### 4. Continuous Monitoring
```bash
reconcli jscli --input monitor_js.txt --engine jsleak \
  --store-db --target-domain production.com \
  --concurrency 5 --delay 2.0
```

This enhanced JSCli provides comprehensive JavaScript analysis capabilities with multiple engines, AI integration, and advanced features for modern reconnaissance workflows.
