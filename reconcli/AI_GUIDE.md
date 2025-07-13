# 🧠 Enterprise AI-Powered Reconnaissance Assistant Guide

## Overview

The AI-Powered Reconnaissance Assistant is an enterprise-grade module that integrates multiple AI providers to enhance reconnaissance capabilities with intelligent analysis, automated planning, and advanced payload generation.

## Features

### 🎯 **Core Capabilities**
- **Multi-Provider AI Support**: OpenAI GPT, Anthropic Claude, Google Gemini
- **Session Management**: Persistent sessions with query history and context
- **Intelligent Recon Planning**: Automated methodology generation
- **Advanced Payload Generation**: Context-aware exploit payloads
- **Target Analysis**: AI-powered security assessment
- **Interactive Chat Mode**: Real-time AI assistance

### 🔧 **AI Provider Configuration**

#### OpenAI GPT
```bash
export OPENAI_API_KEY="your-openai-api-key"
```

#### Anthropic Claude
```bash
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

#### Google Gemini
```bash
export GOOGLE_API_KEY="your-google-api-key"
```

## Usage Examples

### 1. **Basic AI Prompts**
```bash
# Ask general recon questions
reconcli aicli --prompt "What are the best techniques for subdomain enumeration?"

# Get specific tool recommendations
reconcli aicli --prompt "How to bypass WAF during reconnaissance?"

# Security methodology questions
reconcli aicli --prompt "Explain OWASP reconnaissance methodology"
```

### 2. **Advanced Payload Generation**
```bash
# Generate XSS payloads for HTML context
reconcli aicli --payload xss --context html --technique reflection

# SQL injection for MySQL with union technique
reconcli aicli --payload sqli --context mysql --technique union

# SSRF payloads for cloud environments
reconcli aicli --payload ssrf --context cloud --technique bypass

# Local file inclusion for Linux systems
reconcli aicli --payload lfi --context linux --technique traversal

# Server-side template injection for Jinja2
reconcli aicli --payload ssti --context jinja2 --technique sandbox
```

### 3. **Reconnaissance Planning**
```bash
# Comprehensive recon plan
reconcli aicli --plan example.com --scope comprehensive

# Basic reconnaissance
reconcli aicli --plan example.com --scope basic

# Cloud-focused reconnaissance
reconcli aicli --plan example.com --scope cloud

# API-focused reconnaissance
reconcli aicli --plan example.com --scope api

# Export plan to file
reconcli aicli --plan example.com --export-plan recon_plan.json
reconcli aicli --plan example.com --export-plan recon_plan.yaml
```

### 4. **Target Analysis**
```bash
# Comprehensive target analysis
reconcli aicli --analyze example.com

# Analysis with specific AI provider
reconcli aicli --analyze example.com --provider claude

# Verbose analysis output
reconcli aicli --analyze example.com --verbose
```

### 5. **Session Management**
```bash
# Create new session
reconcli aicli --new-session example.com

# Resume existing session
reconcli aicli --session abc123ef --prompt "Continue analysis"

# List all sessions
reconcli aicli --list-sessions

# Interactive mode with session
reconcli aicli --interactive --new-session example.com
```

### 6. **Interactive AI Chat**
```bash
# Start interactive mode
reconcli aicli --interactive

# Interactive with specific provider
reconcli aicli --interactive --provider openai

# Interactive with existing session
reconcli aicli --interactive --session abc123ef
```

## Advanced Features

### **1. Context-Aware Payload Generation**

The AI assistant generates payloads based on:
- **Context**: HTML, JavaScript, SQL, File system, etc.
- **Technique**: Specific exploitation methods
- **Target Environment**: Technology stack considerations

Example payload contexts:
```bash
# XSS Contexts
--context html          # HTML injection points
--context javascript    # JavaScript context
--context attribute     # HTML attribute injection
--context url          # URL parameter injection
--context css          # CSS injection

# SQL Injection Contexts
--context mysql        # MySQL database
--context postgresql   # PostgreSQL database
--context mssql        # Microsoft SQL Server
--context oracle       # Oracle database
--context sqlite       # SQLite database

# File Inclusion Contexts
--context linux        # Linux file system
--context windows      # Windows file system
--context php          # PHP applications
--context java         # Java applications
```

### **2. Reconnaissance Scope Templates**

#### **Basic Scope**
- Subdomain enumeration
- Basic web discovery
- Estimated time: 1-2 hours

#### **Comprehensive Scope**
- Subdomain enumeration
- Web application discovery
- Vulnerability scanning
- Estimated time: 3-6 hours

#### **Cloud Scope**
- Cloud infrastructure discovery
- Bucket enumeration
- Cloud service analysis
- Estimated time: 2-4 hours

#### **API Scope**
- API endpoint discovery
- API vulnerability testing
- Authentication analysis
- Estimated time: 2-3 hours

### **3. AI Provider Selection**

Choose optimal AI provider based on:
- **OpenAI GPT-4**: Best for general reconnaissance and methodology
- **Anthropic Claude**: Excellent for security analysis and code review
- **Google Gemini**: Cost-effective for basic queries and planning

### **4. Session Persistence**

Sessions automatically save:
- Target information
- Query history
- AI responses
- Generated plans
- Analysis results

Session files stored in: `~/.reconcli/ai_sessions/`

## Interactive Commands

In interactive mode, use these commands:
```bash
# Basic AI interaction
"How to enumerate subdomains for example.com?"

# Payload generation
"payload xss"
"payload sqli mysql"

# Plan generation
"plan example.com"
"plan example.com comprehensive"

# Target analysis
"analyze example.com"

# Session management
"session info"
"providers"

# Exit
"quit" or "exit"
```

## Integration with ReconCLI Tools

The AI assistant provides command suggestions for:

### **Subdomain Enumeration**
```bash
python main.py dnscli --target example.com --wordlist-size large
python main.py permutcli --brand example --tools subfinder,amass
python main.py tagger --input subs_resolved.txt --output tagged_subs.json
```

### **Web Discovery**
```bash
python main.py httpcli --target example.com --tech-detect
python main.py urlcli --target example.com --deep-crawl
python main.py dirbcli --target example.com --wordlist-size large
```

### **Vulnerability Assessment**
```bash
python main.py vulncli --target example.com --comprehensive
python main.py vulnsqlicli --target example.com --advanced
python main.py takeovercli --target example.com
```

### **Cloud Reconnaissance**
```bash
python main.py cloudcli --target example.com --provider all
python main.py permutcli --brand example --bucket-scan
```

## Best Practices

### **1. API Key Security**
- Store API keys in `.env` file
- Never commit API keys to version control
- Use different keys for different environments
- Monitor API usage and costs

### **2. Session Management**
- Create new sessions for different targets
- Use descriptive session names
- Regularly clean up old sessions
- Export important plans and analyses

### **3. Payload Safety**
- Only use generated payloads in authorized testing
- Validate payloads in safe environments
- Follow responsible disclosure guidelines
- Respect scope limitations

### **4. AI Provider Optimization**
- Use GPT-4 for complex analysis
- Use Claude for code and security review
- Use Gemini for basic queries to save costs
- Monitor API usage and adjust accordingly

## Output Files

The AI assistant generates various output files:

### **Payload Files**
```
xss_html_1704067200.json       # XSS payloads for HTML context
sqli_mysql_1704067200.json     # SQL injection for MySQL
```

### **Plan Files**
```
recon_plan.json                # JSON format plan
recon_plan.yaml                # YAML format plan
```

### **Analysis Files**
```
analysis_example_com_1704067200.json  # Target analysis results
```

### **Session Files**
```
~/.reconcli/ai_sessions/abc123ef.json  # Session data
```

## Troubleshooting

### **Common Issues**

#### **No AI providers available**
```bash
# Check API keys
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY
echo $GOOGLE_API_KEY

# Install required packages
pip install openai anthropic google-generativeai
```

#### **Session not found**
```bash
# List available sessions
reconcli aicli --list-sessions

# Create new session
reconcli aicli --new-session example.com
```

#### **API rate limits**
- Use different AI providers
- Implement delays between requests
- Monitor API usage dashboards

## Security Considerations

1. **API Key Protection**: Never expose API keys in logs or outputs
2. **Query Logging**: Be aware that queries may be logged by AI providers
3. **Payload Responsibility**: Only use generated payloads in authorized contexts
4. **Data Privacy**: Avoid sending sensitive data to AI providers
5. **Compliance**: Ensure AI usage complies with organizational policies

## Advanced Configuration

Edit `ai_config.json` to customize:
- Model parameters (temperature, max_tokens)
- Rate limiting settings
- Logging preferences
- Security policies
- Cost optimization settings

## Integration Examples

### **Workflow Integration**
```bash
# 1. Create comprehensive plan
reconcli aicli --plan target.com --scope comprehensive --export-plan plan.json

# 2. Execute reconnaissance phases
python main.py dnscli --target target.com
python main.py permutcli --brand target

# 3. Analyze results with AI
reconcli aicli --analyze target.com --session session_id

# 4. Generate specific payloads
reconcli aicli --payload xss --context html
```

### **Automation Scripts**
```python
# Python automation example
import subprocess
import json

# Generate plan
result = subprocess.run([
    "python", "main.py", "aicli",
    "--plan", "example.com",
    "--export-plan", "auto_plan.json"
], capture_output=True, text=True)

# Load and execute plan
with open('auto_plan.json', 'r') as f:
    plan = json.load(f)

for phase in plan['phases']:
    for command in phase['commands']:
        subprocess.run(command.split())
```

---

## 🚀 Enterprise Features

- **Multi-Provider Failover**: Automatic fallback between AI providers
- **Cost Optimization**: Intelligent provider selection based on query complexity
- **Advanced Analytics**: Query performance and success rate tracking
- **Team Collaboration**: Shared sessions and plan templates
- **Compliance Reporting**: Audit logs and security compliance features

---

*Part of the ReconCLI Cyber-Squad z Przyszłości toolkit - Advanced AI-powered reconnaissance for the future of cybersecurity.*
