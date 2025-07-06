# 🧪 VulnCLI Testing & Configuration Examples

**Purpose**: Ready-to-use configurations and test scenarios for VulnCLI  
**Status**: Production-ready examples  
**Usage**: Copy and modify for your specific needs

---

## 📋 **Pipeline Configuration Examples**

### 1. Basic Web Application Assessment
```yaml
# basic_web_assessment.yaml
name: "Basic Web Application Security Assessment"
description: "Standard security testing for web applications"

global_settings:
  timeout: 300
  concurrency: 10
  ai_mode: true
  verbose: true

stages:
  - name: "url_filtering"
    description: "Filter URLs by patterns"
    tools: ["gf_filtering"]
    settings:
      patterns: "xss,lfi,sqli,redirect,ssrf"
      gf_mode: "both"
      dedup: true
    
  - name: "vulnerability_scanning"
    description: "Run vulnerability scanners"
    tools: ["nuclei", "jaeles"]
    depends_on: ["url_filtering"]
    parallel: true
    ai_enhanced: true
    settings:
      nuclei_severity: "critical,high,medium"
      jaeles_level: 2
    
  - name: "specialized_testing"
    description: "Targeted testing based on patterns"
    tools: ["dalfox"]
    depends_on: ["url_filtering"]
    conditions:
      has_xss_patterns: true
    
  - name: "reporting"
    description: "Generate comprehensive reports"
    tools: ["json_report", "markdown_report", "ai_summary"]
    depends_on: ["vulnerability_scanning", "specialized_testing"]
    settings:
      risk_scoring: true
      executive_dashboard: true
```

### 2. Enterprise Full-Scale Assessment
```yaml
# enterprise_assessment.yaml
name: "Enterprise Security Assessment"
description: "Comprehensive security testing with all features"

global_settings:
  timeout: 600
  concurrency: 20
  ai_mode: true
  verbose: true
  risk_scoring: true
  cvss_lookup: true

stages:
  - name: "reconnaissance"
    description: "Information gathering and reconnaissance"
    tools: ["httpx", "technology_detect", "subfinder"]
    parallel: true
    settings:
      httpx_tech_detect: true
      domain: "target.com"
    
  - name: "discovery"
    description: "Content and directory discovery"
    tools: ["gobuster", "ffuf"]
    depends_on: ["reconnaissance"]
    parallel: true
    settings:
      gobuster_wordlist: "/usr/share/wordlists/dirb/common.txt"
      ffuf_extensions: "php,asp,aspx,jsp,html"
    
  - name: "pattern_analysis"
    description: "Advanced pattern matching and filtering"
    tools: ["gf_filtering"]
    depends_on: ["discovery"]
    settings:
      patterns: "xss,lfi,sqli,redirect,ssrf,idor,debug,backup,config"
      smart_dedup: true
      categorize_params: true
      max_urls_per_pattern: 1000
    
  - name: "vulnerability_scanning"
    description: "Multi-tool vulnerability assessment"
    tools: ["nuclei", "jaeles", "nikto"]
    depends_on: ["pattern_analysis"]
    parallel: false  # Sequential for resource management
    ai_enhanced: true
    settings:
      nuclei_select: "http/cves/,http/exposures/,http/misconfiguration/"
      nuclei_severity: "critical,high,medium"
      jaeles_select: "sensitive/.*,common/.*"
      jaeles_level: 2
      ai_reduce_fp: true
      ai_confidence_threshold: 0.7
    
  - name: "specialized_testing"
    description: "Targeted vulnerability testing"
    tools: ["dalfox", "sqlmap", "commix"]
    depends_on: ["pattern_analysis"]
    parallel: true
    conditions:
      min_urls: 5
    settings:
      dalfox_blind: "https://your-xss-hunter.com"
      proxy: "http://127.0.0.1:8080"  # For manual testing
    
  - name: "analysis_and_reporting"
    description: "AI-powered analysis and comprehensive reporting"
    tools: ["risk_analysis", "json_report", "markdown_report", "ai_summary", "executive_dashboard"]
    depends_on: ["vulnerability_scanning", "specialized_testing"]
    settings:
      generate_heatmap: true
      detailed_report: true
      business_impact: 0.8  # High business impact
      risk_threshold: 6.0

notifications:
  slack_webhook: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
  discord_webhook: "https://discord.com/api/webhooks/YOUR/WEBHOOK"
  notify_critical_only: true
  notify_progress: true
```

### 3. Quick Bug Bounty Scan
```yaml
# bug_bounty_quick.yaml
name: "Bug Bounty Quick Scan"
description: "Fast scanning for bug bounty hunting"

global_settings:
  timeout: 180
  concurrency: 15
  ai_mode: true
  verbose: false

stages:
  - name: "quick_filtering"
    tools: ["gf_filtering"]
    settings:
      patterns: "xss,sqli,ssrf,redirect,lfi"
      gf_mode: "global"
      smart_dedup: true
    
  - name: "fast_scanning"
    tools: ["nuclei"]
    depends_on: ["quick_filtering"]
    ai_enhanced: true
    settings:
      nuclei_tags: "exposure,misconfig,rce,xss,sqli"
      nuclei_severity: "critical,high"
      ai_smart_templates: true
      ai_reduce_fp: true
    
  - name: "quick_xss"
    tools: ["dalfox"]
    depends_on: ["quick_filtering"]
    conditions:
      has_xss_patterns: true
    settings:
      concurrency: 10
    
  - name: "quick_report"
    tools: ["markdown_report"]
    depends_on: ["fast_scanning", "quick_xss"]
    settings:
      risk_scoring: true

notifications:
  discord_webhook: "YOUR_DISCORD_WEBHOOK"
  notify_critical_only: true
```

### 4. API Security Assessment
```yaml
# api_security.yaml
name: "API Security Assessment"
description: "Specialized scanning for REST APIs and microservices"

global_settings:
  timeout: 300
  concurrency: 8
  ai_mode: true
  custom_headers: "Authorization:Bearer token,X-API-Key:key"

stages:
  - name: "api_discovery"
    tools: ["httpx"]
    settings:
      httpx_tech_detect: true
      include_status_codes: "200,401,403,404,500"
    
  - name: "api_filtering"
    tools: ["gf_filtering"]
    depends_on: ["api_discovery"]
    settings:
      patterns: "api,json,xml,graphql,jwt"
      extract_params: true
      param_filter: "id,token,key,secret,admin"
    
  - name: "api_vulnerability_scan"
    tools: ["nuclei"]
    depends_on: ["api_filtering"]
    ai_enhanced: true
    settings:
      nuclei_select: "http/exposures/apis/,http/misconfiguration/,http/cves/"
      nuclei_tags: "api,jwt,auth,exposure"
      ai_smart_templates: true
    
  - name: "api_fuzzing"
    tools: ["ffuf"]
    depends_on: ["api_filtering"]
    settings:
      ffuf_extensions: "json,xml"
      wordlist: "/usr/share/wordlists/api_endpoints.txt"
    
  - name: "api_reporting"
    tools: ["json_report", "ai_summary"]
    depends_on: ["api_vulnerability_scan", "api_fuzzing"]
    settings:
      detailed_report: true
      business_impact: 0.9  # APIs often critical
```

---

## 🧪 **Test Scenarios & Commands**

### Scenario 1: Basic Website Testing
```bash
# Create test URLs file
echo -e "https://example.com/search?q=test\\nhttps://example.com/user?id=123\\nhttps://example.com/file?path=../test" > test_urls.txt

# Run basic scan with AI
python vulncli.py \\
  -i test_urls.txt \\
  -o results_basic \\
  --run-nuclei \\
  --run-dalfox \\
  --ai-mode \\
  --markdown \\
  --verbose

# Expected output files:
# - results_basic/nuclei.txt
# - results_basic/dalfox.txt  
# - results_basic/vulncli_report.md
# - results_basic/ai_executive_summary.md
# - results_basic/nuclei_ai_analysis.json
```

### Scenario 2: WordPress Site Assessment
```bash
# WordPress-specific testing
python vulncli.py \\
  -i wordpress_urls.txt \\
  -o results_wordpress \\
  --patterns "xss,lfi,sqli,wp" \\
  --run-nuclei \\
  --nuclei-select "http/cms/wordpress/,http/vulnerabilities/wordpress/" \\
  --run-jaeles \\
  --jaeles-select "cms/wordpress/.*" \\
  --technology-detect \\
  --ai-mode \\
  --json \\
  --markdown \\
  --verbose
```

### Scenario 3: Large Scale Enterprise Scan
```bash
# Enterprise scan with all features
python vulncli.py \\
  -i enterprise_urls.txt \\
  -o results_enterprise \\
  --pipeline-config enterprise_assessment.yaml \\
  --concurrency 20 \\
  --timeout-nuclei 600 \\
  --ai-mode \\
  --ai-confidence-threshold 0.8 \\
  --risk-scoring \\
  --cvss-lookup \\
  --generate-heatmap \\
  --executive-dashboard \\
  --slack-webhook "YOUR_SLACK_WEBHOOK" \\
  --verbose
```

### Scenario 4: Bug Bounty Quick Scan
```bash
# Fast bug bounty scan
python vulncli.py \\
  -i bounty_targets.txt \\
  -o results_bounty \\
  --patterns "xss,sqli,ssrf,redirect" \\
  --run-nuclei \\
  --nuclei-tags "exposure,rce,xss,sqli" \\
  --nuclei-severity "critical,high" \\
  --run-dalfox \\
  --ai-smart-templates \\
  --ai-reduce-fp \\
  --smart-dedup \\
  --exclude-extensions "css,js,png,jpg,gif" \\
  --markdown \\
  --discord-webhook "YOUR_DISCORD_WEBHOOK" \\
  --notify-critical-only
```

### Scenario 5: API Testing
```bash
# API-focused security testing
python vulncli.py \\
  -i api_endpoints.txt \\
  -o results_api \\
  --patterns "api,json,jwt" \\
  --run-nuclei \\
  --nuclei-tags "api,jwt,auth" \\
  --custom-headers "Authorization:Bearer test,X-API-Key:test" \\
  --extract-params \\
  --param-filter "id,token,key,secret" \\
  --technology-detect \\
  --ai-mode \\
  --json
```

---

## 📊 **Performance Benchmarks & Expectations**

### Small Scale (< 100 URLs)
```bash
# Typical performance metrics
URLs: 50-100
Duration: 2-5 minutes
Memory: < 500MB
CPU: 1-2 cores
Tools: GF + Nuclei + Dalfox
AI Features: All enabled
```

### Medium Scale (100-1000 URLs)
```bash
# Expected performance
URLs: 100-1000  
Duration: 10-30 minutes
Memory: 500MB-2GB
CPU: 2-4 cores
Concurrency: 10-15
Rate Limit: 50 req/sec
```

### Large Scale (1000+ URLs)
```bash
# Enterprise scale
URLs: 1000-10000
Duration: 1-3 hours
Memory: 2-8GB
CPU: 4-8 cores  
Concurrency: 15-25
Rate Limit: 25 req/sec (to avoid blocking)
Recommended: Pipeline config, resume enabled
```

---

## 🔧 **Configuration Templates**

### Basic Configuration
```bash
# ~/.vulncli/config.yaml
default_settings:
  concurrency: 10
  timeout: 300
  ai_mode: true
  verbose: true
  
patterns:
  web_app: "xss,lfi,sqli,redirect,ssrf"
  api: "api,json,jwt,graphql"
  cms: "wp,drupal,joomla"
  
nuclei:
  default_severity: "critical,high,medium"
  default_templates: "http/exposures/,http/misconfiguration/"
  
jaeles:
  default_level: 2
  default_signatures: "sensitive/.*,common/.*"
```

### Wordlists Configuration
```bash
# Create wordlists directory
mkdir -p ~/.vulncli/wordlists

# Download common wordlists
wget -O ~/.vulncli/wordlists/common.txt \\
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

wget -O ~/.vulncli/wordlists/api_endpoints.txt \\
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt
```

### Custom GF Patterns
```bash
# Create custom patterns directory
mkdir -p ~/.vulncli/gf_patterns

# Custom XSS pattern
cat > ~/.vulncli/gf_patterns/custom_xss.json << 'EOF'
{
    "flags": "-iE",
    "patterns": [
        "\\\\b(alert|confirm|prompt)\\\\(",
        "javascript:",
        "<script[^>]*>",
        "onerror\\\\s*=",
        "onload\\\\s*="
    ]
}
EOF
```

---

## 🎯 **Testing Checklist**

### Pre-Scan Checklist
- [ ] Target URLs file prepared and validated
- [ ] Output directory has sufficient space
- [ ] Network connectivity to targets confirmed  
- [ ] Required tools installed (nuclei, gf, dalfox, jaeles)
- [ ] Nuclei templates updated (`nuclei -update-templates`)
- [ ] GF patterns installed (`go install github.com/tomnomnom/gf@latest`)
- [ ] Rate limiting configured appropriately
- [ ] Proxy configured if needed

### Post-Scan Validation
- [ ] All expected output files generated
- [ ] No critical errors in scan logs
- [ ] AI analysis results reasonable
- [ ] Risk scores aligned with findings
- [ ] Reports generated successfully
- [ ] Notifications sent (if configured)
- [ ] False positives identified and documented

### Quality Assurance Tests
```bash
# Test 1: Basic functionality
python vulncli.py -i test_urls.txt -o test1 --run-nuclei --ai-mode --verbose

# Test 2: AI features validation
python vulncli.py -i test_urls.txt -o test2 --run-nuclei --ai-smart-templates --ai-reduce-fp --verbose

# Test 3: Pipeline configuration
python vulncli.py --pipeline-config basic_web_assessment.yaml --verbose

# Test 4: Resume functionality  
python vulncli.py -i test_urls.txt -o test4 --run-nuclei --resume

# Test 5: Error handling
python vulncli.py -i nonexistent.txt -o test5 --run-nuclei  # Should handle gracefully
```

---

## 📋 **Troubleshooting Guide**

### Common Issues & Solutions

**Issue**: AI analysis fails
```bash
# Solution: Check dependencies
pip install numpy scikit-learn matplotlib seaborn
```

**Issue**: Nuclei templates not found
```bash
# Solution: Update templates
nuclei -update-templates
```

**Issue**: GF patterns not working
```bash
# Solution: Install/update GF
go install github.com/tomnomnom/gf@latest
gf -list  # Verify patterns available
```

**Issue**: Memory usage too high
```bash
# Solution: Reduce concurrency and batch size
python vulncli.py --concurrency 5 --max-urls-per-pattern 500
```

**Issue**: Scan taking too long
```bash
# Solution: Use smart filtering and AI optimization
python vulncli.py --smart-dedup --ai-smart-templates --exclude-extensions "css,js,png"
```

---

## 📈 **Monitoring & Metrics**

### Key Performance Indicators
```yaml
# Example metrics to track
performance_metrics:
  scan_duration: "< 30 minutes for 1000 URLs"
  memory_usage: "< 4GB peak"
  cpu_usage: "< 80% average"
  accuracy: "> 90% true positives"
  coverage: "> 95% URL processing"
  
quality_metrics:
  false_positive_rate: "< 10%"
  critical_finding_detection: "> 95%"
  ai_confidence_average: "> 0.8"
  user_satisfaction: "> 4.5/5"
```

### Monitoring Commands
```bash
# Monitor resource usage during scan
htop  # Or top on systems without htop

# Monitor disk space
df -h

# Monitor network usage  
iftop  # Or nethogs

# Monitor scan progress
tail -f results/vulncli.log  # If logging enabled
```

---

*These configurations and examples are ready for production use. Customize based on your specific requirements and environment.*
