# MakeWordListCLI - Advanced Features Guide

## 🚀 New Advanced Features Added

### 1. Pattern-Based Generation
Generate wordlists based on specific attack patterns:

```bash
# Generate credential-focused wordlist
python makewordlistcli.py --name john --surname doe --pattern credential --output-prefix creds_test

# Generate subdomain patterns
python makewordlistcli.py --domain example.com --pattern subdomain --output-prefix subdomains_test

# Use custom patterns from file
python makewordlistcli.py --name admin --custom-patterns custom_patterns.txt --output-prefix custom_test
```

**Available patterns:**
- `credential`: admin/user/login patterns
- `subdomain`: subdomain variations
- `directory`: directory path patterns
- `filename`: file name variations
- `parameter`: URL parameter patterns
- `endpoint`: API endpoint patterns

### 2. Hybrid/Intelligent Generation
Advanced AI-like word combination using similarity analysis:

```bash
# Enable hybrid generation
python makewordlistcli.py --name company --domain target.com --hybrid --output-prefix hybrid_test

# Combines words intelligently based on common substrings and patterns
```

### 3. Transformation Rules
Apply hashcat-style transformation rules:

```bash
# Apply specific transformations
python makewordlistcli.py --name password --transform-rules "caps,lower,reverse,substitute_similar" --output-prefix transform_test

# Available rules: caps, lower, title, reverse, duplicate, append_num, prepend_num, toggle_case, remove_vowels, substitute_similar
```

### 4. Keyboard Patterns
Generate keyboard-based patterns for password attacks:

```bash
# Add keyboard patterns
python makewordlistcli.py --keyboard-patterns --output-prefix keyboard_test

# Generates: qwerty, asdf, 123456, etc.
```

### 5. Password Patterns
Intelligent password pattern generation:

```bash
# Generate password-style patterns
python makewordlistcli.py --name admin --password-patterns --output-prefix password_test

# Generates: admin123!, admin@2024, 123admin, etc.
```

### 6. OSINT Enrichment
Enrich wordlists using OSINT sources:

```bash
# GitHub repository enrichment
python makewordlistcli.py --osint-target "targetcompany" --output-prefix osint_test

# Fetches words from GitHub repos, descriptions, etc.
```

### 7. File Extension Combinations
Generate filename variations with extensions:

```bash
# Add file extensions
python makewordlistcli.py --name admin --file-extensions "web,config,backup" --output-prefix files_test

# Generates: admin.php, admin.conf, admin.bak, etc.
```

### 8. Entropy-Based Sorting
Sort wordlist by complexity/entropy score:

```bash
# Sort by complexity
python makewordlistcli.py --name test --entropy-sort --output-prefix entropy_test

# Most complex/random words first
```

### 9. Similarity Filtering
Remove similar/duplicate words:

```bash
# Remove similar words (80% similarity threshold)
python makewordlistcli.py --name admin --similarity-filter 0.8 --output-prefix filtered_test
```

### 10. Frequency Analysis
Include detailed frequency analysis in reports:

```bash
# Enable frequency analysis
python makewordlistcli.py --name admin --frequency-analysis --export-md --output-prefix analysis_test

# Generates detailed MD report with character frequencies, patterns, etc.
```

## 🎯 Advanced Mode
Enable ALL advanced features at once:

```bash
# Ultimate wordlist generation
python makewordlistcli.py --name admin --domain target.com --advanced --output-prefix ultimate_test

# Enables: full, mutations, dates, hybrid, keyboard-patterns, password-patterns,
#          frequency-analysis, entropy-sort, similarity-filter, crawl-deep, etc.
```

## 🔧 Tech Stack Enhancements
Extended tech stack support:

```bash
# New tech stacks available
python makewordlistcli.py --tech-stack mobile --output-prefix mobile_test
python makewordlistcli.py --tech-stack media --output-prefix media_test

# mobile: android, ios, app, apk, ipa, react, flutter, cordova
# media: images, photos, videos, media, upload, download, stream, cdn
```

## 📊 Enhanced Profiles
New profile categories:

```bash
# New profiles available
python makewordlistcli.py --profile healthcare --output-prefix health_test
python makewordlistcli.py --profile education --output-prefix edu_test
python makewordlistcli.py --profile finance --output-prefix finance_test

# healthcare: patient, doctor, medical, hospital, clinic, health, pharmacy
# education: student, teacher, course, class, lesson, exam, grade, school
# finance: bank, account, transaction, payment, invoice, credit, debit
```

## 🎨 Custom Pattern Files
Create custom pattern files:

```bash
# Create custom_patterns.txt
echo "{word}_admin" > custom_patterns.txt
echo "admin_{word}" >> custom_patterns.txt
echo "{word}@company.com" >> custom_patterns.txt
echo "backup_{word}_2024" >> custom_patterns.txt

# Use custom patterns
python makewordlistcli.py --name test --custom-patterns custom_patterns.txt --output-prefix custom_test
```

## 📈 Example Advanced Workflows

### 1. Corporate Penetration Testing
```bash
# Comprehensive corporate wordlist
python makewordlistcli.py \
    --company "TechCorp" \
    --domain "techcorp.com" \
    --profile corp \
    --tech-stack web \
    --pattern credential \
    --password-patterns \
    --hybrid \
    --frequency-analysis \
    --entropy-sort \
    --export-md \
    --output-prefix corporate_pentest
```

### 2. Web Application Testing
```bash
# Web app focused wordlist
python makewordlistcli.py \
    --url "https://target.com" \
    --crawl-deep \
    --tech-stack api \
    --pattern endpoint \
    --file-extensions "web,config" \
    --transform-rules "caps,lower,substitute_similar" \
    --similarity-filter 0.7 \
    --output-prefix webapp_test
```

### 3. Subdomain Enumeration
```bash
# Subdomain discovery wordlist
python makewordlistcli.py \
    --domain "target.com" \
    --pattern subdomain \
    --tech-stack cloud \
    --profile devops \
    --osint-target "target" \
    --keyboard-patterns \
    --max-words 10000 \
    --output-prefix subdomain_enum
```

### 4. Password Attack Wordlist
```bash
# Password cracking wordlist
python makewordlistcli.py \
    --name "john" \
    --surname "doe" \
    --birth "1985" \
    --city "newyork" \
    --company "techcorp" \
    --password-patterns \
    --mutations \
    --dates \
    --transform-rules "caps,lower,reverse,duplicate" \
    --entropy-sort \
    --format hashcat \
    --output-prefix password_attack
```

## 📋 Output Formats
Enhanced output with detailed reporting:

- **TXT**: Standard wordlist format
- **JSON**: Structured data with metadata
- **MD**: Comprehensive report with statistics, frequency analysis, and samples

## 🔍 Quality Control Features
- Smart deduplication
- Length filtering (3-50 chars by default)
- Pattern validation
- Similarity-based filtering
- Entropy scoring
- Bad pattern removal (e.g., only numbers, repeated chars)

## ⚡ Performance Optimizations
- Limits on combination generation to prevent memory issues
- Intelligent sampling for large datasets
- Background process handling for external tools
- Timeout protection for network operations
- Memory-efficient processing for large wordlists

## 🛡️ Security Features
- Input validation and sanitization
- Safe temporary file handling
- SSL verification for web requests
- Command injection protection
- Resource limit enforcement

This enhanced version provides enterprise-level wordlist generation capabilities suitable for professional penetration testing and security research.
