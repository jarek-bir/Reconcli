# 🎯 MakeWordListCLI - Advanced Wordlist Generator

## 🚀 NEW Advanced Features (2025)

### 📁 Resume Functionality
- `--resume-from <file>`: Resume interrupted wordlist generation
- Automatic checkpoints for large operations

### 🚀 Word Boost Profiles
- `--word-boost <profile>`: Enhance specific categories (admin, auth, panel, qa, api)
- Specialized patterns and multiplied variations

### 🔗 Wordlist Combination
- `--combine-with <file>`: Merge with existing wordlists
- `--combine-method`: merge, intersect, combine, permute

### 🎲 Markov Chain Generation
- `--markovify <training_file>`: AI-powered word generation
- Train on existing wordlists (rockyou.txt, custom lists)

📖 **See `ADVANCED_FEATURES_GUIDE.md` for detailed documentation**

---

## 🌟 Enhanced Features

### ✨ **Core Features:**
- **🧬 Word Mutations**: Leet speak, variations, and permutations
- **🌐 Deep Web Crawling**: Extract words from multiple pages
- **📅 Date Variations**: Current and custom date formats
- **🏢 Technology Profiles**: Web, API, database, cloud, security wordlists
- **📊 Smart Filtering**: Length, patterns, and quality filtering
- **📈 Detailed Reports**: JSON metadata and Markdown statistics
- **🎲 Multiple Formats**: Support for FFuF, Hydra, Hashcat
- **📋 External Wordlists**: Import and merge existing lists

## 🚀 Usage Examples

### Basic Personal Wordlist
```bash
reconcli makewordlist \
  --name john \
  --surname smith \
  --birth 1985 \
  --company acme \
  --output-prefix john_smith
```

### Corporate Target Analysis
```bash
reconcli makewordlist \
  --company "Acme Corp" \
  --domain acme.com \
  --profile corp \
  --tech-stack web \
  --mutations \
  --output-prefix acme_corp \
  --export-md \
  --verbose
```

### API Endpoint Discovery
```bash
reconcli makewordlist \
  --domain api.target.com \
  --profile devops \
  --tech-stack api \
  --format ffuf \
  --output-prefix api_endpoints \
  --max-words 5000
```

### Deep Website Analysis
```bash
reconcli makewordlist \
  --url https://target.com \
  --crawl-deep \
  --mutations \
  --dates \
  --output-prefix target_deep \
  --min-length 4 \
  --max-length 20
```

### Full Intelligence Mode
```bash
reconcli makewordlist \
  --name admin \
  --company target \
  --domain target.com \
  --url https://target.com \
  --full \
  --profile corp \
  --tech-stack cloud \
  --mutations \
  --dates \
  --output-prefix target_full \
  --export-json \
  --export-md \
  --verbose
```

### Custom Wordlist Merge
```bash
reconcli makewordlist \
  --wordlist /usr/share/wordlists/common.txt \
  --company target \
  --mutations \
  --output-prefix merged_custom \
  --max-words 10000
```

## 📊 Profiles Available

### 🏢 **corp** - Corporate Environment
- intranet, portal, secure, employee, dashboard, files
- hr, finance, accounting, sales, marketing, support

### 🔐 **login** - Authentication Systems
- admin, login, signin, auth, access, account
- user, member, guest, root, administrator

### ⚙️ **devops** - Development Operations
- grafana, jenkins, prometheus, ci, dev, staging
- docker, kubernetes, gitlab, github, bitbucket

### ☁️ **cloud** - Cloud Infrastructure
- s3, bucket, blob, storage, cdn, gcp, azure
- aws, lambda, ec2, rds, vpc, iam

### 🛒 **ecommerce** - E-commerce Systems
- shop, store, cart, checkout, payment, order
- product, catalog, inventory, customer

### 👥 **social** - Social Media Platforms
- user, profile, friend, message, chat, post
- comment, like, share, follow

## 🔧 Technology Stacks

### 🌐 **web** - Web Applications
- index, default, home, main, app, site, web, www

### 🔌 **api** - API Services
- api, rest, graphql, endpoint, service, micro, gateway

### 🗄️ **database** - Database Systems
- db, database, sql, mysql, postgres, mongo, redis

### ☁️ **cloud** - Cloud Services
- aws, azure, gcp, docker, k8s, kubernetes, terraform

### 🔒 **security** - Security Systems
- auth, oauth, jwt, token, key, cert, ssl, tls

## 🎲 Output Formats

### **Default** - Simple wordlist
```
admin
login
password123
```

### **FFuF** - Web fuzzing format
```
FUZZ=admin
FUZZ=login
FUZZ=password123
```

### **Hydra** - Password attacks
```
admin
login
password123
```

### **Hashcat** - Hash cracking
```
admin
login
password123
```

## 📈 Advanced Options

### 🧬 **Mutations**
- **Leet speak**: admin → @dm1n, 4dm1n
- **Number suffixes**: admin123, admin2024
- **Special chars**: admin!, admin$
- **Case variations**: ADMIN, Admin, admin

### 📅 **Date Variations**
- **Current year**: 2025
- **Date formats**: 20250708, 07/08/2025
- **Combined**: admin2025, 2025admin

### 🧹 **Smart Filtering**
- **Length filtering**: 3-50 characters
- **Pattern removal**: Only numbers, repeated chars
- **Quality control**: Remove obvious junk
- **Deduplication**: Unique words only

### 📊 **Statistics & Reports**
- **Sources tracking**: Where each word came from
- **Generation stats**: Raw vs filtered counts
- **Metadata**: Timestamps, parameters used
- **Sample preview**: First 20 words in report

## 🎯 Use Cases

### 🔍 **Directory Brute Forcing**
```bash
reconcli makewordlist --domain target.com --tech-stack web --format ffuf \
  --output-prefix directories --max-words 5000
```

### 🔐 **Password Attacks**
```bash
reconcli makewordlist --name john --surname smith --birth 1985 \
  --mutations --dates --format hydra --output-prefix passwords
```

### 🌐 **Subdomain Discovery**
```bash
reconcli makewordlist --company acme --profile corp --tech-stack cloud \
  --output-prefix subdomains --min-length 3 --max-length 15
```

### 🔌 **API Endpoint Fuzzing**
```bash
reconcli makewordlist --tech-stack api --profile devops \
  --format ffuf --output-prefix api_paths
```

## 💡 Pro Tips

1. **Start Simple**: Begin with basic name/company combinations
2. **Use Profiles**: Match the target organization type
3. **Enable Mutations**: Greatly increases wordlist quality
4. **Set Limits**: Use --max-words to prevent huge files
5. **Export Reports**: Use --export-md for analysis
6. **Combine Sources**: Use --wordlist to merge existing lists
7. **Filter Smart**: Adjust --min-length and --max-length
8. **Go Deep**: Use --crawl-deep for web targets

## 🔧 Integration

Works seamlessly with other ReconCLI modules:
- **DirBCLI**: Use generated wordlists for directory brute forcing
- **VHostCLI**: Custom virtual host discovery lists
- **UrlCLI**: Targeted URL discovery
- **SubdoCLI**: Subdomain enumeration lists

---

**Enhanced by**: Advanced AI Assistant
**Status**: Production Ready 🚀
**Security**: Reviewed ✅
