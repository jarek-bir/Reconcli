# CSVTKCLI - Advanced CSV Data Analysis for ReconCLI

## 📊 Overview

CSVTKCLI is a powerful CSV data analysis and manipulation module for ReconCLI that integrates with the csvtk tool to provide advanced analytics for reconnaissance data. It offers security-focused analysis, comprehensive reporting, and powerful data filtering capabilities.

## 🚀 Features

- **Comprehensive Analysis**: Full statistical analysis of CSV reconnaissance data
- **Security-Focused Reports**: Automatic categorization of security-relevant findings
- **Advanced Search & Filter**: Regex-powered search with flexible pattern matching
- **Frequency Analysis**: Statistical distribution analysis of data fields
- **Multi-file Operations**: Combine and analyze multiple CSV files
- **Professional Reports**: Generate markdown security reports with risk categorization

## 🔧 Installation & Requirements

### Prerequisites
```bash
# Install csvtk
conda install -c bioconda csvtk
# OR
brew install csvtk
# OR download from: https://github.com/shenwei356/csvtk/releases
```

### Integration Methods

#### Method 1: Through main ReconCLI
```bash
python main.py csvtkcli [command]
```

#### Method 2: Alternative entry point (recommended)
```bash
python reconcli_csvtk.py csvtkcli [command]
```

#### Method 3: Direct module execution
```bash
python csvtkcli.py [command]
python -m csvtkcli [command]
```

## 📋 Commands

### 🔍 analyze
Comprehensive analysis of CSV reconnaissance data
```bash
python reconcli_csvtk.py csvtkcli analyze <file.csv>
python reconcli_csvtk.py csvtkcli analyze tesla_subdomains.csv -o analysis_report.txt
```

### 🛡️ security-report
Generate comprehensive security-focused report
```bash
python reconcli_csvtk.py csvtkcli security-report <file.csv>
python reconcli_csvtk.py csvtkcli security-report tesla_data.csv --target-domain tesla.com
```

**Generated Files:**
- `admin_domains.csv` - Administrative interfaces
- `api_endpoints.csv` - API services
- `dev_environments.csv` - Development/testing environments
- `databases.csv` - Database services
- `auth_services.csv` - Authentication services
- `sensitive_services.csv` - High-risk services
- `security_summary.md` - Executive summary with recommendations

### 🔍 search
Search and filter CSV data with regex support
```bash
python reconcli_csvtk.py csvtkcli search <file.csv> -f <field> -p <pattern> [options]

# Examples:
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "api" -i -r --count
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "admin|auth" -r -i
python reconcli_csvtk.py csvtkcli search data.csv -f tags -p "HIGH_RISK" --output high_risk.csv
```

**Options:**
- `-i, --ignore-case`: Case insensitive search
- `-r, --regex`: Use regular expressions
- `-v, --invert`: Invert match
- `-c, --count`: Count matches only
- `-o, --output`: Save results to file

### 📊 freq
Frequency analysis of specific fields
```bash
python reconcli_csvtk.py csvtkcli freq <file.csv> -f <field> [options]

# Examples:
python reconcli_csvtk.py csvtkcli freq data.csv -f discovery_method
python reconcli_csvtk.py csvtkcli freq data.csv -f country --top 10 --sort-by-count
```

**Options:**
- `-n, --top`: Show top N results
- `--sort-by-count`: Sort by frequency (default: alphabetical)

### 🏷️ categorize
Categorize and analyze CSV data patterns
```bash
python reconcli_csvtk.py csvtkcli categorize <file.csv> [options]

# Examples:
python reconcli_csvtk.py csvtkcli categorize data.csv -f subdomain --security-focus
python reconcli_csvtk.py csvtkcli categorize data.csv -f domain -o categorized.csv
```

**Options:**
- `-f, --field`: Field to categorize
- `--security-focus`: Focus on security-relevant categories
- `-o, --output`: Save categorized data

### 🔗 combine
Combine multiple CSV files for analysis
```bash
python reconcli_csvtk.py csvtkcli combine file1.csv file2.csv file3.csv [options]

# Examples:
python reconcli_csvtk.py csvtkcli combine *.csv --output combined.csv
python reconcli_csvtk.py csvtkcli combine file1.csv file2.csv --key-field domain
```

## 🎯 Usage Examples

### Basic Reconnaissance Workflow
```bash
# 1. Analyze subdomain data
python reconcli_csvtk.py csvtkcli analyze subdomains.csv

# 2. Generate security report
python reconcli_csvtk.py csvtkcli security-report subdomains.csv --target-domain example.com

# 3. Find high-risk services
python reconcli_csvtk.py csvtkcli search subdomains.csv -f subdomain -p "admin|db|auth" -r -i

# 4. Analyze discovery methods
python reconcli_csvtk.py csvtkcli freq subdomains.csv -f discovery_method
```

### Security-Focused Analysis
```bash
# Find administrative interfaces
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "admin|panel|manage" -r -i

# Count API endpoints
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "api|rest|graphql" -r -i --count

# Find development environments
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "dev|test|stage|staging" -r -i

# Generate comprehensive security categorization
python reconcli_csvtk.py csvtkcli categorize data.csv --security-focus
```

### Database Integration
```bash
# Export from database and analyze
python reconcli_csvtk.py dbcli export --table subdomains --analysis

# Analyze exported data
python reconcli_csvtk.py csvtkcli analyze output/exports/subdomains_export.csv

# Create security report from database export
python reconcli_csvtk.py csvtkcli security-report output/exports/subdomains_export.csv
```

## 🛡️ Security Categories

CSVTKCLI automatically categorizes findings into security risk levels:

### 🚨 HIGH RISK
- Administrative interfaces (`admin`, `panel`, `control`, `manage`)
- Database services (`db`, `database`, `mysql`, `postgres`)
- Authentication services (`auth`, `sso`, `login`, `ldap`)

### 🟠 MEDIUM RISK
- API endpoints (`api`, `rest`, `graphql`, `service`)
- Development environments (`dev`, `test`, `stage`, `staging`)
- File services (`ftp`, `files`, `upload`)

### 🔵 LOW RISK
- Standard web services (`www`, `web`, `blog`)
- CDN services (`cdn`, `static`, `assets`)
- Media services (`media`, `img`, `video`)

## 📊 Output Formats

### Security Summary Report
```markdown
# Security Analysis Summary

**Target Domain:** example.com
**Total Records:** 1,250

## Security Risk Categories
- 🚨 **HIGH RISK** - Administrative Interfaces: **15** entries
- 🔴 **HIGH RISK** - Database Services: **8** entries
- 🟠 **MEDIUM RISK** - API Endpoints: **142** entries
- 🟡 **MEDIUM RISK** - Development Environments: **67** entries

## Recommendations
1. 🔍 **Immediate Review**: Focus on HIGH RISK categories first
2. 🛡️ **Security Testing**: Test administrative and database interfaces
3. 🔐 **Access Control**: Verify authentication on sensitive services
```

### CSV Analysis Output
```
📊 COMPREHENSIVE CSV ANALYSIS: subdomains.csv
============================================================

📋 BASIC INFORMATION:
Rows: 1,250
Columns: 4
Headers: subdomain, ip_address, discovery_method, domain

🛡️ SECURITY ANALYSIS:
  Admin interfaces: 15 entries
  API endpoints: 142 entries
  Development envs: 67 entries
  Database services: 8 entries
  Authentication: 23 entries
```

## 🔄 Integration with Other Tools

### Database CLI Integration
```bash
# Export with automatic analysis
python reconcli_csvtk.py dbcli export --table subdomains --analysis

# Export specific data with filters
python reconcli_csvtk.py dbcli export --table subdomains --filter "discovery_method='subdocli'" --analysis
```

### Tagger Integration
```bash
# Generate tagged data with csvtk analysis
python reconcli_csvtk.py taggercli input.csv --output tagged.csv --csvtk-analysis
```

### Report Integration
```bash
# Generate markdown reports with csvtk statistics
python reconcli_csvtk.py mdreportcli input.json --export-csv data.csv --csvtk-analysis
```

## 🚀 Performance Tips

1. **Large Files**: Use `--count` for quick statistics on large datasets
2. **Regex Performance**: Simple patterns are faster than complex regex
3. **Memory Usage**: csvtk efficiently handles large CSV files
4. **Parallel Processing**: Combine multiple files before analysis for better performance

## 🔧 Troubleshooting

### Common Issues

**csvtk not found**
```bash
# Install csvtk
conda install -c bioconda csvtk
# OR
brew install csvtk
```

**Module import errors**
```bash
# Use alternative entry point
python reconcli_csvtk.py csvtkcli [command]
```

**Large file processing**
```bash
# Use streaming for large files
csvtk head -n 1000 large_file.csv | python reconcli_csvtk.py csvtkcli analyze -
```

## 📈 Advanced Usage

### Custom Security Rules
Create custom patterns for specific reconnaissance targets:
```bash
# Corporate environments
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "corp|internal|intranet" -r -i

# Cloud services
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "aws|azure|gcp|cloud" -r -i

# Monitoring systems
python reconcli_csvtk.py csvtkcli search data.csv -f subdomain -p "monitor|grafana|kibana|prometheus" -r -i
```

### Workflow Automation
```bash
#!/bin/bash
# Automated security analysis workflow

# 1. Export from database
python reconcli_csvtk.py dbcli export --table subdomains

# 2. Generate security report
python reconcli_csvtk.py csvtkcli security-report output/exports/subdomains_export.csv

# 3. Find high-risk targets
python reconcli_csvtk.py csvtkcli search output/exports/subdomains_export.csv \
  -f subdomain -p "admin|db|auth" -r -i --output high_risk_targets.csv

# 4. Analyze discovery methods
python reconcli_csvtk.py csvtkcli freq output/exports/subdomains_export.csv -f discovery_method
```

## 🎯 Best Practices

1. **Data Validation**: Always check data quality before analysis
2. **Security Focus**: Use security-report for reconnaissance findings
3. **Pattern Testing**: Test regex patterns on small datasets first
4. **Documentation**: Save analysis commands for reproducibility
5. **Automation**: Integrate csvtkcli into reconnaissance workflows

---

**Author**: ReconCLI Team
**Version**: 1.0
**Last Updated**: July 2025
