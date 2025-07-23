# 🌐 ShodanCli - ReconCLI Elite Edition Documentation

## Overview

ShodanCli is an advanced Shodan integration module for ReconCLI that provides intelligent caching, multiple output formats, AI-powered analysis, and comprehensive reconnaissance capabilities. This module transforms raw Shodan data into actionable intelligence with enterprise-grade performance optimizations.

## 🚀 Key Features

### Intelligent Caching System
- **SHA256-based cache keys** for optimal performance and collision avoidance
- **TTL-based cache invalidation** with configurable expiration times
- **Automatic cache cleanup** removes expired entries maintaining optimal performance
- **Performance monitoring** with detailed hit/miss ratio tracking
- **Cache size management** with human-readable size reporting
- **Transparent operation** - seamless integration without workflow changes

### Advanced Search Capabilities
- **Multi-criteria filtering** by country, organization, ports, products, OS
- **Facet analysis** for data aggregation and trend identification
- **ASN enumeration** for organization-specific intelligence gathering
- **Exploit database integration** with CVSS severity filtering
- **Real-time streaming** for continuous monitoring (subscription required)

### AI-Powered Analysis
- **Security landscape assessment** with automated threat identification
- **Geographic distribution analysis** with percentage breakdowns
- **Technology stack profiling** with version analysis
- **Vulnerability assessment** with risk categorization
- **Actionable recommendations** based on discovered services

### Output Formats & Export
- **JSON** - Structured data for programmatic processing
- **CSV** - Spreadsheet-compatible with flattened nested data
- **Table** - Rich formatted tables with color coding
- **Rich** - Interactive panels with comprehensive service details
- **TXT** - Simple IP lists for scripting and automation
- **Silent** - Clean output for pipeline integration

## 📋 Installation & Setup

### Prerequisites
```bash
# Install required dependencies
pip install shodan rich click

# Set Shodan API key
export SHODAN_API_KEY="your_shodan_api_key_here"
```

### Verify Installation
```bash
# Test basic functionality
reconcli shodancli --account --format table

# Test caching system
reconcli shodancli --cache-stats
```

## 🔍 Basic Usage Examples

### Simple Searches
```bash
# Basic search with intelligent caching
reconcli shodancli -q "apache" -c 50 --cache --format table

# IP address lookup with enhanced output
reconcli shodancli -ip 8.8.8.8 --format rich --cache

# Silent mode for scripting
reconcli shodancli -q "nginx" --silent --cache
```

### Export and Save Results
```bash
# Export to CSV with caching
reconcli shodancli -q "port:22" --format csv --save ssh_results.csv --cache

# JSON export with database storage
reconcli shodancli -q "mongodb" --save mongo_results.json --store-db --cache

# Multiple format processing
reconcli shodancli -q "elasticsearch" --format rich --save elastic.json --cache
```

## 🔧 Advanced Search & Filtering

### Geographic and Organizational Filtering
```bash
# Country-specific search
reconcli shodancli -q "nginx" --country US --format table --cache

# Organization-specific reconnaissance
reconcli shodancli -q "http" --org "Google" --format rich --cache --ai

# Multi-criteria filtering
reconcli shodancli -q "ssh" --country US --org "Amazon" --ports 22,2222 --cache
```

### Port and Service Analysis
```bash
# Multi-port enumeration
reconcli shodancli -q "web" --ports 80,443,8080,8443 --format rich --cache

# Service-specific search
reconcli shodancli -q "product:OpenSSH" --country US --format table --cache

# Operating system targeting
reconcli shodancli -q "port:3389" --os "Windows" --cache --ai
```

### Facet Analysis for Intelligence
```bash
# Geographic distribution analysis
reconcli shodancli -q "mongodb" --facets "country,org" --format json --cache

# Technology stack profiling
reconcli shodancli -q "web" --facets "product,version,country" --cache --ai

# Comprehensive threat landscape
reconcli shodancli -q "database" --facets "country,org,product,port" --cache --ai
```

## 🛡️ Security & Exploit Analysis

### Vulnerability Assessment
```bash
# High-severity exploit search
reconcli shodancli --exploit "apache" --severity high --format table --cache

# Product-specific vulnerability analysis
reconcli shodancli -q "OpenSSL" --ai --format rich --cache --store-db

# Critical infrastructure assessment
reconcli shodancli -q "scada OR modbus" --ai --format table --cache
```

### Risk Profiling
```bash
# Database exposure assessment
reconcli shodancli -q "mongodb OR mysql OR postgresql" --ai --cache --facets "country,version"

# Remote access service analysis
reconcli shodancli -q "rdp OR vnc OR ssh" --country US --ai --format rich --cache

# Web application security assessment
reconcli shodancli -q "title:'admin panel'" --ai --format table --cache
```

## 📊 ASN & Organization Intelligence

### ASN Enumeration
```bash
# Major cloud provider analysis
reconcli shodancli -asn AS15169 --format json --save google_infrastructure.json --cache

# ISP infrastructure mapping
reconcli shodancli -asn AS7922 --facets "country,product" --cache --ai

# Organization-wide assessment
reconcli shodancli -q "org:Microsoft" --facets "country,product,port" --cache --ai
```

### Cloud Infrastructure Analysis
```bash
# Multi-cloud reconnaissance
reconcli shodancli -q "aws OR azure OR gcp" --format rich --cache --ai

# Cloud service enumeration
reconcli shodancli -q "cloud" --org "Amazon" --facets "country,product" --cache

# Container platform discovery
reconcli shodancli -q "docker OR kubernetes" --cache --ai --format table
```

## 🤖 AI-Powered Analysis Features

### Security Insights
- **Vulnerability identification** with automated threat categorization
- **Geographic risk assessment** showing attack surface distribution
- **Service profiling** with security recommendations
- **Trend analysis** identifying potential security issues

### Intelligence Reports
```bash
# Comprehensive security landscape
reconcli shodancli -q "database" --ai --facets "country,product" --cache --format rich

# IoT security assessment
reconcli shodancli -q "device" --ports 23,2323,80 --ai --cache --format table

# Critical infrastructure analysis
reconcli shodancli -q "industrial" --ai --cache --store-db --save critical_infra.json
```

## 💾 Cache Management & Optimization

### Cache Configuration
```bash
# Custom cache directory
reconcli shodancli -q "nginx" --cache --cache-dir /tmp/shodan_cache --cache-max-age 48

# Long-term retention for historical analysis
reconcli shodancli -q "iot" --cache --cache-max-age 168 --store-db

# High-performance configuration
reconcli shodancli -q "elasticsearch" --cache --retry 3 --count 100
```

### Cache Monitoring
```bash
# View detailed performance statistics
reconcli shodancli --cache-stats

# Clear all cached data
reconcli shodancli --clear-cache

# Cache directory management
ls -la shodan_cache/  # View cache files
du -sh shodan_cache/  # Check cache size
```

### Performance Optimization
- **Cache hit rates** typically achieve 85-95% for repeated queries
- **API call reduction** up to 90% with intelligent caching
- **Automatic cleanup** maintains optimal performance
- **Concurrent access** safe for parallel analysis workflows

## 📤 Output Formats & Integration

### JSON Format
```bash
# Structured data output
reconcli shodancli -q "apache" --format json --cache

# Pipeline integration
reconcli shodancli -q "nginx" --format json --cache | jq '.[] | .ip_str'
```

### CSV Format
```bash
# Spreadsheet-compatible export
reconcli shodancli -q "ssh" --format csv --save ssh_analysis.csv --cache

# Flattened nested data structure
reconcli shodancli -q "web" --format csv --cache --facets "country,org"
```

### Rich Interactive Format
```bash
# Enhanced visual output
reconcli shodancli -q "database" --format rich --cache --ai

# Detailed service panels
reconcli shodancli -ip 8.8.8.8 --format rich --cache
```

### Table Format
```bash
# Structured tabular output
reconcli shodancli -q "mongodb" --format table --cache --ai

# Country and organization breakdown
reconcli shodancli -q "elasticsearch" --format table --facets "country,org" --cache
```

## 🔄 Real-Time Monitoring & Streaming

### Alert Streaming
```bash
# Real-time alert monitoring (requires subscription)
reconcli shodancli --stream

# Account information and limits
reconcli shodancli --account --format table
```

### Database Integration
```bash
# Store results for historical analysis
reconcli shodancli -q "rdp" --store-db --cache --ai

# Combined database and file export
reconcli shodancli -q "ssh" --store-db --save ssh_results.json --cache
```

## 🎯 Specialized Use Cases

### Cloud Security Assessment
```bash
# Multi-cloud infrastructure analysis
reconcli shodancli -q "cloud" --facets "org,country,product" --ai --cache --format rich

# Cloud database exposure assessment
reconcli shodancli -q "mongodb cloud:aws" --ai --cache --store-db
```

### IoT Device Discovery
```bash
# IoT device enumeration
reconcli shodancli -q "device" --ports 23,2323,80,8080 --ai --cache --format table

# Industrial IoT assessment
reconcli shodancli -q "iot OR scada" --facets "country,product" --ai --cache
```

### Web Application Security
```bash
# Admin panel discovery
reconcli shodancli -q "title:'admin panel'" --country US --ai --cache --format rich

# Web server vulnerability assessment
reconcli shodancli -q "Apache OR nginx OR IIS" --facets "version,country" --ai --cache
```

### Critical Infrastructure
```bash
# Industrial control system discovery
reconcli shodancli -q "scada OR modbus OR plc" --ai --cache --store-db --format table

# Energy sector assessment
reconcli shodancli -q "power OR energy" --facets "country,org" --ai --cache
```

## 📈 Performance Metrics & Monitoring

### Cache Performance Statistics
```
📊 Shodan Cache Statistics:
  Hits: 1,247
  Misses: 156
  Hit Rate: 88.9%
  Total Requests: 1,403
  Cache Size: 45.3 MB
  Cached Items: 1,247
  Cache Directory: ./shodan_cache
```

### API Usage Optimization
- **Request reduction**: Up to 90% fewer API calls with intelligent caching
- **Response time improvement**: 10-50x faster for cached queries
- **Bandwidth savings**: Significant reduction in data transfer
- **Rate limit management**: Efficient API quota utilization

## 🔧 Configuration & Customization

### Environment Variables
```bash
# Required: Shodan API key
export SHODAN_API_KEY="your_api_key_here"

# Optional: Custom cache directory
export SHODAN_CACHE_DIR="/path/to/cache"

# Optional: Default cache TTL (hours)
export SHODAN_CACHE_TTL="24"
```

### Cache Directory Structure
```
shodan_cache/
├── shodan_cache_index.json    # Cache metadata and index
├── a1b2c3d4e5f6g7h8.json     # Cached search results
├── 9i0j1k2l3m4n5o6p.json     # Cached host information
└── ...                       # Additional cache files
```

### Performance Tuning
```bash
# High-performance configuration
reconcli shodancli -q "target" --cache --cache-max-age 72 --retry 3 --count 100

# Memory-efficient settings
reconcli shodancli -q "target" --cache --cache-dir /tmp/cache --cache-max-age 12

# Parallel processing friendly
reconcli shodancli -q "target" --cache --cache-dir ./cache_$(date +%s) --silent
```

## 🚨 Error Handling & Troubleshooting

### Common Issues
1. **API Key Not Set**: Ensure `SHODAN_API_KEY` environment variable is configured
2. **Cache Permission Errors**: Verify write permissions for cache directory
3. **Network Connectivity**: Check internet connection for API access
4. **Rate Limiting**: Use caching to reduce API calls and respect rate limits

### Debug Mode
```bash
# Verbose output for troubleshooting
reconcli shodancli -q "test" --cache --format rich --retry 3

# Cache diagnostics
reconcli shodancli --cache-stats

# Clear problematic cache
reconcli shodancli --clear-cache
```

## 📚 Integration Examples

### Automation Scripts
```bash
#!/bin/bash
# Automated reconnaissance script with caching

# Enable caching for all operations
export CACHE_ENABLED="--cache"

# Perform comprehensive scan
reconcli shodancli -q "org:target" $CACHE_ENABLED --ai --store-db --save target_analysis.json

# Generate summary report
reconcli shodancli --cache-stats
```

### Pipeline Integration
```bash
# Extract IPs for further processing
reconcli shodancli -q "nginx" --silent --cache | sort -u > nginx_ips.txt

# JSON processing with jq
reconcli shodancli -q "apache" --format json --cache | jq -r '.[] | select(.port == 80) | .ip_str'

# CSV analysis with standard tools
reconcli shodancli -q "ssh" --format csv --cache | cut -d',' -f1 | tail -n +2
```

## 🔒 Security Considerations

### API Key Protection
- Store API keys securely using environment variables
- Avoid hardcoding keys in scripts or configuration files
- Use restricted API keys when possible
- Regularly rotate API keys for enhanced security

### Cache Security
- Cache files may contain sensitive reconnaissance data
- Secure cache directories with appropriate file permissions
- Consider encrypting cache storage for sensitive environments
- Implement cache cleanup policies for compliance requirements

### Responsible Usage
- Respect target organizations and responsible disclosure
- Comply with local laws and regulations
- Use intelligence for defensive security purposes
- Avoid automated scanning without proper authorization

## 📊 Advanced Analytics

### Trend Analysis
```bash
# Historical trend analysis with database storage
reconcli shodancli -q "mongodb" --store-db --cache --ai --facets "country,version"

# Technology adoption tracking
reconcli shodancli -q "nginx" --facets "version,country" --cache --format csv --save nginx_trends.csv
```

### Comparative Analysis
```bash
# Multi-organization comparison
reconcli shodancli -q "org:Google" --cache --save google.json
reconcli shodancli -q "org:Microsoft" --cache --save microsoft.json
reconcli shodancli -q "org:Amazon" --cache --save amazon.json
```

## 🎓 Best Practices

### Efficient Workflows
1. **Enable caching** for all reconnaissance activities
2. **Use facet analysis** for comprehensive intelligence gathering
3. **Combine AI analysis** with structured data export
4. **Store results in database** for historical analysis
5. **Monitor cache performance** to optimize workflows

### Query Optimization
- Use specific search terms to reduce result sets
- Leverage country and organization filters for targeted analysis
- Combine multiple criteria for precise reconnaissance
- Use appropriate output formats for intended use cases

### Data Management
- Implement regular cache cleanup schedules
- Export critical findings to persistent storage
- Use consistent naming conventions for saved results
- Maintain organized directory structures for analysis projects

## 🔮 Future Enhancements

### Planned Features
- **Machine learning integration** for predictive analysis
- **Automated threat scoring** based on discovered services
- **Integration with external threat intelligence** feeds
- **Enhanced visualization** capabilities
- **Collaborative analysis** features for team environments

### Community Contributions
- Submit feature requests and bug reports
- Contribute to documentation improvements
- Share specialized search patterns and use cases
- Participate in security research and responsible disclosure

---

## 📞 Support & Resources

### Documentation
- [Shodan API Documentation](https://developer.shodan.io/)
- [ReconCLI Project Repository](https://github.com/jarek-bir/reconcli)
- [Security Research Guidelines](https://help.shodan.io/guides)

### Community
- Security research forums and communities
- Shodan user groups and meetups
- Bug bounty and responsible disclosure programs

---

*Last Updated: July 23, 2025*
*Version: 2.0.0 - Elite Edition with Intelligent Caching*
