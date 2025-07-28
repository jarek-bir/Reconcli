# CSP (Content-Security-Policy) Analysis for Subdomain Discovery

## Overview

The CSP analysis feature in SubdoCLI extracts subdomains from Content-Security-Policy headers found on web applications. This technique can reveal internal subdomains, API endpoints, CDN domains, and third-party integrations that might not be discovered through traditional subdomain enumeration methods.

## How It Works

1. **Header Fetching**: The tool fetches CSP headers from target URLs using HTTP/HTTPS requests
2. **Directive Parsing**: Parses CSP directives like `script-src`, `frame-src`, `connect-src`, etc.
3. **Domain Extraction**: Extracts domain names from directive values
4. **Filtering**: Optionally filters out common CDN domains (*.cloudfront.net)
5. **Subdomain Discovery**: Returns domains that are subdomains of the target domain

## Supported CSP Directives

The tool analyzes the following CSP directives for domain extraction:

- `default-src` - Fallback for other directives
- `script-src` - JavaScript sources
- `style-src` - CSS sources  
- `img-src` - Image sources
- `connect-src` - AJAX, WebSocket, EventSource connections
- `font-src` - Font sources
- `object-src` - Plugin sources
- `media-src` - Audio/video sources
- `frame-src` - Frame sources
- `child-src` - Worker and frame sources
- `worker-src` - Worker sources
- `manifest-src` - Web app manifest sources
- `form-action` - Form submission targets
- `frame-ancestors` - Parent frame sources
- `base-uri` - Base URI restrictions

## Usage Examples

### Basic CSP Analysis
```bash
# Add CSP analysis to existing tools
subdocli -d example.com --tools "subfinder,csp_analyzer" --csp-analysis -v

# Use CSP analysis only
subdocli -d example.com --tools "csp_analyzer" --csp-analysis -v
```

### Advanced Options
```bash
# Disable cloudfront filtering to see all CDN domains
subdocli -d example.com --tools "csp_analyzer" --csp-analysis --csp-filter-cloudfront=false -v

# Use custom targets file for CSP analysis
subdocli -d example.com --tools "csp_analyzer" --csp-analysis --csp-targets-file targets.txt -v

# Include CSP with all tools
subdocli -d example.com --all-tools --csp-analysis -v
```

### Creating a CSP Targets File

Create a file (e.g., `csp_targets.txt`) with URLs/subdomains to analyze:

```
# Main domain and common subdomains
example.com
www.example.com
app.example.com
api.example.com
admin.example.com

# Specific URLs with protocols
https://secure.example.com
https://portal.example.com/dashboard

# Known subdomains from previous scans
mail.example.com
cdn.example.com
assets.example.com
```

## CSP Analysis Output

### Console Output
```
[+] 📋 Starting CSP header analysis...
[+] 🎯 Using 25 discovered subdomains as CSP targets
[+] 📋 Found CSP at https://app.example.com: 8 domains
[+] 📋 Found CSP at https://www.example.com: 12 domains
[+] 📋 CSP analysis found 15 subdomains
[+] 📄 Detailed CSP results saved to: output/example.com/csp_analysis.json
```

### CSP Analysis Report (`csp_analysis.json`)
```json
{
  "https://app.example.com": [
    "api.example.com",
    "cdn.example.com",
    "assets.example.com",
    "socket.example.com"
  ],
  "https://www.example.com": [
    "api.example.com",
    "cdn.example.com",
    "images.example.com",
    "scripts.example.com",
    "tracking.example.com"
  ]
}
```

## Filtering Options

### Cloudfront Filtering (Default: Enabled)
```bash
# Filter out *.cloudfront.net domains (default behavior)
--csp-filter-cloudfront

# Include cloudfront domains in results
--csp-filter-cloudfront=false
```

### Example Filtered Domains
- `d1234567890123.cloudfront.net` - Filtered by default
- `assets.cloudfront.net` - Filtered by default
- `cdn.example.com` - Included (not cloudfront)
- `api.example.com` - Included (target subdomain)

## Integration with Other Tools

CSP analysis works seamlessly with other subdomain enumeration tools:

```bash
# Combine with traditional passive tools
subdocli -d example.com --tools "subfinder,amass,csp_analyzer" --csp-analysis

# Use discovered subdomains as CSP targets
subdocli -d example.com --passive-only --csp-analysis

# Full comprehensive scan with CSP
subdocli -d example.com --all-tools --csp-analysis --resolve --probe-http
```

## Common CSP Discoveries

### Internal Infrastructure
- `api-internal.example.com`
- `admin.example.com`
- `staging.example.com`
- `dev.example.com`

### CDN and Assets
- `cdn.example.com`
- `assets.example.com`
- `images.example.com`
- `js.example.com`

### Third-party Integrations
- `analytics.example.com`
- `tracking.example.com`
- `payments.example.com`
- `support.example.com`

### WebSocket Endpoints
- `ws.example.com`
- `socket.example.com`
- `realtime.example.com`

## Benefits of CSP Analysis

1. **Discovers Hidden Subdomains**: Finds subdomains not indexed by search engines
2. **Reveals Architecture**: Shows application architecture and dependencies
3. **Identifies Integrations**: Discovers third-party services and APIs
4. **Finds Internal Resources**: Locates internal domains and staging environments
5. **Real-time Discovery**: Analyzes current CSP policies, not historical data

## Tips for Maximum Coverage

1. **Use After Initial Discovery**: Run CSP analysis after discovering initial subdomains for maximum targets
2. **Check Different Pages**: Different application pages may have different CSP policies
3. **Include Various Subdomains**: Analyze admin panels, API documentation, and user portals
4. **Combine with HTTP Probing**: Use `--probe-http` to ensure CSP targets are accessible
5. **Regular Updates**: CSP policies change as applications evolve

## Troubleshooting

### No CSP Headers Found
- Target may not implement CSP
- CSP may be implemented via meta tags (not supported)
- Network connectivity issues
- SSL certificate problems (use `--ignore-ssl-errors`)

### Limited Results
- Enable verbose mode (`-v`) for detailed output
- Disable cloudfront filtering if using CDNs
- Ensure targets file contains accessible URLs
- Check if subdomains respond to HTTP/HTTPS requests

### Performance Optimization
- Adjust thread count (`--threads`) for faster analysis
- Set appropriate timeout (`--timeout`) for slow targets
- Use caching (`--cache`) to avoid re-analyzing same targets
