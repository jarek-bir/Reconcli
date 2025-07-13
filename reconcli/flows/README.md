# URL Discovery Flow Configurations

This directory contains YAML configuration files for different URL discovery scenarios with urlcli.

## Available Flows

### Quick Scans
- **url_quick.yaml** - Fast testing (5 min timeout)
  - Only wayback + sitemap
  - Minimal output
  - Good for quick validation

- **url_katana_fast.yaml** - Fast Katana scan (15 min timeout)
  - Multiple tools with shallow crawling
  - High concurrency, tagged URLs only
  - Quick initial reconnaissance

### Standard Scans
- **url_passive.yaml** - Passive discovery (30 min timeout)
  - wayback + gau
  - No active crawling
  - Good for stealth recon

- **url_debug.yaml** - Debug/testing (15 min timeout)
  - Single tool testing
  - Good for troubleshooting

### Advanced Katana Scans
- **url_katana_advanced.yaml** - Comprehensive Katana (40 min timeout)
  - JavaScript crawling, headless mode
  - Form filling, technology detection
  - Depth 5, enhanced analysis

- **url_katana_headless.yaml** - Headless browser focus (60 min timeout)
  - Headless browsing for JS-heavy apps
  - Automatic form filling
  - SPA and modern web app discovery

### Aggressive Scans
- **url_aggressive.yaml** - Full toolkit (40 min timeout)
  - All tools enabled
  - JS scanning included
  - Comprehensive discovery

- **url_aggressiveV2.yaml** - Alternative config (45 min timeout)
  - Different tool flags
  - Extended parameters

### Deep Scans
- **url_deep.yaml** - Comprehensive discovery (60 min timeout)
  - Maximum depth crawling
  - All providers enabled
  - Extended tool parameters

## New Katana Features

The enhanced urlcli now supports advanced Katana options:

### CLI Options
- `--katana-depth` - Crawl depth (default: 3)
- `--katana-js-crawl` - Enable JavaScript endpoint parsing
- `--katana-headless` - Use headless browser mode
- `--katana-form-fill` - Automatic form filling
- `--katana-tech-detect` - Technology detection
- `--katana-scope` - Custom scope regex
- `--katana-concurrency` - Concurrency level (default: 10)
- `--katana-rate-limit` - Rate limit per second (default: 150)

### Flow Configuration
All Katana options can be configured in YAML flows:

```yaml
katana: true
katana_depth: 5
katana_js_crawl: true
katana_headless: true
katana_form_fill: true
katana_tech_detect: true
katana_scope: ".*\\.target\\.com.*"
katana_concurrency: 15
katana_rate_limit: 200
```

## Usage Examples

```bash
# Quick 5-minute scan
python main.py urlcli --input domains.txt --flow flows/url_quick.yaml

# Fast Katana scan (15 min)
python main.py urlcli --input domains.txt --flow flows/url_katana_fast.yaml

# Advanced Katana with all features (40 min)
python main.py urlcli --input domains.txt --flow flows/url_katana_advanced.yaml

# Headless browser for JS apps (60 min)
python main.py urlcli --input domains.txt --flow flows/url_katana_headless.yaml

# Standard passive scan (30 min)
python main.py urlcli --input domains.txt --flow flows/url_passive.yaml

# Manual Katana options
python main.py urlcli --input domains.txt --katana --katana-depth 5 --katana-js-crawl --katana-headless

# Full aggressive scan (40 min)
python main.py urlcli --input domains.txt --flow flows/url_aggressive.yaml

# Deep comprehensive scan (60 min)
python main.py urlcli --input domains.txt --flow flows/url_deep.yaml

# Override timeout manually
python main.py urlcli --input domains.txt --timeout 7200  # 2 hours
```

## Timeout Reference

| Flow | Timeout | Tools | Use Case |
|------|---------|-------|----------|
| url_quick | 5 min | wayback, sitemap | Quick validation |
| url_debug | 15 min | wayback, favicon | Testing/debug |
| url_passive | 30 min | wayback, gau | Passive recon |
| url_aggressive | 40 min | All tools | Full discovery |
| url_aggressiveV2 | 45 min | All tools + flags | Alternative config |
| url_deep | 60 min | All tools + max params | Deep reconnaissance |

## Custom Patterns

- **custom_patterns.yaml** - Custom URL categorization patterns for urlsorter.py
  - Used with: `python urlsorter.py sort -p flows/custom_patterns.yaml`

## Notes

- Default CLI timeout is now 30 minutes (1800s)
- Flow files can override the default timeout
- Individual tools respect the timeout setting
- Use longer timeouts for large targets or comprehensive scans
- Consider using shorter timeouts for testing or quick validation
