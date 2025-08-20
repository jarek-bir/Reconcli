#!/usr/bin/env python3
import re
import sys
import json
import click
import mimetypes
import requests
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color codes removal
ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")


def clean_ansi_codes(text):
    """Remove ANSI color codes and escape sequences from text."""
    if not text:
        return text
    # Remove ANSI escape sequences
    text = ANSI_REGEX.sub("", text)
    # Remove specific patterns like [36m, [0m, [35m
    text = re.sub(r"\[[\d;]*m", "", text)
    return text


# Enhanced regex patterns for better extraction
URL_REGEX = re.compile(r"https?://[^\s\"'<>\[\](){}]+")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
FORM_REGEX = re.compile(r"<form[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
INPUT_REGEX = re.compile(r"<input[^>]*>", re.IGNORECASE)
AUTH_REGEX = re.compile(
    r"/(auth|login|signin|jwt|token|oauth|sso|saml)[^\"'\s<>]*", re.IGNORECASE
)
API_REGEX = re.compile(r"/(api|v1|v2|v3|rest|graphql)[^\"'\s<>]*", re.IGNORECASE)
SWAGGER_REGEX = re.compile(r"/(swagger|openapi|docs|redoc)[^\"'\s<>]*", re.IGNORECASE)

# Enhanced patterns for API documentation - more precise matching
# Enhanced GraphQL patterns - includes common variations and typos
GRAPHQL_REGEX = re.compile(
    r"\b(graphql|grahql|grafql|graphq|takgraphql|graphiql|graphql.*(?:playground|explorer|interface|endpoint|api|ui|ide))\b",
    re.IGNORECASE,
)
GRAPHQL_FULL_REGEX = re.compile(
    r"\b(GraphQL|GrahQL|GrafQL|GraphQ|takGraphQL|GraphiQL)\s+(playground|explorer|interface|endpoint|API|UI|IDE)\b",
    re.IGNORECASE,
)
API_DOCS_REGEX = re.compile(
    r"\b(Swagger\s+UI|OpenAPI|API\s+Docs|LiteLLM\s+API|uCrawler\s+Agent\s+API\s+Docs)\b",
    re.IGNORECASE,
)
API_TITLE_REGEX = re.compile(
    r"https?://[^\s]+\s+\[([^\]]+(?:API|OpenAPI|Swagger|GraphQL|GrahQL|GraphiQL)[^\]]*)\]",
    re.IGNORECASE,
)  # API-related titles only
TECH_STACK_REGEX = re.compile(
    r"\[([^\]]+,\s*[^\]]+[^\]]*)\]", re.IGNORECASE
)  # Brackets with comma-separated tech stack

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
SUBDOMAIN_REGEX = lambda domain: re.compile(
    rf"\b((?:[\w-]+\.)+{re.escape(domain)})\b", re.IGNORECASE
)
SECRET_REGEX = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|pwd)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=_-]+)"
)
JS_VAR_REGEX = re.compile(r"(?:var|let|const)\s+(\w+)\s*=\s*[\"']([^\"']+)[\"']")
COMMENT_REGEX = re.compile(r"<!--.*?-->|//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
AWS_KEY_REGEX = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_TOKEN_REGEX = re.compile(r"gh[ps]_[A-Za-z0-9]{36}")
SLACK_TOKEN_REGEX = re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")
JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")

# Additional secret patterns
DISCORD_TOKEN_REGEX = re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}")
TELEGRAM_BOT_REGEX = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")
STRIPE_KEY_REGEX = re.compile(r"sk_live_[0-9a-zA-Z]{24}")
PAYPAL_CLIENT_REGEX = re.compile(r"A[0-9A-Za-z_-]{79}")
MAILGUN_KEY_REGEX = re.compile(r"key-[0-9a-z]{32}")
TWILIO_SID_REGEX = re.compile(r"AC[a-z0-9]{32}")
SENDGRID_KEY_REGEX = re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}")
OPENAI_KEY_REGEX = re.compile(r"sk-[a-zA-Z0-9]{48}")
ANTHROPIC_KEY_REGEX = re.compile(r"sk-ant-[a-zA-Z0-9-]{95,}")
GOOGLE_API_KEY_REGEX = re.compile(r"AIza[0-9A-Za-z-_]{35}")
AZURE_KEY_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
DOCKER_TOKEN_REGEX = re.compile(r"dckr_pat_[a-zA-Z0-9_-]{36}")
HEROKU_API_KEY_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
CLOUDFLARE_TOKEN_REGEX = re.compile(r"[a-zA-Z0-9_-]{40}")
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----")
SSH_KEY_REGEX = re.compile(r"ssh-rsa [A-Za-z0-9+/]+[=]{0,3}")
DATABASE_URL_REGEX = re.compile(r"(?:postgres|mysql|mongodb)://[^\s\"'<>]+")
CONNECTION_STRING_REGEX = re.compile(
    r"(?:Server|Data Source|mongodb|redis)=[^\s;\"'<>]+"
)
ENV_VAR_REGEX = re.compile(r"[A-Z_]+=[a-zA-Z0-9+/=_-]{20,}")
# Mobile and Social Media patterns
PHONE_REGEX = re.compile(r"(\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})")
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)
SOCIAL_SECURITY_REGEX = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
TWITTER_HANDLE_REGEX = re.compile(r"@[A-Za-z0-9_]{1,15}")
INSTAGRAM_HANDLE_REGEX = re.compile(r"instagram\.com/([A-Za-z0-9_.]+)")
YOUTUBE_CHANNEL_REGEX = re.compile(
    r"youtube\.com/(?:c/|channel/|user/)([A-Za-z0-9_-]+)"
)
LINKEDIN_PROFILE_REGEX = re.compile(r"linkedin\.com/in/([A-Za-z0-9_-]+)")
FACEBOOK_PROFILE_REGEX = re.compile(r"facebook\.com/([A-Za-z0-9_.]+)")
DISCORD_INVITE_REGEX = re.compile(r"discord\.gg/[A-Za-z0-9]+")
TELEGRAM_CHANNEL_REGEX = re.compile(r"t\.me/([A-Za-z0-9_]+)")

# Crypto and Blockchain patterns
BITCOIN_ADDRESS_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
ETHEREUM_ADDRESS_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
MONERO_ADDRESS_REGEX = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
CRYPTO_WALLET_REGEX = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"
)

# API and configuration patterns
API_ENDPOINT_SECRET_REGEX = re.compile(
    r"(?:secret|key|token|password|pwd|api_key)[\"\']?\s*:\s*[\"\']([a-zA-Z0-9+/=_-]{10,})[\"\']?"
)


@click.command(name="extractorcli")
@click.argument("input", type=click.Path(exists=True), required=False)
@click.option(
    "--input-file",
    "-i",
    type=click.Path(exists=True),
    help="Input file path (alternative to positional argument)",
)
@click.option(
    "--input-url",
    "-u",
    help="Single URL to process directly",
)
@click.option(
    "--input-list",
    "-l",
    type=click.Path(exists=True),
    help="File containing list of URLs to process",
)
@click.option(
    "--types",
    "-t",
    default="url,email,form,auth,api,swagger,graphql,api_docs,tech_stack,ip,domain,subdomain,secret,js,comment",
    help="Types to extract: url,email,form,auth,api,swagger,graphql,api_docs,tech_stack,ip,domain,subdomain,secret,js,comment,hash,base64,phone,crypto,social,pii",
)
@click.option("--target-domain", "-d", help="Domain for subdomain extraction")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--output-dir", type=click.Path(), help="Output directory for multiple files"
)
@click.option(
    "--output-dir", type=click.Path(), help="Output directory for multiple files"
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON format")
@click.option(
    "--to-jsonl", is_flag=True, help="Export each entry as JSONL (JSON Lines)"
)
@click.option("--tagged", is_flag=True, help="Tag results by category with metadata")
@click.option("--csv", is_flag=True, help="Output results as CSV format")
@click.option("--xml", is_flag=True, help="Output results as XML format")
@click.option("--ai-score", is_flag=True, help="Score results based on AI heuristics")
@click.option(
    "--score-threshold", default=0, type=int, help="Minimum score threshold for results"
)
@click.option("--limit", "-n", type=int, help="Limit number of results per category")
@click.option(
    "--smart-detect", is_flag=True, help="Auto-detect file type for better extraction"
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--file-patterns", help="File patterns to match (e.g., '*.html,*.js')")
@click.option(
    "--exclude-patterns", help="File patterns to exclude (e.g., '*.min.js,*.gz')"
)
@click.option(
    "--fetch-urls",
    "-f",
    is_flag=True,
    help="Fetch content from URLs and extract from them",
)
@click.option(
    "--fetch-depth", default=1, type=int, help="Depth level for recursive URL fetching"
)
@click.option(
    "--threads",
    default=10,
    type=int,
    help="Number of threads for concurrent URL fetching",
)
@click.option(
    "--timeout", default=10, type=int, help="Timeout for URL requests (seconds)"
)
@click.option(
    "--retry-count", default=3, type=int, help="Number of retries for failed requests"
)
@click.option(
    "--retry-delay", default=1, type=int, help="Delay between retries (seconds)"
)
@click.option(
    "--user-agent",
    default="ExtractorCLI/2.0 (+https://github.com/reconcli)",
    help="Custom User-Agent for HTTP requests",
)
@click.option(
    "--follow-redirects", is_flag=True, help="Follow HTTP redirects automatically"
)
@click.option(
    "--max-redirects", default=5, type=int, help="Maximum number of redirects to follow"
)
@click.option(
    "--include-comments", is_flag=True, help="Include HTML/JS comments in extraction"
)
@click.option(
    "--deep-js",
    is_flag=True,
    help="Deep JavaScript analysis for variables and functions",
)
@click.option(
    "--extract-inline", is_flag=True, help="Extract inline JavaScript and CSS"
)
@click.option(
    "--extract-base64", is_flag=True, help="Decode and analyze base64 content"
)
@click.option(
    "--verify-ssl", is_flag=True, default=True, help="Verify SSL certificates"
)
@click.option(
    "--insecure", is_flag=True, help="Disable SSL verification (security risk)"
)
@click.option("--proxy", help="HTTP proxy (e.g., http://proxy:8080)")
@click.option("--headers", help="Custom headers as JSON string")
@click.option("--cookies", help="Custom cookies as string")
@click.option(
    "--max-size", default=5, type=int, help="Maximum file size to download (MB)"
)
@click.option(
    "--min-length", default=1, type=int, help="Minimum length for extracted items"
)
@click.option(
    "--max-length", default=2048, type=int, help="Maximum length for extracted items"
)
@click.option("--encoding", default="utf-8", help="File encoding for text processing")
@click.option(
    "--verbose", "-v", is_flag=True, help="Verbose output with detailed information"
)
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode - minimal output")
@click.option("--debug", is_flag=True, help="Debug mode with extra information")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--dedup", is_flag=True, help="Remove duplicates from results")
@click.option(
    "--merge-with",
    type=click.Path(exists=True),
    help="Merge with existing file and deduplicate",
)
@click.option(
    "--dedup-by", default="url", help="Deduplicate by type: url,domain,email,all"
)
@click.option(
    "--dedup-strategy", default="first", help="Dedup strategy: first,last,merge"
)
@click.option("--sort-results", is_flag=True, help="Sort results alphabetically")
@click.option("--sort-by", default="value", help="Sort by: value,length,score")
@click.option(
    "--unique-only",
    is_flag=True,
    help="Only show unique results (removes all seen before)",
)
@click.option("--filter-regex", help="Filter results with regex pattern")
@click.option("--exclude-regex", help="Exclude results matching regex pattern")
@click.option("--whitelist-domains", help="Comma-separated list of allowed domains")
@click.option("--blacklist-domains", help="Comma-separated list of blocked domains")
@click.option("--xss-scan", is_flag=True, help="Run XSS-Vibes scan on extracted URLs")
@click.option("--xss-discover", is_flag=True, help="Use XSS-Vibes endpoint discovery")
@click.option("--xss-threads", default=5, type=int, help="Threads for XSS scanning")
@click.option("--xss-timeout", default=5, type=int, help="Timeout for XSS requests")
@click.option(
    "--xss-depth", default=2, type=int, help="Depth for XSS endpoint discovery"
)
@click.option("--xss-payloads", help="Custom XSS payloads file")
@click.option("--report", is_flag=True, help="Generate comprehensive report")
@click.option("--report-format", default="html", help="Report format: html,pdf,txt")
@click.option("--store-db", is_flag=True, help="Store results in SQLite database")
@click.option("--db-path", default="extractorcli_results.db", help="Database file path")
@click.option("--config", type=click.Path(), help="Configuration file path")
@click.option(
    "--save-config", type=click.Path(), help="Save current options to config file"
)
@click.option("--stats", is_flag=True, help="Show processing statistics")
@click.option("--benchmark", is_flag=True, help="Enable benchmark mode with timing")
@click.option(
    "--custom-patterns",
    type=click.Path(exists=True),
    help="JSON file with custom regex patterns",
)
@click.option(
    "--export-patterns", type=click.Path(), help="Export built-in patterns to JSON file"
)
@click.option("--live-mode", is_flag=True, help="Live monitoring mode for file changes")
@click.option(
    "--watch-dir", type=click.Path(), help="Directory to watch for changes in live mode"
)
@click.option(
    "--scan-cloud", is_flag=True, help="Scan cloud storage URLs (S3, Azure, GCP)"
)
@click.option(
    "--sensitivity",
    default="medium",
    help="Detection sensitivity: low,medium,high,paranoid",
)
def extractor(
    input,
    input_file,
    input_url,
    input_list,
    types,
    target_domain,
    output,
    output_dir,
    json_out,
    to_jsonl,
    tagged,
    csv,
    xml,
    ai_score,
    score_threshold,
    limit,
    smart_detect,
    recursive,
    file_patterns,
    exclude_patterns,
    fetch_urls,
    fetch_depth,
    threads,
    timeout,
    retry_count,
    retry_delay,
    user_agent,
    follow_redirects,
    max_redirects,
    include_comments,
    deep_js,
    extract_inline,
    extract_base64,
    verify_ssl,
    insecure,
    proxy,
    headers,
    cookies,
    max_size,
    min_length,
    max_length,
    encoding,
    verbose,
    quiet,
    debug,
    no_color,
    dedup,
    merge_with,
    dedup_by,
    dedup_strategy,
    sort_results,
    sort_by,
    unique_only,
    filter_regex,
    exclude_regex,
    whitelist_domains,
    blacklist_domains,
    xss_scan,
    xss_discover,
    xss_threads,
    xss_timeout,
    xss_depth,
    xss_payloads,
    report,
    report_format,
    store_db,
    db_path,
    config,
    save_config,
    stats,
    benchmark,
    custom_patterns,
    export_patterns,
    live_mode,
    watch_dir,
    scan_cloud,
    sensitivity,
):
    """
    🧲 ExtractorCLI v2.0 - Advanced Data Extraction & Security Analysis Tool

    Extract URLs, emails, forms, authentication endpoints, API endpoints, secrets,
    cryptocurrency addresses, social media profiles, phone numbers, PII data and more
    from files, directories, or URLs. Includes XSS-Vibes integration for vulnerability
    scanning and advanced AI-powered result analysis.

    BASIC USAGE:
      reconcli extractorcli file.html                           # Extract from file
      reconcli extractorcli --input-file data.txt              # Alternative input syntax
      reconcli extractorcli --input-url https://example.com    # Process single URL
      reconcli extractorcli --input-list urls.txt              # Process URL list

    EXTRACTION TYPES (Enhanced Categories):
      --types url,email,api,secret,subdomain          # Basic web data extraction
      --types crypto,phone,social,pii                 # Personal & financial data
      --types api_docs,tech_stack                     # Technical documentation
      --types auth,swagger,form                       # Security-focused extraction
      --target-domain example.com                     # Target for subdomain extraction

    NEW CATEGORIES:
      crypto     - Bitcoin, Ethereum, Monero addresses and crypto wallets
      phone      - Phone numbers in various formats
      social     - Twitter, Instagram, YouTube, LinkedIn, Discord, Telegram
      pii        - Credit cards, SSN and other personally identifiable info
      graphql    - GraphQL endpoints, playgrounds, schemas, and introspection
      api_docs   - API documentation titles and interfaces
      tech_stack - Technology stacks from comma-separated lists

    ENHANCED SECRET DETECTION:
      secret     - AWS keys, GitHub tokens, OpenAI keys, Stripe keys, Discord tokens,
                   Telegram bots, PayPal clients, Mailgun keys, Twilio SIDs,
                   SendGrid keys, Anthropic keys, Google API keys, Azure keys,
                   Docker tokens, Heroku keys, Cloudflare tokens, private keys,
                   SSH keys, database URLs, connection strings, environment vars

    OUTPUT FORMATS:
      --json --output results.json                    # Structured JSON output
      --tagged --ai-score                             # Categorized with AI scoring
      --csv --output results.csv                      # CSV format for analysis
      --to-jsonl --output results.jsonl               # JSON Lines format

    ADVANCED FEATURES:
      --fetch-urls --deep-js --dedup                  # Fetch URLs, analyze JS, deduplicate
      --recursive --smart-detect                      # Recursive dir scan with auto-detection
      --merge-with old.txt --dedup-by url             # Merge with existing data
      --custom-patterns patterns.json                 # Load custom regex patterns
      --export-patterns patterns.json                 # Export built-in patterns
      --live-mode --watch-dir /path/to/monitor        # Live file monitoring mode
      --scan-cloud                                     # Scan cloud storage URLs

    XSS INTEGRATION:
      --xss-discover --target-domain example.com      # Discover XSS endpoints
      --xss-scan --xss-threads 10                     # Scan URLs for XSS vulnerabilities

    SECURITY FEATURES:
      --types secret,auth,api --ai-score              # Focus on security-relevant data
      --filter-regex "admin|api" --score-threshold 5  # Filter high-value results
      --sensitivity paranoid                          # Detection sensitivity: low,medium,high,paranoid

    REAL-WORLD EXAMPLES:

      # Extract API documentation and tech stacks from Swagger file
      reconcli extractorcli swagger_endpoints.txt --types "api_docs,tech_stack" --verbose

      # Find all secrets in a directory with high sensitivity
      reconcli extractorcli /path/to/code --recursive --types secret --sensitivity paranoid

      # Extract cryptocurrency addresses and social media from text
      reconcli extractorcli data.txt --types "crypto,social,phone" --json --output findings.json

      # Live monitoring for sensitive data in logs
      reconcli extractorcli --live-mode --watch-dir /var/log --types "secret,pii" --tagged

      # Pipeline processing with XSS scanning
      cat urls.txt | reconcli extractorcli --fetch-urls --types api --xss-scan --verbose

      # Comprehensive security scan with AI scoring
      reconcli extractorcli target.com --types "secret,auth,api,crypto,pii" --ai-score --tagged

      # Extract and merge with existing data
      reconcli extractorcli new_data.txt --merge-with old_findings.json --dedup --output merged.json

    PIPELINE USAGE:
      echo "https://example.com" | reconcli extractorcli --fetch-urls --types api
      cat urls.txt | reconcli extractorcli --xss-scan --verbose
      find . -name "*.js" | xargs reconcli extractorcli --types secret --json

    For comprehensive documentation: see EXTRACTORCLI_DOCUMENTATION.md
    """
    # Configure output verbosity
    if quiet:
        verbose = False
    elif debug:
        verbose = True

    # Handle input sources - priority: input_url > input_list > input_file > positional input
    input_source = None
    if input_url:
        input_source = ("url", input_url)
        if verbose:
            click.echo(f"🌐 [INPUT] Processing single URL: {input_url}")
    elif input_list:
        input_source = ("list", input_list)
        if verbose:
            click.echo(f"📄 [INPUT] Processing URL list: {input_list}")
    elif input_file:
        input_source = ("file", input_file)
        if verbose:
            click.echo(f"📁 [INPUT] Processing file: {input_file}")
    elif input:
        input_source = ("file", input)
        if verbose:
            click.echo(f"📁 [INPUT] Processing positional input: {input}")
    else:
        input_source = ("stdin", None)
        if verbose:
            click.echo("📥 [INPUT] Reading from stdin")

    if insecure:
        verify_ssl = False
        if verbose:
            click.echo("⚠️  [WARN] SSL verification disabled", err=True)

    selected = set(types.lower().split(","))
    results = {
        k: set()
        for k in [
            "url",
            "email",
            "form",
            "auth",
            "api",
            "swagger",
            "graphql",  # New: Dedicated GraphQL extraction
            "api_docs",  # New: API documentation titles
            "tech_stack",  # New: Technology stacks
            "ip",
            "domain",
            "subdomain",
            "secret",
            "js",
            "comment",
            "hash",
            "base64",
            "phone",  # New: Phone numbers
            "crypto",  # New: Cryptocurrency addresses
            "social",  # New: Social media handles/links
            "pii",  # New: Personally Identifiable Information
        ]
    }

    processed_urls = set()

    def extract_from_text(text, source=""):
        """Enhanced text extraction with multiple patterns"""
        if verbose and source:
            click.echo(f"🔍 [EXTRACT] Processing: {source}")

        if "url" in selected:
            urls = URL_REGEX.findall(text)
            results["url"].update(urls)
            if verbose:
                click.echo(f"   📌 Found {len(urls)} URLs")

        if "email" in selected:
            emails = EMAIL_REGEX.findall(text)
            results["email"].update(emails)
            if verbose and emails:
                click.echo(f"   📧 Found {len(emails)} emails")

        if "form" in selected:
            forms = FORM_REGEX.findall(text)
            inputs = INPUT_REGEX.findall(text)
            results["form"].update(forms + inputs)
            if verbose and (forms or inputs):
                click.echo(f"   📝 Found {len(forms)} forms, {len(inputs)} inputs")

        if "auth" in selected:
            auth_paths = AUTH_REGEX.findall(text)
            results["auth"].update(auth_paths)
            if verbose and auth_paths:
                click.echo(f"   🔐 Found {len(auth_paths)} auth endpoints")

        if "api" in selected:
            api_paths = API_REGEX.findall(text)
            results["api"].update(api_paths)
            if verbose and api_paths:
                click.echo(f"   🚀 Found {len(api_paths)} API endpoints")

        if "swagger" in selected:
            swagger_paths = SWAGGER_REGEX.findall(text)
            results["swagger"].update(swagger_paths)
            if verbose and swagger_paths:
                click.echo(f"   📚 Found {len(swagger_paths)} documentation endpoints")

        # Dedicated GraphQL extraction
        if "graphql" in selected:
            clean_text = clean_ansi_codes(text)

            # Extract full lines containing GraphQL URLs (with variations and typos)
            graphql_lines = re.findall(
                r"https?://[^\s]+.*\[(.*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql).*)\].*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update([f"[{line}]" for line in graphql_lines])

            # Also get full lines for context
            full_graphql_lines = re.findall(
                r"https?://[^\s]+.*\[.*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql).*\].*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(full_graphql_lines)

            # Extract GraphQL endpoints from URLs (with variations)
            graphql_urls = re.findall(
                r"https?://[^\s]*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s]*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(graphql_urls)

            # Extract GraphQL mentions and interfaces (both patterns)
            graphql_mentions = GRAPHQL_REGEX.findall(clean_text)
            results["graphql"].update(graphql_mentions)

            graphql_full_mentions = GRAPHQL_FULL_REGEX.findall(clean_text)
            results["graphql"].update(
                [f"{match[0]} {match[1]}" for match in graphql_full_mentions]
            )

            # Look for common GraphQL patterns with variations
            graphql_patterns = re.findall(
                r'/(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s"\'<>]*',
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(graphql_patterns)

            # GraphQL introspection endpoints with variations
            introspection_patterns = re.findall(
                r"[^\s]*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s]*query[^\s]*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(introspection_patterns)

            if verbose and (
                graphql_lines
                or full_graphql_lines
                or graphql_urls
                or graphql_mentions
                or graphql_full_mentions
                or graphql_patterns
            ):
                total = (
                    len(graphql_lines)
                    + len(full_graphql_lines)
                    + len(graphql_urls)
                    + len(graphql_mentions)
                    + len(graphql_full_mentions)
                    + len(graphql_patterns)
                    + len(introspection_patterns)
                )
                click.echo(f"   🔮 Found {total} GraphQL endpoints/references")

        # New: API Documentation titles and tech stacks
        if "api_docs" in selected:
            # Clean ANSI first, then extract
            clean_text = clean_ansi_codes(text)

            # Extract API-specific titles (only those containing API-related keywords)
            api_titles = API_TITLE_REGEX.findall(text)
            results["api_docs"].update(api_titles)

            # Extract GraphQL mentions (more precise) - only if graphql not selected separately
            if "graphql" not in selected:
                graphql_matches = GRAPHQL_REGEX.findall(clean_text)
                results["api_docs"].update(
                    [f"GraphQL {match}" for match in graphql_matches]
                )

            # Extract general API docs mentions (more specific)
            docs_matches = API_DOCS_REGEX.findall(clean_text)
            results["api_docs"].update(docs_matches)

            if verbose:
                graphql_count = (
                    len(GRAPHQL_REGEX.findall(clean_text))
                    if "graphql" not in selected
                    else 0
                )
                total = len(api_titles) + graphql_count + len(docs_matches)
                if total > 0:
                    click.echo(f"   📋 Found {total} API documentation references")

        if "tech_stack" in selected:
            # Extract tech stack from end of lines
            tech_stacks = TECH_STACK_REGEX.findall(text)
            for stack in tech_stacks:
                # Split comma-separated and filter out common non-tech words
                technologies = [
                    tech.strip() for tech in stack.split(",") if tech.strip()
                ]
                # Filter out common non-technical terms
                filtered_tech = [
                    tech
                    for tech in technologies
                    if len(tech) > 2
                    and not tech.lower()
                    in ["hsts", "ubuntu", "windows server", "windows"]
                ]
                results["tech_stack"].update(filtered_tech)

            if verbose and tech_stacks:
                click.echo(f"   🔧 Found {len(tech_stacks)} technology references")

        if "ip" in selected:
            ips = IP_REGEX.findall(text)
            results["ip"].update(ips)
            if verbose and ips:
                click.echo(f"   🌐 Found {len(ips)} IP addresses")

        if "domain" in selected:
            domains = DOMAIN_REGEX.findall(text)
            results["domain"].update(domains)
            if verbose and domains:
                click.echo(f"   🏠 Found {len(domains)} domains")

        if "subdomain" in selected and target_domain:
            subdomains = SUBDOMAIN_REGEX(target_domain).findall(text)
            results["subdomain"].update(subdomains)
            if verbose and subdomains:
                click.echo(
                    f"   🌿 Found {len(subdomains)} subdomains for {target_domain}"
                )

        if "secret" in selected:
            # Multiple secret detection patterns
            secrets = SECRET_REGEX.findall(text)
            aws_keys = AWS_KEY_REGEX.findall(text)
            github_tokens = GITHUB_TOKEN_REGEX.findall(text)
            slack_tokens = SLACK_TOKEN_REGEX.findall(text)
            jwt_tokens = JWT_REGEX.findall(text)

            # Enhanced secret detection
            discord_tokens = DISCORD_TOKEN_REGEX.findall(text)
            telegram_bots = TELEGRAM_BOT_REGEX.findall(text)
            stripe_keys = STRIPE_KEY_REGEX.findall(text)
            paypal_clients = PAYPAL_CLIENT_REGEX.findall(text)
            mailgun_keys = MAILGUN_KEY_REGEX.findall(text)
            twilio_sids = TWILIO_SID_REGEX.findall(text)
            sendgrid_keys = SENDGRID_KEY_REGEX.findall(text)
            openai_keys = OPENAI_KEY_REGEX.findall(text)
            anthropic_keys = ANTHROPIC_KEY_REGEX.findall(text)
            google_api_keys = GOOGLE_API_KEY_REGEX.findall(text)
            azure_keys = AZURE_KEY_REGEX.findall(text)
            docker_tokens = DOCKER_TOKEN_REGEX.findall(text)
            heroku_keys = HEROKU_API_KEY_REGEX.findall(text)
            cloudflare_tokens = CLOUDFLARE_TOKEN_REGEX.findall(text)
            private_keys = PRIVATE_KEY_REGEX.findall(text)
            ssh_keys = SSH_KEY_REGEX.findall(text)
            database_urls = DATABASE_URL_REGEX.findall(text)
            connection_strings = CONNECTION_STRING_REGEX.findall(text)
            env_vars = ENV_VAR_REGEX.findall(text)
            api_secrets = API_ENDPOINT_SECRET_REGEX.findall(text)

            all_secrets = (
                [f"{k}:{v}" for k, v in secrets]
                + [f"AWS_KEY:{k}" for k in aws_keys]
                + [f"GITHUB_TOKEN:{t}" for t in github_tokens]
                + [f"SLACK_TOKEN:{t}" for t in slack_tokens]
                + [f"JWT_TOKEN:{t}" for t in jwt_tokens]
                + [f"DISCORD_TOKEN:{t}" for t in discord_tokens]
                + [f"TELEGRAM_BOT:{t}" for t in telegram_bots]
                + [f"STRIPE_KEY:{k}" for k in stripe_keys]
                + [f"PAYPAL_CLIENT:{c}" for c in paypal_clients]
                + [f"MAILGUN_KEY:{k}" for k in mailgun_keys]
                + [f"TWILIO_SID:{s}" for s in twilio_sids]
                + [f"SENDGRID_KEY:{k}" for k in sendgrid_keys]
                + [f"OPENAI_KEY:{k}" for k in openai_keys]
                + [f"ANTHROPIC_KEY:{k}" for k in anthropic_keys]
                + [f"GOOGLE_API_KEY:{k}" for k in google_api_keys]
                + [f"AZURE_KEY:{k}" for k in azure_keys]
                + [f"DOCKER_TOKEN:{t}" for t in docker_tokens]
                + [f"HEROKU_KEY:{k}" for k in heroku_keys]
                + [f"CLOUDFLARE_TOKEN:{t}" for t in cloudflare_tokens]
                + [f"PRIVATE_KEY:{k}" for k in private_keys]
                + [f"SSH_KEY:{k}" for k in ssh_keys]
                + [f"DATABASE_URL:{u}" for u in database_urls]
                + [f"CONNECTION_STRING:{c}" for c in connection_strings]
                + [f"ENV_VAR:{v}" for v in env_vars]
                + [f"API_SECRET:{s}" for s in api_secrets]
            )
            results["secret"].update(all_secrets)
            if verbose and all_secrets:
                click.echo(f"   🔑 Found {len(all_secrets)} potential secrets")

        # New extraction categories
        if "phone" in selected:
            phones = PHONE_REGEX.findall(text)
            results["phone"].update(phones)
            if verbose and phones:
                click.echo(f"   📞 Found {len(phones)} phone numbers")

        if "crypto" in selected:
            bitcoin_addrs = BITCOIN_ADDRESS_REGEX.findall(text)
            ethereum_addrs = ETHEREUM_ADDRESS_REGEX.findall(text)
            monero_addrs = MONERO_ADDRESS_REGEX.findall(text)
            crypto_wallets = CRYPTO_WALLET_REGEX.findall(text)

            all_crypto = (
                [f"BTC:{addr}" for addr in bitcoin_addrs]
                + [f"ETH:{addr}" for addr in ethereum_addrs]
                + [f"XMR:{addr}" for addr in monero_addrs]
                + [f"WALLET:{addr}" for addr in crypto_wallets]
            )
            results["crypto"].update(all_crypto)
            if verbose and all_crypto:
                click.echo(f"   ₿ Found {len(all_crypto)} cryptocurrency addresses")

        if "social" in selected:
            twitter_handles = TWITTER_HANDLE_REGEX.findall(text)
            instagram_handles = INSTAGRAM_HANDLE_REGEX.findall(text)
            youtube_channels = YOUTUBE_CHANNEL_REGEX.findall(text)
            linkedin_profiles = LINKEDIN_PROFILE_REGEX.findall(text)
            facebook_profiles = FACEBOOK_PROFILE_REGEX.findall(text)
            discord_invites = DISCORD_INVITE_REGEX.findall(text)
            telegram_channels = TELEGRAM_CHANNEL_REGEX.findall(text)

            all_social = (
                [f"TWITTER:{h}" for h in twitter_handles]
                + [f"INSTAGRAM:{h}" for h in instagram_handles]
                + [f"YOUTUBE:{c}" for c in youtube_channels]
                + [f"LINKEDIN:{p}" for p in linkedin_profiles]
                + [f"FACEBOOK:{p}" for p in facebook_profiles]
                + [f"DISCORD:{i}" for i in discord_invites]
                + [f"TELEGRAM:{c}" for c in telegram_channels]
            )
            results["social"].update(all_social)
            if verbose and all_social:
                click.echo(f"   📱 Found {len(all_social)} social media references")

        if "pii" in selected:
            credit_cards = CREDIT_CARD_REGEX.findall(text)
            social_security = SOCIAL_SECURITY_REGEX.findall(text)

            all_pii = [f"CC:{cc}" for cc in credit_cards] + [
                f"SSN:{ssn}" for ssn in social_security
            ]
            results["pii"].update(all_pii)
            if verbose and all_pii:
                click.echo(f"   🆔 Found {len(all_pii)} PII items")

        if "js" in selected and deep_js:
            js_vars = JS_VAR_REGEX.findall(text)
            js_formatted = [f"{var}={value}" for var, value in js_vars]
            results["js"].update(js_formatted)
            if verbose and js_formatted:
                click.echo(f"   🔧 Found {len(js_formatted)} JS variables")

        if "comment" in selected and include_comments:
            comments = COMMENT_REGEX.findall(text)
            results["comment"].update(comments)
            if verbose and comments:
                click.echo(f"   💬 Found {len(comments)} comments")

        if "hash" in selected:
            hashes = HASH_REGEX.findall(text)
            results["hash"].update(hashes)
            if verbose and hashes:
                click.echo(f"   #️⃣  Found {len(hashes)} hashes")

        if "base64" in selected:
            base64_strings = BASE64_REGEX.findall(text)
            results["base64"].update(base64_strings)
            if verbose and base64_strings:
                click.echo(f"   📊 Found {len(base64_strings)} base64 strings")

    def fetch_url_content(url):
        """Fetch content from URL with proper error handling"""
        if url in processed_urls:
            return None

        processed_urls.add(url)

        try:
            if verbose:
                click.echo(f"🌐 [FETCH] Getting: {url}")

            headers = {"User-Agent": user_agent}
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=follow_redirects,
                stream=True,
            )

            # Check content length
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > max_size * 1024 * 1024:
                if verbose:
                    click.echo(f"⚠️  [SKIP] File too large: {content_length} bytes")
                return None

            # Read content with size limit
            content = ""
            size = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if chunk:
                    content += chunk
                    size += len(chunk.encode("utf-8"))
                    if size > max_size * 1024 * 1024:
                        if verbose:
                            click.echo(
                                f"⚠️  [TRUNCATED] Content truncated at {max_size}MB"
                            )
                        break

            if verbose:
                click.echo(f"✅ [SUCCESS] Fetched {len(content)} chars from {url}")

            return content

        except requests.exceptions.SSLError as e:
            if verbose:
                click.echo(f"🔒 [SSL-ERROR] {url}: {e}")
        except requests.exceptions.Timeout:
            if verbose:
                click.echo(f"⏱️  [TIMEOUT] {url}")
        except requests.exceptions.RequestException as e:
            if verbose:
                click.echo(f"❌ [ERROR] {url}: {e}")
        except Exception as e:
            if verbose:
                click.echo(f"💥 [UNEXPECTED] {url}: {e}")

        return None

    def process_urls_concurrent(urls_list):
        """Process multiple URLs concurrently"""
        if not urls_list:
            return

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {
                executor.submit(fetch_url_content, url): url for url in urls_list
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        extract_from_text(content, f"URL: {url}")

                        # Extract new URLs and potentially fetch them too
                        if fetch_urls:
                            new_urls = URL_REGEX.findall(content)
                            new_urls = [u for u in new_urls if u not in processed_urls]
                            if new_urls and verbose:
                                click.echo(
                                    f"🔗 [DISCOVERED] {len(new_urls)} new URLs from {url}"
                                )

                except Exception as e:
                    if verbose:
                        click.echo(f"❌ [PROCESSING-ERROR] {url}: {e}")

    def smart_type_detect(path):
        """Enhanced file type detection"""
        mime, _ = mimetypes.guess_type(path.name)
        suffix = path.suffix.lower()

        if mime:
            if "json" in mime or suffix == ".json":
                return "json"
            elif "html" in mime or suffix in [".html", ".htm"]:
                return "html"
            elif "javascript" in mime or suffix in [".js", ".jsx"]:
                return "js"
            elif "xml" in mime or suffix == ".xml":
                return "xml"
            elif "css" in mime or suffix == ".css":
                return "css"

        # Check content for additional detection
        try:
            content_sample = path.read_text(encoding="utf-8", errors="ignore")[:500]
            if content_sample.strip().startswith(("<!DOCTYPE", "<html", "<HTML")):
                return "html"
            elif content_sample.strip().startswith(
                "{"
            ) or content_sample.strip().startswith("["):
                return "json"
            elif (
                "function" in content_sample
                or "var " in content_sample
                or "const " in content_sample
            ):
                return "js"
        except:
            pass

        return "text"

    def process_file(path):
        """Enhanced file processing with type detection"""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")

            if smart_detect:
                ftype = smart_type_detect(path)
                if verbose:
                    click.echo(f"📄 [FILE-TYPE] {path.name}: {ftype}")

                if ftype == "json":
                    try:
                        json_content = json.loads(content)
                        content = json.dumps(
                            json_content, indent=2
                        )  # normalize spacing
                    except:
                        pass
                elif ftype == "html" and deep_js:
                    # Extract and process inline JavaScript
                    script_pattern = r"<script[^>]*>(.*?)</script>"
                    scripts = re.findall(
                        script_pattern, content, re.DOTALL | re.IGNORECASE
                    )
                    for script in scripts:
                        extract_from_text(script, f"Inline JS in {path.name}")

            extract_from_text(content, str(path))

        except Exception as e:
            if verbose:
                click.echo(f"❌ [FILE-ERROR] Failed to process {path}: {e}", err=True)

    # Main processing logic with enhanced input handling
    initial_urls = []

    if input_source[0] == "url":
        # Process single URL directly
        if fetch_urls:
            initial_urls = [input_source[1]]
        else:
            extract_from_text(input_source[1], "direct URL input")

    elif input_source[0] == "list":
        # Process URL list file
        try:
            with open(input_source[1], "r", encoding=encoding) as f:
                urls = [
                    clean_ansi_codes(line.strip())  # Clean ANSI codes
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            if fetch_urls:
                initial_urls = urls
                if verbose:
                    click.echo(f"📋 [URL-LIST] Loaded {len(urls)} URLs for fetching")
            else:
                # Extract from URL strings themselves
                for url in urls:
                    extract_from_text(clean_ansi_codes(url), f"URL from list: {url}")

        except Exception as e:
            if verbose:
                click.echo(f"❌ [ERROR] Failed to read URL list {input_source[1]}: {e}")
            return

    elif input_source[0] == "file":
        # Process file input (original logic)
        p = Path(input_source[1])
        if p.is_file():
            process_file(p)
        elif p.is_dir() and recursive:
            if verbose:
                click.echo(f"📁 [RECURSIVE] Scanning directory: {p}")
            for file in p.rglob("*"):
                if file.is_file():
                    # Apply file pattern filtering
                    if file_patterns:
                        patterns = file_patterns.split(",")
                        if not any(file.match(pattern.strip()) for pattern in patterns):
                            continue

                    if exclude_patterns:
                        patterns = exclude_patterns.split(",")
                        if any(file.match(pattern.strip()) for pattern in patterns):
                            continue

                    process_file(file)
        else:
            click.echo("[!] Use --recursive for directories", err=True)
            return

    else:
        # Process stdin (original logic)
        stdin_content = sys.stdin.read()
        extract_from_text(stdin_content, "stdin")

        # Check if stdin contains URLs to fetch
        if fetch_urls:
            potential_urls = URL_REGEX.findall(stdin_content)
            initial_urls.extend(potential_urls)

    # Process URLs if fetch_urls is enabled
    if fetch_urls and "url" in results:
        urls_to_fetch = list(results["url"]) + initial_urls
        if urls_to_fetch:
            if verbose:
                click.echo(
                    f"🚀 [FETCH-MODE] Processing {len(urls_to_fetch)} URLs with {threads} threads"
                )
            process_urls_concurrent(urls_to_fetch)

    # Filter out empty results and prepare final output
    final = {k: sorted(list(v)) for k, v in results.items() if v}

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔄 DEDUPLICATION AND MERGING LOGIC
    # ═══════════════════════════════════════════════════════════════════════════════

    def load_existing_data(file_path):
        """Load existing data from various file formats"""
        existing_data = {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = clean_ansi_codes(f.read().strip())  # Clean ANSI codes

            # Try to detect format
            if content.startswith("{"):
                # JSON format
                try:
                    data = json.loads(content)
                    for category, items in data.items():
                        if isinstance(items, list):
                            existing_data[category] = set(items)
                        elif isinstance(items, dict):
                            # Handle scored format
                            existing_data[category] = set(
                                item.get("value", item)
                                for item in items
                                if isinstance(item, dict)
                            )
                except json.JSONDecodeError:
                    pass
            else:
                # Plain text format - try to guess content type
                lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Auto-detect content type
                    if line.startswith("http"):
                        if "url" not in existing_data:
                            existing_data["url"] = set()
                        existing_data["url"].add(line)
                    elif "@" in line and "." in line:
                        if "email" not in existing_data:
                            existing_data["email"] = set()
                        existing_data["email"].add(line)
                    elif re.match(r"\d+\.\d+\.\d+\.\d+", line):
                        if "ip" not in existing_data:
                            existing_data["ip"] = set()
                        existing_data["ip"].add(line)
                    elif "." in line and not "/" in line:
                        if "domain" not in existing_data:
                            existing_data["domain"] = set()
                        existing_data["domain"].add(line)
                    else:
                        # Default to URL category
                        if "url" not in existing_data:
                            existing_data["url"] = set()
                        existing_data["url"].add(line)

        except Exception as e:
            if verbose:
                click.echo(f"⚠️  [MERGE-WARNING] Could not load {file_path}: {e}")

        return existing_data

    # Handle merging with existing file
    if merge_with:
        if verbose:
            click.echo(f"🔗 [MERGE] Loading existing data from {merge_with}")
        existing_data = load_existing_data(merge_with)

        # Merge data
        for category in final.keys():
            if category in existing_data:
                combined = final[category] + list(existing_data[category])
                final[category] = combined

    # Apply deduplication
    if dedup or merge_with or unique_only:
        if verbose:
            pre_dedup_count = sum(len(v) for v in final.values())

        dedup_categories = dedup_by.split(",") if dedup_by != "all" else final.keys()

        for category in dedup_categories:
            if category in final:
                if sort_results:
                    final[category] = sorted(list(set(final[category])))
                else:
                    final[category] = list(set(final[category]))

        if verbose:
            post_dedup_count = sum(len(v) for v in final.values())
            removed = pre_dedup_count - post_dedup_count
            click.echo(
                f"🧹 [DEDUP] Removed {removed} duplicates ({post_dedup_count} unique items remain)"
            )

    # Sort results if requested
    elif sort_results:
        final = {k: sorted(v) for k, v in final.items()}

    if verbose:
        total_items = sum(len(v) for v in final.values())
        click.echo(
            f"🎯 [SUMMARY] Final output: {total_items} total items across {len(final)} categories"
        )

    if ai_score:

        def calculate_score(entry, category):
            """Enhanced scoring algorithm"""
            score = 0
            entry_lower = entry.lower()

            # Category-specific scoring
            if category == "url":
                high_value_keywords = [
                    "admin",
                    "api",
                    "swagger",
                    "graphql",
                    "auth",
                    "login",
                    "internal",
                    "dev",
                    "test",
                    "debug",
                ]
                score += sum(
                    3 for keyword in high_value_keywords if keyword in entry_lower
                )

                # File extension scoring
                valuable_extensions = [
                    ".json",
                    ".xml",
                    ".config",
                    ".env",
                    ".properties",
                ]
                score += sum(2 for ext in valuable_extensions if ext in entry_lower)

            elif category == "secret":
                # Higher scores for potential secrets
                secret_indicators = [
                    "key",
                    "token",
                    "secret",
                    "password",
                    "api",
                    "auth",
                ]
                score += sum(
                    5 for indicator in secret_indicators if indicator in entry_lower
                )

            elif category == "api":
                api_indicators = ["v1", "v2", "v3", "rest", "graphql", "swagger"]
                score += sum(
                    2 for indicator in api_indicators if indicator in entry_lower
                )

            elif category == "api_docs":
                # High-value API documentation indicators
                high_value_api_terms = [
                    "management",
                    "admin",
                    "internal",
                    "private",
                    "enterprise",
                    "control",
                    "dashboard",
                ]
                score += sum(3 for term in high_value_api_terms if term in entry_lower)

                # API technology stack scoring
                api_tech_terms = [
                    "graphql",
                    "swagger",
                    "openapi",
                    "rest api",
                    "web api",
                    "api explorer",
                    "api gateway",
                ]
                score += sum(2 for term in api_tech_terms if term in entry_lower)

                # Specific API service indicators
                service_indicators = [
                    "trading",
                    "payment",
                    "banking",
                    "crypto",
                    "financial",
                    "security",
                    "auth",
                ]
                score += sum(
                    1 for indicator in service_indicators if indicator in entry_lower
                )

            # Universal high-value indicators
            high_value_general = [
                "private",
                "internal",
                "admin",
                "management",
                "control",
            ]
            score += sum(1 for keyword in high_value_general if keyword in entry_lower)

            return score

        if verbose:
            click.echo("🧠 [AI-SCORING] Applying intelligent scoring...")

        final = {
            k: sorted(v, key=lambda x: -calculate_score(x, k)) for k, v in final.items()
        }

    # Output formatting
    if to_jsonl:
        lines = []
        for category, values in final.items():
            for value in values:
                entry = {"type": category, "value": value}
                if ai_score:
                    entry["score"] = (
                        calculate_score(value, category)
                        if "calculate_score" in locals()
                        else 0
                    )
                lines.append(json.dumps(entry))
        output_data = "\n".join(lines)

    elif json_out:
        if ai_score and "calculate_score" in locals():
            # Add scores to JSON output
            scored_final = {}
            for category, values in final.items():
                scored_final[category] = [
                    {"value": value, "score": calculate_score(value, category)}
                    for value in values
                ]
            output_data = json.dumps(scored_final, indent=2)
        else:
            output_data = json.dumps(final, indent=2)

    elif tagged:
        output_data = f"# ExtractorCLI Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        output_data += f"# Processed: {input if input else 'stdin'}\n"
        output_data += f"# Types: {types}\n\n"

        for category, items in final.items():
            if items:
                output_data += f"\n## {category.upper()} ({len(items)} found):\n"
                for item in items:
                    if ai_score and "calculate_score" in locals():
                        score = calculate_score(item, category)
                        output_data += f"[Score: {score:2d}] {item}\n"
                    else:
                        output_data += f"{item}\n"

    else:
        # Simple flat output
        all_items = []
        for items in final.values():
            all_items.extend(items)
        output_data = "\n".join(all_items)

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔥 XSS-VIBES INTEGRATION
    # ═══════════════════════════════════════════════════════════════════════════════

    if xss_scan or xss_discover:
        import subprocess
        import tempfile

        if verbose:
            click.echo("🔥 [XSS-VIBES] Starting XSS analysis...")

    # XSS Endpoint Discovery
    if xss_discover and target_domain:
        if verbose:
            click.echo(f"🔍 [XSS-DISCOVER] Discovering endpoints for {target_domain}")

        try:
            discover_output = f"{target_domain}_xss_endpoints.txt"
            subprocess.run(
                [
                    "xss-vibes",
                    "endpoints",
                    target_domain,
                    "--depth",
                    "2",
                    "--output",
                    discover_output,
                ],
                check=True,
                timeout=120,
            )

            if verbose:
                click.echo(f"✅ [XSS-DISCOVER] Results saved to {discover_output}")

            # Merge discovered endpoints back into results
            if Path(discover_output).exists():
                # XSS-vibes creates a directory, look for URL files
                if Path(discover_output).is_dir():
                    url_files = list(Path(discover_output).glob("*urls*.txt"))
                    all_discovered = []

                    for url_file in url_files:
                        with open(url_file, "r") as f:
                            urls = [line.strip() for line in f if line.strip()]
                            all_discovered.extend(urls)

                    if all_discovered:
                        if "url" not in final:
                            final["url"] = []
                        final["url"].extend(all_discovered)
                        final["url"] = list(set(final["url"]))  # Dedup

                        if verbose:
                            click.echo(
                                f"🔗 [MERGE] Added {len(all_discovered)} discovered endpoints"
                            )
                else:
                    # Single file case
                    with open(discover_output, "r") as f:
                        discovered_urls = [line.strip() for line in f if line.strip()]

                    if "url" not in final:
                        final["url"] = []
                    final["url"].extend(discovered_urls)
                    final["url"] = list(set(final["url"]))  # Dedup

                    if verbose:
                        click.echo(
                            f"🔗 [MERGE] Added {len(discovered_urls)} discovered endpoints"
                        )

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo("⏱️  [XSS-DISCOVER] Timeout reached")
        except subprocess.CalledProcessError:
            if verbose:
                click.echo("❌ [XSS-DISCOVER] Failed to run xss-vibes endpoints")
        except FileNotFoundError:
            if verbose:
                click.echo("❌ [XSS-DISCOVER] xss-vibes not found in PATH")

    # XSS Vulnerability Scanning
    if xss_scan and "url" in final and final["url"]:
        if verbose:
            click.echo(f"🎯 [XSS-SCAN] Testing {len(final['url'])} URLs for XSS")

        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp_file:
                for url in final["url"][:100]:  # Limit to first 100 URLs
                    tmp_file.write(f"{url}\n")
                tmp_file_path = tmp_file.name

            # Use first URL as positional argument (required by xss-vibes)
            first_url = final["url"][0] if final["url"] else "https://httpbin.org"
            xss_output = f"xss_scan_results_{int(time.time())}.txt"

            subprocess.run(
                [
                    "xss-vibes",
                    "scan",
                    first_url,
                    "--list",
                    tmp_file_path,
                    "--threads",
                    str(xss_threads),
                    "--timeout",
                    str(xss_timeout),
                    "--output",
                    xss_output,
                ],
                check=True,
                timeout=600,
            )

            if verbose:
                click.echo(f"✅ [XSS-SCAN] Results saved to {xss_output}")

            # Clean up temp file
            Path(tmp_file_path).unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo("⏱️  [XSS-SCAN] Timeout reached")
        except subprocess.CalledProcessError:
            if verbose:
                click.echo("❌ [XSS-SCAN] Failed to run xss-vibes scan")
        except FileNotFoundError:
            if verbose:
                click.echo("❌ [XSS-SCAN] xss-vibes not found in PATH")

    # ═══════════════════════════════════════════════════════════════════════════════
    # 💾 FINAL OUTPUT GENERATION
    # ═══════════════════════════════════════════════════════════════════════════════

    # Regenerate output with merged data
    if xss_discover and "url" in final:
        # Regenerate final output data
        if to_jsonl:
            lines = []
            for category, values in final.items():
                for value in values:
                    entry = {"type": category, "value": value}
                    if ai_score:
                        entry["score"] = (
                            calculate_score(value, category)
                            if "calculate_score" in locals()
                            else 0
                        )
                    lines.append(json.dumps(entry))
            output_data = "\n".join(lines)

        elif json_out:
            if ai_score and "calculate_score" in locals():
                # Add scores to JSON output
                scored_final = {}
                for category, values in final.items():
                    scored_final[category] = [
                        {"value": value, "score": calculate_score(value, category)}
                        for value in values
                    ]
                output_data = json.dumps(scored_final, indent=2)
            else:
                output_data = json.dumps(final, indent=2)

        elif tagged:
            output_data = (
                f"# ExtractorCLI Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            output_data += f"# Processed: {input if input else 'stdin'}\n"
            output_data += f"# Types: {types}\n"
            if xss_discover:
                output_data += f"# XSS-Vibes Integration: Enabled\n"
            output_data += "\n"

            for category, items in final.items():
                if items:
                    output_data += f"\n## {category.upper()} ({len(items)} found):\n"
                    for item in items:
                        if ai_score and "calculate_score" in locals():
                            score = calculate_score(item, category)
                            output_data += f"[Score: {score:2d}] {item}\n"
                        else:
                            output_data += f"{item}\n"

        else:
            # Simple flat output
            all_items = []
            for items in final.values():
                all_items.extend(items)
            output_data = "\n".join(all_items)

    # Output results
    if output:
        output_path = Path(output)
        output_path.write_text(output_data, encoding="utf-8")
        click.echo(f"✅ [SAVED] Results saved to {output}")

        if verbose:
            total_items = sum(len(v) for v in final.values())
            click.echo(
                f"📊 [STATS] {total_items} items saved across {len(final)} categories"
            )
    else:
        click.echo(output_data)

    # ═══════════════════════════════════════════════════════════════════════════════
    # 💾 DATABASE STORAGE
    # ═══════════════════════════════════════════════════════════════════════════════

    if store_db:
        import sqlite3
        from datetime import datetime

        if verbose:
            click.echo(f"💾 [DATABASE] Storing results to {db_path}")

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create tables if they don't exist
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS extraction_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    input_source TEXT,
                    types TEXT,
                    total_items INTEGER,
                    ai_score_enabled BOOLEAN,
                    score_threshold INTEGER
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS extracted_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER,
                    category TEXT,
                    value TEXT,
                    score INTEGER,
                    timestamp TEXT,
                    FOREIGN KEY (run_id) REFERENCES extraction_runs (id)
                )
            """
            )

            # Insert run record
            timestamp = datetime.now().isoformat()
            total_items = sum(len(v) for v in final.values())

            cursor.execute(
                """
                INSERT INTO extraction_runs 
                (timestamp, input_source, types, total_items, ai_score_enabled, score_threshold)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    timestamp,
                    input if input else "stdin",
                    types,
                    total_items,
                    ai_score,
                    score_threshold,
                ),
            )

            run_id = cursor.lastrowid

            # Insert individual items
            for category, items in final.items():
                for item in items:
                    score = 0
                    if ai_score and "calculate_score" in locals():
                        score = calculate_score(item, category)

                    cursor.execute(
                        """
                        INSERT INTO extracted_items 
                        (run_id, category, value, score, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """,
                        (run_id, category, item, score, timestamp),
                    )

            conn.commit()
            conn.close()

            if verbose:
                click.echo(
                    f"✅ [DATABASE] Stored {total_items} items in run ID {run_id}"
                )

        except Exception as e:
            if verbose:
                click.echo(f"❌ [DATABASE] Error storing to database: {e}")


if __name__ == "__main__":
    extractor()
