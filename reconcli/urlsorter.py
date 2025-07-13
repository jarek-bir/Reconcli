#!/usr/bin/env python3
"""
URL Sorter for Reconcli Toolkit
Advanced URL categorization and pattern matching for security testing
"""

import json
import os
import re
import socket
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import click
import yaml

# Import resume utilities
try:
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
except ImportError:

    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def clear_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            os.remove(path)


def load_urls_from_source(input_source):
    """Load URLs from file or stdin"""
    if input_source == "-":
        # Read from stdin
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        # Read from file
        with open(input_source, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    return urls


# Enhanced patterns for comprehensive security testing
DEFAULT_PATTERNS = {
    # Cross-Site Scripting (XSS)
    "xss": r"(?i)(script|onerror|onload|alert|%3Cscript|<svg|xss=|javascript:|vbscript:|expression\(|%253Cscript)",
    # Local File Inclusion (LFI)
    "lfi": r"(?i)(\.\./|\.\.\\\\|etc/passwd|%2e%2e%2f|%2e%2e\\|windows/system32|boot\.ini)",
    # Server-Side Request Forgery (SSRF)
    "ssrf": r"(?i)(http:\/\/127\.|localhost|internal|0\.0\.0\.0|169\.254\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
    # Remote Code Execution (RCE)
    "rce": r"(?i)(cmd=|exec|shell=|run=|system=|command=|eval=|%20ping%20|whoami|id\;|cat%20)",
    # Open Redirect
    "redirect": r"(?i)(redirect=|url=|next=|target=|goto=|link=|forward=|return_url=)",
    # SQL Injection
    "sqli": r"(?i)(union select|select .* from|or 1=1|and 1=1|'|\"|%27|%22|order by|group by|having)",
    # Privilege Bypass
    "bypass": r"(?i)(admin=true|is_admin|access=granted|role=admin|user_type=admin|level=admin)",
    # Authentication Tokens
    "token": r"(?i)(access_token|auth_token|jwt|bearer|api_key|session_id|csrf_token)",
    # Callback Functions (JSONP)
    "callback": r"(?i)(callback=|jsonp=|return=|continue=|_callback=)",
    # GraphQL
    "graphql": r"(?i)(graphql|graphiql|query=|mutation=|subscription=)",
    # Information Disclosure
    "sitemap": r"(?i)(sitemap\.xml|robots\.txt|\.well-known|crossdomain\.xml|security\.txt)",
    # File Upload
    "upload": r"(?i)(upload|file=|filename=|attachment=|document=|image=|photo=)",
    # API Endpoints
    "api": r"(?i)(\/api\/|\/v[0-9]+\/|\.json|\.xml|rest\/|graphql\/|swagger)",
    # Admin Panels
    "admin": r"(?i)(\/admin|\/administrator|\/wp-admin|\/control|\/manage|\/backend|\/dashboard)",
    # Database Operations
    "database": r"(?i)(backup|dump|export|import|migrate|restore|schema|table)",
    # File Extensions of Interest
    "sensitive_files": r"(?i)\.(config|conf|ini|env|bak|backup|old|tmp|log|sql|db)(\?|$)",
    # Parameter Pollution
    "param_pollution": r"(?i)([?&][^=]+=.*&[^=]+=)",
    # Testing Parameters
    "test_params": r"(?i)(test=|debug=|dev=|demo=|example=|sample=|mock=)",
    # Version Disclosure
    "version": r"(?i)(version=|v=|ver=|build=|release=)",
}


@click.group()
def cli():
    """URL Sorter - Advanced URL categorization and pattern matching"""
    pass


@cli.command()
@click.option(
    "-i", "--input", help="Input file with URLs (one per line). Use '-' for stdin."
)
@click.option("-o", "--output-dir", default="output_urlsort", help="Output directory")
@click.option("-p", "--patterns", help="Optional custom pattern file (YAML)")
@click.option("--json", "export_json", is_flag=True, help="Export summary to JSON")
@click.option("--markdown", is_flag=True, help="Export summary to Markdown")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--dedupe", is_flag=True, help="Remove duplicate URLs")
@click.option("--sort", is_flag=True, help="Sort URLs alphabetically")
@click.option("--filter-params", help="Filter URLs by parameter patterns (regex)")
@click.option("--filter-domains", help="Filter URLs by domain patterns (regex)")
@click.option("--exclude-patterns", help="Exclude URLs matching patterns (regex)")
@click.option("--min-params", type=int, help="Minimum number of parameters required")
@click.option("--max-params", type=int, help="Maximum number of parameters allowed")
@click.option("--resume", is_flag=True, help="Resume from previous run")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state",
)
@click.option("--show-resume", is_flag=True, help="Show status of previous runs")
def sort(
    input,
    output_dir,
    patterns,
    export_json,
    markdown,
    verbose,
    dedupe,
    sort,
    filter_params,
    filter_domains,
    exclude_patterns,
    min_params,
    max_params,
    resume,
    clear_resume_flag,
    show_resume,
):
    """Sort URLs by security testing patterns"""

    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir, "urlsort")
        return

    if clear_resume_flag:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Check if we can read from stdin when no input file provided
    import sys

    if not input:
        if not sys.stdin.isatty():
            input = "-"  # stdin
        else:
            click.echo("❌ Error: Input file is required for URL sorting")
            click.echo(
                "Usage: python urlsorter.py sort -i <file> OR echo 'urls' | python urlsorter.py sort"
            )
            raise click.Abort()

    if verbose:
        click.echo("[+] 🚀 Starting URL sorting")
        click.echo(f"[+] 📁 Input source: {input if input != '-' else 'stdin'}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"urlsort_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_state = load_resume(output_dir)

    if resume and resume_state:
        if verbose:
            click.echo(
                f"[+] 📁 Loading resume state with {len(resume_state)} previous scan(s)"
            )
        # Find the most recent incomplete scan
        for key, data in sorted(
            resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True
        ):
            if key.startswith("urlsort_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "input_file": input,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "processed_count": 0,
            "configuration": {
                "dedupe": dedupe,
                "sort": sort,
                "filter_params": filter_params,
                "filter_domains": filter_domains,
                "exclude_patterns": exclude_patterns,
                "min_params": min_params,
                "max_params": max_params,
            },
        }
        save_resume_state(output_dir, resume_state)

    # Load patterns
    if patterns:
        if verbose:
            click.echo(f"[+] 📋 Loading custom patterns from {patterns}")
        with open(patterns, "r") as f:
            pattern_dict = yaml.safe_load(f)
    else:
        pattern_dict = DEFAULT_PATTERNS
        if verbose:
            click.echo(f"[+] 📋 Using {len(pattern_dict)} default patterns")

    # Load and process URLs
    urls = load_urls_from_source(input)

    if verbose:
        click.echo(f"[+] 🌐 Loaded {len(urls)} URLs")

    # Apply filters and processing
    processed_urls = process_urls(
        urls,
        filter_params,
        filter_domains,
        exclude_patterns,
        min_params,
        max_params,
        dedupe,
        sort,
        verbose,
    )

    if verbose:
        click.echo(f"[+] ✅ After processing: {len(processed_urls)} URLs")

    # Categorize URLs by patterns
    matches, analysis = categorize_urls(processed_urls, pattern_dict, verbose)

    # Save categorized URLs
    save_categorized_urls(matches, output_dir, verbose)

    # Generate comprehensive statistics
    stats = generate_comprehensive_stats(
        processed_urls, matches, analysis, pattern_dict
    )

    # Save outputs
    if export_json:
        save_json_output(stats, output_dir, verbose)

    if markdown:
        save_markdown_output(stats, analysis, output_dir, verbose)

    # Update resume state
    current_scan = resume_state[scan_key]
    current_scan["processed_count"] = len(processed_urls)
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()
    save_resume_state(output_dir, resume_state)

    if verbose:
        click.echo("\n[+] 📊 Sorting Summary:")
        click.echo(f"   - Total URLs processed: {len(processed_urls)}")
        click.echo(
            f"   - Categories with matches: {len([k for k, v in matches.items() if v])}"
        )
        click.echo(f"   - Total matches: {sum(len(v) for v in matches.values())}")

    click.echo("\n[+] ✅ URL sorting completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


@cli.command()
@click.option(
    "-i", "--input", help="Input file with URLs (one per line). Use '-' for stdin."
)
@click.option(
    "-o", "--output-dir", default="output_url_analysis", help="Output directory"
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--json", "export_json", is_flag=True, help="Export analysis to JSON")
@click.option("--markdown", is_flag=True, help="Export analysis to Markdown")
def analyze(input, output_dir, verbose, export_json, markdown):
    """Perform advanced URL analysis and statistics"""

    # Check if we can read from stdin when no input file provided
    if not input:
        if not sys.stdin.isatty():
            input = "-"  # stdin
        else:
            click.echo("❌ Error: Input file is required for URL analysis")
            click.echo(
                "Usage: python urlsorter.py analyze -i <file> OR echo 'urls' | python urlsorter.py analyze"
            )
            raise click.Abort()

    if verbose:
        click.echo("[+] 🔍 Starting URL analysis")
        click.echo(f"[+] 📁 Input source: {input if input != '-' else 'stdin'}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Load URLs
    urls = load_urls_from_source(input)

    if verbose:
        click.echo(f"[+] 🌐 Loaded {len(urls)} URLs for analysis")

    # Perform comprehensive analysis
    analysis_results = perform_url_analysis(urls, verbose)

    # Save analysis results
    if export_json:
        save_analysis_json(analysis_results, output_dir, verbose)

    if markdown:
        save_analysis_markdown(analysis_results, output_dir, verbose)

    if verbose:
        click.echo("\n[+] ✅ URL analysis completed!")
        click.echo(f"[+] 📁 Analysis results saved to: {output_dir}")


@cli.command()
@click.option(
    "-i", "--input", help="Input file with URLs (one per line). Use '-' for stdin."
)
@click.option("-o", "--output-dir", default="output_hakcheck", help="Output directory")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--json", "export_json", is_flag=True, help="Export results to JSON")
@click.option("--markdown", is_flag=True, help="Export results to Markdown")
@click.option(
    "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)"
)
@click.option(
    "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)"
)
@click.option(
    "--retries",
    type=int,
    default=3,
    help="Number of retries for failed requests (default: 3)",
)
@click.option(
    "--status-codes", help="Filter by status codes (e.g., '200,201,302' or '2xx,3xx')"
)
@click.option(
    "--exclude-status", help="Exclude status codes (e.g., '404,403' or '4xx')"
)
@click.option("--content-length-min", type=int, help="Minimum content length filter")
@click.option("--content-length-max", type=int, help="Maximum content length filter")
@click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
@click.option(
    "--user-agent",
    default="HakCheckURL/1.0 (ReconCLI)",
    help="Custom User-Agent string",
)
@click.option(
    "--headers",
    help='Custom headers in JSON format (e.g., \'{"X-Forwarded-For": "127.0.0.1"}\')',
)
@click.option("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
@click.option("--grep-content", help="Grep response content for patterns (regex)")
@click.option("--grep-headers", help="Grep response headers for patterns (regex)")
@click.option("--match-length", help="Match specific content lengths (comma-separated)")
@click.option(
    "--technologies", is_flag=True, help="Detect web technologies and frameworks"
)
@click.option("--security-headers", is_flag=True, help="Analyze security headers")
@click.option(
    "--save-responses", is_flag=True, help="Save full HTTP responses to files"
)
@click.option(
    "--rate-limit", type=int, default=50, help="Requests per second limit (default: 50)"
)
@click.option(
    "--method",
    type=click.Choice(["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]),
    default="GET",
    help="HTTP method to use (default: GET)",
)
@click.option("--data", help="POST data for requests")
@click.option("--resume", is_flag=True, help="Resume from previous scan")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state",
)
@click.option("--store-db", is_flag=True, help="Store results in ReconCLI database")
@click.option(
    "--check-live", is_flag=True, help="Perform live domain checking (DNS resolution)"
)
@click.option(
    "--filter-live", is_flag=True, help="Filter and process only live domains"
)
@click.option("--target-domain", help="Primary target domain for database storage")
@click.option("--program", help="Bug bounty program name for database classification")
def hakcheckurl(
    input,
    output_dir,
    verbose,
    export_json,
    markdown,
    threads,
    timeout,
    retries,
    status_codes,
    exclude_status,
    content_length_min,
    content_length_max,
    follow_redirects,
    user_agent,
    headers,
    proxy,
    grep_content,
    grep_headers,
    match_length,
    technologies,
    security_headers,
    save_responses,
    rate_limit,
    method,
    data,
    resume,
    clear_resume_flag,
    store_db,
    check_live,
    filter_live,
    target_domain,
    program,
):
    """Advanced URL checker with status filtering and content analysis"""
    import time

    # Database imports
    try:
        from reconcli.db.operations import store_target, store_urls
    except ImportError:
        store_target = None
        store_urls = None

    # Handle special resume operations
    if clear_resume_flag:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Check if we can read from stdin when no input file provided
    if not input:
        if not sys.stdin.isatty():
            input = "-"  # stdin
        else:
            click.echo("❌ Error: Input file is required for URL checking")
            click.echo(
                "Usage: python urlsorter.py hakcheckurl -i <file> OR echo 'urls' | python urlsorter.py hakcheckurl"
            )
            raise click.Abort()

    # Database setup
    if store_db and not store_target:
        click.echo("⚠️ Database functionality not available (missing dependencies)")
        store_db = False

    if verbose:
        click.echo("[+] 🚀 Starting HakCheckURL")
        click.echo(f"[+] 📁 Input source: {input if input != '-' else 'stdin'}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏱️ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        click.echo(f"[+] ⚡ Rate limit: {rate_limit} req/s")
        click.echo(f"[+] 🌐 Method: {method}")
        if check_live:
            click.echo("[+] 🔍 Live domain checking: enabled")
        if filter_live:
            click.echo("[+] 🔍 Live domain filtering: enabled")
        if store_db:
            click.echo("[+] 💾 Database storage: enabled")

    os.makedirs(output_dir, exist_ok=True)

    # Load URLs
    urls = load_urls_from_source(input)

    if verbose:
        click.echo(f"[+] 🌐 Loaded {len(urls)} URLs for checking")

    # Parse custom headers
    custom_headers = {}
    if headers:
        try:
            custom_headers = json.loads(headers)
        except json.JSONDecodeError:
            click.echo("❌ Error: Invalid JSON format for headers")
            raise click.Abort()

    # Parse status code filters
    allowed_status_codes = parse_status_codes(status_codes) if status_codes else None
    excluded_status_codes = (
        parse_status_codes(exclude_status) if exclude_status else None
    )

    # Parse match lengths
    match_lengths = None
    if match_length:
        try:
            match_lengths = [int(x.strip()) for x in match_length.split(",")]
        except ValueError:
            click.echo("❌ Error: Invalid format for match-length")
            raise click.Abort()

    # Resume functionality
    scan_key = f"hakcheck_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_state = load_resume(output_dir)

    if resume and resume_state:
        # Find most recent incomplete scan
        for key, data in sorted(
            resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True
        ):
            if key.startswith("hakcheck_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "input_file": input,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "processed_urls": [],
            "total_urls": len(urls),
        }
        save_resume_state(output_dir, resume_state)

    # Filter URLs if resuming
    processed_urls = resume_state[scan_key].get("processed_urls", [])
    remaining_urls = [url for url in urls if url not in processed_urls]

    if verbose and resume and processed_urls:
        click.echo(f"[+] 📋 Resuming: {len(remaining_urls)}/{len(urls)} URLs remaining")

    # Perform URL checking
    start_time = time.time()
    results = check_urls_advanced(
        remaining_urls,
        threads=threads,
        timeout=timeout,
        retries=retries,
        user_agent=user_agent,
        custom_headers=custom_headers,
        proxy=proxy,
        follow_redirects=follow_redirects,
        method=method,
        data=data,
        rate_limit=rate_limit,
        verbose=verbose,
        output_dir=output_dir,
        save_responses=save_responses,
        scan_key=scan_key,
        resume_state=resume_state,
    )

    # Add previously processed results if resuming
    if processed_urls:
        # Load previous results
        previous_results_file = os.path.join(
            output_dir, "hakcheck_results_partial.json"
        )
        if os.path.exists(previous_results_file):
            with open(previous_results_file, "r") as f:
                previous_results = json.load(f)
                results.extend(previous_results.get("results", []))

    elapsed_time = time.time() - start_time

    if verbose:
        click.echo(f"[+] ⏱️ URL checking completed in {elapsed_time:.2f}s")

    # Apply filters
    filtered_results = apply_url_filters(
        results,
        allowed_status_codes=allowed_status_codes,
        excluded_status_codes=excluded_status_codes,
        content_length_min=content_length_min,
        content_length_max=content_length_max,
        match_lengths=match_lengths,
        grep_content=grep_content,
        grep_headers=grep_headers,
        verbose=verbose,
    )

    # Perform additional analysis
    analysis_results = {}
    if technologies:
        analysis_results["technologies"] = analyze_technologies(
            filtered_results, verbose
        )

    if security_headers:
        analysis_results["security_headers"] = analyze_security_headers(
            filtered_results, verbose
        )

    # Generate comprehensive statistics
    stats = generate_hakcheck_stats(filtered_results, analysis_results, elapsed_time)

    # Save results
    save_hakcheck_results(
        filtered_results, stats, output_dir, export_json, markdown, verbose
    )

    # Update resume state
    current_scan = resume_state[scan_key]
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()
    current_scan["total_results"] = len(filtered_results)
    save_resume_state(output_dir, resume_state)

    # Summary
    if verbose:
        click.echo("\n[+] 📊 HakCheckURL Summary:")
        click.echo(f"   - Total URLs checked: {len(urls)}")
        click.echo(f"   - Results after filtering: {len(filtered_results)}")
        click.echo(f"   - Processing time: {elapsed_time:.2f}s")
        click.echo(f"   - Average time per URL: {elapsed_time / len(urls):.3f}s")

    click.echo("\n[+] ✅ HakCheckURL completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


def process_urls(
    urls: List[str],
    filter_params: str,
    filter_domains: str,
    exclude_patterns: str,
    min_params: int,
    max_params: int,
    dedupe: bool,
    sort_urls: bool,
    verbose: bool,
) -> List[str]:
    """Process URLs with various filters and transformations"""

    processed = urls.copy()
    original_count = len(processed)

    # Apply domain filter
    if filter_domains:
        domain_regex = re.compile(filter_domains, re.IGNORECASE)
        processed = [
            url for url in processed if domain_regex.search(urlparse(url).netloc)
        ]
        if verbose:
            click.echo(
                f"[+] 🔍 Domain filter: {len(processed)}/{original_count} URLs remaining"
            )

    # Apply parameter filter
    if filter_params:
        param_regex = re.compile(filter_params, re.IGNORECASE)
        processed = [url for url in processed if param_regex.search(url)]
        if verbose:
            click.echo(
                f"[+] 🔍 Parameter filter: {len(processed)}/{original_count} URLs remaining"
            )

    # Apply exclusion patterns
    if exclude_patterns:
        exclude_regex = re.compile(exclude_patterns, re.IGNORECASE)
        processed = [url for url in processed if not exclude_regex.search(url)]
        if verbose:
            click.echo(
                f"[+] 🔍 Exclusion filter: {len(processed)}/{original_count} URLs remaining"
            )

    # Filter by parameter count
    if min_params is not None or max_params is not None:
        filtered = []
        for url in processed:
            parsed = urlparse(url)
            param_count = len(parse_qs(parsed.query))

            if min_params is not None and param_count < min_params:
                continue
            if max_params is not None and param_count > max_params:
                continue
            filtered.append(url)

        processed = filtered
        if verbose:
            click.echo(
                f"[+] 🔍 Parameter count filter: {len(processed)}/{original_count} URLs remaining"
            )

    # Remove duplicates
    if dedupe:
        processed = list(dict.fromkeys(processed))  # Preserves order
        if verbose:
            click.echo(
                f"[+] 🔍 Deduplication: {len(processed)}/{original_count} URLs remaining"
            )

    # Sort URLs
    if sort_urls:
        processed.sort()
        if verbose:
            click.echo("[+] 🔍 URLs sorted alphabetically")

    return processed


def categorize_urls(
    urls: List[str], pattern_dict: Dict[str, str], verbose: bool
) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    """Categorize URLs based on patterns and provide detailed analysis"""

    matches = {k: [] for k in pattern_dict}
    url_details = []

    for url in urls:
        url_analysis = analyze_single_url(url)
        url_details.append(url_analysis)

        for name, regex in pattern_dict.items():
            if re.search(regex, url):
                matches[name].append(url)

    # Generate analysis
    analysis = {
        "url_details": url_details,
        "pattern_matches": {name: len(urls) for name, urls in matches.items()},
        "top_domains": get_top_domains(urls),
        "parameter_analysis": analyze_parameters(urls),
        "file_extension_analysis": analyze_file_extensions(urls),
        "protocol_analysis": analyze_protocols(urls),
    }

    if verbose:
        click.echo("[+] 📊 Analysis completed:")
        for name, count in analysis["pattern_matches"].items():
            if count > 0:
                click.echo(f"   - {name.upper()}: {count} matches")

    return matches, analysis


def analyze_single_url(url: str) -> Dict[str, Any]:
    """Analyze a single URL and extract detailed information"""

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "param_count": len(params),
        "parameter_names": list(params.keys()),
        "has_fragment": bool(parsed.fragment),
        "file_extension": get_file_extension(parsed.path),
        "path_depth": len([p for p in parsed.path.split("/") if p]),
        "suspicious_chars": detect_suspicious_characters(url),
    }


def get_file_extension(path: str) -> str:
    """Extract file extension from URL path"""
    if "." in path:
        return path.split(".")[-1].lower()
    return ""


def detect_suspicious_characters(url: str) -> List[str]:
    """Detect suspicious characters in URL"""
    suspicious = []
    if "%" in url:
        suspicious.append("url_encoded")
    if "<" in url or ">" in url:
        suspicious.append("html_tags")
    if "javascript:" in url.lower():
        suspicious.append("javascript_protocol")
    if re.search(r'[\'"]', url):
        suspicious.append("quotes")
    return suspicious


def get_top_domains(urls: List[str]) -> List[Tuple[str, int]]:
    """Get top domains from URL list"""
    domain_counts = defaultdict(int)
    for url in urls:
        domain = urlparse(url).netloc
        domain_counts[domain] += 1

    return sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]


def analyze_parameters(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL parameters"""
    param_counts = defaultdict(int)
    param_names = defaultdict(int)

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_counts[len(params)] += 1

        for param_name in params.keys():
            param_names[param_name] += 1

    return {
        "parameter_count_distribution": dict(param_counts),
        "most_common_parameters": sorted(
            param_names.items(), key=lambda x: x[1], reverse=True
        )[:20],
        "total_unique_parameters": len(param_names),
    }


def analyze_file_extensions(urls: List[str]) -> Dict[str, int]:
    """Analyze file extensions in URLs"""
    extensions = defaultdict(int)

    for url in urls:
        ext = get_file_extension(urlparse(url).path)
        if ext:
            extensions[ext] += 1

    return dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True))


def analyze_protocols(urls: List[str]) -> Dict[str, int]:
    """Analyze protocols used in URLs"""
    protocols = defaultdict(int)

    for url in urls:
        scheme = urlparse(url).scheme
        protocols[scheme] += 1

    return dict(protocols)


def save_categorized_urls(
    matches: Dict[str, List[str]], output_dir: str, verbose: bool
):
    """Save categorized URLs to separate files"""

    for name, urls in matches.items():
        if urls:
            filepath = os.path.join(output_dir, f"{name}.txt")
            with open(filepath, "w") as f:
                for url in urls:
                    f.write(url + "\n")

            if verbose:
                click.echo(f"[+] 💾 Saved {len(urls)} {name} URLs to {filepath}")


def generate_comprehensive_stats(
    urls: List[str],
    matches: Dict[str, List[str]],
    analysis: Dict[str, Any],
    pattern_dict: Dict[str, str],
) -> Dict[str, Any]:
    """Generate comprehensive statistics"""

    return {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_urls": len(urls),
            "total_patterns": len(pattern_dict),
            "tool": "urlsorter",
        },
        "pattern_matches": {name: len(urls) for name, urls in matches.items()},
        "category_summary": {
            "categories_with_matches": len([k for k, v in matches.items() if v]),
            "total_matches": sum(len(v) for v in matches.values()),
            "unmatched_urls": len(urls) - len(set().union(*matches.values())),
        },
        "url_analysis": analysis,
        "top_categories": sorted(
            [(name, len(urls)) for name, urls in matches.items() if urls],
            key=lambda x: x[1],
            reverse=True,
        )[:10],
    }


def save_json_output(stats: Dict[str, Any], output_dir: str, verbose: bool):
    """Save comprehensive JSON output"""

    json_path = os.path.join(output_dir, "urlsort_results.json")
    with open(json_path, "w") as f:
        json.dump(stats, f, indent=2)

    if verbose:
        click.echo(f"[+] 📄 Saved JSON results to {json_path}")


def save_markdown_output(
    stats: Dict[str, Any], analysis: Dict[str, Any], output_dir: str, verbose: bool
):
    """Save comprehensive Markdown report"""

    md_path = os.path.join(output_dir, "urlsort_report.md")
    with open(md_path, "w") as f:
        f.write("# 🧪 URL Sorter Analysis Report\n\n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total URLs:** {stats['scan_metadata']['total_urls']}\n")
        f.write(f"**Total Patterns:** {stats['scan_metadata']['total_patterns']}\n\n")

        # Pattern matches summary
        f.write("## 📊 Pattern Matches Summary\n\n")
        f.write("| Category | Matches | Description |\n")
        f.write("|----------|---------|-------------|\n")

        category_descriptions = {
            "xss": "Cross-Site Scripting vulnerabilities",
            "sqli": "SQL Injection vulnerabilities",
            "lfi": "Local File Inclusion vulnerabilities",
            "ssrf": "Server-Side Request Forgery vulnerabilities",
            "rce": "Remote Code Execution vulnerabilities",
            "redirect": "Open Redirect vulnerabilities",
            "admin": "Administrative panels and interfaces",
            "api": "API endpoints and services",
            "token": "Authentication tokens and sessions",
            "upload": "File upload functionality",
        }

        for name, count in stats["pattern_matches"].items():
            desc = category_descriptions.get(name, "Security-related patterns")
            f.write(f"| {name.upper()} | {count} | {desc} |\n")

        f.write("\n")

        # Top categories
        f.write("## 🏆 Top Categories\n\n")
        for name, count in stats["top_categories"]:
            f.write(f"- **{name.upper()}**: {count} URLs\n")

        f.write("\n")

        # Domain analysis
        f.write("## 🌐 Domain Analysis\n\n")
        f.write("### Top Domains\n")
        for domain, count in analysis["top_domains"][:5]:
            f.write(f"- {domain}: {count} URLs\n")

        f.write("\n")

        # Parameter analysis
        f.write("## 🔧 Parameter Analysis\n\n")
        param_analysis = analysis["parameter_analysis"]
        f.write(
            f"**Total Unique Parameters:** {param_analysis['total_unique_parameters']}\n\n"
        )

        f.write("### Most Common Parameters\n")
        for param, count in param_analysis["most_common_parameters"][:10]:
            f.write(f"- {param}: {count} occurrences\n")

        f.write("\n")

        # File extensions
        if analysis["file_extension_analysis"]:
            f.write("## 📄 File Extension Analysis\n\n")
            for ext, count in list(analysis["file_extension_analysis"].items())[:10]:
                f.write(f"- .{ext}: {count} files\n")
            f.write("\n")

        # Protocol analysis
        f.write("## 🔒 Protocol Analysis\n\n")
        for protocol, count in analysis["protocol_analysis"].items():
            f.write(f"- {protocol.upper()}: {count} URLs\n")

    if verbose:
        click.echo(f"[+] 📝 Saved Markdown report to {md_path}")


def perform_url_analysis(urls: List[str], verbose: bool) -> Dict[str, Any]:
    """Perform comprehensive URL analysis"""

    if verbose:
        click.echo("[+] 🔍 Analyzing URL structure and patterns...")

    analysis = {
        "total_urls": len(urls),
        "unique_domains": len(set(urlparse(url).netloc for url in urls)),
        "protocol_distribution": analyze_protocols(urls),
        "domain_analysis": {
            "top_domains": get_top_domains(urls),
            "subdomain_analysis": analyze_subdomains(urls),
        },
        "path_analysis": analyze_paths(urls),
        "parameter_analysis": analyze_parameters(urls),
        "file_extension_analysis": analyze_file_extensions(urls),
        "security_indicators": analyze_security_indicators(urls),
        "complexity_analysis": analyze_url_complexity(urls),
    }

    return analysis


def analyze_subdomains(urls: List[str]) -> Dict[str, Any]:
    """Analyze subdomain patterns"""
    subdomains = defaultdict(int)

    for url in urls:
        domain = urlparse(url).netloc
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain = parts[0]
            subdomains[subdomain] += 1

    return {
        "total_subdomains": len(subdomains),
        "most_common_subdomains": sorted(
            subdomains.items(), key=lambda x: x[1], reverse=True
        )[:10],
    }


def analyze_paths(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL path patterns"""
    path_depths = defaultdict(int)
    common_paths = defaultdict(int)

    for url in urls:
        path = urlparse(url).path
        depth = len([p for p in path.split("/") if p])
        path_depths[depth] += 1

        # Analyze first path component
        if path and path != "/":
            first_component = path.split("/")[1] if len(path.split("/")) > 1 else ""
            if first_component:
                common_paths[first_component] += 1

    return {
        "path_depth_distribution": dict(path_depths),
        "most_common_first_paths": sorted(
            common_paths.items(), key=lambda x: x[1], reverse=True
        )[:10],
        "average_path_depth": (
            sum(k * v for k, v in path_depths.items()) / len(urls) if urls else 0
        ),
    }


def analyze_security_indicators(urls: List[str]) -> Dict[str, Any]:
    """Analyze security-related indicators in URLs"""
    indicators = {
        "potentially_vulnerable": 0,
        "suspicious_parameters": 0,
        "encoded_content": 0,
        "javascript_protocols": 0,
        "long_urls": 0,
        "unusual_characters": 0,
    }

    for url in urls:
        if len(url) > 500:
            indicators["long_urls"] += 1

        if "%" in url:
            indicators["encoded_content"] += 1

        if "javascript:" in url.lower():
            indicators["javascript_protocols"] += 1

        if re.search(r'[<>"\'&]', url):
            indicators["unusual_characters"] += 1

        # Check for suspicious parameter patterns
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        suspicious_params = [
            "cmd",
            "exec",
            "eval",
            "system",
            "shell",
            "id",
            "cat",
            "ls",
        ]
        if any(param.lower() in suspicious_params for param in params.keys()):
            indicators["suspicious_parameters"] += 1

        # General vulnerability indicators
        vuln_patterns = [
            r"\.\./",
            r"<script",
            r"javascript:",
            r"SELECT.*FROM",
            r"UNION.*SELECT",
        ]
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in vuln_patterns):
            indicators["potentially_vulnerable"] += 1

    return indicators


def analyze_url_complexity(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL complexity metrics"""
    lengths = [len(url) for url in urls]
    param_counts = []

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_counts.append(len(params))

    return {
        "length_statistics": {
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0,
            "average_length": sum(lengths) / len(lengths) if lengths else 0,
        },
        "parameter_statistics": {
            "min_params": min(param_counts) if param_counts else 0,
            "max_params": max(param_counts) if param_counts else 0,
            "average_params": (
                sum(param_counts) / len(param_counts) if param_counts else 0
            ),
        },
    }


def save_analysis_json(analysis: Dict[str, Any], output_dir: str, verbose: bool):
    """Save analysis results to JSON"""

    json_path = os.path.join(output_dir, "url_analysis.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "analysis_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tool": "urlsorter-analyze",
                },
                "analysis_results": analysis,
            },
            f,
            indent=2,
        )

    if verbose:
        click.echo(f"[+] 📄 Saved analysis JSON to {json_path}")


def save_analysis_markdown(analysis: Dict[str, Any], output_dir: str, verbose: bool):
    """Save analysis results to Markdown"""

    md_path = os.path.join(output_dir, "url_analysis_report.md")
    with open(md_path, "w") as f:
        f.write("# 🔍 URL Analysis Report\n\n")
        f.write(
            f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # Overview
        f.write("## 📊 Overview\n\n")
        f.write(f"- **Total URLs:** {analysis['total_urls']}\n")
        f.write(f"- **Unique Domains:** {analysis['unique_domains']}\n")
        f.write(
            f"- **Average URL Length:** {analysis['complexity_analysis']['length_statistics']['average_length']:.1f}\n"
        )
        f.write(
            f"- **Average Parameters:** {analysis['complexity_analysis']['parameter_statistics']['average_params']:.1f}\n\n"
        )

        # Security indicators
        f.write("## 🚨 Security Indicators\n\n")
        security = analysis["security_indicators"]
        f.write(
            f"- **Potentially Vulnerable URLs:** {security['potentially_vulnerable']}\n"
        )
        f.write(f"- **Suspicious Parameters:** {security['suspicious_parameters']}\n")
        f.write(f"- **URLs with Encoded Content:** {security['encoded_content']}\n")
        f.write(f"- **JavaScript Protocol URLs:** {security['javascript_protocols']}\n")
        f.write(f"- **Long URLs (>500 chars):** {security['long_urls']}\n")
        f.write(
            f"- **URLs with Unusual Characters:** {security['unusual_characters']}\n\n"
        )

        # Domain analysis
        f.write("## 🌐 Domain Analysis\n\n")
        f.write("### Top Domains\n")
        for domain, count in analysis["domain_analysis"]["top_domains"][:10]:
            f.write(f"- {domain}: {count} URLs\n")
        f.write("\n")

        # Path analysis
        f.write("## 📁 Path Analysis\n\n")
        path_analysis = analysis["path_analysis"]
        f.write(
            f"**Average Path Depth:** {path_analysis['average_path_depth']:.1f}\n\n"
        )
        f.write("### Most Common First Path Components\n")
        for path, count in path_analysis["most_common_first_paths"]:
            f.write(f"- /{path}: {count} URLs\n")
        f.write("\n")

        # Parameter analysis
        f.write("## 🔧 Parameter Analysis\n\n")
        param_analysis = analysis["parameter_analysis"]
        f.write(
            f"**Total Unique Parameters:** {param_analysis['total_unique_parameters']}\n\n"
        )
        f.write("### Most Common Parameters\n")
        for param, count in param_analysis["most_common_parameters"][:15]:
            f.write(f"- {param}: {count} occurrences\n")

    if verbose:
        click.echo(f"[+] 📝 Saved analysis report to {md_path}")


def show_resume_status(output_dir: str, tool_prefix: str):
    """Show status of previous scans from resume file"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    matching_scans = [k for k in resume_state.keys() if k.startswith(tool_prefix)]

    if not matching_scans:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    click.echo(f"[+] Found {len(matching_scans)} previous scan(s):")
    click.echo()

    for scan_key in matching_scans:
        scan_data = resume_state[scan_key]
        click.echo(f"🔍 Scan: {scan_key}")
        click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")
        click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

        if scan_data.get("completed"):
            click.echo("   Status: ✅ Completed")
            click.echo(f"   Completed: {scan_data.get('completion_time', 'unknown')}")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
        else:
            click.echo("   Status: ⏳ Incomplete")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

        click.echo()


def check_live_domains(urls: List[str]) -> List[str]:
    """Check which domains are live using DNS resolution."""
    live_urls = []

    for url in urls:
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc

            # Skip if no domain
            if not domain:
                continue

            # Remove port if present
            if ":" in domain and not domain.startswith("["):  # IPv6 addresses
                domain = domain.split(":")[0]

            # Try to resolve the domain
            try:
                socket.gethostbyname(domain)
                live_urls.append(url)
            except socket.gaierror:
                # Domain doesn't resolve
                continue

        except Exception:
            # Invalid URL or other error, skip
            continue

    return live_urls


def parse_status_codes(status_str: str) -> List[int]:
    """Parse status code strings like '200,201,302' or '2xx,3xx'"""
    codes = []
    for code in status_str.split(","):
        code = code.strip()
        if code.endswith("xx"):
            # Range like 2xx, 3xx, 4xx, 5xx
            base = int(code[0]) * 100
            codes.extend(range(base, base + 100))
        else:
            try:
                codes.append(int(code))
            except ValueError:
                continue
    return codes


def check_urls_advanced(
    urls: List[str],
    threads: int = 10,
    timeout: int = 10,
    retries: int = 3,
    user_agent: str = "HakCheckURL/1.0",
    custom_headers: Dict[str, str] = None,
    proxy: str = None,
    follow_redirects: bool = False,
    method: str = "GET",
    data: str = None,
    rate_limit: int = 50,
    verbose: bool = False,
    output_dir: str = None,
    save_responses: bool = False,
    scan_key: str = None,
    resume_state: Dict = None,
    store_db: bool = False,
    check_live: bool = False,
    filter_live: bool = False,
    target_domain: str = None,
    program: str = None,
) -> List[Dict[str, Any]]:
    """Advanced URL checking with concurrent requests"""
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    import httpx

    results = []
    processed_count = 0
    total_urls = len(urls)

    # Live domain checking
    if check_live or filter_live:
        if verbose:
            click.echo(f"[+] 🔍 Checking {total_urls} domains for DNS resolution...")
        live_urls = check_live_domains(urls)
        if verbose:
            click.echo(
                f"[+] ✅ Found {len(live_urls)} live domains out of {total_urls}"
            )

        if filter_live:
            urls = live_urls
            total_urls = len(urls)
            if verbose:
                click.echo(f"[+] 🔍 Filtered to {total_urls} live domains")

    # Database storage initialization
    db_available = False
    if store_db:
        try:
            from reconcli.db.operations import store_target, store_urls

            db_available = True
            if verbose:
                click.echo("[+] 💾 Database storage initialized")

            # Store target if provided
            if target_domain:
                target_id = store_target(target_domain, program or "URLSorter")
                if verbose:
                    click.echo(f"[+] 💾 Stored target: {target_domain}")
        except ImportError:
            if verbose:
                click.echo("[!] ⚠️  Database not available, skipping storage")

    # Rate limiting
    request_delay = 1.0 / rate_limit if rate_limit > 0 else 0
    last_request_time = 0

    # Setup HTTP client
    client_kwargs = {
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": follow_redirects,
        "verify": False,  # Skip SSL verification
    }

    if proxy:
        client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

    # Prepare headers
    headers = {"User-Agent": user_agent}
    if custom_headers:
        headers.update(custom_headers)

    def check_single_url(url: str) -> Dict[str, Any]:
        """Check a single URL and return detailed results"""
        nonlocal last_request_time, processed_count

        result = {
            "url": url,
            "status_code": None,
            "content_length": None,
            "response_time": None,
            "headers": {},
            "technologies": [],
            "security_headers": {},
            "error": None,
            "timestamp": datetime.now().isoformat(),
        }

        # Rate limiting
        current_time = time.time()
        if request_delay > 0:
            time_since_last = current_time - last_request_time
            if time_since_last < request_delay:
                time.sleep(request_delay - time_since_last)
        last_request_time = time.time()

        for attempt in range(retries + 1):
            try:
                with httpx.Client(**client_kwargs) as client:
                    start_time = time.time()

                    if method == "GET":
                        response = client.get(url, headers=headers)
                    elif method == "POST":
                        response = client.post(url, headers=headers, data=data)
                    elif method == "HEAD":
                        response = client.head(url, headers=headers)
                    elif method == "OPTIONS":
                        response = client.options(url, headers=headers)
                    elif method == "PUT":
                        response = client.put(url, headers=headers, data=data)
                    elif method == "DELETE":
                        response = client.delete(url, headers=headers)
                    else:
                        response = client.get(url, headers=headers)

                    result["response_time"] = round(
                        (time.time() - start_time) * 1000, 2
                    )
                    result["status_code"] = response.status_code
                    result["content_length"] = len(response.content)
                    result["headers"] = dict(response.headers)

                    # Save response content if requested
                    if save_responses and output_dir:
                        safe_filename = (
                            url.replace("/", "_")
                            .replace(":", "_")
                            .replace("?", "_")[:100]
                        )
                        response_file = os.path.join(
                            output_dir,
                            "responses",
                            f"{safe_filename}_{response.status_code}.txt",
                        )
                        os.makedirs(os.path.dirname(response_file), exist_ok=True)
                        with open(
                            response_file, "w", encoding="utf-8", errors="ignore"
                        ) as f:
                            f.write(f"URL: {url}\n")
                            f.write(f"Status: {response.status_code}\n")
                            f.write(f"Headers:\n{response.headers}\n\n")
                            f.write(f"Content:\n{response.text}")

                    break  # Success, exit retry loop

            except (
                httpx.ConnectError,
                httpx.TimeoutException,
                httpx.RequestError,
            ) as e:
                if attempt < retries:
                    if verbose:
                        click.echo(
                            f"[!] Retry {attempt + 1}/{retries} for {url}: {str(e)[:100]}"
                        )
                    time.sleep(1)  # Wait before retry
                    continue
                else:
                    result["error"] = str(e)
                    if verbose:
                        click.echo(
                            f"[!] Failed after {retries} retries: {url} - {str(e)[:100]}"
                        )
                    break
            except Exception as e:
                result["error"] = str(e)
                if verbose:
                    click.echo(f"[!] Unexpected error for {url}: {str(e)[:100]}")
                break

        processed_count += 1

        # Progress indicator
        if verbose and processed_count % 50 == 0:
            click.echo(
                f"[+] Progress: {processed_count}/{total_urls} ({processed_count / total_urls * 100:.1f}%)"
            )

        # Update resume state periodically
        if scan_key and resume_state and processed_count % 100 == 0:
            try:
                resume_state[scan_key]["processed_urls"].append(url)
                save_resume_state(output_dir, resume_state)
            except Exception:
                pass

        return result

    # Execute URL checking with thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_single_url, url): url for url in urls}

        for future in as_completed(future_to_url):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                url = future_to_url[future]
                if verbose:
                    click.echo(f"[!] Exception processing {url}: {e}")
                results.append(
                    {
                        "url": url,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

    # Store results in database if enabled
    if store_db and db_available and results:
        try:
            urls_to_store = []
            for result in results:
                if result.get("status_code"):
                    urls_to_store.append(
                        {
                            "url": result["url"],
                            "status_code": result["status_code"],
                            "response_time": result.get("response_time"),
                            "content_length": result.get("content_length"),
                            "title": result.get("title", ""),
                            "technologies": ",".join(result.get("technologies", [])),
                            "source": "hakcheckurl",
                        }
                    )

            if urls_to_store:
                store_urls(urls_to_store, target_domain or "unknown")
                if verbose:
                    click.echo(
                        f"[+] 💾 Stored {len(urls_to_store)} URL results in database"
                    )

        except Exception as e:
            if verbose:
                click.echo(f"[!] ⚠️  Database storage failed: {e}")

    return results


def apply_url_filters(
    results: List[Dict[str, Any]],
    allowed_status_codes: List[int] = None,
    excluded_status_codes: List[int] = None,
    content_length_min: int = None,
    content_length_max: int = None,
    match_lengths: List[int] = None,
    grep_content: str = None,
    grep_headers: str = None,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """Apply various filters to URL checking results"""
    import re

    filtered = []
    original_count = len(results)

    for result in results:
        # Skip if there was an error and no status code
        if result.get("error") and not result.get("status_code"):
            continue

        status_code = result.get("status_code")
        content_length = result.get("content_length")

        # Status code filters
        if allowed_status_codes and status_code not in allowed_status_codes:
            continue

        if excluded_status_codes and status_code in excluded_status_codes:
            continue

        # Content length filters
        if content_length_min is not None and (
            content_length is None or content_length < content_length_min
        ):
            continue

        if content_length_max is not None and (
            content_length is None or content_length > content_length_max
        ):
            continue

        # Match specific lengths
        if match_lengths and (
            content_length is None or content_length not in match_lengths
        ):
            continue

        # Grep filters (would need response content - placeholder for now)
        if grep_content:
            # This would require storing response content
            pass

        if grep_headers:
            headers_str = json.dumps(result.get("headers", {}))
            if not re.search(grep_headers, headers_str, re.IGNORECASE):
                continue

        filtered.append(result)

    if verbose:
        click.echo(
            f"[+] 🔍 Filtering: {len(filtered)}/{original_count} results passed filters"
        )

    return filtered


def analyze_technologies(
    results: List[Dict[str, Any]], verbose: bool = False
) -> Dict[str, Any]:
    """Analyze web technologies from HTTP headers"""
    technologies = defaultdict(int)
    servers = defaultdict(int)
    frameworks = defaultdict(int)

    for result in results:
        headers = result.get("headers", {})

        # Server detection
        server = headers.get("server", "").lower()
        if server:
            servers[server] += 1

        # Framework detection from headers
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower()

            # Common technology indicators
            if "php" in value_lower:
                technologies["PHP"] += 1
            elif "asp.net" in value_lower:
                technologies["ASP.NET"] += 1
            elif "express" in value_lower:
                technologies["Express.js"] += 1
            elif "nginx" in value_lower:
                technologies["Nginx"] += 1
            elif "apache" in value_lower:
                technologies["Apache"] += 1
            elif "cloudflare" in value_lower:
                technologies["Cloudflare"] += 1
            elif "wordpress" in value_lower:
                technologies["WordPress"] += 1

    analysis = {
        "total_responses": len(results),
        "technologies": dict(technologies),
        "servers": dict(servers),
        "frameworks": dict(frameworks),
    }

    if verbose:
        click.echo("[+] 🔧 Technology analysis completed")
        for tech, count in sorted(
            technologies.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            click.echo(f"   - {tech}: {count} instances")

    return analysis


def analyze_security_headers(
    results: List[Dict[str, Any]], verbose: bool = False
) -> Dict[str, Any]:
    """Analyze security headers in HTTP responses"""
    security_headers = {
        "strict-transport-security": 0,
        "content-security-policy": 0,
        "x-frame-options": 0,
        "x-content-type-options": 0,
        "x-xss-protection": 0,
        "referrer-policy": 0,
        "permissions-policy": 0,
        "expect-ct": 0,
    }

    total_responses = len([r for r in results if r.get("status_code")])

    for result in results:
        headers = result.get("headers", {})

        for header_name in security_headers.keys():
            if any(h.lower() == header_name for h in headers.keys()):
                security_headers[header_name] += 1

    # Calculate percentages
    security_analysis = {
        "total_responses": total_responses,
        "security_headers": security_headers,
        "security_score": (
            sum(security_headers.values())
            / (len(security_headers) * total_responses)
            * 100
            if total_responses > 0
            else 0
        ),
    }

    if verbose:
        click.echo("[+] 🔒 Security headers analysis completed")
        click.echo(f"   - Security score: {security_analysis['security_score']:.1f}%")
        for header, count in security_headers.items():
            percentage = (count / total_responses * 100) if total_responses > 0 else 0
            click.echo(f"   - {header}: {count}/{total_responses} ({percentage:.1f}%)")

    return security_analysis


def generate_hakcheck_stats(
    results: List[Dict[str, Any]], analysis_results: Dict[str, Any], elapsed_time: float
) -> Dict[str, Any]:
    """Generate comprehensive statistics for hakcheckurl results"""

    # Status code analysis
    status_codes = defaultdict(int)
    response_times = []
    content_lengths = []
    errors = []

    for result in results:
        if result.get("status_code"):
            status_codes[result["status_code"]] += 1

        if result.get("response_time"):
            response_times.append(result["response_time"])

        if result.get("content_length"):
            content_lengths.append(result["content_length"])

        if result.get("error"):
            errors.append(result["error"])

    stats = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_urls": len(results),
            "successful_requests": len([r for r in results if r.get("status_code")]),
            "failed_requests": len(errors),
            "elapsed_time": elapsed_time,
            "tool": "hakcheckurl",
        },
        "status_code_distribution": dict(status_codes),
        "response_time_stats": {
            "min": min(response_times) if response_times else 0,
            "max": max(response_times) if response_times else 0,
            "average": (
                sum(response_times) / len(response_times) if response_times else 0
            ),
        },
        "content_length_stats": {
            "min": min(content_lengths) if content_lengths else 0,
            "max": max(content_lengths) if content_lengths else 0,
            "average": (
                sum(content_lengths) / len(content_lengths) if content_lengths else 0
            ),
        },
        "analysis_results": analysis_results,
        "top_status_codes": sorted(
            status_codes.items(), key=lambda x: x[1], reverse=True
        )[:10],
        "error_summary": {
            "total_errors": len(errors),
            "unique_errors": len(set(errors)),
        },
    }

    return stats


def save_hakcheck_results(
    results: List[Dict[str, Any]],
    stats: Dict[str, Any],
    output_dir: str,
    export_json: bool,
    markdown: bool,
    verbose: bool,
):
    """Save hakcheckurl results to various formats"""

    # Save individual status code files
    status_groups = defaultdict(list)
    for result in results:
        if result.get("status_code"):
            status_groups[result["status_code"]].append(result["url"])

    for status_code, urls in status_groups.items():
        status_file = os.path.join(output_dir, f"status_{status_code}.txt")
        with open(status_file, "w") as f:
            for url in urls:
                f.write(url + "\n")

        if verbose:
            click.echo(
                f"[+] 💾 Saved {len(urls)} URLs with status {status_code} to {status_file}"
            )

    # Save comprehensive results
    if export_json:
        json_path = os.path.join(output_dir, "hakcheck_results.json")
        with open(json_path, "w") as f:
            json.dump(
                {
                    "results": results,
                    "statistics": stats,
                },
                f,
                indent=2,
            )

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

    if markdown:
        md_path = os.path.join(output_dir, "hakcheck_report.md")
        with open(md_path, "w") as f:
            f.write("# 🔍 HakCheckURL Report\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total URLs:** {stats['scan_metadata']['total_urls']}\n")
            f.write(
                f"**Successful Requests:** {stats['scan_metadata']['successful_requests']}\n"
            )
            f.write(
                f"**Failed Requests:** {stats['scan_metadata']['failed_requests']}\n"
            )
            f.write(f"**Scan Time:** {stats['scan_metadata']['elapsed_time']:.2f}s\n\n")

            # Status code distribution
            f.write("## 📊 Status Code Distribution\n\n")
            f.write("| Status Code | Count | Percentage |\n")
            f.write("|-------------|-------|------------|\n")

            total_successful = stats["scan_metadata"]["successful_requests"]
            for status, count in stats["top_status_codes"]:
                percentage = (
                    (count / total_successful * 100) if total_successful > 0 else 0
                )
                f.write(f"| {status} | {count} | {percentage:.1f}% |\n")

            f.write("\n")

            # Response time statistics
            f.write("## ⏱️ Response Time Statistics\n\n")
            rt_stats = stats["response_time_stats"]
            f.write(f"- **Minimum:** {rt_stats['min']:.2f}ms\n")
            f.write(f"- **Maximum:** {rt_stats['max']:.2f}ms\n")
            f.write(f"- **Average:** {rt_stats['average']:.2f}ms\n\n")

            # Content length statistics
            f.write("## 📏 Content Length Statistics\n\n")
            cl_stats = stats["content_length_stats"]
            f.write(f"- **Minimum:** {cl_stats['min']} bytes\n")
            f.write(f"- **Maximum:** {cl_stats['max']} bytes\n")
            f.write(f"- **Average:** {cl_stats['average']:.0f} bytes\n\n")

            # Technology analysis if available
            if "technologies" in stats["analysis_results"]:
                tech_analysis = stats["analysis_results"]["technologies"]
                f.write("## 🔧 Technology Analysis\n\n")
                for tech, count in sorted(
                    tech_analysis["technologies"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]:
                    f.write(f"- **{tech}:** {count} instances\n")
                f.write("\n")

            # Security headers if available
            if "security_headers" in stats["analysis_results"]:
                sec_analysis = stats["analysis_results"]["security_headers"]
                f.write("## 🔒 Security Headers Analysis\n\n")
                f.write(
                    f"**Security Score:** {sec_analysis['security_score']:.1f}%\n\n"
                )
                for header, count in sec_analysis["security_headers"].items():
                    percentage = (
                        (count / sec_analysis["total_responses"] * 100)
                        if sec_analysis["total_responses"] > 0
                        else 0
                    )
                    f.write(
                        f"- **{header}:** {count}/{sec_analysis['total_responses']} ({percentage:.1f}%)\n"
                    )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown report to {md_path}")


# Backward compatibility
run_urlsort = sort

if __name__ == "__main__":
    cli()
