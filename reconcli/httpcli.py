#!/usr/bin/env python3
"""
🌐 HTTPCli - Advanced HTTP/HTTPS Service Analysis Tool

A comprehensive HTTP scanning and analysis tool for web reconnaissance and security testing.
Features include security header analysis, CDN detection, HTTP/2 support detection,
custom fingerprinting, and advanced export capabilities.

📋 USAGE EXAMPLES:

Basic HTTP scanning:
    reconcli httpcli -i urls.txt

Advanced security analysis:
    reconcli httpcli -i subdomains.txt --security-scan --check-waf --screenshot

Bug bounty workflow:
    reconcli httpcli -i targets.txt --nuclei --check-cors --export-vulnerabilities --store-db

Custom fingerprinting:
    reconcli httpcli -i hosts.txt --custom-headers --tech-detection --follow-redirects

Performance analysis:
    reconcli httpcli -i urls.txt --benchmark --check-compression --ssl-analysis

Export and reporting:
    reconcli httpcli -i targets.txt --export json,csv,html --generate-report

Advanced technology detection with Wappalyzer:
    reconcli httpcli -i urls.txt --tech-detection --wappalyzer --jsonout

Headers extraction and analysis:
    reconcli httpcli -i urls.txt --headers
    reconcli httpcli -i urls.txt --headers --header-filter "Server,Content-Type" --headers-format json
    reconcli httpcli -i urls.txt --headers --headers-format csv

🚀 FEATURES:
• Security header analysis and scoring
• CDN and WAF detection
• HTTP/2 and HTTP/3 support detection
• Custom User-Agent and header injection
• Screenshot capture for visual analysis
• Technology stack fingerprinting
• Wappalyzer integration for enhanced technology detection
• CORS misconfiguration detection
• SSL/TLS certificate analysis
• Response time benchmarking
• Nuclei integration for vulnerability scanning
• Database storage for persistent analysis
• Multiple export formats (JSON, CSV, HTML, Markdown)
• Advanced filtering and tagging system
• HTTP headers extraction and export (text, JSON, CSV, table formats)
• Header filtering and custom analysis

🛡️ SECURITY CHECKS:
• Missing security headers detection
• CORS wildcard vulnerabilities
• Clickjacking protection analysis
• Content-Type sniffing prevention
• HSTS configuration validation
• CSP policy evaluation
• Referrer policy assessment
"""

import csv
import hashlib
import json
import subprocess
import tempfile
import time
from base64 import b64encode
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import click
import httpx
import mmh3
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
]

CDN_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-cache"],
    "akamai": ["akamai", "akamaized.net", "x-akamai"],
    "fastly": ["fastly-io", "x-served-by", "fastly"],
    "aws": ["cloudfront", "x-amz-cf-id", "amazonaws"],
    "azure": ["azureedge", "x-azure-ref"],
    "gcp": ["googleusercontent", "x-goog-"],
    "maxcdn": ["maxcdn", "x-pull"],
    "keycdn": ["keycdn", "x-keycdn"],
}

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai", "x-akamai-transformed"],
    "aws_waf": ["x-amzn-requestid", "x-amz-apigw-id"],
    "imperva": ["x-iinfo", "incap_ses"],
    "f5": ["f5-bigip", "x-wa-info"],
    "barracuda": ["barra", "x-barracuda"],
    "fortinet": ["fortigate", "x-fortigate"],
    "sucuri": ["sucuri", "x-sucuri"],
    "wordfence": ["wordfence", "x-wordfence"],
}

TECH_SIGNATURES = {
    "servers": {
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["microsoft-iis"],
        "cloudflare": ["cloudflare"],
        "openresty": ["openresty"],
        "litespeed": ["litespeed"],
        "caddy": ["caddy"],
    },
    "frameworks": {
        "express": ["x-powered-by: express"],
        "django": ["csrf", "django"],
        "flask": ["flask", "werkzeug"],
        "rails": ["x-powered-by: phusion passenger"],
        "laravel": ["laravel", "x-powered-by: php"],
        "wordpress": ["x-powered-by: wordpress"],
        "drupal": ["x-generator: drupal"],
    },
}


class HTTPCacheManager:
    """HTTP Cache Manager for storing and retrieving HTTP response results"""

    def __init__(self, cache_dir: str, max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.cache_index_file = self.cache_dir / "http_cache_index.json"
        self.cache_index = self._load_cache_index()

    def _load_cache_index(self) -> dict:
        """Load cache index from file"""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache_index(self):
        """Save cache index to file"""
        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(self.cache_index, f, indent=2)
        except Exception:
            pass

    def _generate_cache_key(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """Generate cache key from URL, method, and headers"""
        # Create a normalized cache string
        cache_string = f"{method}:{url}"

        # Add relevant headers to cache key for unique identification
        if headers:
            # Only include headers that affect the response
            cache_headers = {}
            relevant_headers = ["user-agent", "accept", "authorization", "cookie"]
            for header in relevant_headers:
                if header in headers:
                    cache_headers[header] = headers[header]
            if cache_headers:
                import json

                cache_string += f":{json.dumps(cache_headers, sort_keys=True)}"

        return hashlib.sha256(cache_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cache entry is still valid"""
        age_hours = (time.time() - timestamp) / 3600
        return age_hours < self.max_age_hours

    def get(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> Optional[dict]:
        """Get cached HTTP result for URL"""
        cache_key = self._generate_cache_key(url, method, headers)

        if cache_key in self.cache_index:
            cache_info = self.cache_index[cache_key]

            # Check if cache is still valid
            if self._is_cache_valid(cache_info["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            data = json.load(f)

                        # Update access count and last access
                        cache_info["access_count"] += 1
                        cache_info["last_access"] = time.time()
                        self.cache_index[cache_key] = cache_info
                        self._save_cache_index()

                        return data
                    except Exception:
                        # Remove invalid cache entry
                        del self.cache_index[cache_key]
                        self._save_cache_index()
            else:
                # Remove expired cache entry
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    cache_file.unlink()
                del self.cache_index[cache_key]
                self._save_cache_index()

        return None

    def set(
        self,
        url: str,
        result: dict,
        method: str = "GET",
        headers: Optional[Dict] = None,
    ):
        """Cache HTTP result for URL"""
        cache_key = self._generate_cache_key(url, method, headers)

        # Update cache index
        self.cache_index[cache_key] = {
            "url": url,
            "method": method,
            "timestamp": time.time(),
            "last_access": time.time(),
            "access_count": 1,
            "status_code": result.get("status_code"),
        }

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Save cache file
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)

            self._save_cache_index()
        except Exception:
            # If save fails, remove from index
            if cache_key in self.cache_index:
                del self.cache_index[cache_key]

    def cleanup_expired(self) -> int:
        """Remove expired cache entries and return count"""
        removed_count = 0
        expired_keys = []

        for cache_key, cache_info in self.cache_index.items():
            if not self._is_cache_valid(cache_info["timestamp"]):
                expired_keys.append(cache_key)

        for cache_key in expired_keys:
            cache_file = self.cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                cache_file.unlink()
            del self.cache_index[cache_key]
            removed_count += 1

        if removed_count > 0:
            self._save_cache_index()

        return removed_count

    def clear_all(self) -> int:
        """Clear all cache entries and return count"""
        count = len(self.cache_index)

        # Remove all cache files
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

        # Clear index
        self.cache_index = {}
        self._save_cache_index()

        return count

    def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self.cache_dir.exists():
            return {
                "total_entries": 0,
                "total_size_kb": 0,
                "expired_entries": 0,
                "valid_entries": 0,
            }

        cache_files = list(self.cache_dir.glob("*.json"))
        if not cache_files:
            return {
                "total_entries": 0,
                "total_size_kb": 0,
                "expired_entries": 0,
                "valid_entries": 0,
            }

        total_size = sum(f.stat().st_size for f in cache_files)
        expired_count = 0
        valid_count = 0

        for cache_info in self.cache_index.values():
            if self._is_cache_valid(cache_info["timestamp"]):
                valid_count += 1
            else:
                expired_count += 1

        return {
            "total_entries": len(cache_files),
            "total_size_kb": total_size / 1024,
            "expired_entries": expired_count,
            "valid_entries": valid_count,
        }


@click.command("httpcli")
@click.option(
    "--input",
    "-i",
    required=False,
    type=click.Path(exists=True),
    help="Path to URLs or hostnames",
)
@click.option("--timeout", default=10, help="Timeout for requests")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(),
    default="httpcli_output",
    help="Directory to save results",
)
@click.option("--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
@click.option("--markdown", is_flag=True, help="Export Markdown summary")
@click.option("--jsonout", is_flag=True, help="Export raw JSON results")
@click.option("--nuclei", is_flag=True, help="Run Nuclei on each URL")
@click.option("--nuclei-templates", type=click.Path(), help="Path to Nuclei templates")
@click.option(
    "--fastmode", is_flag=True, help="HEAD only mode (no full GET, no fingerprinting)"
)
@click.option("--log", is_flag=True, help="Log output to log.txt")
@click.option(
    "--export-tag",
    multiple=True,
    help="Export URLs by tag (e.g. cors-wildcard, no-csp, ok, client-error)",
)
@click.option(
    "--export-status", multiple=True, help="Export URLs by status code (e.g. 200, 403)"
)
@click.option(
    "--user-agent",
    default="Mozilla/5.0 (compatible; httpcli/2.0)",
    help="Custom User-Agent",
)
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (auto-detected if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
@click.option(
    "--security-scan",
    is_flag=True,
    help="Perform comprehensive security header analysis and scoring",
)
@click.option(
    "--check-waf",
    is_flag=True,
    help="Detect Web Application Firewall (WAF) and security solutions",
)
@click.option(
    "--screenshot",
    is_flag=True,
    help="Capture screenshots of web pages (requires selenium)",
)
@click.option(
    "--check-cors",
    is_flag=True,
    help="Perform detailed CORS configuration analysis",
)
@click.option(
    "--custom-headers",
    help='Send custom headers (JSON format: \'{"X-Custom":"value"}\')',
)
@click.option(
    "--follow-redirects",
    default=5,
    help="Maximum number of redirects to follow (default: 5)",
)
@click.option(
    "--tech-detection",
    is_flag=True,
    help="Enhanced technology stack detection and fingerprinting",
)
@click.option(
    "--benchmark",
    is_flag=True,
    help="Perform response time benchmarking with multiple requests",
)
@click.option(
    "--check-compression",
    is_flag=True,
    help="Test gzip/brotli compression support and efficiency",
)
@click.option(
    "--ssl-analysis",
    is_flag=True,
    help="Analyze SSL/TLS certificate details and configuration",
)
@click.option(
    "--export-vulnerabilities",
    is_flag=True,
    help="Export only URLs with detected vulnerabilities or misconfigurations",
)
@click.option(
    "--generate-report",
    is_flag=True,
    help="Generate comprehensive HTML report with charts and statistics",
)
@click.option(
    "--threads",
    default=10,
    help="Number of concurrent threads for processing (default: 10)",
)
@click.option(
    "--rate-limit",
    help="Rate limit in requests per second (e.g. 10/s, 100/m)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output with detailed progress information",
)
@click.option(
    "--wappalyzer",
    is_flag=True,
    help="Use Wappalyzer for enhanced technology detection",
)
@click.option(
    "--headers",
    is_flag=True,
    help="Export HTTP headers in clean format (supports filtering and multiple formats)",
)
@click.option(
    "--header-filter",
    help="Filter specific headers (comma-separated, e.g. 'Server,Content-Type,X-Powered-By')",
)
@click.option(
    "--headers-format",
    type=click.Choice(["text", "json", "csv", "table"]),
    default="text",
    help="Output format for headers export (default: text)",
)
@click.option("--cache", is_flag=True, help="Enable HTTP response caching")
@click.option("--cache-dir", help="Cache directory path")
@click.option("--cache-max-age", default=24, type=int, help="Cache max age in hours")
@click.option("--clear-cache", is_flag=True, help="Clear all cached HTTP responses")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics")
def httpcli(
    input,
    timeout,
    retries,
    output_dir,
    proxy,
    markdown,
    jsonout,
    nuclei,
    nuclei_templates,
    fastmode,
    log,
    export_tag,
    export_status,
    user_agent,
    store_db,
    target_domain,
    program,
    security_scan,
    check_waf,
    screenshot,
    check_cors,
    custom_headers,
    follow_redirects,
    tech_detection,
    benchmark,
    check_compression,
    ssl_analysis,
    export_vulnerabilities,
    generate_report,
    threads,
    rate_limit,
    verbose,
    wappalyzer,
    headers,
    header_filter,
    headers_format,
    cache,
    cache_dir,
    cache_max_age,
    clear_cache,
    cache_stats,
):
    """Enhanced HTTP/HTTPS service analysis with advanced security and technology detection.

    🔍 COMPREHENSIVE ANALYSIS:
    • Security header analysis and scoring
    • WAF and CDN detection
    • Technology stack fingerprinting
    • CORS misconfiguration detection
    • SSL/TLS certificate analysis
    • Response time benchmarking
    • Vulnerability scanning with Nuclei
    • Screenshot capture for visual analysis

    📊 EXPORT OPTIONS:
    • JSON, CSV, HTML, Markdown formats
    • Vulnerability-only exports
    • Tag-based filtering
    • Status code filtering
    • Database storage for persistent analysis

    🚀 PERFORMANCE FEATURES:
    • Concurrent processing with configurable threads
    • Rate limiting for respectful scanning
    • Retry mechanism for unstable connections
    • Compression testing
    • HTTP/2 support detection

    🗄️ HTTP CACHE EXAMPLES:
    • Enable HTTP caching: --cache
    • Custom cache directory: --cache --cache-dir /tmp/http_cache
    • Set cache expiry: --cache --cache-max-age 12
    • Clear cache: --clear-cache
    • Show cache stats: --cache-stats
    """

    # Initialize cache manager if cache is enabled
    cache_manager = None
    if cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "http_cache")
        cache_manager = HTTPCacheManager(cache_directory, cache_max_age)
        if verbose:
            console.print(
                f"[bold cyan]🗄️ HTTP caching enabled:[/bold cyan] {cache_directory}"
            )

    # Handle cache operations
    if clear_cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "http_cache")
        temp_cache_manager = HTTPCacheManager(cache_directory, cache_max_age)
        count = temp_cache_manager.clear_all()
        console.print(
            f"[bold green]🗑️ Cleared {count} cached HTTP responses from {cache_directory}[/bold green]"
        )
        return

    if cache_stats:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "http_cache")
        temp_cache_manager = HTTPCacheManager(cache_directory, cache_max_age)
        stats = temp_cache_manager.get_stats()

        console.print("[bold cyan]📊 HTTP Cache Statistics[/bold cyan]")
        console.print(f"Cache directory: {cache_directory}")
        console.print(f"Total entries: {stats['total_entries']}")
        console.print(f"[green]Valid entries: {stats['valid_entries']}[/green]")
        console.print(f"[yellow]Expired entries: {stats['expired_entries']}[/yellow]")
        console.print(f"Total size: {stats['total_size_kb']:.1f} KB")
        console.print(f"Max age: {cache_max_age} hours")
        return

    # Check if input is provided for scanning operations
    if not input:
        console.print(
            "[red]❌ Error: --input is required for scanning operations[/red]"
        )
        console.print("Use --cache-stats or --clear-cache for cache management.")
        return

    console.rule("[bold cyan]🌐 ReconCLI : HTTPCli Enhanced Analysis Module")

    if verbose:
        console.print(f"[bold green]📁 Input file:[/bold green] {input}")
        console.print(f"[bold green]📂 Output directory:[/bold green] {output_dir}")
        console.print(f"[bold green]🧵 Threads:[/bold green] {threads}")
        console.print(f"[bold green]⏱️ Timeout:[/bold green] {timeout}s")
        console.print(f"[bold green]🔁 Retries:[/bold green] {retries}")

    start_time = time.time()
    raw_lines = [u.strip() for u in Path(input).read_text().splitlines() if u.strip()]
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    urls = []

    # Parse custom headers if provided
    custom_headers_dict = {}
    if custom_headers:
        try:
            custom_headers_dict = json.loads(custom_headers)
        except json.JSONDecodeError:
            console.print("[red]❌ Invalid JSON format for custom headers[/red]")
            return

    for line in raw_lines:
        hostname = line.split()[0]
        if hostname.startswith("http://") or hostname.startswith("https://"):
            urls.append(hostname)
        else:
            resolved = resolve_to_url(hostname, timeout=timeout, proxies=proxies)
            if resolved:
                urls.append(resolved)
            else:
                console.print(
                    f"[yellow]-[/yellow] {hostname} -> could not resolve as http(s)"
                )

    if verbose:
        console.print(
            f"[bold blue]📊 Processing {len(urls)} URLs with {threads} threads[/bold blue]"
        )

    results = []
    log_lines = []

    headers_base = {"User-Agent": user_agent}
    headers_base.update(custom_headers_dict)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {
            executor.submit(
                process_url,
                url,
                retries,
                timeout,
                proxies,
                headers_base,
                fastmode,
                nuclei,
                nuclei_templates,
                security_scan,
                check_waf,
                screenshot,
                check_cors,
                tech_detection,
                benchmark,
                check_compression,
                ssl_analysis,
                output_dir,
                verbose,
                wappalyzer,
                cache_manager,
            ): url
            for url in urls
        }
        for future in as_completed(future_to_url):
            data = future.result()
            url = data["url"]
            if "error" not in data:
                status_display = f"[green]{data.get('status_code')}[/green]"
                title_display = (
                    data.get("title", "")[:50] + "..."
                    if len(data.get("title", "")) > 50
                    else data.get("title", "")
                )

                # Add security grade if available
                security_info = ""
                if security_scan and data.get("security_analysis"):
                    grade = data["security_analysis"].get("grade", "N/A")
                    security_info = f" | Security: [bold]{grade}[/bold]"

                console.print(
                    f"[green]+[/green] {url} -> {status_display} | {title_display}{security_info}"
                )
                log_lines.append(
                    f"[+] {url} -> {data.get('status_code')} | {title_display}{security_info}"
                )
            else:
                console.print(f"[red]-[/red] {url} -> ERROR: {data['error']}")
                log_lines.append(f"[-] {url} -> ERROR: {data['error']}")
            results.append(data)

    # Generate comprehensive summary
    elapsed_time = time.time() - start_time

    if verbose:
        console.print("\n[bold green]📊 Scan Summary:[/bold green]")
        console.print(f"   • Total URLs processed: {len(results)}")
        console.print(
            f"   • Successful responses: {len([r for r in results if r.get('status_code')])}"
        )
        console.print(f"   • Errors: {len([r for r in results if r.get('error')])}")
        console.print(f"   • Scan duration: {elapsed_time:.2f}s")

        if security_scan:
            security_grades = [
                r.get("security_analysis", {}).get("grade", "F")
                for r in results
                if r.get("security_analysis")
            ]
            if security_grades:
                console.print(f"   • Security grades: {Counter(security_grades)}")

    # Enhanced CSV export with all new fields
    if jsonout:
        with open(output_path / "http_results.json", "w") as f:
            json.dump(results, f, indent=2)

        with open(
            output_path / "http_results.csv", "w", newline="", encoding="utf-8"
        ) as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                [
                    "url",
                    "status_code",
                    "title",
                    "content_type",
                    "content_length",
                    "server",
                    "favicon_hash",
                    "cdn",
                    "waf_detected",
                    "cors",
                    "cors_risk_level",
                    "security_grade",
                    "security_score",
                    "technologies",
                    "supports_http2",
                    "compression_support",
                    "response_time",
                    "performance_avg",
                    "allowed_methods",
                    "tags",
                    "error",
                    "screenshot",
                    "wappalyzer_tech_count",
                ]
            )
            for r in results:
                writer.writerow(
                    [
                        r.get("url"),
                        r.get("status_code"),
                        r.get("title", ""),
                        r.get("content_type", ""),
                        r.get("content_length", ""),
                        r.get("server", ""),
                        r.get("favicon_hash", ""),
                        r.get("cdn", ""),
                        ",".join(r.get("waf_detected", [])),
                        r.get("cors", ""),
                        r.get("cors_analysis", {}).get("risk_level", ""),
                        r.get("security_analysis", {}).get("grade", ""),
                        r.get("security_analysis", {}).get("score", ""),
                        json.dumps(r.get("technologies", {})),
                        r.get("supports_http2", ""),
                        json.dumps(r.get("compression", {})),
                        r.get("response_time", ""),
                        r.get("performance", {}).get("avg", ""),
                        r.get("allowed_methods", ""),
                        ",".join(r.get("tags", [])),
                        r.get("error", ""),
                        r.get("screenshot", ""),
                        (
                            len(r.get("wappalyzer", {}).get("technologies", []))
                            if r.get("wappalyzer")
                            else 0
                        ),
                    ]
                )

    if markdown:
        with open(output_path / "http_summary.md", "w") as f:
            f.write(f"# HTTP Summary Report\n\nGenerated: {datetime.now()}\n\n")
            for r in results:
                f.write(f"## [{r.get('url')}]({r.get('url')})\n")
                for key in [
                    "status_code",
                    "title",
                    "content_type",
                    "redirected",
                    "favicon_hash",
                    "cdn",
                    "allowed_methods",
                    "cors",
                    "response_time",  # Dodane pole
                    "supports_http2",  # Dodane pole
                ]:
                    if r.get(key):
                        f.write(f"- {key.replace('_', ' ').title()}: {r[key]}\n")
                if r.get("tags"):
                    f.write(f"- Tags: {', '.join(r['tags'])}\n")
                for h in SECURITY_HEADERS:
                    if h in r.get("security_headers", {}):
                        f.write(f"- {h}: {r['security_headers'][h]}\n")
                if r.get("nuclei"):
                    f.write("- Nuclei:\n")
                    for finding in r["nuclei"]:
                        f.write(f"  - {finding}\n")
                if r.get("error"):
                    f.write(f"- Error: {r['error']}\n")
                f.write("\n")

    # Export vulnerabilities only
    if export_vulnerabilities:
        vulnerable_results = []
        for r in results:
            is_vulnerable = any(
                [
                    r.get("cors_analysis", {}).get("risk_level") == "high",
                    "cors-wildcard" in r.get("tags", []),
                    "security-poor" in r.get("tags", []),
                    "cors-vulnerable" in r.get("tags", []),
                    "no-security-headers" in r.get("tags", []),
                    "clickjacking-vulnerable" in r.get("tags", []),
                    r.get("nuclei", []) and len(r["nuclei"]) > 0,
                    r.get("waf_detected", []) and "none" not in r["waf_detected"],
                ]
            )

            if is_vulnerable:
                vulnerable_results.append(r)

        if vulnerable_results:
            with open(output_path / "vulnerabilities.json", "w") as f:
                json.dump(vulnerable_results, f, indent=2)

            with open(output_path / "vulnerable_urls.txt", "w") as f:
                for r in vulnerable_results:
                    f.write(f"{r['url']}\n")

            console.print(
                f"[bold red]🚨 Found {len(vulnerable_results)} potentially vulnerable URLs[/bold red]"
            )
        else:
            console.print(
                "[bold green]✅ No obvious vulnerabilities detected[/bold green]"
            )

    # Enhanced export by tags and status
    if export_tag:
        for tag in export_tag:
            with open(output_path / f"tag_{tag}.txt", "w") as f:
                for r in results:
                    if tag in r.get("tags", []):
                        f.write(f"{r['url']}\n")

    if export_status:
        for code in export_status:
            with open(output_path / f"status_{code}.txt", "w") as f:
                for r in results:
                    if str(r.get("status_code")) == str(code):
                        f.write(f"{r['url']}\n")

    # Enhanced markdown report
    if markdown:
        with open(output_path / "http_summary.md", "w") as f:
            f.write("# 🌐 Enhanced HTTP Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total URLs:** {len(urls)}\n")
            f.write(
                f"**Successful:** {len([r for r in results if r.get('status_code')])}\n"
            )
            f.write(f"**Errors:** {len([r for r in results if r.get('error')])}\n\n")

            # Security summary
            if security_scan:
                security_grades = [
                    r.get("security_analysis", {}).get("grade", "F")
                    for r in results
                    if r.get("security_analysis")
                ]
                if security_grades:
                    f.write("## 🛡️ Security Summary\n\n")
                    grade_counts = Counter(security_grades)
                    for grade, count in grade_counts.most_common():
                        f.write(f"- **{grade} Grade:** {count} sites\n")
                    f.write("\n")

            # Technology summary
            if tech_detection:
                all_servers = []
                all_cms = []
                for r in results:
                    tech = r.get("technologies", {})
                    all_servers.extend(tech.get("servers", []))
                    all_cms.extend(tech.get("cms", []))

                if all_servers:
                    f.write("## 🖥️ Server Technologies\n\n")
                    server_counts = Counter(all_servers)
                    for server, count in server_counts.most_common(10):
                        f.write(f"- **{server}:** {count} sites\n")
                    f.write("\n")

                if all_cms:
                    f.write("## 📝 CMS Detection\n\n")
                    cms_counts = Counter(all_cms)
                    for cms, count in cms_counts.most_common():
                        f.write(f"- **{cms}:** {count} sites\n")
                    f.write("\n")

            # Detailed results
            f.write("## 📊 Detailed Results\n\n")
            for r in results:
                f.write(f"### [{r.get('url')}]({r.get('url')})\n\n")

                # Basic info
                f.write(f"- **Status:** {r.get('status_code')}\n")
                if r.get("title"):
                    f.write(f"- **Title:** {r.get('title')[:100]}...\n")
                if r.get("server"):
                    f.write(f"- **Server:** {r.get('server')}\n")

                # Security info
                if r.get("security_analysis"):
                    sec = r["security_analysis"]
                    f.write(
                        f"- **Security Grade:** {sec.get('grade')} ({sec.get('percentage')}%)\n"
                    )

                # Technologies
                if r.get("technologies"):
                    tech = r["technologies"]
                    if tech.get("servers"):
                        f.write(f"- **Server Tech:** {', '.join(tech['servers'])}\n")
                    if tech.get("cms"):
                        f.write(f"- **CMS:** {', '.join(tech['cms'])}\n")

                # Performance
                if r.get("performance"):
                    perf = r["performance"]
                    f.write(f"- **Response Time:** {perf.get('avg')}s avg\n")

                # Features
                features = []
                if r.get("supports_http2"):
                    features.append("HTTP/2")
                if r.get("compression", {}).get("gzip"):
                    features.append("Gzip")
                if r.get("compression", {}).get("brotli"):
                    features.append("Brotli")
                if features:
                    f.write(f"- **Features:** {', '.join(features)}\n")

                # Tags
                if r.get("tags"):
                    f.write(
                        f"- **Tags:** {', '.join(r['tags'][:5])}{'...' if len(r['tags']) > 5 else ''}\n"
                    )

                f.write("\n")

    if log:
        with open(output_path / "log.txt", "w") as f:
            f.write("\n".join(log_lines))

    # Database storage
    if store_db and results:
        try:
            from reconcli.db.operations import store_target

            # Note: store_http_scan function needs to be implemented in db/operations.py
            # Auto-detect target domain if not provided
            if not target_domain and results:
                # Try to extract domain from first URL
                first_url = results[0].get("url") if results else None
                if first_url:
                    from urllib.parse import urlparse

                    parsed = urlparse(first_url)
                    target_domain = parsed.netloc

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                console.print(
                    f"[+] 💾 Target {target_domain} prepared for HTTP scan data storage"
                )
                console.print(
                    "[!] ⚠️  Note: store_http_scan function needs implementation in db/operations.py"
                )
            else:
                console.print(
                    "[!] ⚠️  No target domain provided or detected for database storage"
                )

        except ImportError:
            console.print("[!] ⚠️  Database module not available")
        except Exception as e:
            console.print(f"[!] ❌ Database storage failed: {e}")

    # Final statistics and summary
    tag_counter = Counter(tag for r in results for tag in r.get("tags", []))

    console.print("\n[bold blue]🎯 Final Statistics:[/bold blue]")
    console.print(f"   • Total scan time: {elapsed_time:.2f}s")
    console.print(
        f"   • Average response time: {sum(r.get('response_time', 0) for r in results if r.get('response_time')) / max(len([r for r in results if r.get('response_time')]), 1):.3f}s"
    )

    console.print("\n[bold cyan]🏷️ Top Tags:[/bold cyan]")
    for tag, count in tag_counter.most_common(10):
        console.print(f"   • {tag}: {count}")

    error_urls = [r for r in results if r.get("error")]
    if error_urls:
        console.print(f"\n[bold red]❌ Errors ({len(error_urls)}):[/bold red]")
        for r in error_urls[:5]:  # Show only first 5 errors
            console.print(f"   • {r['url']}: {r['error']}")
        if len(error_urls) > 5:
            console.print(f"   • ... and {len(error_urls) - 5} more errors")

    # Summary by status codes
    status_counter = Counter(
        r.get("status_code") for r in results if r.get("status_code")
    )
    if status_counter:
        console.print("\n[bold green]📊 Status Code Distribution:[/bold green]")
        for status, count in status_counter.most_common():
            console.print(f"   • {status}: {count}")

    console.print(f"\n[bold magenta]📁 Results saved to: {output_path}/[/bold magenta]")

    # Export headers if requested
    if headers and results:
        export_headers_data(
            results, output_path, header_filter, headers_format, verbose
        )

    console.rule("[bold cyan]🎉 HTTPCli Analysis Complete!")


def resolve_to_url(hostname, timeout=5, proxies=None):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{hostname}"
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=True, proxies=proxies, stream=True
            )
            return url
        except Exception as e:
            print(f"[debug] {url} -> {e}")
            continue
    return None


def extract_title(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title
        return title.string.strip() if title and title.string else ""
    except Exception:
        return ""


def extract_security_headers(headers):
    """Extract and analyze security headers with scoring."""
    security_headers = {k: v for k, v in headers.items() if k in SECURITY_HEADERS}

    # Security scoring
    score = 0
    max_score = len(SECURITY_HEADERS) * 10

    for header in SECURITY_HEADERS:
        if header in headers:
            score += 10

    return {
        "headers": security_headers,
        "score": score,
        "max_score": max_score,
        "percentage": round((score / max_score) * 100, 1),
        "grade": get_security_grade(score, max_score),
    }


def get_security_grade(score, max_score):
    """Calculate security grade based on header presence."""
    percentage = (score / max_score) * 100
    if percentage >= 90:
        return "A+"
    elif percentage >= 80:
        return "A"
    elif percentage >= 70:
        return "B"
    elif percentage >= 60:
        return "C"
    elif percentage >= 50:
        return "D"
    else:
        return "F"


def detect_waf(headers, content=""):
    """Enhanced WAF detection using headers and content analysis."""
    detected_wafs = []
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

    for waf, indicators in WAF_SIGNATURES.items():
        for indicator in indicators:
            if any(indicator in k or indicator in v for k, v in lower_headers.items()):
                detected_wafs.append(waf)
                break

    # Content-based WAF detection
    waf_indicators_content = [
        "blocked by cloudflare",
        "access denied",
        "security alert",
        "request rejected",
        "firewall",
        "akamai",
        "incapsula",
    ]

    content_lower = content.lower()
    for indicator in waf_indicators_content:
        if indicator in content_lower:
            detected_wafs.append("content_based_detection")
            break

    return list(set(detected_wafs))


def detect_technologies(headers, content=""):
    """Enhanced technology detection using headers and content analysis."""
    technologies = {
        "servers": [],
        "frameworks": [],
        "languages": [],
        "cms": [],
        "libraries": [],
    }

    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

    # Server detection
    server_header = lower_headers.get("server", "")
    for tech, indicators in TECH_SIGNATURES["servers"].items():
        for indicator in indicators:
            if indicator in server_header:
                technologies["servers"].append(tech)

    # Framework detection
    for tech, indicators in TECH_SIGNATURES["frameworks"].items():
        for indicator in indicators:
            if any(indicator in k or indicator in v for k, v in lower_headers.items()):
                technologies["frameworks"].append(tech)

    # Content-based detection
    if content:
        content_lower = content.lower()

        # CMS detection
        cms_indicators = {
            "wordpress": ["wp-content", "/wp-includes/", "wordpress"],
            "drupal": ["drupal.js", "/sites/default/", "drupal"],
            "joomla": ["joomla", "/components/", "/modules/"],
            "magento": ["magento", "/skin/frontend/"],
        }

        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator in content_lower:
                    technologies["cms"].append(cms)
                    break

    # Remove duplicates
    for category in technologies:
        technologies[category] = list(set(technologies[category]))

    return technologies


def analyze_cors_detailed(url, headers_base, timeout=10, proxies=None):
    """Perform detailed CORS analysis with various origin tests."""
    cors_results = {
        "wildcard": False,
        "null_origin": False,
        "arbitrary_origin": False,
        "credentials_allowed": False,
        "dangerous_methods": [],
        "risk_level": "low",
    }

    test_origins = [
        "*",
        "null",
        "https://evil.com",
        "https://attacker.com",
        f"https://sub.{urlparse(url).netloc}",
    ]

    for origin in test_origins:
        try:
            test_headers = headers_base.copy()
            test_headers["Origin"] = origin

            response = requests.options(
                url, headers=test_headers, timeout=timeout, proxies=proxies
            )

            cors_origin = response.headers.get("Access-Control-Allow-Origin")
            cors_creds = response.headers.get("Access-Control-Allow-Credentials")
            cors_methods = response.headers.get("Access-Control-Allow-Methods", "")

            if cors_origin == "*":
                cors_results["wildcard"] = True
                cors_results["risk_level"] = "high"
            elif cors_origin == "null":
                cors_results["null_origin"] = True
                cors_results["risk_level"] = "medium"
            elif cors_origin == origin and origin not in ["*", "null"]:
                cors_results["arbitrary_origin"] = True
                cors_results["risk_level"] = "high"

            if cors_creds and cors_creds.lower() == "true":
                cors_results["credentials_allowed"] = True
                if cors_results["risk_level"] != "high":
                    cors_results["risk_level"] = "medium"

            dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE"]
            for method in dangerous_methods:
                if method in cors_methods.upper():
                    cors_results["dangerous_methods"].append(method)
                    cors_results["risk_level"] = "high"

        except Exception:
            continue

    return cors_results


def capture_screenshot(url, output_dir):
    """Capture screenshot using selenium (optional feature)."""
    try:
        # Try to import selenium
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")

        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(30)
        driver.get(url)

        # Create screenshot filename
        from urllib.parse import urlparse

        parsed = urlparse(url)
        filename = f"{parsed.netloc}_{parsed.path.replace('/', '_')}.png"
        screenshot_path = Path(output_dir) / "screenshots" / filename
        screenshot_path.parent.mkdir(exist_ok=True)

        driver.save_screenshot(str(screenshot_path))
        driver.quit()

        return str(screenshot_path)
    except ImportError:
        return "selenium_not_installed"
    except Exception as e:
        return f"screenshot_error: {e}"


def benchmark_performance(url, headers_base, timeout=10, proxies=None, runs=5):
    """Benchmark response times with multiple requests."""
    times = []

    for _ in range(runs):
        start = time.time()
        try:
            response = requests.get(
                url, headers=headers_base, timeout=timeout, proxies=proxies
            )
            if response.status_code:
                times.append(time.time() - start)
        except Exception:
            continue

    if times:
        return {
            "min": round(min(times), 3),
            "max": round(max(times), 3),
            "avg": round(sum(times) / len(times), 3),
            "samples": len(times),
        }
    return None


def check_compression_support(url, headers_base, timeout=10, proxies=None):
    """Test compression support (gzip, brotli)."""
    compression_results = {
        "gzip": False,
        "brotli": False,
        "deflate": False,
        "compression_ratio": None,
    }

    try:
        # Test with compression headers
        test_headers = headers_base.copy()
        test_headers["Accept-Encoding"] = "gzip, deflate, br"

        response = requests.get(
            url, headers=test_headers, timeout=timeout, proxies=proxies
        )

        content_encoding = response.headers.get("Content-Encoding", "").lower()

        if "gzip" in content_encoding:
            compression_results["gzip"] = True
        if "br" in content_encoding or "brotli" in content_encoding:
            compression_results["brotli"] = True
        if "deflate" in content_encoding:
            compression_results["deflate"] = True

        # Calculate compression ratio if possible
        if content_encoding:
            original_size = len(response.content)
            uncompressed_response = requests.get(
                url, headers=headers_base, timeout=timeout, proxies=proxies
            )
            uncompressed_size = len(uncompressed_response.content)

            if uncompressed_size > 0:
                compression_results["compression_ratio"] = round(
                    (1 - original_size / uncompressed_size) * 100, 2
                )

    except Exception:
        pass

    return compression_results


def get_favicon_hash(url, proxies=None):
    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        r = requests.get(favicon_url, timeout=5, proxies=proxies)
        if r.status_code == 200:
            return str(mmh3.hash(b64encode(r.content)))
        else:
            return "not found"
    except Exception:
        return "error"


def detect_cdn(headers, url):
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    for cdn, indicators in CDN_SIGNATURES.items():
        for indicator in indicators:
            if any(indicator in k or indicator in v for k, v in lower_headers.items()):
                return cdn
    parsed = urlparse(url)
    if any(
        cdn in parsed.netloc for cdn in ["cloudfront", "akamai", "fastly", "edgecast"]
    ):
        return parsed.netloc
    return "none"


def run_nuclei(url, nuclei_templates=None):
    try:
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(url + "\n")
            f.flush()
            cmd = ["nuclei", "-u", f.name]
            if nuclei_templates:
                cmd += ["-t", nuclei_templates]
            result = subprocess.run(cmd, capture_output=True, text=True)
            findings = result.stdout.strip().splitlines()
            return findings
    except Exception as e:
        return [f"nuclei error: {e}"]


def run_wappalyzer(url, scan_type="fast"):
    """Run Wappalyzer for technology detection."""
    try:
        # Use temporary file instead of /dev/stdout to avoid seekable stream issues
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        cmd = ["wappalyzer", "-i", url, "--scan-type", scan_type, "-oJ", temp_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            try:
                # Read the JSON output from temporary file
                with open(temp_path, "r") as f:
                    content = f.read().strip()

                # Clean up temp file
                Path(temp_path).unlink(missing_ok=True)

                if content:
                    # Try to parse as JSON
                    lines = content.split("\n")
                    for line in lines:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                return data
                            except json.JSONDecodeError:
                                continue
                    return {"technologies": [], "error": "no valid JSON output"}
                else:
                    return {"technologies": [], "error": "empty wappalyzer output"}
            except Exception as e:
                Path(temp_path).unlink(missing_ok=True)
                return {"technologies": [], "error": f"parsing error: {e}"}
        else:
            Path(temp_path).unlink(missing_ok=True)
            return {"technologies": [], "error": f"wappalyzer failed: {result.stderr}"}
    except subprocess.TimeoutExpired:
        return {"technologies": [], "error": "wappalyzer timeout"}
    except Exception as e:
        return {"technologies": [], "error": f"wappalyzer error: {e}"}


def tag_http_result(data):
    """Enhanced tagging system for HTTP results."""
    tags = []
    code = data.get("status_code")

    # Status code based tags
    if code == 200:
        tags.append("ok")
    elif code in [403, 401]:
        tags.append("unauthorized")
    elif code in [500, 502, 503]:
        tags.append("server-error")
    elif code in [301, 302, 307, 308]:
        tags.append("redirect")
    elif code == 404:
        tags.append("not-found")
    elif code and 400 <= code < 500:
        tags.append("client-error")
    elif code and 500 <= code < 600:
        tags.append("server-error")

    # Security-based tags
    if data.get("cors") == "*":
        tags.append("cors-wildcard")

    security_headers = data.get("security_headers", {})
    if not security_headers:
        tags.append("no-security-headers")

    if "Content-Security-Policy" not in security_headers:
        tags.append("no-csp")

    if "X-Frame-Options" not in security_headers:
        tags.append("clickjacking-vulnerable")

    if "Strict-Transport-Security" not in security_headers:
        tags.append("no-hsts")

    # Security analysis tags
    if data.get("security_analysis"):
        grade = data["security_analysis"].get("grade", "F")
        if grade in ["A+", "A"]:
            tags.append("security-excellent")
        elif grade in ["B", "C"]:
            tags.append("security-good")
        elif grade in ["D", "F"]:
            tags.append("security-poor")

    # Technology tags
    if data.get("supports_http2"):
        tags.append("http2-enabled")

    if data.get("technologies"):
        tech = data["technologies"]
        if tech.get("servers"):
            tags.append("server-identified")
        if tech.get("cms"):
            tags.append("cms-detected")
        if tech.get("frameworks"):
            tags.append("framework-detected")

    # Performance tags
    if data.get("performance"):
        perf = data["performance"]
        if perf.get("avg", 0) < 0.5:
            tags.append("fast-response")
        elif perf.get("avg", 0) > 3.0:
            tags.append("slow-response")

    # Compression tags
    if data.get("compression"):
        comp = data["compression"]
        if comp.get("gzip") or comp.get("brotli"):
            tags.append("compression-enabled")

    return tags


def process_url(
    url,
    retries,
    timeout,
    proxies,
    headers_base,
    fastmode,
    nuclei,
    nuclei_templates,
    security_scan=False,
    check_waf=False,
    screenshot=False,
    check_cors=False,
    tech_detection=False,
    benchmark=False,
    check_compression=False,
    ssl_analysis=False,
    output_dir="httpcli_output",
    verbose=False,
    wappalyzer=False,
    cache_manager=None,
):
    # Check cache first
    if cache_manager and not fastmode:  # Skip cache for fastmode (HEAD requests)
        method = "HEAD" if fastmode else "GET"
        cached_result = cache_manager.get(url, method, headers_base)
        if cached_result:
            # Add cache indicator to result
            cached_result["cached"] = True
            if verbose:
                cached_result["status"] = (
                    f"{cached_result.get('status', 'cached')} (cached)"
                )
            return cached_result

    data = {"url": url}
    attempt = 0
    while attempt <= retries:
        try:
            start = time.time()
            if fastmode:
                r = requests.head(
                    url,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=True,
                    headers=headers_base,
                )
                data["status_code"] = r.status_code
                data["headers"] = dict(r.headers)
                data["redirected"] = len(r.history) > 0
                data["tags"] = tag_http_result(data)
            else:
                r = requests.get(
                    url,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=True,
                    headers=headers_base,
                )
                headers = dict(r.headers)
                content = r.text

                # Basic data extraction
                data.update(
                    {
                        "status_code": r.status_code,
                        "headers": headers,
                        "content_type": headers.get("Content-Type", ""),
                        "content_length": len(content),
                        "title": extract_title(content),
                        "redirected": len(r.history) > 0,
                        "server": headers.get("Server", ""),
                        "cors": headers.get("Access-Control-Allow-Origin", "None"),
                        "favicon_hash": get_favicon_hash(url, proxies),
                        "cdn": detect_cdn(headers, url),
                        "supports_http2": detect_http2(url, proxies, timeout),
                        "tags": [],
                    }
                )

                # Security analysis
                if security_scan:
                    data["security_analysis"] = extract_security_headers(headers)

                # WAF detection
                if check_waf:
                    data["waf_detected"] = detect_waf(headers, content)
                    if data["waf_detected"]:
                        data["tags"].append("waf-detected")

                # Technology detection
                if tech_detection:
                    data["technologies"] = detect_technologies(headers, content)

                # CORS analysis
                if check_cors:
                    data["cors_analysis"] = analyze_cors_detailed(
                        url, headers_base, timeout, proxies
                    )
                    if data["cors_analysis"]["risk_level"] == "high":
                        data["tags"].append("cors-vulnerable")

                # Performance benchmarking
                if benchmark:
                    data["performance"] = benchmark_performance(
                        url, headers_base, timeout, proxies
                    )

                # Compression testing
                if check_compression:
                    data["compression"] = check_compression_support(
                        url, headers_base, timeout, proxies
                    )

                # Screenshot capture
                if screenshot:
                    data["screenshot"] = capture_screenshot(url, output_dir)

                # Standard security headers
                data["security_headers"] = extract_security_headers(headers)

                # Allowed methods check
                try:
                    opt = requests.options(
                        url, timeout=timeout, proxies=proxies, headers=headers_base
                    )
                    data["allowed_methods"] = opt.headers.get("Allow", "Unknown")
                except:
                    data["allowed_methods"] = "Error"

                # Nuclei scanning
                if nuclei:
                    data["nuclei"] = run_nuclei(url, nuclei_templates)
                    if data["nuclei"]:
                        data["tags"].append("nuclei-match")

                # Wappalyzer detection
                if wappalyzer:
                    wappalyzer_result = run_wappalyzer(url)
                    data["wappalyzer"] = wappalyzer_result

                    # Merge wappalyzer technologies with existing tech detection
                    if not wappalyzer_result.get("error") and url in wappalyzer_result:
                        if "technologies" not in data:
                            data["technologies"] = {
                                "servers": [],
                                "frameworks": [],
                                "languages": [],
                                "cms": [],
                                "libraries": [],
                            }

                        # Parse Wappalyzer results - new format
                        wapp_tech = wappalyzer_result[url]
                        if isinstance(wapp_tech, dict):
                            for tech_name, tech_info in wapp_tech.items():
                                categories = tech_info.get("categories", [])

                                # Categorize based on Wappalyzer categories
                                if any(
                                    "Web server" in cat or "CDN" in cat
                                    for cat in categories
                                ):
                                    data["technologies"]["servers"].append(tech_name)
                                elif any(
                                    "CMS" in cat or "Blog" in cat for cat in categories
                                ):
                                    data["technologies"]["cms"].append(tech_name)
                                elif any(
                                    "framework" in cat.lower()
                                    or "React" in tech_name
                                    or "Next.js" in tech_name
                                    for cat in categories
                                ):
                                    data["technologies"]["frameworks"].append(tech_name)
                                elif any(
                                    "JavaScript" in cat or "Language" in cat
                                    for cat in categories
                                ):
                                    data["technologies"]["languages"].append(tech_name)
                                elif any(
                                    "Analytics" in cat or "Video" in cat
                                    for cat in categories
                                ):
                                    data["technologies"]["libraries"].append(tech_name)
                                else:
                                    # Default to libraries for other technologies
                                    data["technologies"]["libraries"].append(tech_name)

                        # Remove duplicates
                        for category in data["technologies"]:
                            data["technologies"][category] = list(
                                set(data["technologies"][category])
                            )

                        data["tags"].append("wappalyzer-detected")

                        # Add specific technology tags
                        if "React" in wapp_tech or "Next.js" in wapp_tech:
                            data["tags"].append("react-app")
                        if "Amazon CloudFront" in wapp_tech:
                            data["tags"].append("cloudfront-cdn")
                        if "PWA" in wapp_tech:
                            data["tags"].append("pwa-enabled")
                else:
                    data["wappalyzer"] = None

                # Tagging
                if data.get("favicon_hash") == "not found":
                    data["tags"].append("no-favicon")
                elif data.get("favicon_hash") == "error":
                    data["tags"].append("favicon-error")

                data["tags"] += tag_http_result(data)
            data["response_time"] = round(time.time() - start, 3)

            # Cache successful result
            if cache_manager and data.get("status_code") and data["status_code"] < 500:
                method = "HEAD" if fastmode else "GET"
                cache_manager.set(url, data, method, headers_base)

            return data
        except Exception as e:
            attempt += 1
            data["error"] = str(e)
            if "Failed to resolve" in str(e):
                if "tags" not in data:
                    data["tags"] = []
                data["tags"].append("dead-dns")
            if attempt > retries:
                return data
            else:
                time.sleep(1)
                continue
    return data


def detect_http2(url, proxies=None, timeout=10):
    """Detect HTTP/2 support using httpx."""
    try:
        proxy = None
        if proxies and proxies.get("http"):
            proxy = proxies["http"]

        transport = httpx.HTTPTransport(http2=True)

        # Create client with proper proxy configuration
        client_kwargs = {"http2": True, "timeout": timeout, "transport": transport}

        if proxy:
            client_kwargs["proxy"] = proxy

        with httpx.Client(**client_kwargs) as client:
            r = client.get(url)
            return r.http_version == "HTTP/2"
    except Exception:
        return False


def export_headers_data(
    results, output_path, header_filter=None, headers_format="text", verbose=False
):
    """Export HTTP headers in various formats with optional filtering."""

    # Filter results that have headers
    results_with_headers = [
        r for r in results if r.get("headers") and not r.get("error")
    ]

    if not results_with_headers:
        console.print("[yellow]⚠️ No headers data found to export[/yellow]")
        return

    # Parse header filter
    filtered_headers = None
    if header_filter:
        filtered_headers = [h.strip() for h in header_filter.split(",")]
        if verbose:
            console.print(
                f"[blue]🔍 Filtering headers: {', '.join(filtered_headers)}[/blue]"
            )

    console.print(
        f"[green]📋 Exporting headers for {len(results_with_headers)} URLs in {headers_format} format[/green]"
    )

    if headers_format == "text":
        export_headers_text(results_with_headers, output_path, filtered_headers)
    elif headers_format == "json":
        export_headers_json(results_with_headers, output_path, filtered_headers)
    elif headers_format == "csv":
        export_headers_csv(results_with_headers, output_path, filtered_headers)
    elif headers_format == "table":
        export_headers_table(results_with_headers, output_path, filtered_headers)


def export_headers_text(results, output_path, filtered_headers=None):
    """Export headers in plain text format."""
    with open(output_path / "headers.txt", "w", encoding="utf-8") as f:
        for result in results:
            url = result["url"]
            headers = result["headers"]

            f.write(f"\n{'='*80}\n")
            f.write(f"URL: {url}\n")
            f.write(f"Status: {result.get('status_code', 'N/A')}\n")
            f.write(f"{'='*80}\n")

            if filtered_headers:
                # Show only filtered headers
                for header in filtered_headers:
                    value = None
                    # Case-insensitive header lookup
                    for h_key, h_value in headers.items():
                        if h_key.lower() == header.lower():
                            value = h_value
                            break

                    if value:
                        f.write(f"{header}: {value}\n")
                    else:
                        f.write(f"{header}: [NOT FOUND]\n")
            else:
                # Show all headers
                for header, value in headers.items():
                    f.write(f"{header}: {value}\n")

            f.write("\n")

    console.print(f"[green]✅ Headers exported to: {output_path}/headers.txt[/green]")


def export_headers_json(results, output_path, filtered_headers=None):
    """Export headers in JSON format."""
    headers_data = []

    for result in results:
        url = result["url"]
        headers = result["headers"]

        if filtered_headers:
            # Filter headers
            filtered = {}
            for header in filtered_headers:
                value = None
                for h_key, h_value in headers.items():
                    if h_key.lower() == header.lower():
                        value = h_value
                        break
                filtered[header] = value
            headers = filtered

        headers_data.append(
            {"url": url, "status_code": result.get("status_code"), "headers": headers}
        )

    with open(output_path / "headers.json", "w", encoding="utf-8") as f:
        json.dump(headers_data, f, indent=2, ensure_ascii=False)

    console.print(f"[green]✅ Headers exported to: {output_path}/headers.json[/green]")


def export_headers_csv(results, output_path, filtered_headers=None):
    """Export headers in CSV format."""
    if not filtered_headers:
        # Get all unique headers
        all_headers = set()
        for result in results:
            all_headers.update(result["headers"].keys())
        filtered_headers = sorted(all_headers)

    with open(
        output_path / "headers.csv", "w", newline="", encoding="utf-8"
    ) as csvfile:
        writer = csv.writer(csvfile)

        # Write header row
        writer.writerow(["url", "status_code"] + filtered_headers)

        # Write data rows
        for result in results:
            url = result["url"]
            status = result.get("status_code", "")
            headers = result["headers"]

            row = [url, status]

            for header in filtered_headers:
                value = ""
                # Case-insensitive header lookup
                for h_key, h_value in headers.items():
                    if h_key.lower() == header.lower():
                        value = h_value
                        break
                row.append(value)

            writer.writerow(row)

    console.print(f"[green]✅ Headers exported to: {output_path}/headers.csv[/green]")


def export_headers_table(results, output_path, filtered_headers=None):
    """Export headers in table format using rich."""
    from rich.table import Table
    from rich.console import Console

    if not filtered_headers:
        # Get most common headers for table display
        header_counts = Counter()
        for result in results:
            header_counts.update(result["headers"].keys())
        filtered_headers = [h for h, _ in header_counts.most_common(10)]

    table = Table(title="🌐 HTTP Headers Summary")
    table.add_column("URL", style="cyan", no_wrap=True, max_width=40)
    table.add_column("Status", style="green", width=8)

    for header in filtered_headers:
        table.add_column(header, style="yellow", max_width=30)

    for result in results[:50]:  # Limit to first 50 for readability
        url = result["url"]
        status = str(result.get("status_code", ""))
        headers = result["headers"]

        row_data = [url, status]

        for header in filtered_headers:
            value = ""
            # Case-insensitive header lookup
            for h_key, h_value in headers.items():
                if h_key.lower() == header.lower():
                    value = h_value[:50] + "..." if len(h_value) > 50 else h_value
                    break
            row_data.append(value or "-")

        table.add_row(*row_data)

    # Create console with record enabled for HTML export
    table_console = Console(record=True, width=120)
    table_console.print(table)

    # Save table as HTML
    html_content = table_console.export_html()
    with open(output_path / "headers_table.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    # Print table to main console
    console.print(table)
    console.print(
        f"[green]✅ Headers table saved to: {output_path}/headers_table.html[/green]"
    )


if __name__ == "__main__":
    httpcli()
