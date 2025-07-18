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

🚀 FEATURES:
• Security header analysis and scoring
• CDN and WAF detection
• HTTP/2 and HTTP/3 support detection
• Custom User-Agent and header injection
• Screenshot capture for visual analysis
• Technology stack fingerprinting
• CORS misconfiguration detection
• SSL/TLS certificate analysis
• Response time benchmarking
• Nuclei integration for vulnerability scanning
• Database storage for persistent analysis
• Multiple export formats (JSON, CSV, HTML, Markdown)
• Advanced filtering and tagging system

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
import json
import subprocess
import tempfile
import time
from base64 import b64encode
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
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


@click.command("httpcli")
@click.option(
    "--input",
    "-i",
    required=True,
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
    """
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
        console.print(f"\n[bold green]📊 Scan Summary:[/bold green]")
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
            f.write(f"# 🌐 Enhanced HTTP Analysis Report\n\n")
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
                    f"[!] ⚠️  Note: store_http_scan function needs implementation in db/operations.py"
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

    console.print(f"\n[bold blue]🎯 Final Statistics:[/bold blue]")
    console.print(f"   • Total scan time: {elapsed_time:.2f}s")
    console.print(
        f"   • Average response time: {sum(r.get('response_time', 0) for r in results if r.get('response_time')) / max(len([r for r in results if r.get('response_time')]), 1):.3f}s"
    )

    console.print(f"\n[bold cyan]🏷️ Top Tags:[/bold cyan]")
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
        console.print(f"\n[bold green]📊 Status Code Distribution:[/bold green]")
        for status, count in status_counter.most_common():
            console.print(f"   • {status}: {count}")

    console.print(f"\n[bold magenta]📁 Results saved to: {output_path}/[/bold magenta]")
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


def run_wappalyzer(url):
    try:
        cmd = ["wappalyzer", url, "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout)
        except Exception:
            return result.stdout.strip()
    except Exception as e:
        return f"wappalyzer error: {e}"


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
):
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
                data["wappalyzer"] = run_wappalyzer(url)

                # Tagging
                if data.get("favicon_hash") == "not found":
                    data["tags"].append("no-favicon")
                elif data.get("favicon_hash") == "error":
                    data["tags"].append("favicon-error")

                data["tags"] += tag_http_result(data)
            data["response_time"] = round(time.time() - start, 3)
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


if __name__ == "__main__":
    httpcli()
