#!/usr/bin/env python3
import concurrent.futures
import csv
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import click
import requests

from reconcli.utils.resume import load_resume, save_resume_state, clear_resume


def resolve_subdomains(subdomains, threads=50, verbose=False):
    """Resolve a list of subdomains to IP addresses with concurrent processing."""
    results = []

    def resolve_single_subdomain(subdomain):
        """Resolve a single subdomain to IP address."""
        try:
            socket.setdefaulttimeout(5)  # 5 second timeout
            ip = socket.gethostbyname(subdomain.strip())

            # Try to get PTR record
            ptr = ""
            try:
                ptr = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                ptr = ""

            return {
                "subdomain": subdomain.strip(),
                "ip": ip,
                "ptr": ptr,
                "resolved": True,
                "status": "resolved",
            }
        except (socket.gaierror, socket.timeout, Exception):
            return {
                "subdomain": subdomain.strip(),
                "ip": None,
                "ptr": "",
                "resolved": False,
                "status": "failed",
            }

    # Use ThreadPoolExecutor for concurrent resolution
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all resolution tasks
        future_to_subdomain = {
            executor.submit(resolve_single_subdomain, subdomain): subdomain
            for subdomain in subdomains
        }

        # Collect results as they complete
        completed = 0
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            results.append(result)
            completed += 1

            if verbose and completed % 100 == 0:
                click.echo(
                    f"   🔍 Resolved {completed}/{len(subdomains)} subdomains..."
                )

    if verbose:
        resolved_count = sum(1 for r in results if r["resolved"])
        click.echo(
            f"   ✅ Successfully resolved {resolved_count}/{len(subdomains)} subdomains"
        )

    return results


def probe_http_services(
    targets, timeout=10, threads=50, verbose=False, ignore_ssl_errors=False
):
    """Probe HTTP/HTTPS services on resolved subdomains."""
    results = []

    def probe_single_target(target):
        """Probe HTTP/HTTPS on a single target."""
        subdomain = target.get("subdomain", "")
        if not subdomain:
            return None

        result = {
            "subdomain": subdomain,
            "http": False,
            "https": False,
            "http_status": None,
            "https_status": None,
            "http_title": "",
            "https_title": "",
        }

        # Test HTTP
        try:
            response = requests.get(
                f"http://{subdomain}",
                timeout=timeout,
                verify=True,  # HTTP doesn't use SSL anyway
                allow_redirects=True,
            )
            result["http"] = True
            result["http_status"] = response.status_code
            # Extract title
            if "<title>" in response.text.lower():
                title_start = response.text.lower().find("<title>") + 7
                title_end = response.text.lower().find("</title>", title_start)
                if title_end > title_start:
                    result["http_title"] = response.text[title_start:title_end].strip()[
                        :100
                    ]
        except (requests.RequestException, Exception):
            pass

        # Test HTTPS
        try:
            response = requests.get(
                f"https://{subdomain}",
                timeout=timeout,
                verify=not ignore_ssl_errors,  # Use parameter to control SSL verification
                allow_redirects=True,
            )
            result["https"] = True
            result["https_status"] = response.status_code
            # Extract title
            if "<title>" in response.text.lower():
                title_start = response.text.lower().find("<title>") + 7
                title_end = response.text.lower().find("</title>", title_start)
                if title_end > title_start:
                    result["https_title"] = response.text[
                        title_start:title_end
                    ].strip()[:100]
        except (requests.RequestException, Exception):
            pass

        return result

    # Use ThreadPoolExecutor for concurrent probing
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all probing tasks
        future_to_target = {
            executor.submit(probe_single_target, target): target for target in targets
        }

        # Collect results as they complete
        completed = 0
        for future in concurrent.futures.as_completed(future_to_target):
            result = future.result()
            if result:
                results.append(result)
            completed += 1

            if verbose and completed % 50 == 0:
                click.echo(f"   🌐 Probed {completed}/{len(targets)} targets...")

    if verbose:
        http_count = sum(1 for r in results if r["http"])
        https_count = sum(1 for r in results if r["https"])
        click.echo(f"   ✅ Found {http_count} HTTP and {https_count} HTTPS services")

    return results


def generate_enhanced_markdown_report(
    output_dir, domain, comprehensive_data, verbose=False
):
    """Generate enhanced Markdown report with scan results."""
    report_path = os.path.join(output_dir, "subdomain_report.md")

    with open(report_path, "w") as f:
        f.write(f"# Subdomain Enumeration Report for {domain}\n\n")
        f.write(f"**Scan Time:** {comprehensive_data.get('scan_time', 'Unknown')}\n")
        f.write(
            f"**Total Subdomains Found:** {comprehensive_data.get('total_subdomains', 0)}\n\n"
        )

        # Tool statistics
        if comprehensive_data.get("tool_stats"):
            f.write("## Tool Statistics\n\n")
            for tool, stats in comprehensive_data["tool_stats"].items():
                f.write(f"- **{tool}**: {stats.get('count', 0)} subdomains\n")
            f.write("\n")

        # Resolved subdomains
        if comprehensive_data.get("resolved"):
            f.write("## Resolved Subdomains\n\n")
            resolved_subs = [r for r in comprehensive_data["resolved"] if r["resolved"]]
            f.write(f"Successfully resolved {len(resolved_subs)} subdomains:\n\n")
            for result in resolved_subs[:20]:  # Limit to first 20
                f.write(f"- `{result['subdomain']}` → `{result['ip']}`\n")
            if len(resolved_subs) > 20:
                f.write(f"- ... and {len(resolved_subs) - 20} more\n")
            f.write("\n")

        # HTTP services
        if comprehensive_data.get("http_services"):
            f.write("## HTTP Services\n\n")
            http_services = [
                h
                for h in comprehensive_data["http_services"]
                if h["http"] or h["https"]
            ]
            f.write(f"Found {len(http_services)} active HTTP/HTTPS services:\n\n")
            for service in http_services[:20]:  # Limit to first 20
                protocols = []
                if service["http"]:
                    protocols.append(f"HTTP({service['http_status']})")
                if service["https"]:
                    protocols.append(f"HTTPS({service['https_status']})")
                f.write(f"- `{service['subdomain']}` → {', '.join(protocols)}\n")
            if len(http_services) > 20:
                f.write(f"- ... and {len(http_services) - 20} more\n")

    if verbose:
        click.echo(f"   📝 Enhanced Markdown report saved: {report_path}")


def display_scan_statistics(comprehensive_data, tool_stats):
    """Display scan statistics summary."""
    click.echo("\n" + "=" * 60)
    click.echo("📊 SCAN STATISTICS SUMMARY")
    click.echo("=" * 60)

    total_subs = comprehensive_data.get("total_subdomains", 0)
    click.echo(f"🎯 Total Unique Subdomains: {total_subs}")

    if tool_stats:
        click.echo("\n🔧 Tool Breakdown:")
        for tool, count in tool_stats.items():
            # Handle both int and dict formats
            if isinstance(count, dict):
                count = count.get("count", 0)
            percentage = (count / max(total_subs, 1)) * 100
            click.echo(f"   • {tool}: {count} ({percentage:.1f}%)")

    if comprehensive_data.get("resolved"):
        resolved_count = sum(1 for r in comprehensive_data["resolved"] if r["resolved"])
        click.echo(f"🔍 Resolved Subdomains: {resolved_count}")

    if comprehensive_data.get("http_services"):
        http_count = sum(1 for h in comprehensive_data["http_services"] if h["http"])
        https_count = sum(1 for h in comprehensive_data["http_services"] if h["https"])
        click.echo(f"🌐 Active Services: {http_count} HTTP, {https_count} HTTPS")

    click.echo("=" * 60 + "\n")


def validate_domain(domain):
    """Validate domain to prevent shell injection."""
    # Allow only alphanumeric, dots, hyphens (valid domain characters)
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain


def parse_csp_header(
    csp_header: str, target_domain: str, filter_cloudfront: bool = True
) -> Set[str]:
    """Parse Content-Security-Policy header and extract domains/subdomains.

    Args:
        csp_header: The CSP header value
        target_domain: The main target domain to filter for relevant subdomains
        filter_cloudfront: Whether to filter out *.cloudfront.net domains

    Returns:
        Set of discovered domains/subdomains
    """
    if not csp_header:
        return set()

    domains = set()

    # CSP directives that may contain domains
    domain_directives = [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "child-src",
        "worker-src",
        "manifest-src",
        "form-action",
        "frame-ancestors",
        "base-uri",
        "plugin-types",
    ]

    # Split CSP by semicolons to get individual directives
    directives = [d.strip() for d in csp_header.split(";") if d.strip()]

    for directive in directives:
        parts = directive.split()
        if len(parts) < 2:
            continue

        directive_name = parts[0].lower()
        if directive_name not in domain_directives:
            continue

        # Process each value in the directive
        for value in parts[1:]:
            # Skip CSP keywords
            if value.lower() in [
                "'self'",
                "'unsafe-inline'",
                "'unsafe-eval'",
                "'strict-dynamic'",
                "'nonce-*'",
                "'sha256-*'",
                "'sha384-*'",
                "'sha512-*'",
                "'none'",
                "data:",
                "blob:",
                "filesystem:",
                "about:",
                "javascript:",
            ]:
                continue

            # Remove quotes and protocols
            value = value.strip("'\"")
            if value.startswith(("http://", "https://", "ws://", "wss://")):
                parsed = urllib.parse.urlparse(value)
                domain = parsed.netloc
            elif value.startswith("//"):
                domain = value[2:]
            else:
                domain = value

            # Remove port numbers
            if ":" in domain and not domain.startswith("["):  # Not IPv6
                domain = domain.split(":")[0]

            # Basic domain validation
            if not domain or domain in ["*", "localhost"]:
                continue

            # Filter out non-domain values (like 'unsafe-inline', data URLs, etc.)
            if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
                continue

            # Apply cloudfront filter
            if filter_cloudfront and domain.endswith(".cloudfront.net"):
                continue

            # Add wildcard subdomains without the asterisk
            if domain.startswith("*."):
                domain = domain[2:]

            # Only add domains that are relevant to our target or are subdomains
            if (
                domain.endswith("." + target_domain)
                or domain == target_domain
                or target_domain.endswith("." + domain)
            ):
                domains.add(domain)
            else:
                # Also collect external domains that might be interesting
                # (but we'll mark them separately)
                domains.add(domain)

    return domains


def fetch_csp_from_url(
    url: str, timeout: int = 10, ignore_ssl_errors: bool = False
) -> str:
    """Fetch CSP header from a URL.

    Args:
        url: URL to fetch CSP from
        timeout: Request timeout
        ignore_ssl_errors: Whether to ignore SSL certificate errors

    Returns:
        CSP header value or empty string if not found
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=not ignore_ssl_errors,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )

        # Check for CSP headers (multiple possible header names)
        csp_headers = [
            "Content-Security-Policy",
            "Content-Security-Policy-Report-Only",
            "X-Content-Security-Policy",
            "X-WebKit-CSP",
        ]

        for header_name in csp_headers:
            if header_name in response.headers:
                return response.headers[header_name]

    except (requests.RequestException, Exception):
        pass

    return ""


def enumerate_subdomains_from_csp(
    targets: List[str],
    target_domain: str,
    timeout: int = 10,
    threads: int = 50,
    verbose: bool = False,
    ignore_ssl_errors: bool = False,
    filter_cloudfront: bool = True,
) -> Dict[str, Set[str]]:
    """Enumerate subdomains from CSP headers of target URLs.

    Args:
        targets: List of URLs/subdomains to check for CSP headers
        target_domain: Main target domain for filtering
        timeout: Request timeout
        threads: Number of concurrent threads
        verbose: Enable verbose output
        ignore_ssl_errors: Ignore SSL certificate errors
        filter_cloudfront: Filter out cloudfront domains

    Returns:
        Dictionary mapping URLs to discovered domains from their CSP
    """
    if verbose:
        click.echo(f"[+] 🔍 Analyzing CSP headers from {len(targets)} targets...")

    def check_single_target(target: str) -> Dict[str, Set[str]]:
        result = {}

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            urls_to_check = [f"https://{target}", f"http://{target}"]
        else:
            urls_to_check = [target]

        for url in urls_to_check:
            try:
                csp_header = fetch_csp_from_url(url, timeout, ignore_ssl_errors)
                if csp_header:
                    domains = parse_csp_header(
                        csp_header, target_domain, filter_cloudfront
                    )
                    if domains:
                        result[url] = domains
                        if verbose:
                            click.echo(
                                f"[+] 📋 Found CSP at {url}: {len(domains)} domains"
                            )
                        break  # Found CSP, no need to check other protocol
            except Exception as e:
                if verbose:
                    click.echo(f"[!] ❌ Error checking {url}: {str(e)}")

        return result

    all_results = {}

    # Use ThreadPoolExecutor for concurrent CSP checking
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(check_single_target, target): target for target in targets
        }

        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result:
                    all_results.update(result)
            except Exception as e:
                if verbose:
                    click.echo(f"[!] ❌ Error processing {target}: {str(e)}")

    return all_results


def extract_subdomains_from_csp_results(
    csp_results: Dict[str, Set[str]], target_domain: str
) -> Set[str]:
    """Extract unique subdomains from CSP analysis results.

    Args:
        csp_results: Results from enumerate_subdomains_from_csp
        target_domain: Target domain to filter for relevant subdomains

    Returns:
        Set of unique subdomains discovered from CSP headers
    """
    all_subdomains = set()

    for url, domains in csp_results.items():
        for domain in domains:
            # Only include subdomains of our target domain
            if domain.endswith("." + target_domain) or domain == target_domain:
                all_subdomains.add(domain)

    return all_subdomains


def parse_bbot_output(bbot_output_dir, domain, verbose=False):
    """Parse BBOT output and extract subdomains."""
    subdomains = set()

    if not os.path.exists(bbot_output_dir):
        if verbose:
            click.echo(f"[!] ⚠️  BBOT output directory not found: {bbot_output_dir}")
        return subdomains

    # Try to find the scan output directory (BBOT creates timestamp-based directories)
    scan_dirs = [
        d
        for d in os.listdir(bbot_output_dir)
        if os.path.isdir(os.path.join(bbot_output_dir, d))
    ]

    if not scan_dirs:
        if verbose:
            click.echo(f"[!] ⚠️  No BBOT scan directories found in: {bbot_output_dir}")
        return subdomains

    # Use the most recent scan directory
    latest_scan = max(
        scan_dirs, key=lambda x: os.path.getctime(os.path.join(bbot_output_dir, x))
    )
    scan_path = os.path.join(bbot_output_dir, latest_scan)

    # Parse different BBOT output formats
    output_files = [
        "output.txt",  # Default text output
        "subdomains.txt",  # Subdomain-specific output
        "output.json",  # JSON output for more detailed parsing
    ]

    for output_file in output_files:
        file_path = os.path.join(scan_path, output_file)
        if os.path.exists(file_path):
            try:
                if output_file == "output.json":
                    # Parse JSON output for more detailed information
                    with open(file_path, "r") as f:
                        for line in f:
                            if line.strip():
                                try:
                                    event = json.loads(line)
                                    if event.get("type") == "DNS_NAME":
                                        data = event.get("data", "")
                                        if data.endswith(domain) and data != domain:
                                            subdomains.add(data)
                                except json.JSONDecodeError:
                                    continue
                else:
                    # Parse text output
                    with open(file_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            # Extract domains that end with our target domain
                            if line.endswith(domain) and line != domain and "." in line:
                                # Clean up any prefixes like [DNS_NAME] or similar
                                domain_part = line.split()[-1] if " " in line else line
                                if domain_part.endswith(domain):
                                    subdomains.add(domain_part)

                if verbose and subdomains:
                    click.echo(
                        f"[+] 📊 BBOT parsed {len(subdomains)} subdomains from {output_file}"
                    )

            except Exception as e:
                if verbose:
                    click.echo(f"[!] ❌ Error parsing BBOT file {file_path}: {e}")

    return subdomains


def run_bbot_enumeration(domain, outpath, tool_name, cmd, timeout, verbose=False):
    """Run BBOT enumeration with enhanced parsing and error handling."""
    if verbose:
        click.echo(f"[+] 🤖 Running BBOT: {tool_name}")
        click.echo(f"[+] 🔧 Command: {cmd}")

    start_time = time.time()
    subdomains = set()

    try:
        # Run BBOT command with enhanced timeout and error handling
        # NOTE: shell=True is used here for complex command execution
        # Domain parameter is validated by validate_domain() function to prevent injection
        process = subprocess.Popen(  # nosec B602
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True,
        )

        # Wait for completion with timeout
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            elapsed = round(time.time() - start_time, 2)

            if process.returncode == 0:
                # Parse the BBOT output directory
                bbot_output_dir = None

                # Extract output directory from command
                if "-o " in cmd:
                    bbot_output_dir = cmd.split("-o ")[1].split()[0]
                    subdomains = parse_bbot_output(bbot_output_dir, domain, verbose)

                if verbose:
                    click.echo(
                        f"[+] ✅ {tool_name}: {len(subdomains)} subdomains ({elapsed}s)"
                    )
                    if len(subdomains) > 0:
                        click.echo(
                            f"[+] 🎯 BBOT found unique subdomains with {len([m for m in ['anubisdb', 'crt', 'chaos', 'hackertarget', 'rapiddns', 'certspotter', 'dnsdumpster'] if m in cmd.lower()])} passive sources"
                        )

            else:
                if verbose:
                    click.echo(
                        f"[!] ❌ {tool_name} failed (exit code: {process.returncode})"
                    )
                    if stderr:
                        click.echo(f"[!] 💥 Error: {stderr[:200]}...")

        except subprocess.TimeoutExpired:
            process.kill()
            if verbose:
                click.echo(f"[!] ⏰ {tool_name} timeout after {timeout}s")

    except Exception as e:
        if verbose:
            click.echo(f"[!] 💥 {tool_name} error: {str(e)}")

    return list(subdomains)


def export_results_to_csv(output_dir, domain, comprehensive_data, verbose=False):
    """Export comprehensive scan results to CSV format."""
    import csv

    csv_path = os.path.join(output_dir, f"{domain}_subdomains.csv")

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "subdomain",
                "ip",
                "ptr",
                "resolved",
                "http_status",
                "https_status",
                "http_title",
                "https_title",
                "http_active",
                "https_active",
                "discovery_tool",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Get resolved subdomains data
            resolved_data = {
                r["subdomain"]: r
                for r in comprehensive_data.get("resolved", [])
                if r.get("resolved")
            }

            # Get HTTP services data
            http_data = {
                h["subdomain"]: h for h in comprehensive_data.get("http_services", [])
            }

            # Process all subdomains
            for subdomain in comprehensive_data.get("subdomains", []):
                resolved_info = resolved_data.get(subdomain, {})
                http_info = http_data.get(subdomain, {})

                # Determine discovery tool (simplified - could be enhanced)
                discovery_tool = "multiple"
                for tool, stats in comprehensive_data.get("tool_stats", {}).items():
                    if isinstance(stats, int) and stats > 0:
                        discovery_tool = tool
                        break

                row = {
                    "subdomain": subdomain,
                    "ip": resolved_info.get("ip", ""),
                    "ptr": resolved_info.get("ptr", ""),
                    "resolved": resolved_info.get("resolved", False),
                    "http_status": http_info.get("http_status", ""),
                    "https_status": http_info.get("https_status", ""),
                    "http_title": http_info.get("http_title", "")
                    .replace("\n", " ")
                    .replace("\r", " ")[:100],
                    "https_title": http_info.get("https_title", "")
                    .replace("\n", " ")
                    .replace("\r", " ")[:100],
                    "http_active": http_info.get("http", False),
                    "https_active": http_info.get("https", False),
                    "discovery_tool": discovery_tool,
                }
                writer.writerow(row)

        if verbose:
            click.echo(f"📊 CSV export saved: {csv_path}")

        return csv_path

    except Exception as e:
        if verbose:
            click.echo(f"❌ Error exporting to CSV: {e}")
        return None


def export_results_to_json(output_dir, domain, comprehensive_data, verbose=False):
    """Export comprehensive scan results to enhanced JSON format."""
    json_path = os.path.join(output_dir, f"{domain}_export.json")

    try:
        # Enhanced export data with metadata
        export_data = {
            "metadata": {
                "domain": domain,
                "scan_time": comprehensive_data.get("scan_time"),
                "total_subdomains": comprehensive_data.get("total_subdomains", 0),
                "export_time": datetime.now().isoformat(),
                "reconcli_version": "2.0.0",
                "bbot_integration": True,
            },
            "scan_summary": comprehensive_data.get("scan_summary", {}),
            "tool_statistics": comprehensive_data.get("tool_stats", {}),
            "subdomains": {
                "list": comprehensive_data.get("subdomains", []),
                "count": len(comprehensive_data.get("subdomains", [])),
            },
            "resolved_subdomains": {
                "data": comprehensive_data.get("resolved", []),
                "count": len(
                    [
                        r
                        for r in comprehensive_data.get("resolved", [])
                        if r.get("resolved")
                    ]
                ),
            },
            "http_services": {
                "data": comprehensive_data.get("http_services", []),
                "http_count": len(
                    [
                        h
                        for h in comprehensive_data.get("http_services", [])
                        if h.get("http")
                    ]
                ),
                "https_count": len(
                    [
                        h
                        for h in comprehensive_data.get("http_services", [])
                        if h.get("https")
                    ]
                ),
            },
            "statistics": {
                "resolution_rate": 0,
                "http_service_rate": 0,
                "https_service_rate": 0,
            },
        }

        # Calculate statistics
        total_subs = export_data["metadata"]["total_subdomains"]
        if total_subs > 0:
            resolved_count = export_data["resolved_subdomains"]["count"]
            http_count = export_data["http_services"]["http_count"]
            https_count = export_data["http_services"]["https_count"]

            export_data["statistics"]["resolution_rate"] = round(
                (resolved_count / total_subs) * 100, 2
            )
            export_data["statistics"]["http_service_rate"] = round(
                (http_count / total_subs) * 100, 2
            )
            export_data["statistics"]["https_service_rate"] = round(
                (https_count / total_subs) * 100, 2
            )

        with open(json_path, "w", encoding="utf-8") as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)

        if verbose:
            click.echo(f"📊 JSON export saved: {json_path}")
            click.echo(
                f"   • Total subdomains: {export_data['metadata']['total_subdomains']}"
            )
            click.echo(
                f"   • Resolved: {export_data['resolved_subdomains']['count']} ({export_data['statistics']['resolution_rate']}%)"
            )
            click.echo(
                f"   • HTTP services: {export_data['http_services']['http_count']} ({export_data['statistics']['http_service_rate']}%)"
            )
            click.echo(
                f"   • HTTPS services: {export_data['http_services']['https_count']} ({export_data['statistics']['https_service_rate']}%)"
            )

        return json_path

    except Exception as e:
        if verbose:
            click.echo(f"❌ Error exporting to JSON: {e}")
        return None


def export_results_to_txt(output_dir, domain, comprehensive_data, verbose=False):
    """Export comprehensive scan results to structured TXT format."""
    txt_path = os.path.join(output_dir, f"{domain}_export.txt")

    try:
        with open(txt_path, "w", encoding="utf-8") as txtfile:
            # Header with metadata
            txtfile.write(f"# Subdomain Enumeration Report for {domain}\n")
            txtfile.write(f"# Scan Time: {comprehensive_data.get('scan_time')}\n")
            txtfile.write(
                f"# Total Subdomains: {comprehensive_data.get('total_subdomains', 0)}\n"
            )
            txtfile.write(f"# Export Time: {datetime.now().isoformat()}\n")
            txtfile.write("# Generated by ReconCLI SubdoCLI with BBOT Integration\n")
            txtfile.write("\n")

            # Tool Statistics Section
            if comprehensive_data.get("tool_stats"):
                txtfile.write("# TOOL STATISTICS\n")
                txtfile.write("# ================\n")
                for tool, stats in comprehensive_data["tool_stats"].items():
                    count = (
                        stats.get("count", stats) if isinstance(stats, dict) else stats
                    )
                    txtfile.write(f"# {tool}: {count} subdomains\n")
                txtfile.write("\n")

            # All Subdomains Section
            txtfile.write("# ALL DISCOVERED SUBDOMAINS\n")
            txtfile.write("# ==========================\n")
            for subdomain in comprehensive_data.get("subdomains", []):
                txtfile.write(f"{subdomain}\n")
            txtfile.write("\n")

            # Resolved Subdomains Section (if available)
            if comprehensive_data.get("resolved"):
                resolved_subs = [
                    r for r in comprehensive_data["resolved"] if r.get("resolved")
                ]
                if resolved_subs:
                    txtfile.write("# RESOLVED SUBDOMAINS WITH IP ADDRESSES\n")
                    txtfile.write("# ======================================\n")
                    for result in resolved_subs:
                        ip = result.get("ip", "N/A")
                        ptr = result.get("ptr", "")
                        ptr_info = f" (PTR: {ptr})" if ptr else ""
                        txtfile.write(f"{result['subdomain']} -> {ip}{ptr_info}\n")
                    txtfile.write("\n")

            # HTTP Services Section (if available)
            if comprehensive_data.get("http_services"):
                active_services = [
                    h
                    for h in comprehensive_data["http_services"]
                    if h.get("http") or h.get("https")
                ]
                if active_services:
                    txtfile.write("# ACTIVE HTTP/HTTPS SERVICES\n")
                    txtfile.write("# ===========================\n")
                    for service in active_services:
                        protocols = []
                        if service.get("http"):
                            status = service.get("http_status", "Unknown")
                            title = service.get("http_title", "")
                            title_info = f" - {title[:50]}..." if title else ""
                            protocols.append(f"HTTP({status}){title_info}")
                        if service.get("https"):
                            status = service.get("https_status", "Unknown")
                            title = service.get("https_title", "")
                            title_info = f" - {title[:50]}..." if title else ""
                            protocols.append(f"HTTPS({status}){title_info}")
                        txtfile.write(
                            f"{service['subdomain']} -> {' | '.join(protocols)}\n"
                        )
                    txtfile.write("\n")

            # Statistics Summary
            total_subs = comprehensive_data.get("total_subdomains", 0)
            if total_subs > 0:
                txtfile.write("# SCAN STATISTICS SUMMARY\n")
                txtfile.write("# =======================\n")

                if comprehensive_data.get("resolved"):
                    resolved_count = len(
                        [r for r in comprehensive_data["resolved"] if r.get("resolved")]
                    )
                    resolution_rate = round((resolved_count / total_subs) * 100, 2)
                    txtfile.write(
                        f"# Resolution Rate: {resolved_count}/{total_subs} ({resolution_rate}%)\n"
                    )

                if comprehensive_data.get("http_services"):
                    http_count = len(
                        [
                            h
                            for h in comprehensive_data["http_services"]
                            if h.get("http")
                        ]
                    )
                    https_count = len(
                        [
                            h
                            for h in comprehensive_data["http_services"]
                            if h.get("https")
                        ]
                    )
                    http_rate = round((http_count / total_subs) * 100, 2)
                    https_rate = round((https_count / total_subs) * 100, 2)
                    txtfile.write(
                        f"# HTTP Services: {http_count}/{total_subs} ({http_rate}%)\n"
                    )
                    txtfile.write(
                        f"# HTTPS Services: {https_count}/{total_subs} ({https_rate}%)\n"
                    )

        if verbose:
            click.echo(f"📊 TXT export saved: {txt_path}")

        return txt_path

    except Exception as e:
        if verbose:
            click.echo(f"❌ Error exporting to TXT: {e}")
        return None


class SubdomainCacheManager:
    """Subdomain Enumeration Cache Manager for storing and retrieving subdomain enumeration results"""

    def __init__(self, cache_dir: str, max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.cache_index_file = self.cache_dir / "subdomain_cache_index.json"
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
        self, domain: str, tools: List[str], options: Optional[Dict] = None
    ) -> str:
        """Generate cache key from domain, tools, and options"""
        # Create a normalized cache string
        cache_string = f"subdomain:{domain}:tools={','.join(sorted(tools))}"

        # Add relevant options that affect enumeration results
        if options:
            relevant_opts = [
                "wordlist",
                "resolver",
                "recursive",
                "passive_only",
                "active_only",
            ]
            cache_opts = {}
            for opt in relevant_opts:
                if opt in options and options[opt] is not None:
                    cache_opts[opt] = options[opt]
            if cache_opts:
                cache_string += f":opts={json.dumps(cache_opts, sort_keys=True)}"

        return hashlib.sha256(cache_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cache entry is still valid"""
        age_hours = (time.time() - timestamp) / 3600
        return age_hours < self.max_age_hours

    def get(
        self, domain: str, tools: List[str], options: Optional[Dict] = None
    ) -> Optional[dict]:
        """Get cached subdomain enumeration result for domain"""
        cache_key = self._generate_cache_key(domain, tools, options)

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
        domain: str,
        result: dict,
        tools: List[str],
        options: Optional[Dict] = None,
    ):
        """Cache subdomain enumeration result for domain"""
        cache_key = self._generate_cache_key(domain, tools, options)

        # Update cache index
        self.cache_index[cache_key] = {
            "domain": domain,
            "tools": tools,
            "timestamp": time.time(),
            "last_access": time.time(),
            "access_count": 1,
            "subdomain_count": len(result.get("subdomains", [])),
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


@click.command()
@click.option(
    "--cache", is_flag=True, help="Enable caching of subdomain enumeration results"
)
@click.option(
    "--cache-dir",
    default="subdomain_cache",
    help="Directory for cache storage (default: subdomain_cache)",
)
@click.option(
    "--cache-max-age",
    type=int,
    default=86400,
    help="Maximum cache age in seconds (default: 86400 = 24 hours)",
)
@click.option("--clear-cache", is_flag=True, help="Clear all cached subdomain results")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--domain", "-d", help="Target domain for subdomain enumeration")
@click.option("--output-dir", "-o", default="output", help="Directory to save results")
@click.option(
    "--amass-config",
    default=os.path.expanduser("~/.config/amass/config.ini"),
    help="Path to Amass config",
)
@click.option(
    "--tools",
    help="Comma-separated list of specific tools to run (e.g., 'amass,subfinder,csp_analyzer'). Available tools: subfinder, findomain, assetfinder, chaos, amass, sublist3r, github-subdomains, wayback, otx, hackertarget, rapiddns, certspotter, crtsh_alternative, csp_analyzer",
)
@click.option("--markdown", is_flag=True, help="Generate Markdown report")
@click.option("--resolve", is_flag=True, help="Resolve subdomains to IP addresses")
@click.option("--probe-http", is_flag=True, help="Probe HTTP/HTTPS services")
@click.option(
    "--ignore-ssl-errors",
    is_flag=True,
    help="Ignore SSL certificate errors when probing HTTPS",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--timeout", default=200, help="Timeout for individual operations (seconds)"
)
@click.option(
    "--threads", default=50, help="Number of threads for concurrent operations"
)
@click.option(
    "--all-tools", is_flag=True, help="Use all available tools (including active)"
)
@click.option("--active", is_flag=True, help="Include active enumeration tools")
@click.option(
    "--passive-only",
    is_flag=True,
    help="Use only traditional passive tools (no BBOT, no active)",
)
@click.option(
    "--active-only",
    is_flag=True,
    help="Use only traditional active tools (no BBOT, no passive)",
)
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option("--show-stats", is_flag=True, help="Show detailed statistics")
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (uses --domain if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
@click.option(
    "--bbot",
    is_flag=True,
    help="Enable BBOT (Bighuge BLS OSINT Tool) for superior subdomain enumeration with 53+ modules",
)
@click.option(
    "--bbot-intensive",
    is_flag=True,
    help="Enable BBOT intensive mode with aggressive subdomain bruteforcing and larger wordlists",
)
@click.option(
    "--export",
    type=click.Choice(["csv", "json", "txt"], case_sensitive=False),
    help="Export results to CSV, JSON, or TXT format for analysis and reporting",
)
@click.option(
    "--csp-analysis",
    is_flag=True,
    help="Enable Content-Security-Policy header analysis for subdomain discovery",
)
@click.option(
    "--csp-targets-file",
    help="File containing list of URLs/subdomains to analyze for CSP headers (one per line)",
)
@click.option(
    "--csp-filter-cloudfront",
    is_flag=True,
    default=True,
    help="Filter out *.cloudfront.net domains from CSP analysis results",
)
def subdocli(
    cache,
    cache_dir,
    cache_max_age,
    clear_cache,
    cache_stats,
    domain,
    output_dir,
    amass_config,
    tools,
    markdown,
    resolve,
    probe_http,
    ignore_ssl_errors,
    verbose,
    timeout,
    threads,
    all_tools,
    active,
    passive_only,
    active_only,
    resume,
    clear_resume,
    show_stats,
    store_db,
    target_domain,
    program,
    bbot,
    bbot_intensive,
    export,
    csp_analysis,
    csp_targets_file,
    csp_filter_cloudfront,
):
    """Enhanced subdomain enumeration using multiple tools with resolution and HTTP probing.

    🔧 AVAILABLE TOOLS:
    • Traditional Passive: subfinder, findomain, assetfinder, chaos, amass, sublist3r, github-subdomains
    • API-Based: wayback, otx, hackertarget, rapiddns, certspotter, crtsh_alternative
    • CSP Analysis: Content-Security-Policy header parsing for subdomain discovery
    • Active Tools: gobuster, ffuf, dnsrecon (use --active or --all-tools)
    • BBOT Integration: 53+ modules for superior discovery (use --bbot)

    📝 USAGE EXAMPLES:
    • Single tool: --tools amass
    • Multiple tools: --tools "amass,subfinder,github-subdomains,crtsh_alternative"
    • With CSP analysis: --tools "subfinder,csp_analyzer" --csp-analysis
    • All passive: --passive-only
    • All tools: --all-tools

    📋 CSP ANALYSIS FEATURES:
    • Parse Content-Security-Policy headers from websites
    • Extract domains from script-src, frame-src, connect-src, and other CSP directives
    • Filter out common CDN domains (*.cloudfront.net) with --csp-filter-cloudfront
    • Analyze existing subdomains or provide custom target list with --csp-targets-file
    • Discover internal subdomains and third-party integrations

    Now featuring BBOT (Bighuge BLS OSINT Tool) integration for superior subdomain discovery:

    🤖 BBOT Features:
    • 53+ passive & active subdomain enumeration modules
    • Advanced sources: anubisdb, crt.sh, chaos, hackertarget, certspotter, dnsdumpster
    • Certificate transparency monitoring & DNS bruteforcing
    • Intelligent mutations and target-specific wordlists
    • Cloud resource enumeration and GitHub code search

    ⚙️ Traditional Tools Control:
    • --passive-only: Use only traditional passive tools (subfinder, findomain, amass, github-subdomains, etc.)
    • --active-only: Use only traditional active tools (gobuster, ffuf, dnsrecon)
    • --bbot: Add BBOT integration with traditional tools
    • --all-tools: Use everything (traditional + BBOT + active)

    📊 Export Options:
    • CSV format for spreadsheet analysis and data processing
    • JSON format for programmatic analysis and API integration
    • TXT format for readable reports and simple text processing

    Use --bbot for standard BBOT enumeration or --bbot-intensive for maximum coverage.
    Use --export csv|json|txt for structured data export.
    Use --csp-analysis to discover subdomains from Content-Security-Policy headers.

    🔑 GitHub Token Configuration (for github-subdomains):
    • Set GITHUB_TOKEN environment variable: export GITHUB_TOKEN="your_token_here"
    • Supports single token, comma-separated tokens, or token file (.tokens)
    • Required for github-subdomains tool to search GitHub repositories for subdomains
    • Get your token at: https://github.com/settings/tokens
    """

    # Initialize cache manager
    cache_manager = SubdomainCacheManager(cache_dir, cache_max_age)

    # Handle cache operations that don't require domain
    if clear_cache:
        count = cache_manager.clear_all()
        click.echo(f"✅ Cache cleared successfully ({count} entries removed)")
        return

    if cache_stats:
        stats = cache_manager.get_stats()
        click.echo("\n📊 Cache Statistics:")
        click.echo(f"  Total entries: {stats['total_entries']}")
        click.echo(f"  Total size: {stats['total_size_kb']:.2f} KB")
        click.echo(f"  Valid entries: {stats['valid_entries']}")
        click.echo(f"  Expired entries: {stats['expired_entries']}")
        return

    # Validate domain input (required for actual scanning)
    if not domain:
        click.echo("❌ Error: --domain is required for subdomain enumeration")
        return

    try:
        domain = validate_domain(domain)
    except ValueError as e:
        click.echo(f"❌ Error: {e}")
        return

    # Determine tools list for caching (available for both cache check and storage)
    cache_tools = []
    if tools:
        cache_tools = [t.strip() for t in tools.split(",")]
    elif all_tools:
        cache_tools = ["all_tools"]
    elif active:
        cache_tools = ["active"]
    elif passive_only:
        cache_tools = ["passive_only"]
    elif active_only:
        cache_tools = ["active_only"]
    elif bbot:
        cache_tools = ["bbot"]
    elif bbot_intensive:
        cache_tools = ["bbot_intensive"]
    else:
        cache_tools = ["default"]

    # Check cache if enabled
    if cache:
        cached_result = cache_manager.get(
            domain,
            cache_tools,
            {
                "resolve": resolve,
                "probe_http": probe_http,
                "timeout": timeout,
                "threads": threads,
                "all_tools": all_tools,
                "active": active,
                "passive_only": passive_only,
                "active_only": active_only,
                "bbot": bbot,
                "bbot_intensive": bbot_intensive,
                "csp_analysis": csp_analysis,
                "csp_filter_cloudfront": csp_filter_cloudfront,
            },
        )

        if cached_result:
            click.echo("🎯 Found cached subdomain results!")
            subdomains = cached_result.get("subdomains", [])
            click.echo(f"✅ Loaded {len(subdomains)} subdomains from cache")

            # Display results and exit if cache hit
            for subdomain in subdomains:
                click.echo(subdomain)
            return

    # Determine which amass config to use
    final_amass_config = amass_config

    # Only show amass config if explicitly provided by user
    if verbose and (amass_config != os.path.expanduser("~/.config/amass/config.ini")):
        click.echo(f"[+] 🔧 Using Amass config: {final_amass_config}")

    # Handle resume operations
    if clear_resume:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        return

    # Setup output directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outpath = os.path.join(output_dir, domain)
    os.makedirs(outpath, exist_ok=True)

    # Resume support
    scan_key = f"subdomain_scan_{timestamp}"
    resume_state = load_resume(outpath)

    if resume and resume_state:
        if verbose:
            click.echo("[+] 📁 Loading resume state")
        # Find the most recent incomplete scan
        for key, data in sorted(resume_state.items(), reverse=True):
            if key.startswith("subdomain_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "domain": domain,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "tools_completed": [],
            "total_subdomains": 0,
        }
        save_resume_state(outpath, resume_state)

    if verbose:
        click.echo(f"[+] 🚀 Starting subdomain enumeration for {domain}")
        click.echo(f"[+] 📁 Output directory: {outpath}")
        click.echo(f"[+] ⏰ Base timeout: {timeout}s")
        click.echo(f"[+] 🧵 Threads: {threads}")

    # Enhanced tool configuration with optimized timeouts for better results
    traditional_timeout = (
        max(150, timeout) if timeout < 150 else timeout
    )  # Minimum 150s for traditional tools

    # Increase timeouts: +20% for traditional tools, +40% for amass
    traditional_timeout = int(traditional_timeout * 1.2)  # 20% increase
    amass_timeout = int(min(traditional_timeout, 600) * 1.4)  # 40% increase for amass

    if verbose:
        click.echo(f"[+] ⏰ Traditional tools timeout: {traditional_timeout}s (+20%)")
        click.echo(f"[+] ⏰ Amass timeout: {amass_timeout}s (+40%)")

    # Build amass command with config if provided
    amass_cmd = f"timeout {min(120, amass_timeout)}s amass enum --passive -d {domain}"
    if final_amass_config and os.path.exists(final_amass_config):
        amass_cmd += f" -config {final_amass_config}"
    amass_cmd += " -o /tmp/amass_output.txt && cat /tmp/amass_output.txt"

    base_passive_tools = {
        "subfinder": f"timeout {traditional_timeout}s subfinder -all -d {domain} -silent",
        "findomain": f"timeout {traditional_timeout}s findomain -t {domain} -q",
        "assetfinder": f"timeout {traditional_timeout}s assetfinder --subs-only {domain}",
        "chaos": f"timeout {traditional_timeout}s chaos -d {domain} -silent",
        "amass": amass_cmd,
        "sublist3r": f"timeout {traditional_timeout}s sublist3r -d {domain} -o /tmp/sublist3r_output.txt -n && cat /tmp/sublist3r_output.txt",
        "github-subdomains": f"timeout {int(300 * 1.2)}s github-subdomains -d {domain} -raw -o /tmp/github_subdomains_{domain}.txt && cat /tmp/github_subdomains_{domain}.txt 2>/dev/null || echo ''",
        "wayback": f"timeout {int(90 * 1.2)}s curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey' | sed -e 's_https*://__' -e 's_/.*__' | grep -E '^[a-zA-Z0-9.-]+\\.{domain}$' | sort -u",
        "otx": f"timeout {int(90 * 1.2)}s curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=100&page=1' | jq -r '.url_list[].hostname' 2>/dev/null | grep -E '^[a-zA-Z0-9.-]+\\.{domain}$' | sort -u",
        "hackertarget": f"timeout {int(90 * 1.2)}s curl -s 'https://api.hackertarget.com/hostsearch/?q={domain}' | cut -d',' -f1 | grep -E '^[a-zA-Z0-9.-]+\\.{domain}$' | sort -u",
        "rapiddns": f"timeout {int(90 * 1.2)}s curl -s 'https://rapiddns.io/subdomain/{domain}?full=1' | grep -oE '[a-zA-Z0-9.-]+\\.{domain}' | sort -u",
        "certspotter": f"timeout {int(90 * 1.2)}s curl -s 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' 2>/dev/null | grep -E '^[a-zA-Z0-9.-]+\\.{domain}$' | sort -u",
        "crtsh_alternative": f"timeout {int(180 * 1.2)}s curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u | grep -o '\\w.*{domain}' | grep -v '@' || echo ''",
        "csp_analyzer": "CSP_ANALYSIS_TOOL",  # Special marker for CSP analysis
    }

    # BBOT tools - separate for conditional inclusion
    bbot_passive_tools = {
        "bbot_passive": f"/home/jarek/reconcli_dnscli_full/.venv/bin/bbot -t {domain} -p subdomain-enum -o {outpath}/bbot_passive --force -y",
        "bbot_comprehensive": f"/home/jarek/reconcli_dnscli_full/.venv/bin/bbot -t {domain} -rf passive,safe,subdomain-enum -o {outpath}/bbot_comprehensive --force -y",
    }

    base_active_tools = {
        "gobuster": f"gobuster dns -d {domain} -w /usr/share/wordlists/dirb/common.txt -q",
        "ffuf": f"ffuf -w /usr/share/wordlists/dirb/common.txt -u http://FUZZ.{domain} -mc 200,301,302,403 -fs 0 -s",
        "dnsrecon": f"dnsrecon -d {domain} -t brt -D /usr/share/wordlists/dirb/common.txt --xml {outpath}/dnsrecon.xml",
    }

    # BBOT active tools - separate for conditional inclusion
    bbot_active_tools = {
        "bbot_active": f"/home/jarek/reconcli_dnscli_full/.venv/bin/bbot -t {domain} -rf active,subdomain-enum -o {outpath}/bbot_active --force -y",
    }

    # BBOT intensive tools for maximum coverage
    bbot_intensive_tools = {
        "bbot_intensive": f"/home/jarek/reconcli_dnscli_full/.venv/bin/bbot -t {domain} -rf active,aggressive,subdomain-enum -c modules.dnsbrute.wordlist=big -o {outpath}/bbot_intensive --force -y",
        "bbot_kitchen_sink": f"/home/jarek/reconcli_dnscli_full/.venv/bin/bbot -t {domain} -p kitchen-sink -o {outpath}/bbot_kitchen_sink --force -y",
    }

    # Build tool configuration based on options
    passive_tools = base_passive_tools.copy()
    active_tools = base_active_tools.copy()

    # Handle exclusive modes first
    if passive_only and active_only:
        click.echo("❌ Error: Cannot use --passive-only and --active-only together")
        return

    if passive_only and (bbot or bbot_intensive):
        click.echo(
            "❌ Error: --passive-only excludes BBOT tools. Use traditional passive tools only."
        )
        return

    if active_only and (bbot or bbot_intensive):
        click.echo(
            "❌ Error: --active-only excludes BBOT tools. Use traditional active tools only."
        )
        return

    # Determine which tools to use
    if tools:
        # User specified specific tools
        selected_tools = [tool.strip() for tool in tools.split(",")]
        all_available_tools = {
            **base_passive_tools,
            **base_active_tools,
            **bbot_passive_tools,
            **bbot_active_tools,
            **bbot_intensive_tools,
        }

        tools_dict = {}
        for tool in selected_tools:
            if tool in all_available_tools:
                tools_dict[tool] = all_available_tools[tool]
            else:
                click.echo(f"❌ Warning: Unknown tool '{tool}' - skipping")

        tools = tools_dict
        if verbose:
            click.echo(f"[+] 🎯 Using specified tools: {', '.join(tools.keys())}")
    elif passive_only:
        # Only traditional passive tools
        tools = base_passive_tools.copy()
        if verbose:
            click.echo(
                "[+] 🔵 Using traditional passive tools only (no BBOT, no active)"
            )
    elif active_only:
        # Only traditional active tools
        tools = base_active_tools.copy()
        if verbose:
            click.echo(
                "[+] 🔴 Using traditional active tools only (no BBOT, no passive)"
            )
    else:
        # Normal logic with BBOT integration
        # Add BBOT tools based on flags
        if bbot or all_tools:
            passive_tools.update(bbot_passive_tools)
            active_tools.update(bbot_active_tools)
            if verbose:
                click.echo(
                    "[+] 🤖 BBOT (Bighuge BLS OSINT Tool) enabled with 53+ modules"
                )

        if bbot_intensive or all_tools:
            active_tools.update(bbot_intensive_tools)
            if verbose:
                click.echo(
                    "[+] 🚀 BBOT intensive mode enabled - maximum subdomain coverage"
                )

        # Select tools based on options
        tools = passive_tools.copy()
        if active or all_tools:
            tools.update(active_tools)
            if verbose:
                click.echo("[+] 🔥 Active enumeration enabled")

    # Auto-enable CSP analysis if csp_analyzer tool is selected
    if "csp_analyzer" in tools and not csp_analysis:
        csp_analysis = True
        if verbose:
            click.echo("[+] 📋 Auto-enabled CSP analysis (csp_analyzer tool selected)")

    current_scan = resume_state[scan_key]
    completed_tools = set(current_scan.get("tools_completed", []))
    all_subs = set()
    tool_stats = {}

    if verbose:
        click.echo(f"[+] 🛠️  Using {len(tools)} enumeration tools")
        click.echo(f"[+] ⌨️  Press Ctrl+C to stop current tool and continue with next")

    # Create timeout map for different tools
    tool_timeouts = {
        "github-subdomains": int(300 * 1.2),  # 360 seconds for github-subdomains
        "amass": amass_timeout,
        "wayback": int(90 * 1.2),
        "otx": int(90 * 1.2),
        "hackertarget": int(90 * 1.2),
        "rapiddns": int(90 * 1.2),
        "certspotter": int(90 * 1.2),
        "crtsh_alternative": int(180 * 1.2),
    }

    # Run enumeration tools with enhanced error handling
    total_tools = len(tools)
    current_tool_num = 0

    # Run enumeration tools with enhanced error handling
    total_tools = len(tools)
    current_tool_num = 0
    for tool, cmd in tools.items():
        current_tool_num += 1

        if tool in completed_tools:
            if verbose:
                click.echo(
                    f"[=] ⏭️  Skipping {tool} (already completed) [{current_tool_num}/{total_tools}]"
                )
            # Load previous results
            tool_file = os.path.join(outpath, f"{tool}.txt")
            if os.path.exists(tool_file):
                with open(tool_file, "r") as f:
                    lines = [line.strip() for line in f if line.strip()]
                    all_subs.update(lines)
                    tool_stats[tool] = len(lines)
            continue

        if verbose:
            click.echo(f"[+] 🔧 Running: {tool} [{current_tool_num}/{total_tools}]")
            if tool == "amass":
                click.echo(
                    f"[+] ⏰ Amass timeout set to {amass_timeout}s (+40% increase) to prevent hanging"
                )
            elif tool == "github-subdomains":
                click.echo(
                    f"[+] ⏰ GitHub-subdomains timeout set to {tool_timeouts.get(tool, timeout)}s for comprehensive search"
                )

        start_time = time.time()
        lines = []
        process = None  # Initialize process variable

        try:
            # Special handling for BBOT tools
            if tool.startswith("bbot_"):
                lines = run_bbot_enumeration(
                    domain, outpath, tool, cmd, timeout, verbose
                )
            # Special handling for CSP analysis
            elif tool == "csp_analyzer":
                if csp_analysis:
                    if verbose:
                        click.echo("[+] 📋 Starting CSP header analysis...")

                    # Determine targets for CSP analysis
                    csp_targets = []

                    if csp_targets_file and os.path.exists(csp_targets_file):
                        # Load targets from file
                        with open(csp_targets_file, "r") as f:
                            csp_targets = [line.strip() for line in f if line.strip()]
                        if verbose:
                            click.echo(
                                f"[+] 📂 Loaded {len(csp_targets)} targets from {csp_targets_file}"
                            )
                    else:
                        # Use already discovered subdomains as targets
                        csp_targets = list(all_subs) if all_subs else [domain]
                        if verbose:
                            click.echo(
                                f"[+] 🎯 Using {len(csp_targets)} discovered subdomains as CSP targets"
                            )

                    if csp_targets:
                        # Run CSP analysis
                        csp_results = enumerate_subdomains_from_csp(
                            csp_targets,
                            domain,
                            timeout,
                            threads,
                            verbose,
                            ignore_ssl_errors,
                            csp_filter_cloudfront,
                        )

                        # Extract subdomains from CSP results
                        csp_subdomains = extract_subdomains_from_csp_results(
                            csp_results, domain
                        )
                        lines = list(csp_subdomains)

                        # Save detailed CSP analysis results
                        csp_report_path = os.path.join(outpath, "csp_analysis.json")
                        with open(csp_report_path, "w") as f:
                            csp_export = {}
                            for url, domains in csp_results.items():
                                csp_export[url] = list(domains)
                            json.dump(csp_export, f, indent=2)

                        if verbose:
                            click.echo(
                                f"[+] 📋 CSP analysis found {len(lines)} subdomains"
                            )
                            click.echo(
                                f"[+] 📄 Detailed CSP results saved to: {csp_report_path}"
                            )
                    else:
                        lines = []
                        if verbose:
                            click.echo("[!] ⚠️  No targets available for CSP analysis")
                else:
                    lines = []
                    if verbose:
                        click.echo(
                            "[!] ⚠️  CSP analysis tool selected but --csp-analysis flag not set"
                        )
            else:
                # Enhanced tool execution with better timeout handling
                # NOTE: shell=True is required for complex commands with pipes and redirections
                # Domain is validated above to prevent shell injection
                process = subprocess.Popen(  # nosec B602
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=os.setsid if hasattr(os, "setsid") else None,
                )

                try:
                    # Use tool-specific timeout or fall back to general timeout
                    tool_timeout = tool_timeouts.get(tool, timeout)
                    stdout, stderr = process.communicate(timeout=tool_timeout)
                    if process.returncode == 0:
                        lines = [
                            line.strip() for line in stdout.splitlines() if line.strip()
                        ]
                    else:
                        if verbose:
                            click.echo(
                                f"[!] ⚠️  {tool} returned exit code {process.returncode}"
                            )
                        lines = []
                except subprocess.TimeoutExpired:
                    if verbose:
                        click.echo(f"[!] ⏰ {tool} timeout - killing process...")

                    # Kill the entire process group to ensure all child processes are terminated
                    if hasattr(os, "killpg") and hasattr(os, "setsid"):
                        try:
                            os.killpg(os.getpgid(process.pid), 9)
                        except:
                            process.kill()
                    else:
                        process.kill()

                    process.wait()
                    actual_timeout = tool_timeouts.get(tool, timeout) or timeout
                    raise subprocess.TimeoutExpired(cmd, float(actual_timeout))

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo(f"[!] ⏰ {tool} timeout after {timeout}s")
            # Still save partial results if any
            if lines:
                with open(os.path.join(outpath, f"{tool}.txt"), "w") as f:
                    f.write("\n".join(lines) + "\n")
                all_subs.update(lines)
                if verbose:
                    click.echo(f"[+] 💾 Saved {len(lines)} partial results from {tool}")
            tool_stats[tool] = len(lines)
        except KeyboardInterrupt:
            if verbose:
                click.echo(
                    f"[!] ⏹️  {tool} interrupted by user - killing process and continuing with next tool"
                )

            # Try to get partial output before killing
            partial_output = []
            if process is not None:
                try:
                    # Try to read any available output
                    if process.stdout:
                        partial_stdout = process.stdout.read()
                        if partial_stdout:
                            partial_output = [
                                line.strip()
                                for line in partial_stdout.splitlines()
                                if line.strip()
                            ]
                except (OSError, ValueError, AttributeError):
                    # Handle various errors that can occur when reading from process
                    pass

                # Kill the process when user interrupts
                try:
                    # Kill the entire process group to ensure all child processes are terminated
                    if hasattr(os, "killpg") and hasattr(os, "setsid"):
                        try:
                            os.killpg(os.getpgid(process.pid), 9)
                        except:
                            process.kill()
                    else:
                        process.kill()
                    process.wait()
                except (ProcessLookupError, OSError):
                    # Process might already be dead or other OS errors
                    pass

            # Extra cleanup for amass - kill any remaining amass processes
            if tool == "amass":
                try:
                    subprocess.run(
                        ["/usr/bin/pkill", "-f", "amass"],
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if verbose:
                        click.echo(f"[!] 🔪 Killed any remaining {tool} processes")
                except (subprocess.SubprocessError, FileNotFoundError, OSError):
                    # pkill might not be available or other subprocess errors
                    pass

            # Save partial results if any (from lines or partial_output)
            results_to_save = lines if lines else partial_output
            if results_to_save:
                with open(os.path.join(outpath, f"{tool}.txt"), "w") as f:
                    f.write("\n".join(results_to_save) + "\n")
                all_subs.update(results_to_save)
                if verbose:
                    click.echo(
                        f"[+] 💾 Saved {len(results_to_save)} partial results from {tool}"
                    )
            tool_stats[tool] = len(results_to_save)
        except subprocess.CalledProcessError:
            if verbose:
                click.echo(f"[!] ❌ {tool} failed or returned no results")
            # Still save partial results if any
            if lines:
                with open(os.path.join(outpath, f"{tool}.txt"), "w") as f:
                    f.write("\n".join(lines) + "\n")
                all_subs.update(lines)
                if verbose:
                    click.echo(f"[+] 💾 Saved {len(lines)} partial results from {tool}")
            tool_stats[tool] = len(lines)
        except Exception as e:
            if verbose:
                click.echo(f"[!] 💥 {tool} error: {str(e)}")
            # Still save partial results if any
            if lines:
                with open(os.path.join(outpath, f"{tool}.txt"), "w") as f:
                    f.write("\n".join(lines) + "\n")
                all_subs.update(lines)
                if verbose:
                    click.echo(f"[+] 💾 Saved {len(lines)} partial results from {tool}")
            tool_stats[tool] = len(lines)
        else:
            # Normal completion - save results
            with open(os.path.join(outpath, f"{tool}.txt"), "w") as f:
                f.write("\n".join(lines) + "\n")

            all_subs.update(lines)
            tool_stats[tool] = len(lines)

            # Update resume state
            completed_tools.add(tool)
            current_scan["tools_completed"] = list(completed_tools)
            save_resume_state(outpath, resume_state)

            elapsed = round(time.time() - start_time, 2)
            if verbose:
                click.echo(f"[+] ✅ {tool}: {len(lines)} subdomains ({elapsed}s)")

    # Clean up and deduplicate subdomains
    if verbose:
        click.echo("[+] 🧹 Processing and deduplicating subdomains...")

    all_subs = sorted(set([s for s in all_subs if s.endswith(domain) and s.strip()]))

    if verbose:
        click.echo(f"[+] 📊 Found {len(all_subs)} unique subdomains")

    # Save basic results
    with open(os.path.join(outpath, "all.txt"), "w") as f:
        f.write("\n".join(all_subs) + "\n")

    # DNS Resolution
    resolved_subs = []
    if resolve:
        if verbose:
            click.echo(f"[+] 🔍 Resolving {len(all_subs)} subdomains...")
        resolved_subs = resolve_subdomains(all_subs, threads, verbose)

        # Save resolved results
        with open(os.path.join(outpath, "resolved.json"), "w") as f:
            json.dump(resolved_subs, f, indent=2)

    # HTTP Probing
    http_results = []
    if probe_http:
        targets = (
            resolved_subs if resolved_subs else [{"subdomain": sub} for sub in all_subs]
        )
        if verbose:
            click.echo(f"[+] 🌐 Probing HTTP services on {len(targets)} targets...")
        http_results = probe_http_services(
            targets, timeout, threads, verbose, ignore_ssl_errors
        )

        # Save HTTP results
        with open(os.path.join(outpath, "http_services.json"), "w") as f:
            json.dump(http_results, f, indent=2)

    # Generate comprehensive JSON report
    comprehensive_data = {
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "total_subdomains": len(all_subs),
        "subdomains": all_subs,
        "tool_stats": tool_stats,
        "resolved": resolved_subs if resolve else [],
        "http_services": http_results if probe_http else [],
        "scan_summary": {
            "tools_used": list(tools.keys()),
            "passive_tools": len(passive_tools),
            "active_tools": len(active_tools) if (active or all_tools) else 0,
            "resolution_enabled": resolve,
            "http_probing_enabled": probe_http,
            "csp_analysis_enabled": csp_analysis and "csp_analyzer" in tools,
            "csp_filter_cloudfront": csp_filter_cloudfront if csp_analysis else False,
        },
    }

    with open(os.path.join(outpath, "comprehensive_report.json"), "w") as f:
        json.dump(comprehensive_data, f, indent=2)

    # Store results in cache if caching is enabled
    if cache:
        if verbose:
            click.echo("[+] 💾 Storing results in cache...")
        cache_manager.set(
            domain,
            comprehensive_data,
            cache_tools,
            {
                "resolve": resolve,
                "probe_http": probe_http,
                "timeout": timeout,
                "threads": threads,
                "all_tools": all_tools,
                "active": active,
                "passive_only": passive_only,
                "active_only": active_only,
                "bbot": bbot,
                "bbot_intensive": bbot_intensive,
                "csp_analysis": csp_analysis,
                "csp_filter_cloudfront": csp_filter_cloudfront,
            },
        )

    # Generate enhanced markdown report
    if markdown:
        generate_enhanced_markdown_report(outpath, domain, comprehensive_data, verbose)

    # Export results to CSV or JSON if requested
    if export:
        if verbose:
            click.echo(f"[+] 📊 Exporting results to {export.upper()} format...")

        if export.lower() == "csv":
            csv_file = export_results_to_csv(
                outpath, domain, comprehensive_data, verbose
            )
            if csv_file and verbose:
                click.echo(f"[+] ✅ CSV export completed: {csv_file}")

        elif export.lower() == "json":
            json_file = export_results_to_json(
                outpath, domain, comprehensive_data, verbose
            )
            if json_file and verbose:
                click.echo(f"[+] ✅ JSON export completed: {json_file}")

        elif export.lower() == "txt":
            txt_file = export_results_to_txt(
                outpath, domain, comprehensive_data, verbose
            )
            if txt_file and verbose:
                click.echo(f"[+] ✅ TXT export completed: {txt_file}")

    # Show statistics
    if show_stats or verbose:
        display_scan_statistics(comprehensive_data, tool_stats)

    # Mark scan as completed
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()
    current_scan["total_subdomains"] = len(all_subs)
    save_resume_state(outpath, resume_state)

    if verbose:
        click.echo("[+] ✅ Subdomain enumeration completed!")
        click.echo(f"[+] 📁 Results saved to: {outpath}/")

    # Database storage
    if store_db:
        try:
            from reconcli.db.operations import store_subdomains, store_target

            # Use provided target_domain or fall back to domain
            final_target_domain = target_domain or domain

            if final_target_domain:
                # Ensure target exists in database
                target_id = store_target(final_target_domain, program=program)

                # Prepare subdomain data for database storage
                subdomain_data = []

                # If we have resolved subdomains, use those with IP info
                if comprehensive_data.get("resolved"):
                    for result in comprehensive_data["resolved"]:
                        if result["resolved"]:  # Only store successfully resolved
                            entry = {
                                "subdomain": result["subdomain"],
                                "ip": result["ip"],
                            }
                            subdomain_data.append(entry)
                else:
                    # Fall back to basic subdomain list
                    for subdomain in all_subs:
                        entry = {"subdomain": subdomain, "ip": None}
                        subdomain_data.append(entry)

                # Store subdomains in database
                if subdomain_data:
                    stored_ids = store_subdomains(
                        final_target_domain, subdomain_data, "subdocli"
                    )
                    if verbose:
                        click.echo(
                            f"🗄️ Stored {len(stored_ids)} subdomains in database for {final_target_domain}"
                        )
                        if program:
                            click.echo(f"   Program: {program}")
                        tools_used = comprehensive_data.get("scan_summary", {}).get(
                            "tools_used", []
                        )
                        if tools_used:
                            click.echo(f"   Tools: {', '.join(tools_used)}")
                else:
                    if verbose:
                        click.echo("⚠️ No subdomains to store in database")
            else:
                if verbose:
                    click.echo(
                        "⚠️ Could not determine target domain for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo(
                    "⚠️ Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if verbose:
                click.echo(f"❌ Error storing to database: {e}")


if __name__ == "__main__":
    subdocli()
