#!/usr/bin/env python3
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime

import click
import requests

from reconcli.utils.resume import load_resume, save_resume_state


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
            except:
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
        except:
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
        except:
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
        process = subprocess.Popen(
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


@click.command()
@click.option(
    "--domain", "-d", required=True, help="Target domain for subdomain enumeration"
)
@click.option("--output-dir", "-o", default="output", help="Directory to save results")
@click.option(
    "--amass-config",
    default=os.path.expanduser("~/.config/amass/config.ini"),
    help="Path to Amass config",
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
    "--passive-only", is_flag=True, help="Use only traditional passive tools (no BBOT, no active)"
)
@click.option(
    "--active-only", is_flag=True, help="Use only traditional active tools (no BBOT, no passive)"
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
def subdocli(
    domain,
    output_dir,
    amass_config,
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
):
    """Enhanced subdomain enumeration using multiple tools with resolution and HTTP probing.

    Now featuring BBOT (Bighuge BLS OSINT Tool) integration for superior subdomain discovery:

    🤖 BBOT Features:
    • 53+ passive & active subdomain enumeration modules
    • Advanced sources: anubisdb, crt.sh, chaos, hackertarget, certspotter, dnsdumpster
    • Certificate transparency monitoring & DNS bruteforcing
    • Intelligent mutations and target-specific wordlists
    • Cloud resource enumeration and GitHub code search

    �️ Traditional Tools Control:
    • --passive-only: Use only traditional passive tools (subfinder, findomain, amass, etc.)
    • --active-only: Use only traditional active tools (gobuster, ffuf, dnsrecon)
    • --bbot: Add BBOT integration with traditional tools
    • --all-tools: Use everything (traditional + BBOT + active)

    �📊 Export Options:
    • CSV format for spreadsheet analysis and data processing
    • JSON format for programmatic analysis and API integration
    • TXT format for readable reports and simple text processing

    Use --bbot for standard BBOT enumeration or --bbot-intensive for maximum coverage.
    Use --export csv|json|txt for structured data export.
    """

    # Validate domain input to prevent shell injection
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        click.echo(f"❌ Error: {e}")
        return

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
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🧵 Threads: {threads}")

    # Enhanced tool configuration with BBOT integration
    base_passive_tools = {
        "subfinder": f"subfinder -all -d {domain} -silent",
        "findomain": f"findomain -t {domain} -q",
        "assetfinder": f"assetfinder --subs-only {domain}",
        "amass": f"amass enum -config {amass_config} -d {domain} -silent",
        "chaos": f"chaos -d {domain} -silent",
        "rapiddns": f"curl -s 'https://rapiddns.io/subdomain/{domain}?full=1' | grep -oE '[a-zA-Z0-9.-]+\\.{domain}' | sort -u",
        "crtsh": f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u",
        "bufferover": f"curl -s 'https://dns.bufferover.run/dns?q=.{domain}' | jq -r '.FDNS_A[],.RDNS[]' | cut -d',' -f2 | grep -o '[a-zA-Z0-9.-]*\\.{domain}' | sort -u",
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
        click.echo("❌ Error: --passive-only excludes BBOT tools. Use traditional passive tools only.")
        return
        
    if active_only and (bbot or bbot_intensive):
        click.echo("❌ Error: --active-only excludes BBOT tools. Use traditional active tools only.")
        return

    # Determine which tools to use
    if passive_only:
        # Only traditional passive tools
        tools = base_passive_tools.copy()
        if verbose:
            click.echo("[+] 🔵 Using traditional passive tools only (no BBOT, no active)")
    elif active_only:
        # Only traditional active tools
        tools = base_active_tools.copy()
        if verbose:
            click.echo("[+] 🔴 Using traditional active tools only (no BBOT, no passive)")
    else:
        # Normal logic with BBOT integration
        # Add BBOT tools based on flags
        if bbot or all_tools:
            passive_tools.update(bbot_passive_tools)
            active_tools.update(bbot_active_tools)
            if verbose:
                click.echo("[+] 🤖 BBOT (Bighuge BLS OSINT Tool) enabled with 53+ modules")

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

    current_scan = resume_state[scan_key]
    completed_tools = set(current_scan.get("tools_completed", []))
    all_subs = set()
    tool_stats = {}

    if verbose:
        click.echo(f"[+] 🛠️  Using {len(tools)} enumeration tools")

    # Run enumeration tools
    for tool, cmd in tools.items():
        if tool in completed_tools:
            if verbose:
                click.echo(f"[=] ⏭️  Skipping {tool} (already completed)")
            # Load previous results
            tool_file = os.path.join(outpath, f"{tool}.txt")
            if os.path.exists(tool_file):
                with open(tool_file, "r") as f:
                    lines = [line.strip() for line in f if line.strip()]
                    all_subs.update(lines)
                    tool_stats[tool] = len(lines)
            continue

        if verbose:
            click.echo(f"[+] 🔧 Running: {tool}")

        start_time = time.time()
        lines = []

        try:
            # Special handling for BBOT tools
            if tool.startswith("bbot_"):
                lines = run_bbot_enumeration(
                    domain, outpath, tool, cmd, timeout, verbose
                )
            else:
                # Standard tool execution
                # NOTE: shell=True is required for complex commands with pipes and redirections
                # Domain is validated above to prevent shell injection
                result = subprocess.check_output(  # nosec B602
                    cmd,
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=timeout,
                )
                lines = [line.strip() for line in result.splitlines() if line.strip()]

            # Save individual tool results
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

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo(f"[!] ⏰ {tool} timeout after {timeout}s")
            tool_stats[tool] = 0
        except subprocess.CalledProcessError:
            if verbose:
                click.echo(f"[!] ❌ {tool} failed or returned no results")
            tool_stats[tool] = 0
        except Exception as e:
            if verbose:
                click.echo(f"[!] 💥 {tool} error: {str(e)}")
            tool_stats[tool] = 0

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
        },
    }

    with open(os.path.join(outpath, "comprehensive_report.json"), "w") as f:
        json.dump(comprehensive_data, f, indent=2)

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
