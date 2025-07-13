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
    "--timeout", default=30, help="Timeout for individual operations (seconds)"
)
@click.option(
    "--threads", default=50, help="Number of threads for concurrent operations"
)
@click.option(
    "--all-tools", is_flag=True, help="Use all available tools (including active)"
)
@click.option("--active", is_flag=True, help="Include active enumeration tools")
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
    resume,
    clear_resume,
    show_stats,
    store_db,
    target_domain,
    program,
):
    """Enhanced subdomain enumeration using multiple tools with resolution and HTTP probing"""

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

    # Enhanced tool configuration
    passive_tools = {
        "subfinder": f"subfinder -all -d {domain} -silent",
        "findomain": f"findomain -t {domain} -q",
        "assetfinder": f"assetfinder --subs-only {domain}",
        "amass": f"amass enum -passive -config {amass_config} -d {domain} -silent",
        "chaos": f"chaos -d {domain} -silent",
        "rapiddns": f"curl -s 'https://rapiddns.io/subdomain/{domain}?full=1' | grep -oE '[a-zA-Z0-9.-]+\\.{domain}' | sort -u",
        "crtsh": f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u",
        "bufferover": f"curl -s 'https://dns.bufferover.run/dns?q=.{domain}' | jq -r '.FDNS_A[],.RDNS[]' | cut -d',' -f2 | grep -o '[a-zA-Z0-9.-]*\\.{domain}' | sort -u",
    }

    active_tools = {
        "gobuster": f"gobuster dns -d {domain} -w /usr/share/wordlists/dirb/common.txt -q",
        "ffuf": f"ffuf -w /usr/share/wordlists/dirb/common.txt -u http://FUZZ.{domain} -mc 200,301,302,403 -fs 0 -s",
        "dnsrecon": f"dnsrecon -d {domain} -t brt -D /usr/share/wordlists/dirb/common.txt --xml {outpath}/dnsrecon.xml",
    }

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
        try:
            # NOTE: shell=True is required for complex commands with pipes and redirections
            # Domain is validated above to prevent shell injection
            result = subprocess.check_output(  # nosec B602
                cmd, shell=True, stderr=subprocess.DEVNULL, text=True, timeout=timeout
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
