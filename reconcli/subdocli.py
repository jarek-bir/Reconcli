#!/usr/bin/env python3
import os
import json
import subprocess
import click
import requests
import socket
import concurrent.futures
from datetime import datetime
import time

# Import resume utilities
try:
    from reconcli.utils.resume import load_resume, save_resume_state, clear_resume
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
def subdocli(
    domain,
    output_dir,
    amass_config,
    markdown,
    resolve,
    probe_http,
    verbose,
    timeout,
    threads,
    all_tools,
    active,
    resume,
    clear_resume,
    show_stats,
):
    """Enhanced subdomain enumeration using multiple tools with resolution and HTTP probing"""

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
            click.echo(f"[+] 📁 Loading resume state")
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
            click.echo(f"[+] 🔥 Active enumeration enabled")

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
            result = subprocess.check_output(
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
        click.echo(f"[+] 🧹 Processing and deduplicating subdomains...")

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
        http_results = probe_http_services(targets, timeout, threads, verbose)

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
        click.echo(f"[+] ✅ Subdomain enumeration completed!")
        click.echo(f"[+] 📁 Results saved to: {outpath}/")


def resolve_subdomains(subdomains, threads, verbose):
    """Resolve subdomains to IP addresses using multithreading"""
    resolved = []

    def resolve_single(subdomain):
        try:
            ip = socket.gethostbyname(subdomain)
            return {"subdomain": subdomain, "ip": ip, "resolved": True}
        except socket.gaierror:
            return {"subdomain": subdomain, "ip": None, "resolved": False}
        except Exception as e:
            return {
                "subdomain": subdomain,
                "ip": None,
                "resolved": False,
                "error": str(e),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(resolve_single, sub): sub for sub in subdomains
        }

        for i, future in enumerate(
            concurrent.futures.as_completed(future_to_subdomain), 1
        ):
            result = future.result()
            resolved.append(result)

            if verbose and i % 100 == 0:
                click.echo(f"[+] 📊 Resolved {i}/{len(subdomains)} subdomains")

    # Filter successful resolutions
    successful = [r for r in resolved if r["resolved"]]
    if verbose:
        click.echo(
            f"[+] ✅ Successfully resolved {len(successful)}/{len(subdomains)} subdomains"
        )

    return resolved


def probe_http_services(targets, timeout, threads, verbose):
    """Probe HTTP/HTTPS services on subdomains"""
    results = []

    def probe_single(target):
        subdomain = target["subdomain"]
        result = {
            "subdomain": subdomain,
            "http": {"accessible": False, "status": None, "title": None},
            "https": {"accessible": False, "status": None, "title": None},
        }

        # Test both HTTP and HTTPS
        for scheme in ["http", "https"]:
            try:
                url = f"{scheme}://{subdomain}"
                response = requests.get(
                    url, timeout=timeout, allow_redirects=True, verify=False
                )

                result[scheme]["accessible"] = True
                result[scheme]["status"] = response.status_code
                result[scheme]["url"] = url
                result[scheme]["final_url"] = response.url

                # Extract title
                if "text/html" in response.headers.get("content-type", ""):
                    try:
                        title_start = response.text.find("<title>")
                        title_end = response.text.find("</title>")
                        if title_start != -1 and title_end != -1:
                            title = response.text[title_start + 7 : title_end].strip()
                            result[scheme]["title"] = title[:100]  # Limit title length
                    except:
                        pass

            except requests.exceptions.Timeout:
                result[scheme]["error"] = "timeout"
            except requests.exceptions.ConnectionError:
                result[scheme]["error"] = "connection_error"
            except Exception as e:
                result[scheme]["error"] = str(e)[:100]

        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(probe_single, target): target for target in targets
        }

        for i, future in enumerate(
            concurrent.futures.as_completed(future_to_target), 1
        ):
            result = future.result()
            results.append(result)

            if verbose and i % 50 == 0:
                click.echo(f"[+] 🌐 Probed {i}/{len(targets)} services")

    # Count accessible services
    accessible = [
        r for r in results if r["http"]["accessible"] or r["https"]["accessible"]
    ]
    if verbose:
        click.echo(f"[+] ✅ Found {len(accessible)} accessible HTTP/HTTPS services")

    return results


def generate_enhanced_markdown_report(outpath, domain, data, verbose):
    """Generate enhanced markdown report with statistics"""
    md_path = os.path.join(outpath, "enhanced_report.md")

    with open(md_path, "w") as f:
        f.write(f"# Subdomain Enumeration Report: {domain}\n\n")
        f.write(f"**Scan Date:** {data['scan_time']}\n")
        f.write(f"**Total Subdomains:** {data['total_subdomains']}\n\n")

        # Tool statistics
        f.write("## Tool Performance\n\n")
        f.write("| Tool | Subdomains Found |\n")
        f.write("|------|------------------|\n")
        for tool, count in sorted(
            data["tool_stats"].items(), key=lambda x: x[1], reverse=True
        ):
            f.write(f"| {tool} | {count} |\n")
        f.write("\n")

        # DNS Resolution results
        if data["resolved"]:
            resolved_count = len([r for r in data["resolved"] if r["resolved"]])
            f.write(f"## DNS Resolution\n\n")
            f.write(
                f"**Successfully Resolved:** {resolved_count}/{len(data['resolved'])}\n\n"
            )

            f.write("### Resolved Subdomains\n\n")
            for result in sorted(data["resolved"], key=lambda x: x["subdomain"]):
                if result["resolved"]:
                    f.write(f"- `{result['subdomain']}` → `{result['ip']}`\n")
            f.write("\n")

        # HTTP Services
        if data["http_services"]:
            http_accessible = [
                r for r in data["http_services"] if r["http"]["accessible"]
            ]
            https_accessible = [
                r for r in data["http_services"] if r["https"]["accessible"]
            ]

            f.write(f"## HTTP Services\n\n")
            f.write(f"**HTTP Accessible:** {len(http_accessible)}\n")
            f.write(f"**HTTPS Accessible:** {len(https_accessible)}\n\n")

            f.write("### Accessible Services\n\n")
            for result in sorted(data["http_services"], key=lambda x: x["subdomain"]):
                subdomain = result["subdomain"]
                if result["http"]["accessible"] or result["https"]["accessible"]:
                    f.write(f"#### {subdomain}\n\n")

                    if result["http"]["accessible"]:
                        status = result["http"]["status"]
                        title = result["http"].get("title", "N/A")
                        f.write(f"- **HTTP:** Status {status}, Title: {title}\n")

                    if result["https"]["accessible"]:
                        status = result["https"]["status"]
                        title = result["https"].get("title", "N/A")
                        f.write(f"- **HTTPS:** Status {status}, Title: {title}\n")

                    f.write("\n")

        # All subdomains list
        f.write("## All Discovered Subdomains\n\n")
        for subdomain in sorted(data["subdomains"]):
            f.write(f"- {subdomain}\n")

    if verbose:
        click.echo(f"[+] 📄 Enhanced markdown report saved to {md_path}")


def display_scan_statistics(data, tool_stats):
    """Display comprehensive scan statistics"""
    click.echo(f"\n[+] 📊 Scan Statistics:")
    click.echo(f"   Domain: {data['domain']}")
    click.echo(f"   Total Subdomains: {data['total_subdomains']}")
    click.echo(f"   Tools Used: {len(data['scan_summary']['tools_used'])}")

    click.echo(f"\n[+] 🛠️  Tool Performance:")
    for tool, count in sorted(tool_stats.items(), key=lambda x: x[1], reverse=True):
        click.echo(f"   {tool:12} → {count:4} subdomains")

    if data["resolved"]:
        resolved_count = len([r for r in data["resolved"] if r["resolved"]])
        click.echo(f"\n[+] 🔍 DNS Resolution:")
        click.echo(f"   Resolved: {resolved_count}/{len(data['resolved'])}")

    if data["http_services"]:
        http_count = len([r for r in data["http_services"] if r["http"]["accessible"]])
        https_count = len(
            [r for r in data["http_services"] if r["https"]["accessible"]]
        )
        click.echo(f"\n[+] 🌐 HTTP Services:")
        click.echo(f"   HTTP accessible: {http_count}")
        click.echo(f"   HTTPS accessible: {https_count}")
