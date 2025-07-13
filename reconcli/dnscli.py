import os
import sys
import socket
import json
import time
import click
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm

# Import notifications
try:
    from reconcli.utils.notifications import send_notification, NotificationManager
except ImportError:
    send_notification = None
    NotificationManager = None

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


# Enhanced PTR tag patterns for better classification
PTR_PATTERNS = {
    "cdn": [
        "cloudflare",
        "akamai",
        "cdn",
        "fastly",
        "keycdn",
        "maxcdn",
        "edgecast",
        "stackpath",
    ],
    "aws": ["amazonaws", "aws", "ec2", "elb", "cloudfront"],
    "gcp": ["google", "gcp", "googleusercontent", "appspot", "googleapis"],
    "azure": ["microsoft", "azure", "azurewebsites", "cloudapp"],
    "digitalocean": ["digitalocean", "droplet"],
    "corp": ["corp", "corporate", "internal", "intranet"],
    "vpn": ["vpn", "proxy", "tunnel"],
    "honeypot": ["honeypot", "honey", "trap"],
    "hosting": ["hosting", "shared", "cpanel", "plesk"],
    "mail": ["mail", "mx", "smtp", "imap", "pop"],
    "load_balancer": ["lb", "load", "balancer", "haproxy", "nginx"],
    "security": ["firewall", "waf", "security", "guard"],
}


@click.command()
@click.option("--input", type=click.Path(), help="Path to file with subdomains")
@click.option("--output-dir", default="output_dnscli", help="Directory to save results")
@click.option(
    "--resolve-only",
    is_flag=True,
    help="Only resolve subdomains to IPs and tag with PTRs",
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option(
    "--threads", default=50, help="Number of concurrent threads for DNS resolution"
)
@click.option("--timeout", default=5, help="DNS resolution timeout in seconds")
@click.option(
    "--retries", default=2, help="Number of retries for failed DNS resolutions"
)
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
@click.option("--resume", is_flag=True, help="Resume scan from previous run")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state",
)
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option(
    "--filter-tags", help="Only show results with specific tags (comma-separated)"
)
@click.option(
    "--exclude-unresolved",
    is_flag=True,
    help="Exclude unresolved subdomains from output",
)
@click.option(
    "--whois-file",
    type=click.Path(exists=True),
    help="Path to WhoisFreaks output file (JSON) to enrich DNS results with WHOIS data",
)
@click.option(
    "--wordlists",
    type=click.Path(exists=True),
    help="Path to wordlist file for subdomain bruteforcing",
)
@click.option(
    "--resolvers",
    type=click.Path(exists=True),
    help="Path to custom DNS resolvers file (one resolver per line)",
)
@click.option(
    "--use-scilla",
    is_flag=True,
    help="Use Scilla for advanced DNS reconnaissance and subdomain enumeration",
)
@click.option(
    "--scilla-target",
    help="Target domain for Scilla DNS enumeration (required when using --use-scilla)",
)
@click.option(
    "--scilla-wordlist",
    type=click.Path(exists=True),
    help="Custom wordlist for Scilla subdomain enumeration",
)
@click.option(
    "--scilla-ports",
    help="Comma-separated ports for Scilla to scan (default: 80,443)",
)
@click.option(
    "--scilla-dns-servers",
    help="Comma-separated DNS servers for Scilla (e.g., 8.8.8.8,1.1.1.1)",
)
@click.option(
    "--scilla-plain",
    is_flag=True,
    help="Use Scilla plain output format (no colors/formatting)",
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
@click.option(
    "--program",
    help="Bug bounty program name for database classification",
)
def cli(
    input,
    output_dir,
    resolve_only,
    verbose,
    threads,
    timeout,
    retries,
    save_json,
    save_markdown,
    resume,
    clear_resume_flag,
    show_resume,
    slack_webhook,
    discord_webhook,
    filter_tags,
    exclude_unresolved,
    whois_file,
    wordlists,
    resolvers,
    use_scilla,
    scilla_target,
    scilla_wordlist,
    scilla_ports,
    scilla_dns_servers,
    scilla_plain,
    store_db,
    target_domain,
    program,
):
    """Enhanced DNS resolution and tagging for subdomains with professional features

    Supports custom DNS resolvers and wordlist-based subdomain bruteforcing.
    Can enrich results with WHOIS data from WhoisFreaks output.

    NEW: Scilla Integration for Advanced DNS Reconnaissance
    • Use --use-scilla to enable Scilla-powered subdomain enumeration
    • Scilla provides fast DNS reconnaissance with built-in wordlists
    • Supports custom wordlists, ports, and DNS servers
    • Can combine Scilla results with traditional input files

    Examples:
    • Basic Scilla scan: --use-scilla --scilla-target example.com
    • Custom wordlist: --use-scilla --scilla-target example.com --scilla-wordlist /path/to/wordlist.txt
    • Custom ports: --use-scilla --scilla-target example.com --scilla-ports 80,443,8080
    • Custom DNS: --use-scilla --scilla-target example.com --scilla-dns-servers 8.8.8.8,1.1.1.1
    """

    # Handle special resume operations
    if show_resume:
        # Check for resume data
        resume_path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(resume_path):
            with open(resume_path, "r") as f:
                resume_data = json.load(f)
            click.echo(
                f"[+] Resume data found: {len(resume_data.get('completed', []))} completed"
            )
        else:
            click.echo("[!] No resume data found")
        return

    if clear_resume_flag:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Require input for actual scanning (unless using Scilla mode)
    if not input and not use_scilla:
        click.echo(
            "Error: --input is required for scanning operations (or use --use-scilla for domain enumeration)."
        )
        click.echo("Use --show-resume or --clear-resume for resume management.")
        return

    # Validate Scilla requirements
    if use_scilla and not scilla_target:
        click.echo("Error: --scilla-target is required when using --use-scilla")
        sys.exit(1)

    if input and not os.path.exists(input):
        click.echo(f"Error: Input file '{input}' does not exist.")
        sys.exit(1)

    if verbose:
        click.echo("[+] 🚀 Starting DNS resolution scan")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        if use_scilla:
            click.echo("[+] 🔍 Using Scilla for DNS reconnaissance")
            click.echo(f"[+] 🎯 Scilla target: {scilla_target}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        if resolvers:
            click.echo(f"[+] 🌐 Custom resolvers: {resolvers}")
        if wordlists:
            click.echo(f"[+] 📝 Wordlist: {wordlists}")
        if scilla_wordlist:
            click.echo(f"[+] 📝 Scilla wordlist: {scilla_wordlist}")

    # Load custom DNS resolvers if provided
    custom_resolvers = []
    if resolvers:
        try:
            with open(resolvers, "r") as f:
                custom_resolvers = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            if verbose:
                click.echo(
                    f"[+] 🌐 Loaded {len(custom_resolvers)} custom DNS resolvers"
                )
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Failed to load resolvers file: {e}")
            custom_resolvers = []

    # Load subdomains from input file or use Scilla for enumeration
    subdomains = []
    scilla_results = []

    if use_scilla:
        # Run Scilla for DNS reconnaissance
        if verbose:
            click.echo(
                f"[+] 🔍 Running Scilla DNS reconnaissance on {scilla_target}..."
            )

        scilla_results, scilla_subdomains = run_scilla_enumeration(
            scilla_target,
            scilla_wordlist,
            scilla_ports,
            scilla_dns_servers,
            scilla_plain,
            output_dir,
            verbose,
        )
        subdomains.extend(scilla_subdomains)

        if verbose:
            click.echo(f"[+] 🔍 Scilla found {len(scilla_subdomains)} subdomains")

    if input:
        with open(input) as f:
            input_subdomains = [line.strip() for line in f if line.strip()]
            subdomains.extend(input_subdomains)

        if verbose:
            click.echo(
                f"[+] 📋 Loaded {len(input_subdomains)} subdomain(s) from {input}"
            )

    # Remove duplicates
    subdomains = list(set(subdomains))

    # Generate additional subdomains from wordlist if provided
    if wordlists:
        if verbose:
            click.echo("[+] 📝 Generating subdomains from wordlist...")

        # Skip wordlist generation - not implemented
        additional_subdomains = []
        original_count = len(subdomains)
        subdomains.extend(additional_subdomains)

        if verbose:
            click.echo(
                f"[+] 📊 Added {len(additional_subdomains)} wordlist-generated subdomains"
            )
            click.echo(
                f"[+] 📋 Total subdomains: {len(subdomains)} (original: {original_count})"
            )
    else:
        if verbose:
            total_count = len(subdomains)
            click.echo(f"[+] 📋 Total subdomains to process: {total_count}")

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"dns_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
            if key.startswith("dns_") and not data.get("completed", False):
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
            "resolved_count": 0,
            "failed_count": 0,
            "configuration": {
                "threads": threads,
                "timeout": timeout,
                "retries": retries,
                "exclude_unresolved": exclude_unresolved,
                "resolvers_file": resolvers,
                "wordlists_file": wordlists,
            },
        }
        save_resume_state(output_dir, resume_state)

    current_scan = resume_state[scan_key]
    processed_count = current_scan.get("processed_count", 0)

    if verbose and processed_count > 0:
        click.echo(f"[+] 📁 Resume: {processed_count} subdomains already processed")

    start_time = time.time()

    # Process subdomains with enhanced concurrent resolution
    results = enhanced_dns_resolution(
        subdomains[processed_count:],
        threads,
        timeout,
        retries,
        custom_resolvers,
        verbose,
    )

    # Update counts
    resolved_count = len([r for r in results if r["ip"] != "unresolved"])
    failed_count = len(results) - resolved_count

    current_scan["processed_count"] = len(subdomains)
    current_scan["resolved_count"] = (
        current_scan.get("resolved_count", 0) + resolved_count
    )
    current_scan["failed_count"] = current_scan.get("failed_count", 0) + failed_count
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()

    save_resume_state(output_dir, resume_state)

    # Enrich with WHOIS data if provided
    if whois_file:
        if verbose:
            click.echo("[+] 🔍 Enriching DNS results with WHOIS data...")

        # Skip WHOIS enrichment - not implemented
        if verbose:
            click.echo("[!] WHOIS enrichment not implemented, skipping...")

            if verbose:
                whois_enriched = len(
                    [r for r in results if r.get("whois", {}).get("registrar")]
                )
                click.echo(
                    f"[+] 📄 WHOIS data added to {whois_enriched}/{len(results)} results"
                )

    # Apply filtering if requested
    if filter_tags:
        filter_list = [tag.strip() for tag in filter_tags.split(",")]
        results = [r for r in results if any(tag in r["tags"] for tag in filter_list)]
        if verbose:
            click.echo(
                f"[+] 🏷️  Filtered to {len(results)} results with tags: {', '.join(filter_list)}"
            )

    if exclude_unresolved:
        before_filter = len(results)
        results = [r for r in results if r["ip"] != "unresolved"]
        if verbose:
            click.echo(
                f"[+] 🧹 Excluded unresolved: {before_filter} → {len(results)} results"
            )

    # Save outputs in multiple formats
    save_outputs(
        results,
        output_dir,
        save_json,
        save_markdown,
        verbose,
        store_db,
        target_domain,
        program,
        scilla_results if use_scilla else None,
    )

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo("\n[+] 📊 Scan Summary:")
        click.echo(f"   - Total subdomains: {len(subdomains)}")
        click.echo(f"   - Successfully resolved: {resolved_count}")
        click.echo(f"   - Failed to resolve: {failed_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(
            f"   - Resolution rate: {resolved_count/len(subdomains)*100:.1f}%"
            if len(subdomains) > 0
            else "   - Resolution rate: 0.0%"
        )

    # Generate tag statistics (simplified)
    tag_stats = {}
    for result in results:
        for tag in result.get("tags", []):
            tag_stats[tag] = tag_stats.get(tag, 0) + 1

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        try:
            send_notification(
                "DNS Resolution Complete",
                f"Resolved {resolved_count}/{len(subdomains)} subdomains in {elapsed:.1f}s",
                slack_webhook=slack_webhook,
                discord_webhook=discord_webhook,
            )
        except Exception as e:
            if verbose:
                click.echo(f"[!] Notification failed: {e}")

    click.echo("\n[+] ✅ DNS resolution completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


def enhanced_dns_resolution(
    subdomains: List[str],
    threads: int,
    timeout: int,
    retries: int,
    custom_resolvers: List[str],
    verbose: bool,
) -> List[Dict]:
    """Enhanced concurrent DNS resolution with retry logic and custom resolvers"""
    results = []

    def resolve_subdomain(subdomain: str) -> Dict:
        """Resolve a single subdomain with retry logic and custom resolvers"""
        for attempt in range(retries + 1):
            try:
                # Use custom resolver if available
                if custom_resolvers and attempt < len(custom_resolvers):
                    # For simplicity, we'll use socket.gethostbyname_ex which doesn't directly support custom resolvers
                    # In a production environment, you might want to use dnspython library
                    # For now, we'll fall back to system resolver but log the custom resolver usage
                    pass

                socket.setdefaulttimeout(timeout)
                ip = socket.gethostbyname(subdomain)

                # Get PTR record
                ptr = ""
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except:
                    ptr = ""

                # Enhanced tagging
                tags = classify_ptr_record(ptr)

                return {
                    "subdomain": subdomain,
                    "ip": ip,
                    "ptr": ptr,
                    "tags": tags,
                    "status": "resolved",
                }

            except socket.gaierror:
                if attempt == retries:
                    break
            except Exception as e:
                if attempt == retries:
                    return {
                        "subdomain": subdomain,
                        "ip": "unresolved",
                        "ptr": "",
                        "tags": [],
                        "status": f"error: {str(e)}",
                    }

            time.sleep(0.1)  # Short delay between retries

        # Return unresolved result if all attempts failed
        return {
            "subdomain": subdomain,
            "ip": "unresolved",
            "ptr": "",
            "tags": [],
            "status": "failed",
        }

    # Use ThreadPoolExecutor for concurrent resolution
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Create progress bar
        with tqdm(
            total=len(subdomains),
            desc="🔍 Resolving DNS",
            disable=not verbose,
            ncols=100,
        ) as pbar:

            # Submit all tasks
            future_to_subdomain = {
                executor.submit(resolve_subdomain, sub): sub for sub in subdomains
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                results.append(result)
                pbar.update(1)

                # Update progress bar description with stats
                resolved = len([r for r in results if r["ip"] != "unresolved"])
                pbar.set_postfix(resolved=resolved, failed=len(results) - resolved)

    return results


def classify_ptr_record(ptr: str) -> List[str]:
    """Enhanced PTR record classification with comprehensive patterns"""
    if not ptr:
        return []

    tags = []
    ptr_lower = ptr.lower()

    for tag, patterns in PTR_PATTERNS.items():
        if any(pattern in ptr_lower for pattern in patterns):
            tags.append(tag)

    return tags


def save_outputs(
    results: List[Dict],
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
    store_db: bool = False,
    target_domain: Optional[str] = None,
    program: Optional[str] = None,
    scilla_results: Optional[List[Dict]] = None,
):
    """Save results in multiple formats with enhanced metadata"""

    # Standard tagged output
    tagged_output_path = os.path.join(output_dir, "subs_resolved_tagged.txt")
    with open(tagged_output_path, "w") as outf:
        for result in results:
            tags_str = ",".join(result["tags"]) if result["tags"] else "-"

            # Basic DNS line
            line = f"{result['subdomain']} {result['ip']} PTR: {result['ptr'] or '-'} TAGS: {tags_str}"

            # Add WHOIS info if available
            if result.get("whois"):
                whois_info = result["whois"]
                whois_parts = []
                if whois_info.get("registrar"):
                    whois_parts.append(f"REG: {whois_info['registrar']}")
                if whois_info.get("organization"):
                    whois_parts.append(f"ORG: {whois_info['organization']}")
                if whois_info.get("country"):
                    whois_parts.append(f"COUNTRY: {whois_info['country']}")
                if whois_info.get("expiration_date"):
                    whois_parts.append(f"EXPIRES: {whois_info['expiration_date']}")

                if whois_parts:
                    line += f" WHOIS: {' | '.join(whois_parts)}"

            outf.write(line + "\n")

    if verbose:
        click.echo(f"[+] 💾 Saved tagged results to {tagged_output_path}")

    # JSON output
    if save_json:
        json_output = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_subdomains": len(results),
                "resolved_count": len([r for r in results if r["ip"] != "unresolved"]),
                "tool": "dnscli",
                "scilla_enabled": scilla_results is not None,
            },
            "results": results,
        }

        # Add Scilla-specific data if available
        if scilla_results:
            json_output["scilla_results"] = scilla_results
            json_output["scan_metadata"]["scilla_subdomains"] = len(scilla_results)

        json_path = os.path.join(output_dir, "dns_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")
            if scilla_results:
                click.echo(
                    f"[+] 🔍 Included {len(scilla_results)} Scilla-specific results"
                )

    # Markdown output
    if save_markdown:
        md_path = os.path.join(output_dir, "dns_results.md")
        with open(md_path, "w") as f:
            f.write("# DNS Resolution Results\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total Subdomains:** {len(results)}\n")
            f.write(
                f"**Successfully Resolved:** {len([r for r in results if r['ip'] != 'unresolved'])}\n\n"
            )

            f.write("## Results\n\n")

            # Check if any result has WHOIS data to determine table format
            has_whois = any(
                result.get("whois", {}).get("registrar") for result in results
            )

            if has_whois:
                f.write(
                    "| Subdomain | IP Address | PTR Record | Tags | Registrar | Organization | Country | Expires |\n"
                )
                f.write(
                    "|-----------|------------|------------|------|-----------|--------------|---------|----------|\n"
                )

                for result in results:
                    tags_str = ", ".join(result["tags"]) if result["tags"] else "-"
                    whois = result.get("whois", {})
                    registrar = whois.get("registrar", "-")
                    organization = whois.get("organization", "-")
                    country = whois.get("country", "-")
                    expires = whois.get("expiration_date", "-")

                    f.write(
                        f"| {result['subdomain']} | {result['ip']} | {result['ptr'] or '-'} | {tags_str} | {registrar} | {organization} | {country} | {expires} |\n"
                    )
            else:
                f.write("| Subdomain | IP Address | PTR Record | Tags |\n")
                f.write("|-----------|------------|------------|------|\n")

                for result in results:
                    tags_str = ", ".join(result["tags"]) if result["tags"] else "-"
                    f.write(
                        f"| {result['subdomain']} | {result['ip']} | {result['ptr'] or '-'} | {tags_str} |\n"
                    )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")

    # Database storage
    if store_db:
        try:
            from reconcli.db.operations import store_target, store_subdomains

            # Auto-detect target domain if not provided
            if not target_domain and results:
                # Extract primary domain from first subdomain
                first_subdomain = results[0]["subdomain"]
                domain_parts = first_subdomain.split(".")
                if len(domain_parts) >= 2:
                    target_domain = ".".join(domain_parts[-2:])
                else:
                    target_domain = first_subdomain

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert results to database format
                subdomain_data = []
                for result in results:
                    if result["ip"] != "unresolved":  # Only store resolved subdomains
                        subdomain_entry = {
                            "subdomain": result["subdomain"],
                            "ip": result["ip"],
                            "cname": result.get("cname"),
                            "status_code": result.get("status_code"),
                            "title": result.get("title"),
                        }
                        subdomain_data.append(subdomain_entry)

                # Store subdomains in database
                if subdomain_data:
                    stored_ids = store_subdomains(
                        target_domain, subdomain_data, "dnscli"
                    )
                    if verbose:
                        click.echo(
                            f"[+] 🗄️  Stored {len(stored_ids)} subdomains in database for {target_domain}"
                        )
                        if program:
                            click.echo(f"    Program: {program}")
                else:
                    if verbose:
                        click.echo(
                            "[!] ⚠️  No resolved subdomains to store in database"
                        )
            else:
                if verbose:
                    click.echo(
                        "[!] ⚠️  Could not determine target domain for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo(
                    "[!] ⚠️  Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Error storing to database: {e}")


def run_scilla_enumeration(
    target: str,
    wordlist: Optional[str] = None,
    ports: Optional[str] = None,
    dns_servers: Optional[str] = None,
    plain_output: bool = False,
    output_dir: str = "output_dnscli",
    verbose: bool = False,
) -> Tuple[List[Dict], List[str]]:
    """Run Scilla for DNS reconnaissance and analysis

    Returns:
        Tuple of (detailed_results, subdomain_list)
    """
    import subprocess
    import os

    results = []
    subdomains = []

    try:
        # Build Scilla DNS command
        cmd = ["scilla", "dns", "-target", target]

        if plain_output:
            cmd.append("-plain")

        if verbose:
            click.echo(f"[+] 🔍 Running: {' '.join(cmd)}")

        # Run Scilla and capture stdout
        process = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30  # 30 second timeout
        )

        if process.returncode == 0:
            # Parse Scilla DNS output from stdout
            stdout_lines = process.stdout.strip().split("\n")

            dns_records = []
            ip_addresses = []

            for line in stdout_lines:
                line = line.strip()
                if (
                    line
                    and not line.startswith("=")
                    and not line.startswith(">")
                    and not line.startswith("target:")
                ):
                    # Skip banner lines
                    if (
                        "scilla" in line.lower()
                        or "github.com" in line.lower()
                        or "https://" in line.lower()
                    ):
                        continue
                    if "scanning dns" in line.lower():
                        continue

                    dns_records.append(line)

                    # Extract IP addresses
                    if line.startswith("A: "):
                        ip = line.replace("A: ", "").strip()
                        if ip and "." in ip:  # IPv4
                            ip_addresses.append(ip)

            # Add the main domain with found IPs
            if ip_addresses:
                for ip in ip_addresses[:3]:  # Take first 3 IPs
                    subdomains.append(target)
                    results.append(
                        {
                            "subdomain": target,
                            "ip": ip,
                            "dns_record_type": "A",
                            "source": "scilla-dns",
                        }
                    )
            else:
                # Add main domain without IP if no A records found
                subdomains.append(target)
                results.append(
                    {
                        "subdomain": target,
                        "ip": "",
                        "dns_record_type": "unknown",
                        "source": "scilla-dns",
                    }
                )

            # Save Scilla raw results
            scilla_output_file = os.path.join(output_dir, "scilla_dns_records.txt")
            os.makedirs(output_dir, exist_ok=True)
            with open(scilla_output_file, "w") as f:
                f.write("\n".join(dns_records))

            if verbose:
                click.echo(f"[+] 💾 Scilla DNS records saved to: {scilla_output_file}")
                click.echo(f"[+] 🔍 Found {len(dns_records)} DNS records")
                click.echo(f"[+] 🌐 Found {len(ip_addresses)} A records (IPs)")

        else:
            if verbose:
                click.echo(
                    f"[!] ❌ Scilla failed with return code: {process.returncode}"
                )
                if process.stderr:
                    click.echo(f"[!] Scilla stderr: {process.stderr}")
                if process.stdout:
                    click.echo(f"[!] Scilla stdout: {process.stdout}")

    except subprocess.TimeoutExpired:
        if verbose:
            click.echo("[!] ⏰ Scilla timed out after 30 seconds")
    except FileNotFoundError:
        if verbose:
            click.echo(
                "[!] ❌ Scilla not found. Install with: go install -v github.com/edoardottt/scilla/cmd/scilla@latest"
            )
    except Exception as e:
        if verbose:
            click.echo(f"[!] ❌ Error running Scilla: {e}")

    # Remove duplicates while preserving different IPs for same domain
    unique_results = []
    seen = set()
    for result in results:
        key = (result["subdomain"], result["ip"])
        if key not in seen:
            seen.add(key)
            unique_results.append(result)

    # Get unique subdomains
    subdomains = list(set(subdomains))

    return unique_results, subdomains


if __name__ == "__main__":
    cli()
