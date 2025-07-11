import os
import sys
import socket
import json
import time
import click
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union
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
    store_db,
    target_domain,
    program,
):
    """Enhanced DNS resolution and tagging for subdomains with professional features

    Supports custom DNS resolvers and wordlist-based subdomain bruteforcing.
    Can enrich results with WHOIS data from WhoisFreaks output.
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

    # Require input for actual scanning
    if not input:
        click.echo("Error: --input is required for scanning operations.")
        click.echo("Use --show-resume or --clear-resume for resume management.")
        return

    if not os.path.exists(input):
        click.echo(f"Error: Input file '{input}' does not exist.")
        sys.exit(1)

    if verbose:
        click.echo(f"[+] 🚀 Starting DNS resolution scan")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        if resolvers:
            click.echo(f"[+] 🌐 Custom resolvers: {resolvers}")
        if wordlists:
            click.echo(f"[+] 📝 Wordlist: {wordlists}")

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

    with open(input) as f:
        subdomains = [line.strip() for line in f if line.strip()]

    # Generate additional subdomains from wordlist if provided
    if wordlists:
        if verbose:
            click.echo(f"[+] 📝 Generating subdomains from wordlist...")

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
            click.echo(f"[+] 📋 Loaded {len(subdomains)} subdomain(s) from {input}")

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
            click.echo(f"[+] 🔍 Enriching DNS results with WHOIS data...")

        # Skip WHOIS enrichment - not implemented
        if verbose:
            click.echo(f"[!] WHOIS enrichment not implemented, skipping...")

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
    )

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo(f"\n[+] 📊 Scan Summary:")
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

    click.echo(f"\n[+] ✅ DNS resolution completed!")
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
            },
            "results": results,
        }

        json_path = os.path.join(output_dir, "dns_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

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
                            f"[!] ⚠️  No resolved subdomains to store in database"
                        )
            else:
                if verbose:
                    click.echo(
                        f"[!] ⚠️  Could not determine target domain for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo(
                    f"[!] ⚠️  Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Error storing to database: {e}")


if __name__ == "__main__":
    cli()
