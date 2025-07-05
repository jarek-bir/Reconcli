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
):
    """Enhanced DNS resolution and tagging for subdomains with professional features"""

    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir)
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

    with open(input) as f:
        subdomains = [line.strip() for line in f if line.strip()]

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
        subdomains[processed_count:], threads, timeout, retries, verbose
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
    save_outputs(results, output_dir, save_json, save_markdown, verbose)

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo(f"\n[+] 📊 Scan Summary:")
        click.echo(f"   - Total subdomains: {len(subdomains)}")
        click.echo(f"   - Successfully resolved: {resolved_count}")
        click.echo(f"   - Failed to resolve: {failed_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(f"   - Resolution rate: {resolved_count/len(subdomains)*100:.1f}%" if len(subdomains) > 0 else "   - Resolution rate: 0.0%")

    # Generate tag statistics
    tag_stats = generate_tag_statistics(results, verbose)

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        send_dns_notifications(
            results,
            tag_stats,
            len(subdomains),
            resolved_count,
            failed_count,
            elapsed,
            slack_webhook,
            discord_webhook,
            verbose,
        )

    click.echo(f"\n[+] ✅ DNS resolution completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


def enhanced_dns_resolution(
    subdomains: List[str], threads: int, timeout: int, retries: int, verbose: bool
) -> List[Dict]:
    """Enhanced concurrent DNS resolution with retry logic"""
    results = []

    def resolve_subdomain(subdomain: str) -> Dict:
        """Resolve a single subdomain with retry logic"""
        for attempt in range(retries + 1):
            try:
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
):
    """Save results in multiple formats with enhanced metadata"""

    # Standard tagged output
    tagged_output_path = os.path.join(output_dir, "subs_resolved_tagged.txt")
    with open(tagged_output_path, "w") as outf:
        for result in results:
            tags_str = ",".join(result["tags"]) if result["tags"] else "-"
            outf.write(
                f"{result['subdomain']} {result['ip']} PTR: {result['ptr'] or '-'} TAGS: {tags_str}\n"
            )

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
            f.write("| Subdomain | IP Address | PTR Record | Tags |\n")
            f.write("|-----------|------------|------------|------|\n")

            for result in results:
                tags_str = ", ".join(result["tags"]) if result["tags"] else "-"
                f.write(
                    f"| {result['subdomain']} | {result['ip']} | {result['ptr'] or '-'} | {tags_str} |\n"
                )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")


def generate_tag_statistics(results: List[Dict], verbose: bool) -> Dict:
    """Generate comprehensive tag statistics"""
    tag_counts = {}
    total_resolved = len([r for r in results if r["ip"] != "unresolved"])

    for result in results:
        for tag in result["tags"]:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    if verbose and tag_counts:
        click.echo(f"\n[+] 🏷️  Tag Statistics:")
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
            percentage = (count / total_resolved * 100) if total_resolved > 0 else 0
            click.echo(f"   - {tag}: {count} ({percentage:.1f}%)")

    return tag_counts


def send_dns_notifications(
    results: List[Dict],
    tag_stats: Dict,
    total: int,
    resolved: int,
    failed: int,
    elapsed: float,
    slack_webhook: str,
    discord_webhook: str,
    verbose: bool,
):
    """Send comprehensive DNS scan notifications"""
    if not (send_notification and (slack_webhook or discord_webhook)):
        return

    try:
        scan_metadata = {
            "total_subdomains": total,
            "resolved_count": resolved,
            "failed_count": failed,
            "resolution_rate": round(resolved / total * 100, 1) if total > 0 else 0,
            "scan_duration": f"{elapsed}s",
            "top_tags": dict(sorted(tag_stats.items(), key=lambda x: -x[1])[:5]),
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "tool": "dnscli",
        }

        # Prepare sample results for notification
        sample_results = results[:10]  # First 10 results

        if verbose:
            click.echo("[+] 📱 Sending DNS scan notifications...")

        success = send_notification(
            notification_type="dns",
            results=sample_results,
            scan_metadata=scan_metadata,
            slack_webhook=slack_webhook,
            discord_webhook=discord_webhook,
            verbose=verbose,
        )

        if success and verbose:
            click.echo("[+] ✅ Notifications sent successfully")

    except Exception as e:
        if verbose:
            click.echo(f"[!] ❌ Notification failed: {e}")


def show_resume_status(output_dir: str):
    """Show status of previous DNS scans from resume file"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous DNS scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        if scan_key.startswith("dns_"):
            click.echo(f"🔍 Scan: {scan_key}")
            click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")
            click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

            if scan_data.get("completed"):
                click.echo(f"   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
                click.echo(f"   Resolved: {scan_data.get('resolved_count', 0)}")
                click.echo(f"   Failed: {scan_data.get('failed_count', 0)}")
            else:
                click.echo(f"   Status: ⏳ Incomplete")
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

            click.echo()


if __name__ == "__main__":
    cli()
