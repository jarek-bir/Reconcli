#!/usr/bin/env python3

import os
import sys
import json
import time
import click
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from tqdm import tqdm
import socket

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


# Comprehensive TLD lists for different categories
DEFAULT_TLDS = {
    "popular": [
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "co",
        "io",
        "me",
        "tv",
        "cc",
        "biz",
        "info",
        "name",
        "pro",
        "mobi",
        "travel",
        "jobs",
        "tel",
        "cat",
        "asia",
    ],
    "country": [
        "us",
        "uk",
        "ca",
        "au",
        "de",
        "fr",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "mx",
        "es",
        "it",
        "nl",
        "pl",
        "se",
        "no",
        "dk",
        "fi",
        "be",
        "ch",
        "at",
        "cz",
        "hu",
        "pt",
        "ie",
        "gr",
        "tr",
        "il",
        "kr",
        "th",
        "sg",
        "my",
        "ph",
        "id",
        "vn",
        "pk",
        "bd",
        "lk",
        "mm",
        "kh",
        "la",
        "mn",
        "np",
        "bt",
        "mv",
        "af",
        "kz",
        "kg",
        "tj",
        "tm",
        "uz",
        "az",
        "am",
        "ge",
        "by",
        "ua",
        "md",
        "ro",
        "bg",
        "hr",
        "si",
        "sk",
        "lt",
        "lv",
        "ee",
        "is",
        "fo",
        "gl",
        "sj",
        "ad",
        "mc",
        "sm",
        "va",
        "li",
        "lu",
        "mt",
    ],
    "new_generic": [
        "app",
        "dev",
        "tech",
        "cloud",
        "online",
        "site",
        "website",
        "store",
        "shop",
        "blog",
        "news",
        "media",
        "photo",
        "video",
        "music",
        "game",
        "sport",
        "health",
        "food",
        "travel",
        "hotel",
        "restaurant",
        "cafe",
        "bar",
        "club",
        "gym",
        "spa",
        "beauty",
        "fashion",
        "style",
        "design",
        "art",
        "culture",
        "museum",
        "gallery",
        "theater",
        "cinema",
        "book",
        "library",
        "school",
        "university",
        "academy",
        "training",
        "course",
        "coach",
        "guru",
        "expert",
        "consulting",
        "agency",
        "studio",
        "lab",
        "center",
        "institute",
        "foundation",
        "charity",
        "church",
        "community",
        "social",
        "network",
        "email",
        "chat",
        "forum",
        "wiki",
        "blog",
    ],
    "business": [
        "ltd",
        "llc",
        "inc",
        "corp",
        "company",
        "business",
        "enterprise",
        "group",
        "holdings",
        "ventures",
        "capital",
        "invest",
        "fund",
        "bank",
        "finance",
        "insurance",
        "law",
        "legal",
        "consulting",
        "marketing",
        "advertising",
        "media",
        "publishing",
        "software",
        "technology",
        "engineering",
        "construction",
        "manufacturing",
        "logistics",
        "transport",
        "energy",
        "mining",
        "agriculture",
        "healthcare",
        "pharma",
        "medical",
        "dental",
        "vet",
        "clinic",
        "hospital",
    ],
}

# HTTP status codes that indicate a potential active domain
ACTIVE_HTTP_CODES = [200, 301, 302, 303, 307, 308, 403, 404, 405, 429, 500, 502, 503]


@click.command()
@click.option("--domain", "-d", required=True, help="Base domain name (without TLD)")
@click.option(
    "--output-dir", default="output_tldrcli", help="Directory to save results"
)
@click.option(
    "--tld-list",
    type=click.Path(exists=True),
    help="Custom TLD list file (one per line)",
)
@click.option(
    "--categories",
    default="popular,country",
    help="TLD categories to use: popular,country,new_generic,business,all",
)
@click.option("--threads", default=50, help="Number of concurrent threads")
@click.option("--timeout", default=5, help="DNS/HTTP timeout in seconds")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--dns-only", is_flag=True, help="Only perform DNS resolution (no HTTP probing)"
)
@click.option("--http-check", is_flag=True, help="Perform HTTP/HTTPS status checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option(
    "--filter-active",
    is_flag=True,
    help="Only show domains that resolve or respond to HTTP",
)
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option(
    "--whois-check", is_flag=True, help="Perform basic WHOIS availability check"
)
@click.option(
    "--exclude-wildcards",
    is_flag=True,
    help="Exclude domains that appear to be wildcards",
)
def cli(
    domain,
    output_dir,
    tld_list,
    categories,
    threads,
    timeout,
    retries,
    dns_only,
    http_check,
    verbose,
    save_json,
    save_markdown,
    resume,
    clear_resume,
    show_resume,
    filter_active,
    slack_webhook,
    discord_webhook,
    whois_check,
    exclude_wildcards,
):
    """Advanced TLD reconnaissance - discover domains across alternative TLDs

    Systematically checks if a domain exists across different top-level domains,
    performs DNS resolution, HTTP probing, and basic availability analysis.

    Examples:
        tldrcli -d example --categories popular,country --http-check --verbose
        tldrcli -d mycompany --tld-list custom_tlds.txt --filter-active
        tldrcli -d brand --categories all --whois-check --save-json
    """

    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir)
        return

    if clear_resume:
        clear_resume_state(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    if verbose:
        click.echo(f"[+] 🌍 Starting TLD reconnaissance for: {domain}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        if http_check:
            click.echo(f"[+] 🌐 HTTP probing enabled")
        if whois_check:
            click.echo(f"[+] 📋 WHOIS checking enabled")

    # Build TLD list
    tld_list_final = build_tld_list(tld_list, categories, verbose)

    if not tld_list_final:
        click.echo(
            "[!] ❌ No TLDs to check. Please specify valid categories or TLD list."
        )
        return

    if verbose:
        click.echo(f"[+] 📝 Testing {len(tld_list_final)} TLD(s)")

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"tldr_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
            if key.startswith("tldr_") and not data.get("completed", False):
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
            "processed_count": 0,
            "resolved_count": 0,
            "http_active_count": 0,
            "configuration": {
                "threads": threads,
                "timeout": timeout,
                "retries": retries,
                "dns_only": dns_only,
                "http_check": http_check,
                "whois_check": whois_check,
                "categories": categories,
            },
        }
        save_resume_state(output_dir, resume_state)

    current_scan = resume_state[scan_key]
    processed_count = current_scan.get("processed_count", 0)

    if verbose and processed_count > 0:
        click.echo(f"[+] 📁 Resume: {processed_count} TLDs already processed")

    start_time = time.time()

    # Process TLDs with concurrent checking
    results = process_tlds_concurrent(
        domain,
        tld_list_final[processed_count:],
        threads,
        timeout,
        retries,
        dns_only,
        http_check,
        whois_check,
        exclude_wildcards,
        verbose,
    )

    # Update counts
    resolved_count = len([r for r in results if r["dns_resolved"]])
    http_active_count = len(
        [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
    )

    current_scan["processed_count"] = len(tld_list_final)
    current_scan["resolved_count"] = (
        current_scan.get("resolved_count", 0) + resolved_count
    )
    current_scan["http_active_count"] = (
        current_scan.get("http_active_count", 0) + http_active_count
    )
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()

    save_resume_state(output_dir, resume_state)

    # Apply filtering if requested
    if filter_active:
        before_filter = len(results)
        results = [
            r
            for r in results
            if r["dns_resolved"] or r.get("http_status") in ACTIVE_HTTP_CODES
        ]
        if verbose:
            click.echo(
                f"[+] 🧹 Filtered to active domains: {before_filter} → {len(results)} results"
            )

    # Save outputs in multiple formats
    save_outputs(results, output_dir, save_json, save_markdown, verbose)

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo(f"\n[+] 📊 TLD Reconnaissance Summary:")
        click.echo(f"   - Base domain: {domain}")
        click.echo(f"   - Total TLDs tested: {len(tld_list_final)}")
        click.echo(f"   - DNS resolved: {resolved_count}")
        click.echo(f"   - HTTP active: {http_active_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(f"   - Success rate: {resolved_count/len(tld_list_final)*100:.1f}%")

    # Generate statistics
    stats = generate_statistics(results, verbose)

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        send_tldr_notifications(
            results,
            stats,
            domain,
            len(tld_list_final),
            resolved_count,
            http_active_count,
            elapsed,
            slack_webhook,
            discord_webhook,
            verbose,
        )

    click.echo(f"\n[+] ✅ TLD reconnaissance completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


def build_tld_list(
    tld_file: Optional[str], categories: str, verbose: bool
) -> List[str]:
    """Build comprehensive TLD list from file or categories"""
    tlds = set()

    # Load from file if provided
    if tld_file:
        try:
            with open(tld_file, "r") as f:
                file_tlds = [
                    line.strip().lstrip(".")
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                tlds.update(file_tlds)
            if verbose:
                click.echo(f"[+] 📄 Loaded {len(file_tlds)} TLDs from file")
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Failed to load TLD file: {e}")

    # Add from categories
    if categories:
        category_list = [cat.strip() for cat in categories.split(",")]

        for category in category_list:
            if category == "all":
                for cat_tlds in DEFAULT_TLDS.values():
                    tlds.update(cat_tlds)
            elif category in DEFAULT_TLDS:
                tlds.update(DEFAULT_TLDS[category])
            else:
                if verbose:
                    click.echo(f"[!] ⚠️  Unknown category: {category}")

        if verbose:
            click.echo(f"[+] 📋 Added TLDs from categories: {', '.join(category_list)}")

    return sorted(list(tlds))


def process_tlds_concurrent(
    domain: str,
    tlds: List[str],
    threads: int,
    timeout: int,
    retries: int,
    dns_only: bool,
    http_check: bool,
    whois_check: bool,
    exclude_wildcards: bool,
    verbose: bool,
) -> List[Dict]:
    """Process TLD list with concurrent checking"""
    results = []

    def check_domain_tld(tld: str) -> Dict:
        """Check a single domain.tld combination"""
        full_domain = f"{domain}.{tld}"
        result = {
            "domain": full_domain,
            "tld": tld,
            "dns_resolved": False,
            "ip_address": None,
            "http_status": None,
            "https_status": None,
            "whois_available": None,
            "is_wildcard": False,
            "error": None,
        }

        try:
            # DNS Resolution
            socket.setdefaulttimeout(timeout)
            try:
                ip = socket.gethostbyname(full_domain)
                result["dns_resolved"] = True
                result["ip_address"] = ip
            except socket.gaierror:
                result["dns_resolved"] = False

            # Wildcard detection
            if exclude_wildcards and result["dns_resolved"]:
                result["is_wildcard"] = detect_wildcard(domain, tld, ip, timeout)

            # HTTP/HTTPS checking
            if http_check and result["dns_resolved"] and not result["is_wildcard"]:
                http_status, https_status = check_http_status(
                    full_domain, timeout, retries
                )
                result["http_status"] = http_status
                result["https_status"] = https_status

            # Basic WHOIS checking (simplified)
            if whois_check:
                result["whois_available"] = simple_whois_check(full_domain, timeout)

        except Exception as e:
            result["error"] = str(e)

        return result

    # Use ThreadPoolExecutor for concurrent processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Create progress bar
        with tqdm(
            total=len(tlds),
            desc="🌍 Checking TLDs",
            disable=not verbose,
            ncols=100,
        ) as pbar:

            # Submit all tasks
            future_to_tld = {
                executor.submit(check_domain_tld, tld): tld for tld in tlds
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_tld):
                result = future.result()
                results.append(result)
                pbar.update(1)

                # Update progress bar with stats
                resolved = len([r for r in results if r["dns_resolved"]])
                active = len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                )
                pbar.set_postfix(resolved=resolved, active=active)

    return results


def detect_wildcard(domain: str, tld: str, resolved_ip: str, timeout: int) -> bool:
    """Simple wildcard detection by testing random subdomain"""
    import random
    import string

    try:
        # Generate random subdomain
        random_sub = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=15)
        )
        test_domain = f"{random_sub}.{domain}.{tld}"

        socket.setdefaulttimeout(timeout)
        test_ip = socket.gethostbyname(test_domain)

        # If random subdomain resolves to same IP, likely wildcard
        return test_ip == resolved_ip
    except:
        return False


def check_http_status(
    domain: str, timeout: int, retries: int
) -> Tuple[Optional[int], Optional[int]]:
    """Check HTTP and HTTPS status codes"""
    import urllib.request
    import urllib.error
    import ssl

    def get_status(url: str) -> Optional[int]:
        for attempt in range(retries + 1):
            try:
                # Create SSL context that doesn't verify certificates
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 (TLD-Recon/1.0)"}
                )

                with urllib.request.urlopen(
                    req, timeout=timeout, context=ssl_context
                ) as response:
                    return response.getcode()
            except urllib.error.HTTPError as e:
                return e.code
            except Exception:
                if attempt == retries:
                    return None
                time.sleep(0.1)
        return None

    http_status = get_status(f"http://{domain}")
    https_status = get_status(f"https://{domain}")

    return http_status, https_status


def simple_whois_check(domain: str, timeout: int) -> Optional[bool]:
    """Simple WHOIS availability check (placeholder)"""
    # This is a simplified placeholder
    # In production, you might want to use python-whois library
    # or integrate with WHOIS APIs
    try:
        import subprocess

        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Simple heuristic: if whois returns info, domain might be registered
        return "No match" not in result.stdout and "NOT FOUND" not in result.stdout
    except:
        return None


def save_outputs(
    results: List[Dict],
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
):
    """Save results in multiple formats"""

    # Standard output
    output_path = os.path.join(output_dir, "tld_results.txt")
    with open(output_path, "w") as f:
        for result in results:
            status_parts = []

            if result["dns_resolved"]:
                status_parts.append(f"IP:{result['ip_address']}")
            else:
                status_parts.append("DNS:FAIL")

            if result.get("http_status"):
                status_parts.append(f"HTTP:{result['http_status']}")
            if result.get("https_status"):
                status_parts.append(f"HTTPS:{result['https_status']}")

            if result.get("is_wildcard"):
                status_parts.append("WILDCARD")

            if result.get("whois_available") is not None:
                status_parts.append(
                    f"WHOIS:{'REG' if result['whois_available'] else 'AVAIL'}"
                )

            status_str = " | ".join(status_parts) if status_parts else "INACTIVE"
            f.write(f"{result['domain']} - {status_str}\n")

    if verbose:
        click.echo(f"[+] 💾 Saved results to {output_path}")

    # JSON output
    if save_json:
        json_output = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_domains": len(results),
                "resolved_count": len([r for r in results if r["dns_resolved"]]),
                "active_count": len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                ),
                "tool": "tldrcli",
            },
            "results": results,
        }

        json_path = os.path.join(output_dir, "tld_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

    # Markdown output
    if save_markdown:
        md_path = os.path.join(output_dir, "tld_results.md")
        with open(md_path, "w") as f:
            f.write("# TLD Reconnaissance Results\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total Domains:** {len(results)}\n")
            f.write(
                f"**DNS Resolved:** {len([r for r in results if r['dns_resolved']])}\n"
            )
            f.write(
                f"**HTTP Active:** {len([r for r in results if r.get('http_status') in ACTIVE_HTTP_CODES])}\n\n"
            )

            f.write("## Results\n\n")
            f.write("| Domain | TLD | DNS | IP Address | HTTP | HTTPS | Status |\n")
            f.write("|--------|-----|-----|------------|------|-------|--------|\n")

            for result in results:
                dns_status = "✅" if result["dns_resolved"] else "❌"
                ip_addr = result["ip_address"] or "-"
                http_status = result.get("http_status", "-")
                https_status = result.get("https_status", "-")

                status_flags = []
                if result.get("is_wildcard"):
                    status_flags.append("🌟 Wildcard")
                if result.get("whois_available"):
                    status_flags.append("📋 Registered")
                elif result.get("whois_available") is False:
                    status_flags.append("🆓 Available")

                status = " ".join(status_flags) if status_flags else "-"

                f.write(
                    f"| {result['domain']} | {result['tld']} | {dns_status} | {ip_addr} | {http_status} | {https_status} | {status} |\n"
                )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")


def generate_statistics(results: List[Dict], verbose: bool) -> Dict:
    """Generate comprehensive statistics"""
    stats = {
        "total_domains": len(results),
        "dns_resolved": len([r for r in results if r["dns_resolved"]]),
        "http_active": len(
            [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
        ),
        "https_active": len(
            [r for r in results if r.get("https_status") in ACTIVE_HTTP_CODES]
        ),
        "wildcards": len([r for r in results if r.get("is_wildcard")]),
        "registered": len([r for r in results if r.get("whois_available")]),
        "available": len([r for r in results if r.get("whois_available") is False]),
    }

    if verbose:
        click.echo(f"\n[+] 📊 Detailed Statistics:")
        click.echo(f"   - Total domains tested: {stats['total_domains']}")
        click.echo(f"   - DNS resolved: {stats['dns_resolved']}")
        click.echo(f"   - HTTP active: {stats['http_active']}")
        click.echo(f"   - HTTPS active: {stats['https_active']}")
        if stats["wildcards"] > 0:
            click.echo(f"   - Wildcards detected: {stats['wildcards']}")
        if stats["registered"] > 0:
            click.echo(f"   - Registered domains: {stats['registered']}")
        if stats["available"] > 0:
            click.echo(f"   - Available domains: {stats['available']}")

    return stats


def send_tldr_notifications(
    results: List[Dict],
    stats: Dict,
    domain: str,
    total: int,
    resolved: int,
    active: int,
    elapsed: float,
    slack_webhook: str,
    discord_webhook: str,
    verbose: bool,
):
    """Send TLD reconnaissance notifications"""
    if not (send_notification and (slack_webhook or discord_webhook)):
        return

    try:
        scan_metadata = {
            "base_domain": domain,
            "total_tlds": total,
            "resolved_count": resolved,
            "active_count": active,
            "scan_duration": f"{elapsed}s",
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "tool": "tldrcli",
            "statistics": stats,
        }

        # Prepare interesting results for notification
        interesting_results = []
        for result in results[:20]:  # First 20 results
            if result["dns_resolved"] or result.get("http_status") in ACTIVE_HTTP_CODES:
                interesting_results.append(result)

        if verbose:
            click.echo("[+] 📱 Sending TLD reconnaissance notifications...")

        success = send_notification(
            notification_type="tldr",
            results=interesting_results,
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
    """Show status of previous TLD scans"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous TLD scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        if scan_key.startswith("tldr_"):
            click.echo(f"🌍 Scan: {scan_key}")
            click.echo(f"   Domain: {scan_data.get('domain', 'unknown')}")
            click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

            if scan_data.get("completed"):
                click.echo(f"   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
                click.echo(f"   DNS Resolved: {scan_data.get('resolved_count', 0)}")
                click.echo(f"   HTTP Active: {scan_data.get('http_active_count', 0)}")
            else:
                click.echo(f"   Status: ⏳ Incomplete")
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

            click.echo()


def clear_resume_state(output_dir: str):
    """Clear resume state for TLD scans"""
    clear_resume(output_dir)


if __name__ == "__main__":
    cli()
