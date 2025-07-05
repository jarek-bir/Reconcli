import json as json_module
import os
import json
import click
import subprocess
import hashlib
import requests
import urllib3
import time
from reconcli.url_tagger import tag_urls
from reconcli.utils.loaders import dedupe_paths

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


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

# Heurystyki do wykrywania sekretów
SENSITIVE_PATTERNS = [
    "apikey",
    "token",
    "authorization",
    "bearer",
    "auth",
    "access_token",
    "client_secret",
    "password",
    "secret",
    "jwt",
    "basic",
]


CDN_HOST_BLACKLIST = [
    "intercomassets.com",
    "googletagmanager.com",
    "google-analytics.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "static.xx.fbcdn.net",
    "connect.facebook.net",
]
all_urls_global = set()


def save_outputs(domain, tagged, output_dir, save_markdown, save_json):
    os.makedirs(output_dir, exist_ok=True)

    if save_json:
        json_file = os.path.join(output_dir, f"{domain}_tagged.json")
        with open(json_file, "w") as f:
            json.dump(tagged, f, indent=2)
        print(f"[+] Saved JSON output: {json_file}")

    if save_markdown:
        md_file = os.path.join(output_dir, f"{domain}_tagged.md")
        with open(md_file, "w") as f:
            f.write("# Tagged URLs\n\n")
            for url, tags in tagged:
                tags_str = ", ".join(tags) if tags else "no tags"
                f.write(f"- {url} — {tags_str}\n")
        print(f"[+] Saved Markdown output: {md_file}")


def scan_js(domain, output_dir, session):
    js_file = os.path.join(output_dir, f"{domain}_js_urls.txt")
    if not os.path.exists(js_file):
        print(f"[!] No JS URLs found for scanning: {js_file}")
        return

    with open(js_file, "r") as f:
        js_urls = [line.strip() for line in f if line.strip()]

    findings = []

    for js_url in js_urls:
        try:
            resp = session.get(js_url, timeout=10)
            content = resp.text

            # Proste heurystyki na sekretne klucze
            for pattern in SENSITIVE_PATTERNS:
                if pattern.lower() in content.lower():
                    findings.append((js_url, pattern))
        except Exception as e:
            print(f"[!] Failed to fetch {js_url}: {e}")

    report_file = os.path.join(output_dir, f"{domain}_js_scan.txt")
    with open(report_file, "w") as f:
        for url, pattern in findings:
            f.write(f"{url} — matched pattern: {pattern}\n")

    print(f"[+] JS scan results saved to {report_file}")


@click.command()
@click.option("--input", help="File with resolved subdomains or plain list")
@click.option(
    "--from-subs-resolved",
    is_flag=True,
    help="Extract unique subdomains from subs_resolved.txt",
)
@click.option(
    "--output-dir", default="output_urlcli", help="Directory to store results"
)
@click.option("--flow", type=click.Path(), help="YAML flow file for urlcli config")
@click.option("--resume", is_flag=True, help="Resume scan from previous run")
@click.option("--resume-file", default="resume_urlcli.json", help="Path to resume file")
@click.option("--wayback", is_flag=True, help="Use waybackurls")
@click.option("--gau", is_flag=True, help="Use gau")
@click.option("--katana", is_flag=True, help="Use katana")
@click.option("--gospider", is_flag=True, help="Use GoSpider")
@click.option("--sitemap", is_flag=True, help="Parse sitemap.xml")
@click.option("--favicon", is_flag=True, help="Fetch and hash favicon")
@click.option(
    "--extract-js", is_flag=True, help="Extract .js URLs from discovered URLs"
)
@click.option(
    "--js-scan", is_flag=True, help="Download and scan .js files for endpoints/secrets"
)
@click.option("--save-json", is_flag=True, help="Save JSON output")
@click.option("--save-markdown", is_flag=True, help="Save markdown report")
@click.option("--tag-only", is_flag=True, help="Only keep URLs with tags")
@click.option("--dedupe", is_flag=True, help="Deduplicate similar endpoints")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
@click.option("--verify-ssl/--no-verify-ssl", default=True, help="Verify SSL certs")
@click.option(
    "--smart-filter",
    is_flag=True,
    help="Remove URLs pointing to CDNs and irrelevant scripts",
)
@click.option("--export-tag", default=None, help="Export only URLs with this tag")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option(
    "--timeout", default=60, help="Timeout for individual operations (seconds)"
)
@click.option("--retries", default=3, help="Number of retries for failed operations")
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
    "--threads", default=5, help="Number of concurrent threads for processing"
)
def main(
    input,
    from_subs_resolved,
    output_dir,
    flow,
    resume,
    resume_file,
    wayback,
    gau,
    katana,
    gospider,
    sitemap,
    favicon,
    extract_js,
    js_scan,
    save_json,
    save_markdown,
    tag_only,
    dedupe,
    proxy,
    verify_ssl,
    smart_filter,
    export_tag,
    verbose,
    timeout,
    retries,
    clear_resume_flag,
    show_resume,
    slack_webhook,
    discord_webhook,
    threads,
):
    global all_urls_global

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

    # Enhanced resume system with more detailed tracking
    os.makedirs(output_dir, exist_ok=True)
    scan_key = f"url_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
            if key.startswith("url_") and not data.get("completed", False):
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
            "domains_processed": [],
            "domains_failed": [],
            "total_urls_found": 0,
            "configuration": {
                "wayback": wayback,
                "gau": gau,
                "katana": katana,
                "gospider": gospider,
                "sitemap": sitemap,
                "extract_js": extract_js,
                "js_scan": js_scan,
            },
        }
        save_resume_state(output_dir, resume_state)

    if verbose:
        click.echo(f"[+] 🚀 Starting URL discovery scan")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        click.echo(f"[+] 🧵 Threads: {threads}")

    if flow:
        with open(flow, "r") as f:
            config = yaml.safe_load(f)
        wayback = config.get("wayback", wayback)
        gau = config.get("gau", gau)
        katana = config.get("katana", katana)
        gospider = config.get("gospider", gospider)
        sitemap = config.get("sitemap", sitemap)
        favicon = config.get("favicon", favicon)
        extract_js = config.get("extract_js", extract_js)
        js_scan = config.get("js_scan", js_scan)
        save_json = config.get("save_json", save_json)
        save_markdown = config.get("save_markdown", save_markdown)
        tag_only = config.get("tag_only", tag_only)
        dedupe = config.get("dedupe", dedupe)

    if from_subs_resolved:
        with open(input, "r") as f:
            targets = sorted(set([line.split()[0] for line in f if line.strip()]))
    else:
        with open(input, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    if verbose:
        click.echo(f"[+] 📋 Loaded {len(targets)} target(s) from {input}")

    # Configure session
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; ReconCLI URLCli)"})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        if verbose:
            click.echo(f"[+] 🔀 Using proxy: {proxy}")
    session.verify = verify_ssl

    all_tagged = []
    current_scan = resume_state[scan_key]
    processed_domains = set(current_scan.get("domains_processed", []))
    failed_domains = set(current_scan.get("domains_failed", []))
    total_errors = []

    if verbose and processed_domains:
        click.echo(f"[+] 📁 Resume: {len(processed_domains)} domains already processed")

    for domain_idx, domain in enumerate(targets, 1):
        if domain in processed_domains:
            if verbose:
                click.echo(f"[=] ⏭️  Skipping (already processed): {domain}")
            continue

        click.echo(f"\n[+] 🎯 [{domain_idx}/{len(targets)}] Processing: {domain}")

        start_time = time.time()
        domain_errors = []

        try:
            # Enhanced URL discovery
            urls, errors = enhanced_url_discovery(
                domain,
                wayback,
                gau,
                katana,
                gospider,
                sitemap,
                favicon,
                session,
                output_dir,
                timeout,
                retries,
                verbose,
            )

            if errors:
                domain_errors.extend(errors)
                total_errors.extend(errors)

            if verbose:
                click.echo(f"[+] 📊 Raw URLs discovered: {len(urls)}")

            # Apply smart filtering
            if smart_filter:
                original_count = len(urls)
                urls = apply_smart_filtering(urls, verbose)
                if verbose:
                    click.echo(
                        f"[+] 🧹 Smart filter: {original_count} → {len(urls)} URLs"
                    )

            all_urls_global.update(urls)

            if verbose:
                click.echo(f"[+] 🏷️  Starting URL tagging...")

            # Tag URLs
            tagged = tag_urls(list(urls))

            if tag_only:
                before_filter = len(tagged)
                tagged = [t for t in tagged if t[1]]
                if verbose:
                    click.echo(
                        f"[+] 🏷️  Tag filter: {before_filter} → {len(tagged)} URLs"
                    )

            if dedupe:
                before_dedupe = len(tagged)
                tagged = dedupe_paths(tagged)
                if verbose:
                    click.echo(
                        f"[+] 🔄 Deduplication: {before_dedupe} → {len(tagged)} URLs"
                    )

            # Save domain-specific outputs
            save_outputs(domain, tagged, output_dir, save_markdown, save_json)
            all_tagged.extend(tagged)

            # Extract JS URLs if requested
            if extract_js:
                js_urls = [u for u, _ in tagged if u.endswith(".js")]
                js_file = os.path.join(output_dir, f"{domain}_js_urls.txt")
                with open(js_file, "w") as f:
                    f.write("\n".join(js_urls))
                if verbose:
                    click.echo(f"[+] 📄 Extracted {len(js_urls)} JS URLs to {js_file}")

            # Scan JS files if requested
            if js_scan:
                if verbose:
                    click.echo(f"[+] 🔍 Starting JS scan for {domain}")
                scan_js_enhanced(domain, output_dir, session, timeout, verbose)

            # Update resume state - domain completed successfully
            processed_domains.add(domain)
            current_scan["domains_processed"] = list(processed_domains)
            current_scan["total_urls_found"] = current_scan.get(
                "total_urls_found", 0
            ) + len(tagged)

            elapsed = round(time.time() - start_time, 2)

            if domain_errors:
                current_scan["domains_failed"] = list(failed_domains | {domain})
                current_scan["last_error"] = "; ".join(
                    domain_errors[:3]
                )  # Keep only first 3 errors

            save_resume_state(output_dir, resume_state)

            if verbose:
                status_emoji = "⚠️" if domain_errors else "✅"
                click.echo(
                    f"[+] {status_emoji} Completed {domain} in {elapsed}s - {len(tagged)} tagged URLs"
                )
                if domain_errors:
                    click.echo(f"[!] ⚠️  {len(domain_errors)} error(s) encountered")

        except KeyboardInterrupt:
            click.echo(f"\n[!] ⏹️  Scan interrupted by user")
            current_scan["last_error"] = "Interrupted by user"
            save_resume_state(output_dir, resume_state)
            return
        except Exception as e:
            error_msg = f"Critical error processing {domain}: {str(e)}"
            click.echo(f"[!] 💥 {error_msg}")
            failed_domains.add(domain)
            total_errors.append(error_msg)
            current_scan["domains_failed"] = list(failed_domains)
            current_scan["last_error"] = error_msg
            save_resume_state(output_dir, resume_state)
            save_resume_state(output_dir, resume_state)
            continue

    # Mark scan as completed
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()
    save_resume_state(output_dir, resume_state)

    if verbose:
        click.echo(f"\n[+] 📊 Scan Summary:")
        click.echo(f"   - Domains processed: {len(processed_domains)}")
        click.echo(f"   - Domains failed: {len(failed_domains)}")
        click.echo(f"   - Total URLs found: {len(all_tagged)}")
        click.echo(f"   - Total errors: {len(total_errors)}")

    # Generate final reports
    if export_tag:
        filtered = [t for t in all_tagged if export_tag in t[1]]
        export_file = os.path.join(output_dir, f"{export_tag}_urls.txt")
        with open(export_file, "w") as f:
            for url, tags in filtered:
                f.write(url + "\n")
        if verbose:
            click.echo(
                f"[+] 📋 Exported {len(filtered)} URLs with tag '{export_tag}' to {export_file}"
            )

    # Save all URLs
    try:
        all_urls_file = os.path.join(output_dir, "all_urls.txt")
        with open(all_urls_file, "w") as f:
            for url in sorted(all_urls_global):
                f.write(url + "\n")
        if verbose:
            click.echo(
                f"[+] 💾 Saved {len(all_urls_global)} unique URLs to {all_urls_file}"
            )
    except Exception as e:
        click.echo(f"[!] ❌ Error saving all_urls.txt: {e}")

    # Generate summary report
    summarize_tags(output_dir, all_tagged)

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        scan_metadata = {
            "domains_processed": len(processed_domains),
            "domains_failed": len(failed_domains),
            "total_urls_found": len(all_tagged),
            "tools_used": [
                tool
                for tool, enabled in [
                    ("wayback", wayback),
                    ("gau", gau),
                    ("katana", katana),
                    ("gospider", gospider),
                    ("sitemap", sitemap),
                ]
                if enabled
            ],
            "scan_duration": "completed",
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        }

        if verbose:
            click.echo("[+] 📱 Sending notifications...")

        try:
            notification_msg = f"🔗 URL Discovery completed!\n\n📊 **Summary:**\n• URLs found: {len(all_tagged)}\n• Domains processed: {len(processed_domains)}\n• Tools used: {', '.join(scan_metadata['tools_used'])}\n• Output: {output_dir}"

            # For now, use a simple approach until we add url notification support
            if NotificationManager and (slack_webhook or discord_webhook):
                notifier = NotificationManager(slack_webhook, discord_webhook, verbose)

                # Create a temporary vhost-style notification for URL discovery
                temp_results = [
                    {
                        "type": "url_discovery",
                        "summary": f"{len(all_tagged)} URLs found across {len(processed_domains)} domains",
                        "details": notification_msg,
                    }
                ]

                if verbose:
                    click.echo(
                        f"[+] 📱 Sending notification: {len(all_tagged)} URLs found"
                    )

                # Use URL notification type
                success = send_notification(
                    notification_type="url",
                    results=temp_results,
                    scan_metadata=scan_metadata,
                    slack_webhook=slack_webhook,
                    discord_webhook=discord_webhook,
                    verbose=verbose,
                )

                if success and verbose:
                    click.echo(f"[+] ✅ Notifications sent successfully")
            elif (slack_webhook or discord_webhook) and verbose:
                click.echo(f"[!] ⚠️  Notification system not available")

        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Notification failed: {e}")

    click.echo(f"\n[+] ✅ URL discovery scan completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")
    if total_errors:
        click.echo(f"[!] ⚠️  {len(total_errors)} error(s) encountered during scan")


def categorize_urls(urls):
    categories = {"xss": [], "lfi": [], "redirect": [], "other": []}
    for url in urls:
        lowered = url.lower()
        if any(
            x in lowered for x in ["<script", "onerror", "alert(", "document.cookie"]
        ):
            categories["xss"].append(url)
        elif any(x in lowered for x in ["../", "..\\", "/etc/passwd", "boot.ini"]):
            categories["lfi"].append(url)
        elif any(x in lowered for x in ["url=", "redirect", "next=", "return="]):
            categories["redirect"].append(url)
        else:
            categories["other"].append(url)
    return categories


def save_category_exports(categories, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for cat, urls in categories.items():
        with open(os.path.join(output_dir, f"{cat}.txt"), "w") as f:
            for u in sorted(set(urls)):
                f.write(u + "\n")


def summarize_tags(output_dir, tagged_urls):
    summary_file = os.path.join(output_dir, "urls_summary.md")
    total = len(tagged_urls)
    with open(summary_file, "w") as f:
        f.write(f"# URL Summary\n\nTotal tagged URLs: {total}\n\n")
        tag_counts = {}
        for _, tags in tagged_urls:
            for tag in tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
            f.write(f"- {tag}: {count}\n")


def show_resume_status(output_dir):
    """Show status of previous URL scans from resume file."""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous URL scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        if scan_key.startswith("url_"):
            click.echo(f"🔍 Scan: {scan_key}")
            click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")
            click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

            if scan_data.get("completed"):
                click.echo(f"   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(
                    f"   Domains processed: {len(scan_data.get('domains_processed', []))}"
                )
                click.echo(
                    f"   Total URLs found: {scan_data.get('total_urls_found', 0)}"
                )
            else:
                click.echo(f"   Status: ⏳ Incomplete")
                click.echo(
                    f"   Domains processed: {len(scan_data.get('domains_processed', []))}"
                )
                if scan_data.get("domains_failed"):
                    click.echo(
                        f"   Domains failed: {len(scan_data.get('domains_failed', []))}"
                    )
                if scan_data.get("last_error"):
                    click.echo(f"   Last Error: {scan_data.get('last_error')}")

            click.echo()


def run_tool_with_retry(cmd, domain, tool_name, timeout, retries, verbose):
    """Run external tool with retry logic and proper error handling."""
    for attempt in range(retries):
        try:
            if verbose:
                click.echo(
                    f"[+] 🔧 Running {tool_name} on {domain} (attempt {attempt + 1}/{retries})"
                )

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=True
            )

            urls = result.stdout.splitlines()
            if verbose:
                click.echo(f"[+] ✅ {tool_name} found {len(urls)} URLs for {domain}")
            return urls, None

        except subprocess.TimeoutExpired:
            error = f"{tool_name} timeout after {timeout}s"
            if verbose:
                click.echo(f"[!] ⏰ {error}")
            if attempt == retries - 1:
                return [], error
        except subprocess.CalledProcessError as e:
            error = f"{tool_name} failed: {e.stderr or e.returncode}"
            if verbose:
                click.echo(f"[!] ❌ {error}")
            if attempt == retries - 1:
                return [], error
        except Exception as e:
            error = f"{tool_name} unexpected error: {str(e)}"
            if verbose:
                click.echo(f"[!] 💥 {error}")
            if attempt == retries - 1:
                return [], error

        if attempt < retries - 1:
            sleep_time = 2**attempt  # Exponential backoff
            if verbose:
                click.echo(f"[+] 😴 Retrying in {sleep_time}s...")
            time.sleep(sleep_time)

    return [], f"{tool_name} failed after {retries} attempts"


def enhanced_url_discovery(
    domain,
    wayback,
    gau,
    katana,
    gospider,
    sitemap,
    favicon,
    session,
    output_dir,
    timeout,
    retries,
    verbose,
):
    """Enhanced URL discovery with better error handling and progress tracking."""
    urls = set()
    errors = []

    if verbose:
        click.echo(f"[+] 🎯 Starting URL discovery for {domain}")

    # External tools
    tools_config = [
        (wayback, ["waybackurls", domain], "waybackurls"),
        (gau, ["gau", domain], "gau"),
        (katana, ["katana", "-u", f"http://{domain}"], "katana"),
        (gospider, ["gospider", "-s", f"http://{domain}", "-q"], "gospider"),
    ]

    for enabled, cmd, tool_name in tools_config:
        if enabled:
            tool_urls, error = run_tool_with_retry(
                cmd, domain, tool_name, timeout, retries, verbose
            )
            if tool_urls:
                urls.update(tool_urls)
            if error:
                errors.append(error)

    # Sitemap discovery
    if sitemap:
        try:
            if verbose:
                click.echo(f"[+] 🗺️  Fetching sitemap for {domain}")

            for protocol in ["https", "http"]:
                try:
                    resp = session.get(
                        f"{protocol}://{domain}/sitemap.xml", timeout=timeout
                    )
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.content, "xml")
                        sitemap_urls = {loc.text for loc in soup.find_all("loc")}
                        urls.update(sitemap_urls)
                        if verbose:
                            click.echo(
                                f"[+] ✅ Found {len(sitemap_urls)} URLs in sitemap"
                            )
                        break
                except Exception:
                    continue
            else:
                error = f"Sitemap not accessible for {domain}"
                errors.append(error)
                if verbose:
                    click.echo(f"[!] ⚠️  {error}")

        except Exception as e:
            error = f"Sitemap parsing failed: {str(e)}"
            errors.append(error)
            if verbose:
                click.echo(f"[!] ❌ {error}")

    # Favicon hash collection
    if favicon:
        try:
            if verbose:
                click.echo(f"[+] 🎨 Fetching favicon for {domain}")

            for protocol in ["https", "http"]:
                try:
                    resp = session.get(
                        f"{protocol}://{domain}/favicon.ico", timeout=timeout
                    )
                    if resp.status_code == 200:
                        h = hashlib.md5(resp.content).hexdigest()
                        favicon_file = os.path.join(output_dir, "favicon_hashes.txt")
                        with open(favicon_file, "a") as f:
                            f.write(f"{domain} {h} {protocol}\n")
                        if verbose:
                            click.echo(f"[+] ✅ Favicon hash: {h}")
                        break
                except Exception:
                    continue
            else:
                error = f"Favicon not accessible for {domain}"
                if verbose:
                    click.echo(f"[!] ⚠️  {error}")

        except Exception as e:
            error = f"Favicon processing failed: {str(e)}"
            errors.append(error)
            if verbose:
                click.echo(f"[!] ❌ {error}")

    return list(urls), errors


def apply_smart_filtering(urls, verbose):
    """Apply smart filtering to remove irrelevant URLs."""
    if not urls:
        return urls

    original_count = len(urls)

    # Filter by hostname (CDN blacklist)
    urls = [u for u in urls if urlparse(u).hostname not in CDN_HOST_BLACKLIST]

    # Filter by scheme and other patterns
    urls = [
        u
        for u in urls
        if not u.startswith(("mailto:", "tel:", "javascript:", "data:"))
        and not u.strip().startswith("#")
        and not u.strip().startswith("//")
    ]

    # Filter file extensions (already done in main, but extra safety)
    excluded_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".css",
        ".scss",
        ".less",
        ".mp4",
        ".mp3",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".pdf",
        ".doc",
        ".docx",
        ".ppt",
        ".xls",
        ".xlsx",
        ".zip",
        ".rar",
        ".tar",
        ".gz",
        ".7z",
        ".bz2",
    ]

    urls = [
        u
        for u in urls
        if not any(u.lower().endswith(ext) for ext in excluded_extensions)
    ]

    # Remove very long URLs (likely garbage)
    urls = [u for u in urls if len(u) < 2000]

    # Remove URLs with too many parameters (likely session-based)
    urls = [u for u in urls if u.count("&") < 20]

    if verbose:
        filtered_count = original_count - len(urls)
        if filtered_count > 0:
            click.echo(f"[+] 🧹 Filtered out {filtered_count} irrelevant URLs")

    return urls


def scan_js_enhanced(domain, output_dir, session, timeout, verbose):
    """Enhanced JS scanning with better error handling."""
    js_file = os.path.join(output_dir, f"{domain}_js_urls.txt")
    if not os.path.exists(js_file):
        if verbose:
            click.echo(f"[!] ⚠️  No JS URLs found for scanning: {js_file}")
        return

    with open(js_file, "r") as f:
        js_urls = [line.strip() for line in f if line.strip()]

    if verbose:
        click.echo(f"[+] 🔍 Scanning {len(js_urls)} JS files for secrets...")

    findings = []
    errors = []

    for idx, js_url in enumerate(js_urls, 1):
        if verbose and len(js_urls) > 10 and idx % 10 == 0:
            click.echo(f"[+] 📊 Progress: {idx}/{len(js_urls)} JS files")

        try:
            resp = session.get(js_url, timeout=timeout)
            content = resp.text

            # Enhanced secret pattern detection
            for pattern in SENSITIVE_PATTERNS:
                if pattern.lower() in content.lower():
                    # Try to extract actual values
                    lines = content.split("\n")
                    for line_num, line in enumerate(lines, 1):
                        if pattern.lower() in line.lower():
                            findings.append(
                                {
                                    "url": js_url,
                                    "pattern": pattern,
                                    "line": line_num,
                                    "context": line.strip()[:200],  # First 200 chars
                                }
                            )
                            break

        except requests.exceptions.Timeout:
            error = f"Timeout fetching {js_url}"
            errors.append(error)
            if verbose:
                click.echo(f"[!] ⏰ {error}")
        except Exception as e:
            error = f"Failed to fetch {js_url}: {str(e)}"
            errors.append(error)
            if verbose:
                click.echo(f"[!] ❌ {error}")

    # Save enhanced results
    report_file = os.path.join(output_dir, f"{domain}_js_scan.json")
    scan_results = {
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "js_files_scanned": len(js_urls),
        "findings": findings,
        "errors": errors,
        "summary": {
            "total_findings": len(findings),
            "patterns_found": list(set(f["pattern"] for f in findings)),
            "error_count": len(errors),
        },
    }

    with open(report_file, "w") as f:
        json.dump(scan_results, f, indent=2)

    if verbose:
        click.echo(
            f"[+] 📄 JS scan complete: {len(findings)} findings, {len(errors)} errors"
        )
        click.echo(f"[+] 💾 Results saved to {report_file}")

    return scan_results


# ...existing code...
