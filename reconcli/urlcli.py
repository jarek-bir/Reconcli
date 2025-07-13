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


@click.command()
@click.option("--input", help="File with resolved subdomains or plain list")
@click.option("--domain", help="Single domain to scan (e.g., example.com)")
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
@click.option("--katana-depth", default=3, help="Katana crawl depth (default: 3)")
@click.option(
    "--katana-js-crawl", is_flag=True, help="Enable Katana JavaScript crawling"
)
@click.option("--katana-headless", is_flag=True, help="Enable Katana headless mode")
@click.option(
    "--katana-form-fill", is_flag=True, help="Enable Katana automatic form filling"
)
@click.option(
    "--katana-tech-detect", is_flag=True, help="Enable Katana technology detection"
)
@click.option(
    "--katana-scope",
    default=None,
    help="Katana crawl scope regex (e.g., '.*\\.target\\.com.*')",
)
@click.option(
    "--katana-concurrency", default=10, help="Katana concurrency level (default: 10)"
)
@click.option(
    "--katana-rate-limit",
    default=150,
    help="Katana rate limit per second (default: 150)",
)
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
    "--timeout",
    default=1800,
    help="Timeout for individual operations (seconds, default: 30 minutes)",
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
    "--use-cariddi",
    is_flag=True,
    help="Use Cariddi for advanced web crawling and endpoint discovery",
)
@click.option(
    "--cariddi-depth",
    default=2,
    help="Cariddi crawling depth (default: 2)",
)
@click.option(
    "--cariddi-concurrency",
    default=20,
    help="Cariddi concurrency level (default: 20)",
)
@click.option(
    "--cariddi-delay",
    default=0,
    help="Cariddi delay between requests in milliseconds (default: 0)",
)
@click.option(
    "--cariddi-timeout",
    default=10,
    help="Cariddi timeout per request in seconds (default: 10)",
)
@click.option(
    "--cariddi-secrets",
    is_flag=True,
    help="Enable Cariddi secrets hunting in discovered content",
)
@click.option(
    "--cariddi-endpoints",
    is_flag=True,
    help="Enable Cariddi endpoint discovery mode",
)
@click.option(
    "--cariddi-extensions",
    default="",
    help="Cariddi file extensions to crawl (comma-separated, e.g., js,php,asp)",
)
@click.option(
    "--cariddi-ignore-extensions",
    default="",
    help="Cariddi file extensions to ignore (comma-separated, e.g., png,jpg,gif)",
)
@click.option(
    "--cariddi-plain",
    is_flag=True,
    help="Use Cariddi plain output format (no colors/formatting)",
)
@click.option(
    "--threads", default=5, help="Number of concurrent threads for processing"
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
def main(
    input,
    domain,
    from_subs_resolved,
    output_dir,
    flow,
    resume,
    resume_file,
    wayback,
    gau,
    katana,
    katana_depth,
    katana_js_crawl,
    katana_headless,
    katana_form_fill,
    katana_tech_detect,
    katana_scope,
    katana_concurrency,
    katana_rate_limit,
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
    use_cariddi,
    cariddi_depth,
    cariddi_concurrency,
    cariddi_delay,
    cariddi_timeout,
    cariddi_secrets,
    cariddi_endpoints,
    cariddi_extensions,
    cariddi_ignore_extensions,
    cariddi_plain,
    store_db,
    target_domain,
    program,
):
    """Enhanced URL discovery and crawling for reconnaissance with professional features

    Supports multiple URL discovery tools including wayback, gau, katana, gospider, sitemap parsing, and Cariddi.
    Can extract JavaScript URLs, perform content analysis, and tag URLs for categorization.

    NEW: Cariddi Integration for Advanced Web Crawling
    • Use --use-cariddi to enable Cariddi-powered web crawling and endpoint discovery
    • Cariddi provides fast crawling with built-in endpoint discovery and secrets hunting
    • Supports custom extensions filtering, concurrency control, and timeout management
    • Can combine Cariddi results with traditional URL discovery tools

    Examples:
    • Basic Cariddi crawling: --use-cariddi --cariddi-depth 2 --cariddi-secrets
    • Endpoint discovery mode: --use-cariddi --cariddi-endpoints --cariddi-extensions js,php
    • Secrets hunting: --use-cariddi --cariddi-secrets --cariddi-depth 3
    • Combined tools: --wayback --katana --use-cariddi --cariddi-endpoints
    """
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
    if not input and not domain:
        click.echo(
            "Error: Either --input or --domain is required for scanning operations."
        )
        click.echo("Use --show-resume or --clear-resume for resume management.")
        return

    # Handle single domain input
    if domain and not input:
        # Create temporary file for single domain
        import tempfile

        temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
        temp_file.write(domain + "\n")
        temp_file.close()
        input = temp_file.name
        # Mark as our temporary file for cleanup
        is_our_temp_file = True
        if verbose:
            click.echo(f"[+] 🎯 Single domain mode: {domain}")
    elif input and domain:
        click.echo("Error: Cannot specify both --input and --domain. Choose one.")
        return
    else:
        is_our_temp_file = False

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
            "single_domain": domain if domain else None,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "domains_processed": [],
            "domains_failed": [],
            "total_urls_found": 0,
            "configuration": {
                "wayback": wayback,
                "gau": gau,
                "katana": katana,
                "katana_depth": katana_depth,
                "katana_js_crawl": katana_js_crawl,
                "katana_headless": katana_headless,
                "katana_form_fill": katana_form_fill,
                "katana_tech_detect": katana_tech_detect,
                "katana_scope": katana_scope,
                "katana_concurrency": katana_concurrency,
                "katana_rate_limit": katana_rate_limit,
                "gospider": gospider,
                "sitemap": sitemap,
                "extract_js": extract_js,
                "js_scan": js_scan,
                "use_cariddi": use_cariddi,
                "cariddi_depth": cariddi_depth,
                "cariddi_concurrency": cariddi_concurrency,
                "cariddi_delay": cariddi_delay,
                "cariddi_timeout": cariddi_timeout,
                "cariddi_secrets": cariddi_secrets,
                "cariddi_endpoints": cariddi_endpoints,
                "cariddi_extensions": cariddi_extensions,
                "cariddi_ignore_extensions": cariddi_ignore_extensions,
                "cariddi_plain": cariddi_plain,
            },
        }
        save_resume_state(output_dir, resume_state)

    if flow:
        with open(flow, "r") as f:
            config = yaml.safe_load(f)
        wayback = config.get("wayback", wayback)
        gau = config.get("gau", gau)
        katana = config.get("katana", katana)
        katana_depth = config.get("katana_depth", katana_depth)
        katana_js_crawl = config.get("katana_js_crawl", katana_js_crawl)
        katana_headless = config.get("katana_headless", katana_headless)
        katana_form_fill = config.get("katana_form_fill", katana_form_fill)
        katana_tech_detect = config.get("katana_tech_detect", katana_tech_detect)
        katana_scope = config.get("katana_scope", katana_scope)
        katana_concurrency = config.get("katana_concurrency", katana_concurrency)
        katana_rate_limit = config.get("katana_rate_limit", katana_rate_limit)
        gospider = config.get("gospider", gospider)
        sitemap = config.get("sitemap", sitemap)
        favicon = config.get("favicon", favicon)
        extract_js = config.get("extract_js", extract_js)
        js_scan = config.get("js_scan", js_scan)
        save_json = config.get("save_json", save_json)
        save_markdown = config.get("save_markdown", save_markdown)
        tag_only = config.get("tag_only", tag_only)
        dedupe = config.get("dedupe", dedupe)
        # Cariddi configuration from flow
        use_cariddi = config.get("use_cariddi", use_cariddi)
        cariddi_depth = config.get("cariddi_depth", cariddi_depth)
        cariddi_concurrency = config.get("cariddi_concurrency", cariddi_concurrency)
        cariddi_delay = config.get("cariddi_delay", cariddi_delay)
        cariddi_timeout = config.get("cariddi_timeout", cariddi_timeout)
        cariddi_secrets = config.get("cariddi_secrets", cariddi_secrets)
        cariddi_endpoints = config.get("cariddi_endpoints", cariddi_endpoints)
        cariddi_extensions = config.get("cariddi_extensions", cariddi_extensions)
        cariddi_ignore_extensions = config.get(
            "cariddi_ignore_extensions", cariddi_ignore_extensions
        )
        cariddi_plain = config.get("cariddi_plain", cariddi_plain)
        # Override timeout if specified in flow
        timeout = config.get("timeout", timeout)

    if verbose:
        click.echo("[+] 🚀 Starting URL discovery scan")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        if use_cariddi:
            click.echo("[+] 🕷️  Using Cariddi for advanced web crawling")
            click.echo(f"[+] 🎯 Cariddi depth: {cariddi_depth}")
            click.echo(f"[+] 🧵 Cariddi concurrency: {cariddi_concurrency}")
            if cariddi_secrets:
                click.echo("[+] 🕵️‍♂️ Cariddi secrets hunting: enabled")
            if cariddi_endpoints:
                click.echo("[+] 📂 Cariddi endpoint discovery: enabled")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        click.echo(f"[+] 🧵 Threads: {threads}")

    if from_subs_resolved:
        with open(input, "r") as f:
            targets = sorted(set([line.split()[0] for line in f if line.strip()]))
    else:
        with open(input, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    if verbose:
        target_info = f"single domain: {domain}" if domain else f"file: {input}"
        click.echo(f"[+] 📋 Loaded {len(targets)} target(s) from {target_info}")

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
                katana_depth,
                katana_js_crawl,
                katana_headless,
                katana_form_fill,
                katana_tech_detect,
                katana_scope,
                katana_concurrency,
                katana_rate_limit,
                gospider,
                sitemap,
                favicon,
                session,
                output_dir,
                timeout,
                retries,
                verbose,
                use_cariddi,
                cariddi_depth,
                cariddi_concurrency,
                cariddi_delay,
                cariddi_timeout,
                cariddi_secrets,
                cariddi_endpoints,
                cariddi_extensions,
                cariddi_ignore_extensions,
                cariddi_plain,
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
                click.echo("[+] 🏷️  Starting URL tagging...")

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
            click.echo("\n[!] ⏹️  Scan interrupted by user")
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
        click.echo("\n[+] 📊 Scan Summary:")
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
                    ("cariddi", use_cariddi),
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
                    click.echo("[+] ✅ Notifications sent successfully")
            elif (slack_webhook or discord_webhook) and verbose:
                click.echo("[!] ⚠️  Notification system not available")

        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Notification failed: {e}")

    click.echo("\n[+] ✅ URL discovery scan completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")
    if total_errors:
        click.echo(f"[!] ⚠️  {len(total_errors)} error(s) encountered during scan")

    # Database storage
    if store_db and all_tagged:
        try:
            from reconcli.db.operations import store_target, store_url_scan

            # Auto-detect target domain if not provided
            if not target_domain and all_tagged:
                # Try to extract domain from first URL
                first_url = all_tagged[0][0] if all_tagged else None
                if first_url:
                    from urllib.parse import urlparse

                    parsed = urlparse(first_url)
                    target_domain = parsed.netloc

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert URLs to database format
                url_scan_data = []
                for url, tags in all_tagged:
                    url_entry = {
                        "url": url,
                        "tags": tags,
                        "status_code": None,  # Could be enhanced to include HTTP status
                        "content_type": None,
                        "content_length": None,
                        "response_time": None,
                    }
                    url_scan_data.append(url_entry)

                # Store URLs in database
                stored_ids = store_url_scan(
                    target_domain,
                    url_scan_data,
                    tools_used=[
                        tool
                        for tool, enabled in [
                            ("wayback", wayback),
                            ("gau", gau),
                            ("katana", katana),
                            ("gospider", gospider),
                            ("sitemap", sitemap),
                            ("cariddi", use_cariddi),
                        ]
                        if enabled
                    ],
                )

                if verbose:
                    click.echo(
                        f"[+] 💾 Stored {len(stored_ids)} URLs in database for target: {target_domain}"
                    )
            else:
                if verbose:
                    click.echo(
                        "[!] ⚠️  No target domain provided or detected for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo("[!] ⚠️  Database module not available")
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Database storage failed: {e}")

    # Clean up temporary file if it was created by us
    if domain and input and is_our_temp_file:
        try:
            os.unlink(input)
            if verbose:
                click.echo("[+] 🧹 Cleaned up temporary file")
        except:
            pass


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
                click.echo("   Status: ✅ Completed")
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
                click.echo("   Status: ⏳ Incomplete")
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
    katana_depth,
    katana_js_crawl,
    katana_headless,
    katana_form_fill,
    katana_tech_detect,
    katana_scope,
    katana_concurrency,
    katana_rate_limit,
    gospider,
    sitemap,
    favicon,
    session,
    output_dir,
    timeout,
    retries,
    verbose,
    use_cariddi,
    cariddi_depth,
    cariddi_concurrency,
    cariddi_delay,
    cariddi_timeout,
    cariddi_secrets,
    cariddi_endpoints,
    cariddi_extensions,
    cariddi_ignore_extensions,
    cariddi_plain,
    store_db,
    target_domain,
    program,
):
    """Enhanced URL discovery with better error handling and progress tracking."""
    urls = set()
    errors = []

    if verbose:
        click.echo(f"[+] 🎯 Starting URL discovery for {domain}")

    # Build advanced Katana command with new options
    katana_cmd = None
    if katana:
        katana_cmd = [
            "katana",
            "-u",
            f"http://{domain}",
            "-timeout",
            str(timeout),
            "-d",
            str(katana_depth),
            "-c",
            str(katana_concurrency),
            "-rl",
            str(katana_rate_limit),
            "-silent",  # Reduce noise
        ]

        # Add optional features
        if katana_js_crawl:
            katana_cmd.extend(["-jc"])
            if verbose:
                click.echo("[+] 🟡 Katana: JavaScript crawling enabled")

        if katana_headless:
            katana_cmd.extend(["-hl"])
            if verbose:
                click.echo("[+] 🤖 Katana: Headless mode enabled")

        if katana_form_fill:
            katana_cmd.extend(["-aff"])
            if verbose:
                click.echo("[+] 📝 Katana: Automatic form filling enabled")

        if katana_tech_detect:
            katana_cmd.extend(["-td"])
            if verbose:
                click.echo("[+] 🔍 Katana: Technology detection enabled")

        if katana_scope:
            katana_cmd.extend(["-cs", katana_scope])
            if verbose:
                click.echo(f"[+] 🎯 Katana: Custom scope: {katana_scope}")

    # External tools with proper timeout configuration
    tools_config = [
        (wayback, ["waybackurls", domain], "waybackurls"),
        (gau, ["gau", "--timeout", str(timeout), domain], "gau"),
        (katana and katana_cmd, katana_cmd, "katana"),
        (
            gospider,
            ["gospider", "-s", f"http://{domain}", "-q", "-m", str(timeout)],
            "gospider",
        ),
    ]

    for enabled, cmd, tool_name in tools_config:
        if enabled and cmd:
            tool_urls, error = run_tool_with_retry(
                cmd, domain, tool_name, timeout, retries, verbose
            )
            if tool_urls:
                urls.update(tool_urls)
                if verbose and tool_name == "katana":
                    # Parse Katana JSON output if available
                    try:
                        katana_enhanced_output = parse_katana_output(tool_urls, verbose)
                        if katana_enhanced_output:
                            save_katana_analysis(
                                domain, katana_enhanced_output, output_dir
                            )
                    except Exception as e:
                        if verbose:
                            click.echo(f"[!] ⚠️  Katana analysis parsing failed: {e}")
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
                        h = hashlib.md5(resp.content, usedforsecurity=False).hexdigest()
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

    # Cariddi integration
    if use_cariddi:
        try:
            if verbose:
                click.echo(f"[+] 🕷️  Running Cariddi on {domain}")

            # Prepare Cariddi command
            cariddi_cmd = [
                "cariddi",
                "-md",
                str(cariddi_depth),
                "-c",
                str(cariddi_concurrency),
                "-d",
                str(cariddi_delay),
                "-t",
                str(cariddi_timeout),
            ]

            # Only add -plain if we're not using secrets or endpoints
            if not cariddi_secrets and not cariddi_endpoints:
                cariddi_cmd.append("-plain")

            if cariddi_secrets:
                cariddi_cmd.append("-s")
                if verbose:
                    click.echo("[+] 🕵️‍♂️ Cariddi: Secrets hunting enabled")

            if cariddi_endpoints:
                cariddi_cmd.append("-e")
                if verbose:
                    click.echo("[+] 📂 Cariddi: Endpoint discovery mode enabled")

            if cariddi_extensions:
                # Cariddi uses -ext with integer levels (1=juicy to 7=not juicy)
                cariddi_cmd.extend(["-ext", "2"])  # level 2 juicy extensions
                if verbose:
                    click.echo("[+] 📂 Cariddi: Hunting for juicy file extensions")

            if cariddi_ignore_extensions:
                cariddi_cmd.extend(["-ie", cariddi_ignore_extensions])
                if verbose:
                    click.echo(
                        f"[+] 🚫 Cariddi: Ignored extensions: {cariddi_ignore_extensions}"
                    )

            # Run Cariddi with domain URL as input
            target_urls = [f"http://{domain}", f"https://{domain}"]
            cariddi_urls = []

            for target_url in target_urls:
                try:
                    if verbose:
                        click.echo(f"[+] 🔍 Cariddi crawling: {target_url}")

                    import subprocess

                    process = subprocess.run(
                        cariddi_cmd,
                        input=target_url + "\n",
                        text=True,
                        capture_output=True,
                        timeout=cariddi_timeout
                        * 5,  # Allow more time for complete crawl
                    )

                    if process.returncode == 0 and process.stdout:
                        discovered_urls = [
                            url.strip()
                            for url in process.stdout.split("\n")
                            if url.strip()
                        ]
                        cariddi_urls.extend(discovered_urls)
                        if verbose and discovered_urls:
                            click.echo(
                                f"[+] ✅ Cariddi found {len(discovered_urls)} URLs from {target_url}"
                            )
                    else:
                        if verbose:
                            click.echo(
                                f"[!] ⚠️  Cariddi returncode: {process.returncode}"
                            )
                            if process.stdout:
                                click.echo(
                                    f"[!] 📤 Cariddi stdout: {process.stdout[:200]}"
                                )
                            if process.stderr:
                                click.echo(
                                    f"[!] 📥 Cariddi stderr: {process.stderr[:200]}"
                                )

                except subprocess.TimeoutExpired:
                    if verbose:
                        click.echo(f"[!] ⏰ Cariddi timeout for {target_url}")
                except Exception as e:
                    if verbose:
                        click.echo(f"[!] ❌ Cariddi error for {target_url}: {e}")

            if cariddi_urls:
                urls.update(cariddi_urls)
                if verbose:
                    click.echo(
                        f"[+] 🎯 Cariddi total: {len(cariddi_urls)} URLs discovered"
                    )

        except Exception as e:
            error = f"Cariddi integration failed: {str(e)}"
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


def parse_katana_output(tool_urls, verbose):
    """Parse Katana output for enhanced analysis."""
    try:
        analysis = {
            "total_urls": len(tool_urls),
            "unique_domains": set(),
            "file_extensions": {},
            "url_depths": {},
            "potential_apis": [],
            "forms_found": [],
            "technologies": [],
        }

        for url in tool_urls:
            try:
                parsed = urlparse(url)
                analysis["unique_domains"].add(parsed.netloc)

                # Analyze URL depth
                path_parts = parsed.path.strip("/").split("/")
                depth = len([p for p in path_parts if p])
                analysis["url_depths"][depth] = analysis["url_depths"].get(depth, 0) + 1

                # Extract file extensions
                if "." in parsed.path:
                    ext = parsed.path.split(".")[-1].lower()
                    if len(ext) <= 5:  # Reasonable extension length
                        analysis["file_extensions"][ext] = (
                            analysis["file_extensions"].get(ext, 0) + 1
                        )

                # Detect potential API endpoints
                if any(
                    api_indicator in url.lower()
                    for api_indicator in [
                        "/api/",
                        "/v1/",
                        "/v2/",
                        "/v3/",
                        "/rest/",
                        "/graphql",
                        ".json",
                        "/ajax",
                    ]
                ):
                    analysis["potential_apis"].append(url)

            except Exception:
                continue

        # Convert sets to lists for JSON serialization
        analysis["unique_domains"] = list(analysis["unique_domains"])

        if verbose:
            click.echo(
                f"[+] 📊 Katana analysis: {len(analysis['unique_domains'])} domains, {len(analysis['potential_apis'])} API endpoints"
            )

        return analysis

    except Exception as e:
        if verbose:
            click.echo(f"[!] ❌ Katana output parsing failed: {e}")
        return None


def save_katana_analysis(domain, analysis, output_dir):
    """Save enhanced Katana analysis to file."""
    try:
        analysis_file = os.path.join(output_dir, f"{domain}_katana_analysis.json")

        # Add timestamp and domain info
        enhanced_analysis = {
            "domain": domain,
            "scan_time": datetime.now().isoformat(),
            "analysis": analysis,
            "summary": {
                "total_urls_found": analysis.get("total_urls", 0),
                "unique_domains_discovered": len(analysis.get("unique_domains", [])),
                "potential_api_endpoints": len(analysis.get("potential_apis", [])),
                "top_file_extensions": dict(
                    sorted(
                        analysis.get("file_extensions", {}).items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:10]
                ),
                "url_depth_distribution": analysis.get("url_depths", {}),
            },
        }

        with open(analysis_file, "w") as f:
            json.dump(enhanced_analysis, f, indent=2)

        # Also save API endpoints separately for easy access
        if analysis.get("potential_apis"):
            api_file = os.path.join(output_dir, f"{domain}_potential_apis.txt")
            with open(api_file, "w") as f:
                for api_url in analysis["potential_apis"]:
                    f.write(api_url + "\n")

        return True

    except Exception:
        return False


def run_katana_with_json_output(
    domain, katana_cmd, timeout, retries, verbose, output_dir
):
    """Run Katana with JSON output for enhanced analysis."""
    try:
        # Modify command to include JSON output
        json_output_file = os.path.join(output_dir, f"{domain}_katana_raw.jsonl")
        enhanced_cmd = katana_cmd + ["-jsonl", "-o", json_output_file]

        if verbose:
            click.echo("[+] 🔧 Running enhanced Katana with JSON output")

        result = subprocess.run(
            enhanced_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Don't raise on non-zero exit
        )

        urls = []
        enhanced_data = []

        # Parse JSONL output if available
        if os.path.exists(json_output_file):
            try:
                with open(json_output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line.strip())
                                if "url" in data:
                                    urls.append(data["url"])
                                enhanced_data.append(data)
                            except json.JSONDecodeError:
                                continue

                if verbose:
                    click.echo(
                        f"[+] 📊 Katana JSON: {len(enhanced_data)} detailed records"
                    )

                # Save enhanced analysis
                if enhanced_data:
                    enhanced_file = os.path.join(
                        output_dir, f"{domain}_katana_enhanced.json"
                    )
                    with open(enhanced_file, "w") as f:
                        json.dump(
                            {
                                "domain": domain,
                                "scan_time": datetime.now().isoformat(),
                                "total_records": len(enhanced_data),
                                "records": enhanced_data,
                            },
                            f,
                            indent=2,
                        )

            except Exception as e:
                if verbose:
                    click.echo(f"[!] ⚠️  JSON parsing failed: {e}")

        # Fallback to stdout if JSON parsing failed
        if not urls and result.stdout:
            urls = result.stdout.splitlines()

        return urls, None

    except subprocess.TimeoutExpired:
        return [], f"Katana timeout after {timeout}s"
    except Exception as e:
        return [], f"Katana enhanced run failed: {str(e)}"


if __name__ == "__main__":
    main()
