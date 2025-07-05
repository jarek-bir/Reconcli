import os
import re
import json
import click
import requests
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys

# Import resume utilities
try:
    from reconcli.utils.resume import load_resume, save_resume_state, clear_resume
except ImportError:
    # Fallback if utils not available
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


# Heurystyki wykrywania sekretów w JS
SECRET_PATTERNS = {
    "api_key": r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][a-z0-9\-_]{16,}[\"']",
    "secret": r"(?i)secret[\"']?\s*[:=]\s*[\"'][a-z0-9\-_]{16,}[\"']",
    "token": r"(?i)token[\"']?\s*[:=]\s*[\"'][a-z0-9\-_]{16,}[\"']",
    "auth": r"(?i)auth[\"']?\s*[:=]\s*[\"'][a-z0-9\-_]{16,}[\"']",
    "bearer": r"(?i)bearer\s+[a-z0-9\-_]{16,}",
    "aws_key": r"(?i)aws[_-]?(?:access[_-]?)?key[_-]?id[\"']?\s*[:=]\s*[\"'][A-Z0-9]{20}[\"']",
    "aws_secret": r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']",
    "github_token": r"(?i)github[_-]?token[\"']?\s*[:=]\s*[\"']ghp_[A-Za-z0-9]{36}[\"']",
    "slack_token": r"(?i)slack[_-]?token[\"']?\s*[:=]\s*[\"']xox[bpoa]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}[\"']",
    "private_key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
}

ENDPOINT_REGEX = re.compile(r'["\'](/[^"\'#<>\s]+)["\']')
EXTENSION_TAGS = [".php", ".asp", ".jsp", ".aspx", ".py", ".rb", ".go", ".cgi"]


# Thread-safe statistics
class ThreadSafeStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.with_findings = 0
        self.secrets = 0
        self.endpoints = 0
        self.errors = 0
        self.processed_urls = set()

    def increment(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, getattr(self, key) + value)

    def add_processed_url(self, url):
        with self._lock:
            self.processed_urls.add(url)

    def is_processed(self, url):
        with self._lock:
            return url in self.processed_urls

    def get_stats(self):
        with self._lock:
            return {
                "total": self.total,
                "with_findings": self.with_findings,
                "secrets": self.secrets,
                "endpoints": self.endpoints,
                "errors": self.errors,
            }


@click.command()
@click.option("--input", "-i", required=False, help="File with JS URLs (one per line)")
@click.option("--output-dir", "-o", default="js_output", help="Directory for results")
@click.option("--json", is_flag=True, help="Save results as JSON")
@click.option("--markdown", is_flag=True, help="Save results as Markdown")
@click.option(
    "--proxy", default=None, help="Proxy for requests (http://127.0.0.1:8080)"
)
@click.option(
    "--verify-ssl/--no-verify-ssl", default=True, help="Verify SSL certificates"
)
@click.option("--save-raw", is_flag=True, help="Save raw JS files to disk")
@click.option(
    "--only-with-findings", is_flag=True, help="Only save results with findings"
)
@click.option("--threads", "-t", default=10, help="Number of concurrent threads")
@click.option("--timeout", default=20, help="Request timeout in seconds")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--resume", is_flag=True, help="Resume previous JS scan")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state",
)
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option("--progress", is_flag=True, help="Show progress bar")
def main(
    input,
    output_dir,
    json,
    markdown,
    proxy,
    verify_ssl,
    save_raw,
    only_with_findings,
    threads,
    timeout,
    verbose,
    resume,
    clear_resume_flag,
    show_resume,
    progress,
):
    os.makedirs(output_dir, exist_ok=True)
    raw_dir = Path(output_dir) / "raw"
    if save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; jscli)"})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = verify_ssl

    with open(input) as f:
        js_urls = [line.strip() for line in f if line.strip()]

    results = []
    summary_stats = {"total": 0, "with_findings": 0, "secrets": 0, "endpoints": 0}

    # Load resume state if available
    resume_state = load_resume(output_dir)
    if resume_state and "last_url" in resume_state:
        start_index = next(
            (i for i, url in enumerate(js_urls) if url == resume_state["last_url"]), 0
        )
    else:
        start_index = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(
                fetch_js,
                url,
                session,
                raw_dir,
                save_raw,
                only_with_findings,
                resume_state,
            ): url
            for url in js_urls[start_index:]
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings, stats = future.result()
                results.append(findings)
                summary_stats["total"] += 1
                if findings["secrets"] or findings["endpoints"]:
                    summary_stats["with_findings"] += 1
                    summary_stats["secrets"] += len(findings["secrets"])
                    summary_stats["endpoints"] += len(findings["endpoints"])
            except Exception as e:
                print(f"[!] Error fetching {url}: {e}")

    # Save resume state
    if summary_stats["total"] > 0:
        save_resume_state(
            output_dir, {"last_url": js_urls[start_index + summary_stats["total"] - 1]}
        )

    timestamp = datetime.utcnow().isoformat() + "Z"

    if json:
        with open(Path(output_dir) / "js_findings.json", "w") as f:
            json.dump(results, f, indent=2)

    if markdown:
        with open(Path(output_dir) / "js_findings.md", "w") as f:
            f.write(f"# JS Findings\n\nGenerated: {timestamp}\n\n")
            for entry in results:
                f.write(f"## {entry['url']}\n")
                if entry["tags"]:
                    f.write(f"Tags: `{', '.join(entry['tags'])}`\n\n")
                if entry["endpoints"]:
                    f.write("**Endpoints:**\n")
                    for ep in entry["endpoints"]:
                        f.write(f"- `{ep}`\n")
                if entry["secrets"]:
                    f.write("\n**Secrets/Keys:**\n")
                    for sec in entry["secrets"]:
                        f.write(f"- `{sec}`\n")
                f.write("\n")

        with open(Path(output_dir) / "js_summary.md", "w") as f:
            f.write(f"# JS Scan Summary\n\nGenerated: {timestamp}\n\n")
            f.write(f"- Total URLs scanned: {summary_stats['total']}\n")
            f.write(f"- URLs with findings: {summary_stats['with_findings']}\n")
            f.write(f"- Total secrets found: {summary_stats['secrets']}\n")
            f.write(f"- Total endpoints found: {summary_stats['endpoints']}\n")

    print(
        f"[+] Done. {summary_stats['with_findings']} URLs with findings saved to {output_dir}"
    )


def show_resume_status(output_dir):
    """Show status of previous JS scans from resume file."""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous JS scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        if scan_key.startswith("js_"):
            click.echo(f"🔍 Scan: {scan_key}")
            click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")
            click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

            if scan_data.get("completed"):
                click.echo(f"   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(f"   URLs processed: {scan_data.get('urls_processed', 0)}")
                click.echo(f"   Secrets found: {scan_data.get('secrets_found', 0)}")
            else:
                click.echo(f"   Status: ⏳ Incomplete")
                click.echo(f"   URLs processed: {scan_data.get('urls_processed', 0)}")
                if scan_data.get("last_error"):
                    click.echo(f"   Last Error: {scan_data.get('last_error')}")

            click.echo()


def fetch_js_content(url, session, stats, save_raw, raw_dir, verbose, timeout):
    """Fetch and analyze single JS file."""
    try:
        if verbose:
            click.echo(f"[+] Fetching {url}")

        r = session.get(url, timeout=timeout)
        content = r.text

        if save_raw:
            parsed = urlparse(url)
            filename = parsed.netloc.replace(":", "_") + parsed.path.replace("/", "_")
            if not filename.endswith(".js"):
                filename += ".js"
            with open(raw_dir / filename, "w", encoding="utf-8") as rf:
                rf.write(content)

        findings = {
            "url": url,
            "endpoints": list(set(ENDPOINT_REGEX.findall(content))),
            "secrets": [],
            "tags": [],
            "size": len(content),
            "status_code": r.status_code,
        }

        # Search for secrets
        for tag, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings["secrets"].extend(matches)
                findings["tags"].append(tag)

        # Tag endpoints by extension
        for ep in findings["endpoints"]:
            for ext in EXTENSION_TAGS:
                if ep.endswith(ext) and ext[1:] not in findings["tags"]:
                    findings["tags"].append(ext[1:])

        # Update stats
        stats.increment(total=1)
        if findings["secrets"] or findings["endpoints"]:
            stats.increment(
                with_findings=1,
                secrets=len(findings["secrets"]),
                endpoints=len(findings["endpoints"]),
            )

        stats.add_processed_url(url)
        return findings

    except requests.exceptions.Timeout:
        if verbose:
            click.echo(f"[!] Timeout fetching {url}")
        stats.increment(errors=1)
        return {
            "url": url,
            "error": "timeout",
            "endpoints": [],
            "secrets": [],
            "tags": [],
        }
    except requests.exceptions.RequestException as e:
        if verbose:
            click.echo(f"[!] Request error fetching {url}: {e}")
        stats.increment(errors=1)
        return {"url": url, "error": str(e), "endpoints": [], "secrets": [], "tags": []}
    except Exception as e:
        if verbose:
            click.echo(f"[!] Error fetching {url}: {e}")
        stats.increment(errors=1)
        return {"url": url, "error": str(e), "endpoints": [], "secrets": [], "tags": []}


def fetch_js(url, session, raw_dir, save_raw, only_with_findings, resume_state):
    print(f"[+] Fetching {url}")
    content = ""
    findings = {"url": url, "endpoints": [], "secrets": [], "tags": []}

    try:
        r = session.get(url, timeout=20)
        content = r.text

        if save_raw:
            parsed = urlparse(url)
            filename = parsed.netloc.replace(":", "_") + parsed.path.replace("/", "_")
            if not filename.endswith(".js"):
                filename += ".js"
            with open(raw_dir / filename, "w", encoding="utf-8") as rf:
                rf.write(content)

        findings["endpoints"] = list(set(ENDPOINT_REGEX.findall(content)))

        for tag, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings["secrets"].extend(matches)
                findings["tags"].append(tag)

        for ep in findings["endpoints"]:
            for ext in EXTENSION_TAGS:
                if ep.endswith(ext) and ext[1:] not in findings["tags"]:
                    findings["tags"].append(ext[1:])

    except Exception as e:
        print(f"[!] Error processing {url}: {e}")

    return findings, {
        "secrets": len(findings["secrets"]),
        "endpoints": len(findings["endpoints"]),
    }


if __name__ == "__main__":
    main()
