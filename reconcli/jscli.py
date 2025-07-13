import json as json_module
import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import click
import requests

# Database and AI imports
try:
    from reconcli.aicli import AIReconAssistant
    from reconcli.db.operations import store_js_findings, store_target
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
except ImportError:
    store_target = None
    store_js_findings = None
    AIReconAssistant = None

    # Fallback if utils not available
    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json_module.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json_module.dump(state, f, indent=2)

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
@click.option(
    "--engine",
    type=click.Choice(
        ["native", "jsluice", "jsleak", "subjs", "cariddi", "getjs", "mantra"]
    ),
    default="native",
    help="Engine to use for JS analysis (native, jsluice, jsleak, subjs, cariddi, getjs, mantra)",
)
@click.option("--store-db", is_flag=True, help="Store results in ReconCLI database")
@click.option(
    "--ai-mode", is_flag=True, help="Enable AI-powered analysis of JS findings"
)
@click.option(
    "--ai-model",
    default="gpt-3.5-turbo",
    help="AI model to use for analysis (default: gpt-3.5-turbo)",
)
@click.option(
    "--retry",
    type=int,
    default=3,
    help="Number of retries for failed requests (default: 3)",
)
@click.option(
    "--delay",
    type=float,
    default=0.0,
    help="Delay between requests in seconds (default: 0.0)",
)
@click.option(
    "--concurrency",
    type=int,
    default=10,
    help="Maximum concurrent requests (default: 10)",
)
@click.option("--target-domain", help="Primary target domain for database storage")
@click.option("--program", help="Bug bounty program name for database classification")
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
    engine,
    store_db,
    ai_mode,
    ai_model,
    retry,
    delay,
    concurrency,
    target_domain,
    program,
):
    """
    JavaScript Analysis CLI with multiple engines and advanced features.
    """
    # Handle show-resume flag
    if show_resume:
        show_resume_status(output_dir)
        return

    # Handle clear-resume flag
    if clear_resume_flag:
        clear_resume(output_dir)
        click.echo("[+] Resume state cleared")
        return

    # Input validation
    if not input:
        click.echo("❌ Error: --input is required")
        return

    # AI initialization
    ai_assistant = None
    if ai_mode and AIReconAssistant:
        try:
            ai_assistant = AIReconAssistant()
            if verbose:
                click.echo(f"🧠 AI mode enabled with model: {ai_model}")
        except Exception as e:
            click.echo(f"⚠️ AI initialization failed: {e}")
            ai_mode = False

    # Database setup
    if store_db and not store_target:
        click.echo("⚠️ Database functionality not available (missing dependencies)")
        store_db = False

    # Check engine availability
    if engine != "native":
        engine_binary = engine
        if engine == "getjs":
            engine_binary = "getJS"  # Correct case for getJS binary

        if not shutil.which(engine_binary):
            click.echo(f"❌ Error: {engine} is not installed or not in PATH")
            if engine == "jsluice":
                click.echo(
                    "💡 Install with: go install github.com/BishopFox/jsluice@latest"
                )
            elif engine == "jsleak":
                click.echo(
                    "💡 Install with: go install github.com/channyein1337/jsleak@latest"
                )
            elif engine == "subjs":
                click.echo("💡 Install with: go install github.com/lc/subjs@latest")
            elif engine == "cariddi":
                click.echo(
                    "💡 Install with: go install github.com/edoardottt/cariddi/cmd/cariddi@latest"
                )
            elif engine == "getjs":
                click.echo(
                    "💡 Install with: go install github.com/003random/getJS@latest"
                )
            elif engine == "mantra":
                click.echo(
                    "💡 Install with: go install github.com/MrEmpy/mantra@latest"
                )
            return

    os.makedirs(output_dir, exist_ok=True)
    raw_dir = Path(output_dir) / "raw"
    if save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)

    # Read input file
    try:
        with open(input) as f:
            js_urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        click.echo(f"❌ Error reading input file: {e}")
        return

    if verbose:
        click.echo(f"📝 Loaded {len(js_urls)} URLs from {input}")
        click.echo(f"🔧 Engine: {engine}")
        click.echo(f"⚡ Concurrency: {concurrency}")
        click.echo(f"⏱️ Timeout: {timeout}s")
        click.echo(f"🔄 Retries: {retry}")
        click.echo(f"⏲️ Delay: {delay}s")
        if proxy:
            click.echo(f"🔀 Proxy: {proxy}")
        if ai_mode:
            click.echo("🧠 AI analysis: enabled")
        if store_db:
            click.echo("💾 Database storage: enabled")

    # Initialize session
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; jscli)"})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = verify_ssl

    # Process based on engine
    if engine == "native":
        results = process_with_native_engine(
            js_urls,
            session,
            raw_dir,
            save_raw,
            only_with_findings,
            concurrency,
            timeout,
            retry,
            delay,
            verbose,
            progress,
        )
    else:
        results = process_with_external_engine(
            js_urls, engine, output_dir, proxy, timeout, verbose
        )

    # AI Analysis
    ai_analysis = None
    if ai_mode and ai_assistant and results:
        ai_analysis = analyze_js_with_ai(ai_assistant, results, ai_model, verbose)

    # Database storage
    if store_db and store_target and store_js_findings and results:
        try:
            target_domain_final = target_domain or "unknown"
            tid = store_target(target_domain_final, program=program)

            # Store JS findings
            js_entries = []
            for result in results:
                js_entries.append(
                    {
                        "url": result["url"],
                        "secrets_count": len(result.get("secrets", [])),
                        "endpoints_count": len(result.get("endpoints", [])),
                        "tags": ",".join(result.get("tags", [])),
                        "source": result.get("source", engine),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            if js_entries:
                store_js_findings(target_domain_final, js_entries)
                if verbose:
                    click.echo(f"💾 Stored {len(js_entries)} JS findings in database")

        except Exception as e:
            if verbose:
                click.echo(f"❌ Database storage error: {e}")

    # Calculate summary stats
    summary_stats = {
        "total": len(results),
        "with_findings": len(
            [r for r in results if r.get("secrets") or r.get("endpoints")]
        ),
        "secrets": sum(len(r.get("secrets", [])) for r in results),
        "endpoints": sum(len(r.get("endpoints", [])) for r in results),
    }

    timestamp = datetime.utcnow().isoformat() + "Z"

    # Save results in various formats
    if json:
        json_data = {
            "scan_info": {
                "engine": engine,
                "timestamp": timestamp,
                "total_urls": len(js_urls),
                "results_found": len(results),
                "concurrency": concurrency,
                "timeout": timeout,
                "retries": retry,
                "delay": delay,
            },
            "results": results,
            "ai_analysis": ai_analysis,
            "summary": summary_stats,
        }

        with open(Path(output_dir) / "js_findings.json", "w") as f:
            json_module.dump(json_data, f, indent=2)

    if markdown:
        with open(Path(output_dir) / "js_findings.md", "w") as f:
            f.write("# 🔍 JavaScript Analysis Results\n\n")
            f.write(f"**Generated:** {timestamp}  \n")
            f.write(f"**Engine:** {engine}  \n")
            f.write(f"**Total URLs:** {len(js_urls)}  \n")
            f.write(f"**Results Found:** {len(results)}  \n")
            f.write(f"**URLs with Findings:** {summary_stats['with_findings']}  \n")
            f.write(f"**Total Secrets:** {summary_stats['secrets']}  \n")
            f.write(f"**Total Endpoints:** {summary_stats['endpoints']}  \n")
            f.write("\n---\n\n")

            for entry in results:
                if (
                    not only_with_findings
                    or entry.get("secrets")
                    or entry.get("endpoints")
                ):
                    f.write(f"## 📄 {entry['url']}\n\n")

                    if entry.get("tags"):
                        f.write(f"**Tags:** `{', '.join(entry['tags'])}`  \n")
                    if entry.get("source"):
                        f.write(f"**Source:** `{entry['source']}`  \n")
                    if entry.get("size"):
                        f.write(f"**Size:** `{entry['size']} bytes`  \n")
                    f.write("\n")

                    if entry.get("endpoints"):
                        f.write("### 🔗 Endpoints\n\n")
                        for ep in entry["endpoints"]:
                            f.write(f"- `{ep}`\n")
                        f.write("\n")

                    if entry.get("secrets"):
                        f.write("### 🔑 Secrets/Keys\n\n")
                        for sec in entry["secrets"]:
                            f.write(f"- `{sec}`\n")
                        f.write("\n")

                    if entry.get("error"):
                        f.write(f"### ❌ Error\n\n`{entry['error']}`\n\n")

                    f.write("---\n\n")

            # Add AI analysis if available
            if ai_analysis:
                f.write("## 🧠 AI Analysis\n\n")
                f.write(f"```\n{ai_analysis}\n```\n\n")

        # Save summary report
        with open(Path(output_dir) / "js_summary.md", "w") as f:
            f.write("# 📊 JavaScript Scan Summary\n\n")
            f.write(f"**Generated:** {timestamp}  \n")
            f.write(f"**Engine:** {engine}  \n")
            f.write("**Scan Configuration:**\n")
            f.write(f"- Concurrency: {concurrency}\n")
            f.write(f"- Timeout: {timeout}s\n")
            f.write(f"- Retries: {retry}\n")
            f.write(f"- Delay: {delay}s\n")
            f.write("\n**Results:**\n")
            f.write(f"- Total URLs scanned: {summary_stats['total']}\n")
            f.write(f"- URLs with findings: {summary_stats['with_findings']}\n")
            f.write(f"- Total secrets found: {summary_stats['secrets']}\n")
            f.write(f"- Total endpoints found: {summary_stats['endpoints']}\n")

            if ai_analysis:
                f.write("\n**AI Analysis:** ✅ Completed\n")
            if store_db:
                f.write("**Database Storage:** ✅ Enabled\n")

    # Final summary
    click.echo("\n🏁 JavaScript analysis completed!")
    click.echo("📊 Summary:")
    click.echo(f"   • Total URLs processed: {summary_stats['total']}")
    click.echo(f"   • URLs with findings: {summary_stats['with_findings']}")
    click.echo(f"   • Secrets discovered: {summary_stats['secrets']}")
    click.echo(f"   • Endpoints discovered: {summary_stats['endpoints']}")

    if ai_analysis:
        click.echo("   • AI analysis: ✅ Completed")
    if store_db:
        click.echo("   • Database storage: ✅ Completed")

    click.echo(f"💾 Results saved to: {output_dir}/")

    return results


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
                click.echo("   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(f"   URLs processed: {scan_data.get('urls_processed', 0)}")
                click.echo(f"   Secrets found: {scan_data.get('secrets_found', 0)}")
            else:
                click.echo("   Status: ⏳ Incomplete")
                click.echo(f"   URLs processed: {scan_data.get('urls_processed', 0)}")
                if scan_data.get("last_error"):
                    click.echo(f"   Last Error: {scan_data.get('last_error')}")

            click.echo()


def process_with_native_engine(
    js_urls,
    session,
    raw_dir,
    save_raw,
    only_with_findings,
    concurrency,
    timeout,
    retry,
    delay,
    verbose,
    progress,
):
    """Process JS URLs using native Python engine."""
    results = []
    stats = ThreadSafeStats()

    if verbose:
        click.echo("🚀 Starting native engine analysis...")

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_url = {
            executor.submit(
                fetch_js_content,
                url,
                session,
                stats,
                save_raw,
                raw_dir,
                verbose,
                timeout,
                retry,
                delay,
            ): url
            for url in js_urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings = future.result()
                if findings and (
                    not only_with_findings
                    or findings.get("secrets")
                    or findings.get("endpoints")
                ):
                    results.append(findings)

                if progress and len(results) % 10 == 0:
                    current_stats = stats.get_stats()
                    click.echo(
                        f"📊 Progress: {current_stats['total']} processed, {current_stats['with_findings']} with findings"
                    )

            except Exception as e:
                if verbose:
                    click.echo(f"❌ Error processing {url}: {e}")
                stats.increment(errors=1)

    return results


def process_with_external_engine(js_urls, engine, output_dir, proxy, timeout, verbose):
    """Process JS URLs using external tools."""
    results = []

    # Create input file for external tool
    urls_file = os.path.join(output_dir, f"{engine}_input.txt")
    with open(urls_file, "w") as f:
        for url in js_urls:
            f.write(f"{url}\n")

    if engine == "jsluice":
        results = run_jsluice(urls_file, output_dir, proxy, timeout, verbose)
    elif engine == "jsleak":
        results = run_jsleak(urls_file, output_dir, proxy, timeout, verbose)
    elif engine == "subjs":
        results = run_subjs(urls_file, output_dir, proxy, timeout, verbose)
    elif engine == "cariddi":
        results = run_cariddi(urls_file, output_dir, proxy, timeout, verbose)
    elif engine == "getjs":
        results = run_getjs(urls_file, output_dir, proxy, timeout, verbose)
    elif engine == "mantra":
        results = run_mantra(urls_file, output_dir, proxy, timeout, verbose)

    return results


def run_jsluice(urls_file, output_dir, proxy, timeout, verbose):
    """Run JSLuice tool for JS analysis."""
    results = []

    # JSLuice expects URLs as command line arguments, not from file
    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        return results

    # Run JSLuice urls mode first
    cmd = ["jsluice", "urls"] + urls

    if verbose:
        click.echo(
            f"🚀 Running JSLuice URLs: {' '.join(cmd[:3])}... ({len(urls)} URLs)"
        )

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            urls_output = result.stdout.strip()
            if verbose:
                click.echo("✅ JSLuice URLs completed successfully")
        else:
            if verbose:
                click.echo(f"❌ JSLuice URLs failed: {result.stderr}")
            urls_output = ""
    except subprocess.TimeoutExpired:
        if verbose:
            click.echo(f"⏰ JSLuice URLs timed out after {timeout}s")
        urls_output = ""
    except FileNotFoundError:
        click.echo(
            "❌ JSLuice not found. Install with: go install github.com/BishopFox/jsluice@latest"
        )
        return results
    except Exception as e:
        if verbose:
            click.echo(f"❌ JSLuice URLs error: {e}")
        urls_output = ""

    # Run JSLuice secrets mode
    cmd_secrets = ["jsluice", "secrets"] + urls
    if verbose:
        click.echo(
            f"🚀 Running JSLuice Secrets: {' '.join(cmd_secrets[:3])}... ({len(urls)} URLs)"
        )

    try:
        result_secrets = subprocess.run(
            cmd_secrets, capture_output=True, text=True, timeout=timeout
        )
        if result_secrets.returncode == 0:
            secrets_output = result_secrets.stdout.strip()
            if verbose:
                click.echo("✅ JSLuice Secrets completed successfully")
        else:
            if verbose:
                click.echo(f"❌ JSLuice Secrets failed: {result_secrets.stderr}")
            secrets_output = ""
    except subprocess.TimeoutExpired:
        if verbose:
            click.echo(f"⏰ JSLuice Secrets timed out after {timeout}s")
        secrets_output = ""
    except Exception as e:
        if verbose:
            click.echo(f"❌ JSLuice Secrets error: {e}")
        secrets_output = ""

    # Process results for each URL
    for url in urls:
        url_endpoints = []
        url_secrets = []

        # Parse URLs output (simple line-by-line)
        if urls_output:
            for line in urls_output.split("\n"):
                line = line.strip()
                if line and line.startswith("/"):
                    url_endpoints.append(line)

        # Parse secrets output (simple line-by-line)
        if secrets_output:
            for line in secrets_output.split("\n"):
                line = line.strip()
                if line and not line.startswith("/"):
                    url_secrets.append(line)

        if url_endpoints or url_secrets:
            results.append(
                {
                    "url": url,
                    "endpoints": url_endpoints,
                    "secrets": url_secrets,
                    "tags": ["jsluice"],
                    "source": "jsluice",
                    "size": 0,
                    "status_code": 200,
                }
            )

    return results


def run_jsleak(urls_file, output_dir, proxy, timeout, verbose):
    """Run JSLeak tool for JS analysis."""
    results = []
    output_file = os.path.join(output_dir, "jsleak_output.txt")

    cmd = ["jsleak", "-l", urls_file, "-o", output_file]
    if proxy:
        cmd += ["-p", proxy]
    if timeout:
        cmd += ["-t", str(timeout)]

    if verbose:
        click.echo(f"🚀 Running JSLeak: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if verbose:
            click.echo("✅ JSLeak completed successfully")

        # Parse JSLeak output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            item = json_module.loads(line.strip())
                            results.append(
                                {
                                    "url": item.get("url", ""),
                                    "endpoints": item.get("endpoints", []),
                                    "secrets": item.get("secrets", []),
                                    "tags": ["jsleak"],
                                    "source": "jsleak",
                                }
                            )
                        except json_module.JSONDecodeError:
                            continue

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ JSLeak failed: {e.stderr}")
    except FileNotFoundError:
        click.echo(
            "❌ JSLeak not found. Install with: go install github.com/channyein1337/jsleak@latest"
        )

    return results


def run_subjs(urls_file, output_dir, proxy, timeout, verbose):
    """Run SubJS tool for JS analysis."""
    results = []

    cmd = ["subjs", "-l", urls_file]
    if proxy:
        cmd += ["-p", proxy]
    if timeout:
        cmd += ["-t", str(timeout)]

    if verbose:
        click.echo(f"🚀 Running SubJS: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if verbose:
            click.echo("✅ SubJS completed successfully")

        # Parse SubJS output (URLs only)
        for line in result.stdout.split("\n"):
            if line.strip():
                results.append(
                    {
                        "url": line.strip(),
                        "endpoints": [],
                        "secrets": [],
                        "tags": ["subjs"],
                        "source": "subjs",
                    }
                )

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ SubJS failed: {e.stderr}")
    except FileNotFoundError:
        click.echo(
            "❌ SubJS not found. Install with: go install github.com/lc/subjs@latest"
        )

    return results


def run_cariddi(urls_file, output_dir, proxy, timeout, verbose):
    """Run Cariddi tool for JS analysis."""
    results = []
    output_file = os.path.join(output_dir, "cariddi_output.txt")

    cmd = ["cariddi", "-l", urls_file, "-o", output_file, "-s"]
    if proxy:
        cmd += ["-proxy", proxy]
    if timeout:
        cmd += ["-t", str(timeout)]

    if verbose:
        click.echo(f"🚀 Running Cariddi: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if verbose:
            click.echo("✅ Cariddi completed successfully")

        # Parse Cariddi output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                endpoints = []
                secrets = []
                for line in f:
                    line = line.strip()
                    if line.startswith("/"):
                        endpoints.append(line)
                    elif "api" in line.lower() or "key" in line.lower():
                        secrets.append(line)

                if endpoints or secrets:
                    results.append(
                        {
                            "url": "cariddi_scan",
                            "endpoints": endpoints,
                            "secrets": secrets,
                            "tags": ["cariddi"],
                            "source": "cariddi",
                        }
                    )

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Cariddi failed: {e.stderr}")
    except FileNotFoundError:
        click.echo(
            "❌ Cariddi not found. Install with: go install github.com/edoardottt/cariddi/cmd/cariddi@latest"
        )

    return results


def run_getjs(urls_file, output_dir, proxy, timeout, verbose):
    """Run GetJS tool for JS analysis."""
    results = []
    output_file = os.path.join(output_dir, "getjs_output.txt")

    cmd = ["getJS", "-input", urls_file, "-output", output_file]
    if timeout:
        cmd += ["-timeout", f"{timeout}s"]
    cmd += ["-verbose"] if verbose else []

    if verbose:
        click.echo(f"🚀 Running GetJS: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if verbose:
            click.echo("✅ GetJS completed successfully")

        # Parse GetJS output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if line.strip() and line.strip().startswith("http"):
                        results.append(
                            {
                                "url": line.strip(),
                                "endpoints": [],
                                "secrets": [],
                                "tags": ["getjs"],
                                "source": "getjs",
                                "size": 0,
                                "status_code": 200,
                            }
                        )

    except subprocess.CalledProcessError as e:
        if verbose:
            click.echo(f"❌ GetJS failed: {e.stderr}")
    except FileNotFoundError:
        click.echo(
            "❌ GetJS not found. Install with: go install github.com/003random/getJS@latest"
        )

    return results


def run_mantra(urls_file, output_dir, proxy, timeout, verbose):
    """Run Mantra tool for JS analysis."""
    results = []
    output_file = os.path.join(output_dir, "mantra_output.txt")

    # Mantra reads URLs from stdin
    cmd = ["mantra"]
    if verbose:
        cmd += ["-d"]  # detailed output
    else:
        cmd += ["-s"]  # silent mode

    if verbose:
        click.echo(f"🚀 Running Mantra: {' '.join(cmd)}")

    try:
        with open(urls_file, "r") as f:
            urls_content = f.read()

        result = subprocess.run(
            cmd, input=urls_content, capture_output=True, text=True, check=True
        )

        if verbose:
            click.echo("✅ Mantra completed successfully")

        # Save output to file
        with open(output_file, "w") as f:
            f.write(result.stdout)

        # Parse Mantra output - it returns endpoints and secrets directly
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("█") and not line.startswith("["):
                # Skip banner lines
                if line.startswith("http") or line.startswith("/"):
                    results.append(
                        {
                            "url": "mantra_scan",
                            "endpoints": [line] if line.startswith("/") else [],
                            "secrets": (
                                [line]
                                if not line.startswith("/")
                                and not line.startswith("http")
                                else []
                            ),
                            "tags": ["mantra"],
                            "source": "mantra",
                            "size": 0,
                            "status_code": 200,
                        }
                    )

    except subprocess.CalledProcessError as e:
        if verbose:
            click.echo(f"❌ Mantra failed: {e.stderr}")
    except FileNotFoundError:
        click.echo(
            "❌ Mantra not found. Install with: go install github.com/MrEmpy/mantra@latest"
        )

    return results


def analyze_js_with_ai(ai_assistant, results, ai_model, verbose):
    """Analyze JS findings using AI."""
    if not ai_assistant or not results:
        return None

    try:
        # Prepare data for AI analysis
        total_secrets = sum(len(r.get("secrets", [])) for r in results)
        total_endpoints = sum(len(r.get("endpoints", [])) for r in results)

        sample_findings = {
            "total_files": len(results),
            "total_secrets": total_secrets,
            "total_endpoints": total_endpoints,
            "sample_secrets": [s for r in results[:5] for s in r.get("secrets", [])],
            "sample_endpoints": [
                e for r in results[:5] for e in r.get("endpoints", [])
            ],
            "common_patterns": list(
                set([tag for r in results for tag in r.get("tags", [])])
            ),
        }

        prompt = f"""
        Analyze these JavaScript scan results:

        {json_module.dumps(sample_findings, indent=2)}

        Please provide:
        1. Security assessment of discovered secrets and endpoints
        2. Risk level classification
        3. Recommendations for further investigation
        4. Potential attack vectors based on findings
        5. Priority areas for manual review
        """

        if verbose:
            click.echo(f"🧠 Analyzing {len(results)} JS files with AI...")

        response = ai_assistant.ask_ai(prompt)
        return response

    except Exception as e:
        if verbose:
            click.echo(f"⚠️ AI analysis failed: {e}")
        return None


def fetch_js_content(
    url, session, stats, save_raw, raw_dir, verbose, timeout, retry, delay
):
    """Enhanced fetch function with retry logic and delay."""
    for attempt in range(retry + 1):
        try:
            if verbose and attempt > 0:
                click.echo(f"🔄 Retry {attempt}/{retry} for {url}")

            if delay > 0:
                time.sleep(delay)

            r = session.get(url, timeout=timeout)
            content = r.text

            if save_raw:
                parsed = urlparse(url)
                filename = parsed.netloc.replace(":", "_") + parsed.path.replace(
                    "/", "_"
                )
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
            if attempt == retry:
                if verbose:
                    click.echo(f"❌ Final timeout for {url}")
                stats.increment(errors=1)
                return {
                    "url": url,
                    "error": "timeout",
                    "endpoints": [],
                    "secrets": [],
                    "tags": [],
                }
        except requests.exceptions.RequestException as e:
            if attempt == retry:
                if verbose:
                    click.echo(f"❌ Final request error for {url}: {e}")
                stats.increment(errors=1)
                return {
                    "url": url,
                    "error": str(e),
                    "endpoints": [],
                    "secrets": [],
                    "tags": [],
                }
        except Exception as e:
            if attempt == retry:
                if verbose:
                    click.echo(f"❌ Final error for {url}: {e}")
                stats.increment(errors=1)
                return {
                    "url": url,
                    "error": str(e),
                    "endpoints": [],
                    "secrets": [],
                    "tags": [],
                }

    return {
        "url": url,
        "error": "max_retries_exceeded",
        "endpoints": [],
        "secrets": [],
        "tags": [],
    }


if __name__ == "__main__":
    main()
