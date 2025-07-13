# updated httpcli.py with:
# - extract_security_headers() included
# - CSV export added as http_results.csv
# - retries support for unstable HTTP responses

import csv
import json
import subprocess
import tempfile
import time
from base64 import b64encode
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import click
import httpx
import mmh3
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
]

CDN_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "akamai": ["akamai", "akamaized.net"],
}


@click.command("httpcli")
@click.option(
    "--input",
    "-i",
    required=True,
    type=click.Path(exists=True),
    help="Path to URLs or hostnames",
)
@click.option("--timeout", default=10, help="Timeout for requests")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(),
    default="httpcli_output",
    help="Directory to save results",
)
@click.option("--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
@click.option("--markdown", is_flag=True, help="Export Markdown summary")
@click.option("--jsonout", is_flag=True, help="Export raw JSON results")
@click.option("--nuclei", is_flag=True, help="Run Nuclei on each URL")
@click.option("--nuclei-templates", type=click.Path(), help="Path to Nuclei templates")
@click.option(
    "--fastmode", is_flag=True, help="HEAD only mode (no full GET, no fingerprinting)"
)
@click.option("--log", is_flag=True, help="Log output to log.txt")
@click.option(
    "--export-tag",
    multiple=True,
    help="Export URLs by tag (e.g. cors-wildcard, no-csp, ok, client-error)",
)
@click.option(
    "--export-status", multiple=True, help="Export URLs by status code (e.g. 200, 403)"
)
@click.option(
    "--user-agent",
    default="Mozilla/5.0 (compatible; httpcli)",
    help="Custom User-Agent",
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
def httpcli(
    input,
    timeout,
    retries,
    output_dir,
    proxy,
    markdown,
    jsonout,
    nuclei,
    nuclei_templates,
    fastmode,
    log,
    export_tag,
    export_status,
    user_agent,
    store_db,
    target_domain,
    program,
):
    console.rule("[bold cyan]reconcli : httpcli module")
    raw_lines = [u.strip() for u in Path(input).read_text().splitlines() if u.strip()]
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    urls = []

    for line in raw_lines:
        hostname = line.split()[0]
        if hostname.startswith("http://") or hostname.startswith("https://"):
            urls.append(hostname)
        else:
            resolved = resolve_to_url(hostname, timeout=timeout, proxies=proxies)
            if resolved:
                urls.append(resolved)
            else:
                console.print(
                    f"[yellow]-[/yellow] {hostname} -> could not resolve as http(s)"
                )

    results = []
    log_lines = []

    headers_base = {"User-Agent": user_agent}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {
            executor.submit(
                process_url,
                url,
                retries,
                timeout,
                proxies,
                headers_base,
                fastmode,
                nuclei,
                nuclei_templates,
            ): url
            for url in urls
        }
        for future in as_completed(future_to_url):
            data = future.result()
            url = data["url"]
            if "error" not in data:
                console.print(
                    f"[green]+[/green] {url} -> {data.get('status_code')} | {data.get('title', '')}"
                )
                log_lines.append(
                    f"[+] {url} -> {data.get('status_code')} | {data.get('title', '')}"
                )
            else:
                console.print(f"[red]-[/red] {url} -> ERROR: {data['error']}")
                log_lines.append(f"[-] {url} -> ERROR: {data['error']}")
            results.append(data)

    if jsonout:
        with open(output_path / "http_results.json", "w") as f:
            json.dump(results, f, indent=2)

        with open(
            output_path / "http_results.csv", "w", newline="", encoding="utf-8"
        ) as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                [
                    "url",
                    "status_code",
                    "title",
                    "favicon_hash",
                    "cdn",
                    "cors",
                    "tags",
                    "error",
                    "response_time",  # Dodane pole
                    "supports_http2",  # Dodane pole w nagłówku
                ]
            )
            for r in results:
                writer.writerow(
                    [
                        r.get("url"),
                        r.get("status_code"),
                        r.get("title", ""),
                        r.get("favicon_hash", ""),
                        r.get("cdn", ""),
                        r.get("cors", ""),
                        ",".join(r.get("tags", [])),
                        r.get("error", ""),
                        r.get("response_time", ""),  # Dodane pole
                        r.get("supports_http2", ""),  # Dodane pole w wierszu
                    ]
                )

    if markdown:
        with open(output_path / "http_summary.md", "w") as f:
            f.write(f"# HTTP Summary Report\n\nGenerated: {datetime.now()}\n\n")
            for r in results:
                f.write(f"## [{r.get('url')}]({r.get('url')})\n")
                for key in [
                    "status_code",
                    "title",
                    "content_type",
                    "redirected",
                    "favicon_hash",
                    "cdn",
                    "allowed_methods",
                    "cors",
                    "response_time",  # Dodane pole
                    "supports_http2",  # Dodane pole
                ]:
                    if r.get(key):
                        f.write(f"- {key.replace('_', ' ').title()}: {r[key]}\n")
                if r.get("tags"):
                    f.write(f"- Tags: {', '.join(r['tags'])}\n")
                for h in SECURITY_HEADERS:
                    if h in r.get("security_headers", {}):
                        f.write(f"- {h}: {r['security_headers'][h]}\n")
                if r.get("nuclei"):
                    f.write("- Nuclei:\n")
                    for finding in r["nuclei"]:
                        f.write(f"  - {finding}\n")
                if r.get("error"):
                    f.write(f"- Error: {r['error']}\n")
                f.write("\n")

    if export_tag:
        for tag in export_tag:
            with open(output_path / f"tag_{tag}.txt", "w") as f:
                for r in results:
                    if tag in r.get("tags", []):
                        f.write(f"{r['url']}\n")

    if export_status:
        for code in export_status:
            with open(output_path / f"status_{code}.txt", "w") as f:
                for r in results:
                    if str(r.get("status_code")) == str(code):
                        f.write(f"{r['url']}\n")

    if log:
        with open(output_path / "log.txt", "w") as f:
            f.write("\n".join(log_lines))

    # Database storage
    if store_db and results:
        try:
            from reconcli.db.operations import store_http_scan, store_target

            # Auto-detect target domain if not provided
            if not target_domain and results:
                # Try to extract domain from first URL
                first_url = results[0].get("url") if results else None
                if first_url:
                    from urllib.parse import urlparse

                    parsed = urlparse(first_url)
                    target_domain = parsed.netloc

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert results to database format
                http_scan_data = []
                for result in results:
                    http_entry = {
                        "url": result.get("url"),
                        "status_code": result.get("status_code"),
                        "content_length": result.get("content_length", 0),
                        "content_type": result.get("content_type"),
                        "response_time": result.get("response_time", 0),
                        "title": result.get("title"),
                        "server": result.get("server"),
                        "technologies": result.get("technologies", []),
                        "headers": result.get("headers", {}),
                        "tags": result.get("tags", []),
                        "redirect_url": result.get("redirect_url"),
                        "favicon_hash": result.get("favicon_hash"),
                        "error": result.get("error"),
                    }
                    http_scan_data.append(http_entry)

                # Store HTTP scan in database
                stored_ids = store_http_scan(target_domain, http_scan_data)

                console.print(
                    f"[+] 💾 Stored {len(stored_ids)} HTTP scan results in database for target: {target_domain}"
                )
            else:
                console.print(
                    "[!] ⚠️  No target domain provided or detected for database storage"
                )

        except ImportError:
            console.print("[!] ⚠️  Database module not available")
        except Exception as e:
            console.print(f"[!] ❌ Database storage failed: {e}")

    tag_counter = Counter(tag for r in results for tag in r.get("tags", []))
    console.print("[bold]Podsumowanie tagów:[/bold]")
    for tag, count in tag_counter.most_common():
        console.print(f"{tag}: {count}")

    error_urls = [r for r in results if r.get("error")]
    if error_urls:
        console.print("[bold red]Błędy dla URL-i:[/bold red]")
        for r in error_urls:
            console.print(f"{r['url']}: {r['error']}")


def resolve_to_url(hostname, timeout=5, proxies=None):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{hostname}"
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=True, proxies=proxies, stream=True
            )
            return url
        except Exception as e:
            print(f"[debug] {url} -> {e}")
            continue
    return None


def extract_title(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title
        return title.string.strip() if title and title.string else ""
    except Exception:
        return ""


def extract_security_headers(headers):
    return {k: v for k, v in headers.items() if k in SECURITY_HEADERS}


def get_favicon_hash(url, proxies=None):
    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        r = requests.get(favicon_url, timeout=5, proxies=proxies)
        if r.status_code == 200:
            return str(mmh3.hash(b64encode(r.content)))
        else:
            return "not found"
    except Exception:
        return "error"


def detect_cdn(headers, url):
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    for cdn, indicators in CDN_SIGNATURES.items():
        for indicator in indicators:
            if any(indicator in k or indicator in v for k, v in lower_headers.items()):
                return cdn
    parsed = urlparse(url)
    if any(
        cdn in parsed.netloc for cdn in ["cloudfront", "akamai", "fastly", "edgecast"]
    ):
        return parsed.netloc
    return "none"


def run_nuclei(url, nuclei_templates=None):
    try:
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(url + "\n")
            f.flush()
            cmd = ["nuclei", "-u", f.name]
            if nuclei_templates:
                cmd += ["-t", nuclei_templates]
            result = subprocess.run(cmd, capture_output=True, text=True)
            findings = result.stdout.strip().splitlines()
            return findings
    except Exception as e:
        return [f"nuclei error: {e}"]


def run_wappalyzer(url):
    try:
        cmd = ["wappalyzer", url, "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout)
        except Exception:
            return result.stdout.strip()
    except Exception as e:
        return f"wappalyzer error: {e}"


def tag_http_result(data):
    tags = []
    code = data.get("status_code")
    if code == 200:
        tags.append("ok")
    if code in [403, 401]:
        tags.append("unauthorized")
    if code in [500, 502, 503]:
        tags.append("server-error")
    if code in [301, 302]:
        tags.append("redirect")
    if code == 404:
        tags.append("not-found")
    if code and 400 <= code < 500:
        tags.append("client-error")
    if code and 500 <= code < 600:
        tags.append("server-error")
    if data.get("cors") == "*":
        tags.append("cors-wildcard")
    if not data.get("security_headers"):
        tags.append("no-security-headers")
    if "Content-Security-Policy" not in data.get("security_headers", {}):
        tags.append("no-csp")
    return tags


def process_url(
    url, retries, timeout, proxies, headers_base, fastmode, nuclei, nuclei_templates
):
    data = {"url": url}
    attempt = 0
    while attempt <= retries:
        try:
            start = time.time()
            if fastmode:
                r = requests.head(
                    url,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=True,
                    headers=headers_base,
                )
                data["status_code"] = r.status_code
                data["headers"] = dict(r.headers)
                data["redirected"] = len(r.history) > 0
                data["tags"] = tag_http_result(data)
            else:
                r = requests.get(
                    url,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=True,
                    headers=headers_base,
                )
                headers = dict(r.headers)
                data.update(
                    {
                        "status_code": r.status_code,
                        "headers": headers,
                        "content_type": headers.get("Content-Type", ""),
                        "title": extract_title(r.text),
                        "redirected": len(r.history) > 0,
                        "security_headers": extract_security_headers(headers),
                        "cors": headers.get("Access-Control-Allow-Origin", "None"),
                        "favicon_hash": get_favicon_hash(url, proxies),
                        "cdn": detect_cdn(headers, url),
                        "wappalyzer": run_wappalyzer(url),
                        "supports_http2": detect_http2(url, proxies, timeout),  # Dodane
                        "tags": [],
                    }
                )
                try:
                    opt = requests.options(
                        url, timeout=timeout, proxies=proxies, headers=headers_base
                    )
                    data["allowed_methods"] = opt.headers.get("Allow", "Unknown")
                except:
                    data["allowed_methods"] = "Error"
                if nuclei:
                    data["nuclei"] = run_nuclei(url, nuclei_templates)
                    if data["nuclei"]:
                        data["tags"].append("nuclei-match")
                if data.get("favicon_hash") == "not found":
                    data["tags"].append("no-favicon")
                elif data.get("favicon_hash") == "error":
                    data["tags"].append("favicon-error")
                data["tags"] += tag_http_result(data)
            data["response_time"] = round(time.time() - start, 3)
            return data
        except Exception as e:
            attempt += 1
            data["error"] = str(e)
            if "Failed to resolve" in str(e):
                if "tags" not in data:
                    data["tags"] = []
                data["tags"].append("dead-dns")
            if attempt > retries:
                return data
            else:
                time.sleep(1)
                continue
    return data


def detect_http2(url, proxies=None, timeout=10):
    try:
        proxy = None
        if proxies and proxies.get("http"):
            proxy = proxies["http"]
        transport = httpx.HTTPTransport(http2=True)
        with httpx.Client(
            http2=True, proxies=proxy, timeout=timeout, transport=transport
        ) as client:
            r = client.get(url)
            return r.http_version == "HTTP/2"
    except Exception:
        return False


if __name__ == "__main__":
    httpcli()
