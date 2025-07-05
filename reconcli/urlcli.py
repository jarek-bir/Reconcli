import json as json_module
import os
import json
import click
import subprocess
import hashlib
import requests
import urllib3
from reconcli.url_tagger import tag_urls
from reconcli.utils.loaders import dedupe_paths

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


def summarize_tags(output_dir):
    # Placeholder: tutaj możesz dodać zbieranie statystyk lub raportów z tagów
    pass


@click.command()
@click.option(
    "--input", required=True, help="File with resolved subdomains or plain list"
)
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
    smart_filter,  # <-- dodaj ten argument
    export_tag,
):

    global all_urls_global

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

    os.makedirs(output_dir, exist_ok=True)
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = verify_ssl

    resume_data = {}
    if resume and os.path.exists(resume_file):
        with open(resume_file, "r") as f:
            resume_data = json.load(f)

    all_tagged = []

    for domain in targets:
        if resume and resume_data.get(domain):
            print(f"[=] Skipping (resume): {domain}")
            continue

        print(f"[+] Scanning: {domain}")
        urls = set()

        try:
            if wayback:
                out = subprocess.check_output(
                    ["waybackurls", domain], text=True, timeout=3600
                )
                urls.update(out.splitlines())
            if gau:
                out = subprocess.check_output(["gau", domain], text=True, timeout=3600)
                urls.update(out.splitlines())
            if katana:
                out = subprocess.check_output(
                    ["katana", "-u", f"http://{domain}"], text=True, timeout=3600
                )
                urls.update(out.splitlines())
            if gospider:
                out = subprocess.check_output(
                    ["gospider", "-s", f"http://{domain}", "-q"],
                    text=True,
                    timeout=3600,
                )
                urls.update(out.splitlines())
            if sitemap:
                try:
                    resp = session.get(f"http://{domain}/sitemap.xml", timeout=120)
                    soup = BeautifulSoup(resp.content, "xml")
                    urls.update({loc.text for loc in soup.find_all("loc")})
                except Exception as e:
                    print(f"[!] sitemap failed: {e}")
            if favicon:
                try:
                    resp = session.get(f"http://{domain}/favicon.ico", timeout=120)
                    h = hashlib.md5(resp.content).hexdigest()
                    with open(os.path.join(output_dir, "favicon_hashes.txt"), "a") as f:
                        f.write(f"{domain} {h}\n")
                except Exception as e:
                    print(f"[!] favicon failed: {e}")
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout during subprocess for {domain}")

        urls = [
            u
            for u in urls
            if not any(
                u.lower().endswith(ext)
                for ext in [
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
            )
        ]

        if smart_filter:
            urls = [u for u in urls if urlparse(u).hostname not in CDN_HOST_BLACKLIST]
            urls = [
                u
                for u in urls
                if not u.startswith(("mailto:", "tel:", "javascript:"))
                and not u.strip().startswith("#")
            ]
        all_urls_global.update(urls)
        print(f"[*] URLs before tagging: {len(urls)}")

        tagged = tag_urls(list(urls))
        if tag_only:
            tagged = [t for t in tagged if t[1]]
        if dedupe:
            tagged = dedupe_paths(tagged)

        save_outputs(domain, tagged, output_dir, save_markdown, save_json)
        all_tagged.extend(tagged)  # <-- zbieraj wszystkie tagi

        if extract_js:
            js_urls = [u for u, _ in tagged if u.endswith(".js")]
            with open(os.path.join(output_dir, f"{domain}_js_urls.txt"), "w") as f:
                f.write("\n".join(js_urls))

        if js_scan:
            scan_js(domain, output_dir, session)

        if resume:
            resume_data[domain] = True
            with open(resume_file, "w") as f:
                json_module.dump(resume_data, f, indent=2)

        summarize_tags(output_dir, tagged)  # <-- poprawne wywołanie

    summarize_tags(output_dir, all_tagged)  # <-- poprawne wywołanie

    if export_tag:
        filtered = [t for t in all_tagged if export_tag in t[1]]
        with open(os.path.join(output_dir, f"{export_tag}_urls.txt"), "w") as f:
            for url, tags in filtered:
                f.write(url + "\n")

    try:
        with open(os.path.join(output_dir, "all_urls.txt"), "w") as f:
            for url in sorted(all_urls_global):
                f.write(url + "\n")
    except Exception as e:
        print(f"[!] Błąd zapisu all_urls.txt: {e}")

    print(f"\n[=] Skanowanie zakończone. Otagowano {len(all_tagged)} URL-i.")
    print(f"[=] Wyniki zapisano w katalogu: {output_dir}")


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


if __name__ == "__main__":
    main()
