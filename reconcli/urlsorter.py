import click
import os
import re
import yaml
import json
from datetime import datetime, timezone

DEFAULT_PATTERNS = {
    "xss": r"(?i)(script|onerror|alert|%3Cscript|<svg|xss=)",
    "lfi": r"(?i)(\.\./|\.\.\\\\|etc/passwd)",
    "ssrf": r"(?i)(http:\/\/127\.|localhost|internal)",
    "rce": r"(?i)(cmd=|exec|shell=|run=)",
    "redirect": r"(?i)(redirect=|url=|next=|target=)",
    "sqli": r"(?i)(union select|select .* from|or 1=1)",
    "bypass": r"(?i)(admin=true|is_admin|access=granted)",
    "token": r"(?i)(access_token|auth_token|jwt|bearer)",
    "callback": r"(?i)(callback=|return=|continue=)",
    "graphql": r"(?i)(graphql|graphiql|query=)",
    "sitemap": r"(?i)(sitemap\.xml|robots\.txt)",
}


@click.command()
@click.option(
    "-i", "--input", required=True, help="Input file with URLs (one per line)"
)
@click.option("-o", "--output-dir", required=True, help="Output directory")
@click.option("-p", "--patterns", help="Optional custom pattern file (YAML)")
@click.option("--json", "export_json", is_flag=True, help="Export summary to JSON")
@click.option("--markdown", is_flag=True, help="Export summary to Markdown")
def main(input, output_dir, patterns, export_json, markdown):
    os.makedirs(output_dir, exist_ok=True)

    # Load patterns
    if patterns:
        with open(patterns, "r") as f:
            pattern_dict = yaml.safe_load(f)
    else:
        pattern_dict = DEFAULT_PATTERNS

    with open(input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    matches = {k: [] for k in pattern_dict}
    for url in urls:
        for name, regex in pattern_dict.items():
            if re.search(regex, url):
                matches[name].append(url)

    for name, urls in matches.items():
        if urls:
            with open(os.path.join(output_dir, f"{name}.txt"), "w") as f:
                for url in urls:
                    f.write(url + "\n")

    stats = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_urls": len(urls),
        "categories": {name: len(urls) for name, urls in matches.items()},
    }

    if export_json:
        with open(os.path.join(output_dir, "urls_summary.json"), "w") as f:
            json.dump(stats, f, indent=2)

    if markdown:
        md_path = os.path.join(output_dir, "urls_summary.md")
        with open(md_path, "w") as f:
            f.write("# 🧪 URL Pattern Sorter Summary\n\n")
            f.write(f"- 📅 Time: {stats['timestamp']}\n")
            f.write(f"- 🌐 Total URLs: {stats['total_urls']}\n\n")
            for name, count in stats["categories"].items():
                f.write(f"- **{name.upper()}**: {count} matches\n")


# Allow use as subcommand
run_urlsort = main

if __name__ == "__main__":
    main()
