import os
import re


def strip_ansi(text):
    """
    Remove ANSI escape sequences (color codes) from a string.
    """
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def generate_dns_summary(domain, resolved_results, output_dir):
    """
    Generate clean dns_summary.md file (no ANSI colors) for Obsidian.
    """
    summary_path = os.path.join(output_dir, "dns_summary.md")

    with open(summary_path, "w") as f:
        f.write(f"# DNS Summary Report\n\n")

        for entry in resolved_results:
            subdomain = strip_ansi(entry.get("subdomain", ""))
            ip = strip_ansi(entry.get("ip", ""))
            ptr = strip_ansi(entry.get("ptr", "None"))
            tags = ", ".join(entry.get("tags", [])) or "–"
            country = strip_ansi(entry.get("country", "None"))
            city = strip_ansi(entry.get("city", "None"))
            asn_raw = entry.get("asn", {})
            if isinstance(asn_raw, dict):
                asn = strip_ansi(asn_raw.get("asn", "-"))
            else:
                asn = strip_ansi(asn_raw)

            f.write(f"## {subdomain}\n")
            f.write(f"- IP: {ip}\n")
            f.write(f"- PTR: {ptr}\n")
            f.write(f"- Tags: {tags}\n")
            f.write(f"- Country: {country}, City: {city}\n")
            f.write(f"- ASN: {asn}\n\n")

    print(f"[+] Generated clean DNS summary: {summary_path}")
