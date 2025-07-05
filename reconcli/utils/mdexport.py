import re
import os


def strip_ansi(text):
    """
    Usuwa kody ANSI (kolory terminalowe) z tekstu
    """
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text or "")


def generate_dns_summary(domain, enriched_data, output_dir):
    """
    Generuje dns_summary.md na podstawie wzbogaconych danych
    """
    output_file = f"{output_dir}/dns_summary.md"
    with open(output_file, "w") as f:
        f.write(f"# DNS Summary for `{domain}`\n\n")
        f.write("| Subdomain | IP | PTR | ASN | Country | Org | City | Tags |\n")
        f.write("|-----------|----|-----|-----|---------|-----|------|------|\n")
        for entry in enriched_data:
            sub = strip_ansi(entry.get("domain", ""))
            ip = strip_ansi(entry.get("ip", ""))
            ptr = strip_ansi(entry.get("ptr") or "–")

            asn_raw = entry.get("asn", {})
            if isinstance(asn_raw, dict):
                asn = strip_ansi(asn_raw.get("asn", "–"))
            else:
                asn = strip_ansi(asn_raw or "–")

            country = strip_ansi(entry.get("country") or "–")
            org = strip_ansi(entry.get("org") or "–")
            city = strip_ansi(entry.get("city") or "–")
            tags = ", ".join(entry.get("tags", []))

            f.write(
                f"| `{sub}` | `{ip}` | `{ptr}` | `{asn}` | `{country}` | `{org}` | `{city}` | `{tags}` |\n"
            )
    print(f"[+] Markdown summary saved to {output_file}")


def export_zonewalk_report(domain, result, output_dir):
    """
    Eksportuje wynik zone walking jako markdown
    """
    output_file = os.path.join(output_dir, f"{domain}_zonewalk_report.md")
    with open(output_file, "w") as f:
        f.write(f"# Zone Walk Report for `{domain}`\n\n")

        if "error" in result:
            f.write(f"❌ **Error**: {result['error']}\n\n")
            return

        f.write(
            f"- ✅ Zone transfer: {'Yes' if result.get('zone_transfer_success') else 'No'}\n"
        )
        f.write(
            f"- 🔒 NSEC supported: {'Yes' if result.get('nsec_supported') else 'No'}\n"
        )
        f.write(
            f"- 🔐 NSEC3 supported: {'Yes' if result.get('nsec3_supported') else 'No'}\n"
        )
        f.write(
            f"- 🧭 Delegated subdomains: {', '.join(result.get('delegated_subs', [])) or 'None'}\n\n"
        )

        entries = result.get("zone_entries", [])
        if entries:
            f.write("## Zone Entries (from AXFR):\n")
            for entry in entries:
                f.write(f"- `{entry}`\n")
        else:
            f.write("_No zone entries discovered._\n")

    print(f"[+] Zonewalk markdown saved to {output_file}")
