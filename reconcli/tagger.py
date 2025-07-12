import json
import re
import click
import socket
import ipaddress
import urllib.parse
import os
import subprocess
from datetime import datetime


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def load_resolved(input_file):
    results = []
    with open(input_file, "r") as f:
        for line in f:
            line = strip_ansi(line.strip())
            if not line or " " not in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                subdomain = parts[0]
                ip = parts[-1].strip("[]")
                results.append({"domain": subdomain, "ip": ip, "tags": []})
    return results


def auto_tag(entry):
    """Enhanced auto-tagging with comprehensive patterns"""
    domain = entry["domain"]
    ip = entry.get("ip", "")
    tags = []
    confidence_scores = {}

    # Infrastructure & CDN
    if any(
        t in domain.lower()
        for t in ["cdn", "cloudfront", "akamai", "fastly", "cloudflare", "maxcdn"]
    ):
        tags.append("cdn")
        confidence_scores["cdn"] = 0.9

    # Mail services
    if any(
        t in domain.lower()
        for t in ["mail", "smtp", "imap", "pop", "mx", "webmail", "exchange"]
    ):
        tags.append("mail")
        confidence_scores["mail"] = 0.85

    # Development & Testing
    if any(
        t in domain.lower()
        for t in ["dev", "test", "staging", "stage", "qa", "uat", "beta", "alpha"]
    ):
        tags.append("development")
        confidence_scores["development"] = 0.8

    # Administration
    if any(
        t in domain.lower()
        for t in ["admin", "panel", "control", "manage", "cpanel", "plesk", "dashboard"]
    ):
        tags.append("admin")
        confidence_scores["admin"] = 0.85

    # API & Services
    if any(
        t in domain.lower()
        for t in ["api", "rest", "graphql", "service", "ws", "webhook"]
    ):
        tags.append("api")
        confidence_scores["api"] = 0.8

    # Database services
    if any(
        t in domain.lower()
        for t in ["db", "database", "mysql", "postgres", "mongo", "redis", "elastic"]
    ):
        tags.append("database")
        confidence_scores["database"] = 0.9

    # Monitoring & Analytics
    if any(
        t in domain.lower()
        for t in ["monitor", "metrics", "analytics", "grafana", "kibana", "prometheus"]
    ):
        tags.append("monitoring")
        confidence_scores["monitoring"] = 0.85

    # File services
    if any(
        t in domain.lower()
        for t in ["ftp", "sftp", "files", "upload", "download", "assets", "static"]
    ):
        tags.append("files")
        confidence_scores["files"] = 0.8

    # Security services
    if any(
        t in domain.lower() for t in ["auth", "sso", "login", "ldap", "vpn", "firewall"]
    ):
        tags.append("security")
        confidence_scores["security"] = 0.85

    # Mobile & Apps
    if any(
        t in domain.lower() for t in ["mobile", "app", "ios", "android", "m.", "wap"]
    ):
        tags.append("mobile")
        confidence_scores["mobile"] = 0.8

    # E-commerce
    if any(
        t in domain.lower()
        for t in ["shop", "store", "cart", "checkout", "payment", "pay"]
    ):
        tags.append("ecommerce")
        confidence_scores["ecommerce"] = 0.8

    # Media & Content
    if any(
        t in domain.lower()
        for t in ["media", "img", "image", "video", "stream", "content"]
    ):
        tags.append("media")
        confidence_scores["media"] = 0.75

    # Blog & CMS
    if any(
        t in domain.lower()
        for t in ["blog", "news", "cms", "wp", "wordpress", "drupal"]
    ):
        tags.append("content-management")
        confidence_scores["content-management"] = 0.8

    # Support & Help
    if any(
        t in domain.lower()
        for t in ["help", "support", "docs", "wiki", "kb", "knowledge"]
    ):
        tags.append("support")
        confidence_scores["support"] = 0.8

    # Backup services
    if any(t in domain.lower() for t in ["backup", "bak", "archive", "snapshot"]):
        tags.append("backup")
        confidence_scores["backup"] = 0.9

    # Load balancers & Proxy
    if any(t in domain.lower() for t in ["lb", "proxy", "gateway", "edge", "balancer"]):
        tags.append("load-balancer")
        confidence_scores["load-balancer"] = 0.85

    # Git & Version Control
    if any(
        t in domain.lower()
        for t in ["git", "gitlab", "github", "bitbucket", "svn", "repo"]
    ):
        tags.append("version-control")
        confidence_scores["version-control"] = 0.9

    # CI/CD
    if any(
        t in domain.lower()
        for t in ["jenkins", "ci", "cd", "build", "deploy", "pipeline"]
    ):
        tags.append("ci-cd")
        confidence_scores["ci-cd"] = 0.85

    # Subdomain patterns
    if domain.startswith("www."):
        tags.append("web-frontend")
        confidence_scores["web-frontend"] = 0.9

    # IP-based tagging
    if ip:
        cloud_provider = detect_cloud_provider(ip)
        if cloud_provider:
            tags.append(f"cloud-{cloud_provider}")
            confidence_scores[f"cloud-{cloud_provider}"] = 0.8

        if is_private_ip(ip):
            tags.append("internal")
            confidence_scores["internal"] = 0.95
        else:
            tags.append("external")
            confidence_scores["external"] = 0.95

    # Priority/Risk scoring
    risk_score = calculate_risk_score(domain, tags)
    entry["risk_score"] = risk_score
    entry["confidence_scores"] = confidence_scores

    return list(set(tags))  # Remove duplicates


def detect_cloud_provider(ip):
    """Detect cloud provider based on IP ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # AWS IP ranges (przykładowe - w praktyce potrzebna byłaby pełna lista)
        aws_ranges = [
            "52.0.0.0/8",
            "54.0.0.0/8",
            "18.0.0.0/8",
            "3.0.0.0/8",
            "13.0.0.0/8",
            "35.0.0.0/8",
            "52.0.0.0/8",
            "54.0.0.0/8",
        ]

        # Google Cloud IP ranges
        gcp_ranges = ["35.0.0.0/8", "34.0.0.0/8", "35.184.0.0/13", "35.192.0.0/12"]

        # Azure IP ranges
        azure_ranges = ["13.0.0.0/8", "40.0.0.0/8", "52.0.0.0/8", "104.0.0.0/8"]

        # DigitalOcean IP ranges
        do_ranges = ["159.203.0.0/16", "159.89.0.0/16", "68.183.0.0/16"]

        # Cloudflare IP ranges
        cf_ranges = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"]

        for range_str in aws_ranges:
            try:
                if ip_obj in ipaddress.ip_network(range_str):
                    return "aws"
            except:
                continue

        for range_str in gcp_ranges:
            try:
                if ip_obj in ipaddress.ip_network(range_str):
                    return "gcp"
            except:
                continue

        for range_str in azure_ranges:
            try:
                if ip_obj in ipaddress.ip_network(range_str):
                    return "azure"
            except:
                continue

        for range_str in do_ranges:
            try:
                if ip_obj in ipaddress.ip_network(range_str):
                    return "digitalocean"
            except:
                continue

        for range_str in cf_ranges:
            try:
                if ip_obj in ipaddress.ip_network(range_str):
                    return "cloudflare"
            except:
                continue

    except Exception:
        pass

    return None


def is_private_ip(ip):
    """Check if IP is in private ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except Exception:
        return False


def calculate_risk_score(domain, tags):
    """Calculate risk score based on domain and tags"""
    risk_score = 0

    # High risk tags
    high_risk_tags = ["admin", "database", "security", "backup", "internal"]
    medium_risk_tags = ["api", "ci-cd", "version-control", "development"]
    low_risk_tags = ["cdn", "media", "files", "web-frontend"]

    for tag in tags:
        if tag in high_risk_tags:
            risk_score += 3
        elif tag in medium_risk_tags:
            risk_score += 2
        elif tag in low_risk_tags:
            risk_score += 1

    # Domain-based risk factors
    if any(word in domain.lower() for word in ["admin", "root", "manage", "control"]):
        risk_score += 2

    if any(word in domain.lower() for word in ["test", "dev", "staging"]):
        risk_score += 1  # Development environments can be less secure

    # Normalize to 0-10 scale
    return min(risk_score, 10)


def load_custom_rules(rules_file):
    """Load custom tagging rules from JSON file"""
    if not os.path.exists(rules_file):
        return {}

    try:
        with open(rules_file, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def apply_custom_rules(entry, custom_rules):
    """Apply custom rules to entry"""
    domain = entry["domain"].lower()
    additional_tags = []

    for rule_name, rule_config in custom_rules.items():
        patterns = rule_config.get("patterns", [])
        tag = rule_config.get("tag", rule_name)
        confidence = rule_config.get("confidence", 0.5)

        for pattern in patterns:
            if re.search(pattern.lower(), domain):
                additional_tags.append(tag)
                if "confidence_scores" not in entry:
                    entry["confidence_scores"] = {}
                entry["confidence_scores"][tag] = confidence
                break

    return additional_tags


def generate_summary_stats(entries):
    """Generate summary statistics"""
    stats = {
        "total_domains": len(entries),
        "tag_distribution": {},
        "risk_distribution": {"low": 0, "medium": 0, "high": 0},
        "cloud_providers": {},
        "top_tags": [],
        "most_risky": [],
    }

    all_tags = []
    risk_scores = []

    for entry in entries:
        tags = entry.get("tags", [])
        risk_score = entry.get("risk_score", 0)

        all_tags.extend(tags)
        risk_scores.append(risk_score)

        # Risk distribution
        if risk_score <= 3:
            stats["risk_distribution"]["low"] += 1
        elif risk_score <= 6:
            stats["risk_distribution"]["medium"] += 1
        else:
            stats["risk_distribution"]["high"] += 1

        # Cloud providers
        for tag in tags:
            if tag.startswith("cloud-"):
                provider = tag.replace("cloud-", "")
                stats["cloud_providers"][provider] = (
                    stats["cloud_providers"].get(provider, 0) + 1
                )

    # Tag distribution
    from collections import Counter

    tag_counts = Counter(all_tags)
    stats["tag_distribution"] = dict(tag_counts)
    stats["top_tags"] = tag_counts.most_common(10)

    # Most risky domains
    risky_domains = sorted(entries, key=lambda x: x.get("risk_score", 0), reverse=True)
    stats["most_risky"] = [
        {
            "domain": d["domain"],
            "risk_score": d.get("risk_score", 0),
            "tags": d.get("tags", []),
        }
        for d in risky_domains[:10]
    ]

    return stats


def export_to_format(entries, output_file, format_type="json", csvtk_analysis=False):
    """Export entries to different formats with optional csvtk analysis"""
    if format_type == "json":
        with open(output_file, "w") as f:
            json.dump(entries, f, indent=2)

    elif format_type == "csv":
        import csv
        import subprocess

        with open(output_file, "w", newline="") as f:
            if not entries:
                return

            fieldnames = ["domain", "ip", "tags", "risk_score"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in entries:
                row = entry.copy()
                row["tags"] = ",".join(entry.get("tags", []))
                writer.writerow(row)

        # Run csvtk analysis if requested
        if csvtk_analysis:
            run_csvtk_analysis(output_file)

    elif format_type == "txt":
        with open(output_file, "w") as f:
            for entry in entries:
                tags_str = ",".join(entry.get("tags", []))
                risk = entry.get("risk_score", 0)
                f.write(
                    f"{entry['domain']} [{entry.get('ip', 'N/A')}] Tags: {tags_str} Risk: {risk}\n"
                )

    elif format_type == "markdown":
        with open(output_file, "w") as f:
            f.write("# Domain Tagging Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("| Domain | IP | Tags | Risk Score |\n")
            f.write("|--------|----|----- |-----------|\n")

            for entry in entries:
                tags_str = ", ".join(entry.get("tags", []))
                risk = entry.get("risk_score", 0)
                ip = entry.get("ip", "N/A")
                f.write(f"| {entry['domain']} | {ip} | {tags_str} | {risk} |\n")


def run_csvtk_analysis(csv_file):
    """Run comprehensive csvtk analysis on tagged domain data"""
    try:
        # Check if csvtk is available
        subprocess.run(["csvtk", "--version"], capture_output=True, check=True)

        print(f"\n📊 CSVTK Analysis for {csv_file}")
        print("=" * 50)

        # Basic statistics
        print("\n📋 Basic Statistics:")
        subprocess.run(["csvtk", "nrow", csv_file], check=True)
        subprocess.run(["csvtk", "ncol", csv_file], check=True)

        # Tag frequency analysis
        print("\n🏷️ Tag Distribution:")
        subprocess.run(["csvtk", "freq", "-f", "tags", csv_file], check=True)

        # Risk score analysis
        print("\n⚠️ Risk Score Analysis:")
        subprocess.run(["csvtk", "freq", "-f", "risk_score", csv_file], check=True)

        # High risk domains
        print("\n🚨 High Risk Domains (Risk Score >= 7):")
        subprocess.run(
            [
                "csvtk",
                "grep",
                "-f",
                "risk_score",
                "-r",
                "-p",
                "^[789]|10",
                csv_file,
                "|",
                "csvtk",
                "pretty",
            ],
            shell=True,
            check=True,
        )

        # Domains with admin tags
        print("\n🔑 Admin/Security Related Domains:")
        subprocess.run(
            [
                "csvtk",
                "grep",
                "-f",
                "tags",
                "-i",
                "-r",
                "-p",
                "admin|security|auth",
                csv_file,
                "|",
                "csvtk",
                "pretty",
            ],
            shell=True,
            check=True,
        )

        # API endpoints
        print("\n🔌 API Endpoints:")
        subprocess.run(
            [
                "csvtk",
                "grep",
                "-f",
                "tags",
                "-i",
                "-r",
                "-p",
                "api",
                csv_file,
                "|",
                "csvtk",
                "pretty",
            ],
            shell=True,
            check=True,
        )

        # Development environments
        print("\n🛠️ Development/Testing Environments:")
        subprocess.run(
            [
                "csvtk",
                "grep",
                "-f",
                "tags",
                "-i",
                "-r",
                "-p",
                "development",
                csv_file,
                "|",
                "csvtk",
                "pretty",
            ],
            shell=True,
            check=True,
        )

    except subprocess.CalledProcessError:
        print("⚠️ csvtk not found. Install from: https://github.com/shenwei356/csvtk")
    except Exception as e:
        print(f"⚠️ Analysis error: {e}")


def generate_security_focused_report(entries, output_file):
    """Generate a security-focused CSV report optimized for csvtk analysis"""
    import csv

    # Enhanced CSV with more security-relevant fields
    with open(output_file, "w", newline="") as f:
        fieldnames = [
            "domain",
            "ip",
            "risk_score",
            "is_admin",
            "is_api",
            "is_dev",
            "is_database",
            "is_internal",
            "cloud_provider",
            "all_tags",
            "confidence",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            tags = entry.get("tags", [])
            row = {
                "domain": entry["domain"],
                "ip": entry.get("ip", ""),
                "risk_score": entry.get("risk_score", 0),
                "is_admin": "yes" if "admin" in tags else "no",
                "is_api": "yes" if "api" in tags else "no",
                "is_dev": "yes" if "development" in tags else "no",
                "is_database": "yes" if "database" in tags else "no",
                "is_internal": "yes" if "internal" in tags else "no",
                "cloud_provider": next(
                    (
                        tag.replace("cloud-", "")
                        for tag in tags
                        if tag.startswith("cloud-")
                    ),
                    "none",
                ),
                "all_tags": "|".join(tags),
                "confidence": (
                    max(entry.get("confidence_scores", {}).values())
                    if entry.get("confidence_scores")
                    else 0
                ),
            }
            writer.writerow(row)

    print(f"✅ Security-focused CSV saved: {output_file}")
    print("🔍 Suggested csvtk analysis commands:")
    print(f"   csvtk freq -f is_admin {output_file}")
    print(f"   csvtk freq -f cloud_provider {output_file}")
    print(f"   csvtk grep -f risk_score -r -p '^[8-9]|10' {output_file} | csvtk pretty")
    print(
        f"   csvtk sort -k risk_score:nr {output_file} | csvtk head -n 10 | csvtk pretty"
    )
    if format_type == "json":
        with open(output_file, "w") as f:
            json.dump(entries, f, indent=2)

    elif format_type == "csv":
        import csv

        with open(output_file, "w", newline="") as f:
            if not entries:
                return

            fieldnames = ["domain", "ip", "tags", "risk_score"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in entries:
                row = entry.copy()
                row["tags"] = ",".join(entry.get("tags", []))
                writer.writerow(row)

    elif format_type == "txt":
        with open(output_file, "w") as f:
            for entry in entries:
                tags_str = ",".join(entry.get("tags", []))
                risk = entry.get("risk_score", 0)
                f.write(
                    f"{entry['domain']} [{entry.get('ip', 'N/A')}] Tags: {tags_str} Risk: {risk}\n"
                )

    elif format_type == "markdown":
        with open(output_file, "w") as f:
            f.write("# Domain Tagging Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("| Domain | IP | Tags | Risk Score |\n")
            f.write("|--------|----|----- |-----------|\n")

            for entry in entries:
                tags_str = ", ".join(entry.get("tags", []))
                risk = entry.get("risk_score", 0)
                ip = entry.get("ip", "N/A")
                f.write(f"| {entry['domain']} | {ip} | {tags_str} | {risk} |\n")


@click.command()
@click.option(
    "--input", "-i", required=True, help="Path to subs_resolved.txt or JSON file"
)
@click.option("--output", "-o", required=True, help="Path to output file")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "txt", "markdown"], case_sensitive=False),
    default="json",
    help="Output format",
)
@click.option("--rules", "-r", help="Path to custom tagging rules JSON file")
@click.option("--filter-tags", help="Filter results by tags (comma-separated)")
@click.option("--min-risk", type=int, help="Filter by minimum risk score")
@click.option("--max-risk", type=int, help="Filter by maximum risk score")
@click.option(
    "--exclude-tags", help="Exclude results with these tags (comma-separated)"
)
@click.option("--cloud-only", is_flag=True, help="Show only cloud-hosted domains")
@click.option("--internal-only", is_flag=True, help="Show only internal domains")
@click.option("--stats", is_flag=True, help="Generate statistics report")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--sort-by",
    type=click.Choice(["domain", "risk", "tags"], case_sensitive=False),
    default="domain",
    help="Sort results by field",
)
def cli(
    input,
    output,
    format,
    rules,
    filter_tags,
    min_risk,
    max_risk,
    exclude_tags,
    cloud_only,
    internal_only,
    stats,
    verbose,
    sort_by,
):
    """🏷️ Advanced Subdomain Tagging and Classification Tool

    Intelligently tags subdomains with categories like:
    - Infrastructure (CDN, Load Balancers, Proxies)
    - Services (API, Mail, Database, Monitoring)
    - Security (Admin, Auth, VPN)
    - Development (Dev, Test, Staging, CI/CD)
    - Cloud Providers (AWS, GCP, Azure, etc.)

    Supports multiple output formats and advanced filtering options.
    """

    if verbose:
        click.secho("[*] 🏷️  Starting advanced domain tagging...", fg="cyan")

    # Load input data
    try:
        if input.endswith(".json"):
            with open(input, "r") as f:
                resolved = json.load(f)
        else:
            resolved = load_resolved(input)

        if verbose:
            click.secho(f"[+] 📋 Loaded {len(resolved)} domains", fg="green")
    except Exception as e:
        click.secho(f"[!] ❌ Error loading input: {e}", fg="red")
        return

    # Load custom rules if provided
    custom_rules = {}
    if rules:
        custom_rules = load_custom_rules(rules)
        if verbose and custom_rules:
            click.secho(f"[+] 📜 Loaded {len(custom_rules)} custom rules", fg="green")

    # Process each entry
    tagged_count = 0
    for entry in resolved:
        # Apply auto-tagging
        entry["tags"] = auto_tag(entry)

        # Apply custom rules
        if custom_rules:
            additional_tags = apply_custom_rules(entry, custom_rules)
            entry["tags"].extend(additional_tags)
            entry["tags"] = list(set(entry["tags"]))  # Remove duplicates

        if entry["tags"]:
            tagged_count += 1

    if verbose:
        click.secho(f"[+] 🎯 Tagged {tagged_count}/{len(resolved)} domains", fg="green")

    # Apply filters
    filtered_results = resolved.copy()

    if filter_tags:
        filter_list = [tag.strip() for tag in filter_tags.split(",")]
        filtered_results = [
            r
            for r in filtered_results
            if any(tag in r.get("tags", []) for tag in filter_list)
        ]
        if verbose:
            click.secho(
                f"[+] 🔍 Filtered by tags: {len(filtered_results)} results", fg="yellow"
            )

    if exclude_tags:
        exclude_list = [tag.strip() for tag in exclude_tags.split(",")]
        filtered_results = [
            r
            for r in filtered_results
            if not any(tag in r.get("tags", []) for tag in exclude_list)
        ]
        if verbose:
            click.secho(
                f"[+] 🚫 Excluded tags: {len(filtered_results)} results", fg="yellow"
            )

    if min_risk is not None:
        filtered_results = [
            r for r in filtered_results if r.get("risk_score", 0) >= min_risk
        ]
        if verbose:
            click.secho(
                f"[+] ⚠️  Min risk filter: {len(filtered_results)} results", fg="yellow"
            )

    if max_risk is not None:
        filtered_results = [
            r for r in filtered_results if r.get("risk_score", 0) <= max_risk
        ]
        if verbose:
            click.secho(
                f"[+] ✅ Max risk filter: {len(filtered_results)} results", fg="yellow"
            )

    if cloud_only:
        filtered_results = [
            r
            for r in filtered_results
            if any(tag.startswith("cloud-") for tag in r.get("tags", []))
        ]
        if verbose:
            click.secho(
                f"[+] ☁️  Cloud-only filter: {len(filtered_results)} results",
                fg="yellow",
            )

    if internal_only:
        filtered_results = [
            r for r in filtered_results if "internal" in r.get("tags", [])
        ]
        if verbose:
            click.secho(
                f"[+] 🏠 Internal-only filter: {len(filtered_results)} results",
                fg="yellow",
            )

    # Sort results
    if sort_by == "risk":
        filtered_results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    elif sort_by == "tags":
        filtered_results.sort(key=lambda x: len(x.get("tags", [])), reverse=True)
    else:  # domain
        filtered_results.sort(key=lambda x: x["domain"])

    if verbose:
        click.secho(f"[+] 📊 Sorted by: {sort_by}", fg="blue")

    # Generate statistics if requested
    if stats:
        stats_data = generate_summary_stats(filtered_results)
        stats_file = output.replace(".", "_stats.")

        with open(stats_file, "w") as f:
            json.dump(stats_data, f, indent=2)

        if verbose:
            click.secho(f"[+] 📈 Statistics saved to: {stats_file}", fg="green")

        # Print summary to console
        click.secho("\n📊 TAGGING STATISTICS", fg="cyan", bold=True)
        click.secho(f"Total domains: {stats_data['total_domains']}", fg="white")
        click.secho("Risk distribution:", fg="white")
        for risk_level, count in stats_data["risk_distribution"].items():
            color = (
                "red"
                if risk_level == "high"
                else "yellow" if risk_level == "medium" else "green"
            )
            click.secho(f"  {risk_level.capitalize()}: {count}", fg=color)

        click.secho("Top tags:", fg="white")
        for tag, count in stats_data["top_tags"][:5]:
            click.secho(f"  {tag}: {count}", fg="blue")

        if stats_data["cloud_providers"]:
            click.secho("Cloud providers:", fg="white")
            for provider, count in stats_data["cloud_providers"].items():
                click.secho(f"  {provider}: {count}", fg="magenta")

    # Export results
    try:
        export_to_format(filtered_results, output, format)

        if verbose:
            click.secho(
                f"[+] 💾 Results saved to: {output} ({format} format)", fg="green"
            )
            click.secho(
                f"[+] 🎯 Final result count: {len(filtered_results)}", fg="green"
            )
        else:
            click.secho(
                f"[TAGGING] Saved {len(filtered_results)} tagged results to: {output}",
                fg="green",
            )

    except Exception as e:
        click.secho(f"[!] ❌ Error saving output: {e}", fg="red")


if __name__ == "__main__":
    cli()
