import json
import os
import sys
import click
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from reconcli.utils.mdexport import generate_dns_summary, export_zonewalk_report
from reconcli.utils.resume import (
    load_resume,
    save_resume_state,
    clear_resume as clear_resume_fn,
)


@click.command()
@click.option("--input", help="Path to enriched JSON input file")
@click.option("--output", help="Path to output markdown file (dns_summary.md)")
@click.option("--resume", is_flag=True, help="Resume previous session")
@click.option("--resume-from", type=str, help="Resume from specific step")
@click.option(
    "--template",
    type=click.Choice(["obsidian", "standard", "github", "confluence", "notion"]),
    default="obsidian",
    help="Output template format",
)
@click.option("--include-stats", is_flag=True, help="Include statistics section")
@click.option("--include-timeline", is_flag=True, help="Include discovery timeline")
@click.option("--include-security", is_flag=True, help="Include security analysis")
@click.option("--include-charts", is_flag=True, help="Include mermaid charts")
@click.option("--filter-country", help="Filter by specific country")
@click.option("--filter-org", help="Filter by specific organization")
@click.option("--filter-asn", help="Filter by specific ASN")
@click.option(
    "--sort-by",
    type=click.Choice(["subdomain", "ip", "country", "org", "asn"]),
    default="subdomain",
    help="Sort results by field",
)
@click.option(
    "--group-by",
    type=click.Choice(["country", "org", "asn", "ip_range", "none"]),
    default="none",
    help="Group results by field",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--export-json", help="Also export filtered data to JSON file")
@click.option("--export-csv", help="Also export filtered data to CSV file")
@click.option(
    "--csvtk-analysis", is_flag=True, help="Run csvtk analysis on exported CSV"
)
@click.option(
    "--csvtk-stats", is_flag=True, help="Show csvtk statistics for CSV exports"
)
@click.option("--auto-tags", is_flag=True, help="Auto-generate tags based on analysis")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option(
    "--emoji-off", is_flag=True, help="Disable emoji in output for clean text reports"
)
def cli(
    input,
    output,
    resume,
    resume_from,
    template,
    include_stats,
    include_timeline,
    include_security,
    include_charts,
    filter_country,
    filter_org,
    filter_asn,
    sort_by,
    group_by,
    verbose,
    export_json,
    export_csv,
    auto_tags,
    clear_resume,
    emoji_off,
):
    """
    🧠 Advanced Markdown Report Generator for ReconCLI
    
    Generate comprehensive, template-based markdown reports from enriched DNS/subdomain data.
    Supports multiple output formats including Obsidian, GitHub, Confluence, and Notion.
    
    Features:
    - Multiple template formats (Obsidian, GitHub, Confluence, Notion)
    - Statistical analysis and visualizations
    - Security-focused insights and recommendations
    - Filtering and grouping capabilities
    - Resume functionality for large datasets
    - Export to multiple formats (JSON, CSV)
    - Auto-tagging based on analysis
    - Mermaid chart generation
    
    Examples:
        # Basic Obsidian report
        reconcli mdreport --input enriched_data.json --output report.md
        
        # Advanced security report with stats and charts
        reconcli mdreport --input data.json --output security_report.md \
                         --template github --include-stats --include-security \
                         --include-charts --auto-tags
        
        # Filtered report by country
        reconcli mdreport --input data.json --output us_report.md \
                         --filter-country "United States" --include-timeline
        
        # Grouped report with multiple exports
        reconcli mdreport --input data.json --output grouped_report.md \
                         --group-by org --export-json results.json \
                         --export-csv results.csv
        
        # Resume interrupted session
        reconcli mdreport --resume
    """
    # Validate required parameters for non-resume operations
    if not resume and not clear_resume and not resume_from:
        if not input:
            click.echo(
                "❌ --input is required unless using --resume, --clear-resume, or --resume-from"
            )
            sys.exit(1)
        if not output:
            click.echo(
                "❌ --output is required unless using --resume, --clear-resume, or --resume-from"
            )
            sys.exit(1)

    output_dir = os.path.dirname(output) if output else "."

    # Create output directory if it doesn't exist
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if resume:
        if verbose:
            click.echo("[RESUME] Loading previous session state...")
        state = load_resume(output_dir)
        if state:
            click.echo(json.dumps(state, indent=2))
        else:
            click.echo("❌ No previous session found")
        return

    if resume_from:
        if verbose:
            click.echo(f"[RESUME] Resuming from step: {resume_from}")
        state = load_resume(output_dir)
        click.echo(json.dumps(state, indent=2))
        # TODO: Add selective resume logic here
        return

    if verbose:
        click.echo("🧠 Advanced Markdown Report Generator")
        click.echo("Part of the ReconCLI Cyber-Squad z Przyszłości")

    # Clear resume state if requested
    if clear_resume:
        clear_resume_fn(output_dir)
        click.echo("✅ Resume state cleared")
        return

    if resume:
        if verbose:
            click.echo("[RESUME] Loading previous session state...")
        state = load_resume(output_dir)
        if state:
            click.echo(json.dumps(state, indent=2))
        else:
            click.echo("❌ No previous session found")
        return

    if resume_from:
        if verbose:
            click.echo(f"[RESUME] Resuming from step: {resume_from}")
        state = load_resume(output_dir)
        click.echo(json.dumps(state, indent=2))
        # TODO: Add selective resume logic here
        return

    # Load and validate input data
    try:
        with open(input, "r") as f:
            enriched_data = json.load(f)
    except FileNotFoundError:
        click.echo(f"❌ Input file not found: {input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"❌ Invalid JSON in input file: {e}")
        sys.exit(1)

    if not enriched_data:
        click.echo("[!] No data found in enriched JSON.")
        return

    if verbose:
        click.echo(f"📊 Loaded {len(enriched_data)} records")

    # Extract domain name
    domain = extract_domain_name(enriched_data)

    # Flatten data for processing
    flat_data = flatten_data(enriched_data)

    # Apply filters
    filtered_data = apply_filters(
        flat_data, filter_country, filter_org, filter_asn, verbose
    )

    # Apply auto-tagging if requested
    if auto_tags:
        filtered_data = apply_auto_tags(filtered_data, verbose)

    # Sort data
    sorted_data = sort_data(filtered_data, sort_by, verbose)

    # Group data if requested
    grouped_data = (
        group_data(sorted_data, group_by, verbose)
        if group_by != "none"
        else {"all": sorted_data}
    )

    # Generate statistics
    stats = generate_statistics(filtered_data, verbose) if include_stats else None

    # Generate timeline
    timeline = generate_timeline(filtered_data, verbose) if include_timeline else None

    # Generate security analysis
    security_analysis = (
        generate_security_analysis(filtered_data, verbose) if include_security else None
    )

    # Generate charts
    charts = (
        generate_mermaid_charts(filtered_data, grouped_data, verbose)
        if include_charts
        else None
    )

    # Generate markdown report
    report_content = generate_advanced_report(
        domain=domain,
        data=grouped_data,
        template=template,
        stats=stats,
        timeline=timeline,
        security_analysis=security_analysis,
        charts=charts,
        verbose=verbose,
        emoji_off=emoji_off,
    )

    # Write main markdown report
    with open(output, "w", encoding="utf-8") as f:
        f.write(report_content)

    if verbose:
        click.echo(f"✅ Markdown report saved to {output}")

    # Export additional formats if requested
    if export_json:
        export_to_json(filtered_data, export_json, verbose)

    if export_csv:
        export_to_csv(filtered_data, export_csv, verbose)

    # Save resume state
    save_resume_state(
        output_dir,
        {
            "last_module": "mdreport_advanced",
            "completed": True,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "template": template,
            "records_processed": len(filtered_data),
            "output_file": output,
        },
    )

    if verbose:
        click.echo(f"💾 Resume state saved to {output_dir}/resume.cfg")


def extract_domain_name(enriched_data: Union[Dict, List[Dict]]) -> str:
    """Extract domain name from enriched data"""
    # Handle different data formats
    if isinstance(enriched_data, dict):
        # Data is organized by record type
        for record_type, entries in enriched_data.items():
            for entry in entries:
                if isinstance(entry, dict):
                    subdomain = entry.get("subdomain") or entry.get("domain") or ""
                    if subdomain and "." in subdomain:
                        parts = subdomain.split(".")
                        if len(parts) >= 2:
                            return ".".join(parts[-2:])
    elif isinstance(enriched_data, list):
        # Data is a flat list
        for entry in enriched_data:
            if isinstance(entry, dict):
                subdomain = entry.get("subdomain") or entry.get("domain") or ""
                if subdomain and "." in subdomain:
                    parts = subdomain.split(".")
                    if len(parts) >= 2:
                        return ".".join(parts[-2:])

    return "unknown"


def apply_filters(
    data: List[Dict],
    filter_country: Optional[str],
    filter_org: Optional[str],
    filter_asn: Optional[str],
    verbose: bool,
) -> List[Dict]:
    """Apply various filters to the data"""
    filtered = data.copy()
    original_count = len(filtered)

    if filter_country:
        filtered = [
            item
            for item in filtered
            if (item.get("country") or "").lower() == filter_country.lower()
        ]
        if verbose:
            click.echo(
                f"🌍 Country filter applied: {len(filtered)}/{original_count} records"
            )

    if filter_org:
        filtered = [
            item
            for item in filtered
            if filter_org.lower() in (item.get("org") or "").lower()
        ]
        if verbose:
            click.echo(
                f"🏢 Organization filter applied: {len(filtered)}/{original_count} records"
            )

    if filter_asn:
        filtered = [
            item for item in filtered if filter_asn in str(item.get("asn") or "")
        ]
        if verbose:
            click.echo(
                f"🔢 ASN filter applied: {len(filtered)}/{original_count} records"
            )

    return filtered


def apply_auto_tags(data: List[Dict], verbose: bool) -> List[Dict]:
    """Apply automatic tags based on analysis"""
    if verbose:
        click.echo("🏷️  Applying automatic tags...")

    for item in data:
        tags = item.get("tags", [])

        # Cloud provider detection
        org = (item.get("org") or "").lower()
        if "amazon" in org or "aws" in org:
            tags.append("cloud-aws")
        elif "google" in org or "gcp" in org:
            tags.append("cloud-gcp")
        elif "microsoft" in org or "azure" in org:
            tags.append("cloud-azure")
        elif "cloudflare" in org:
            tags.append("cdn-cloudflare")

        # Security-related tags
        subdomain = (item.get("subdomain") or item.get("domain") or "").lower()
        if any(word in subdomain for word in ["dev", "test", "staging", "beta"]):
            tags.append("environment-dev")
        elif any(word in subdomain for word in ["prod", "production", "www"]):
            tags.append("environment-prod")
        elif any(word in subdomain for word in ["admin", "manage", "panel"]):
            tags.append("security-sensitive")
        elif any(word in subdomain for word in ["api", "rest", "graphql"]):
            tags.append("api-endpoint")
        elif any(word in subdomain for word in ["mail", "smtp", "mx"]):
            tags.append("mail-service")

        # IP range analysis
        ip = item.get("ip", "")
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            tags.append("ip-private")
        elif ip.startswith("127."):
            tags.append("ip-localhost")
        else:
            tags.append("ip-public")

        item["tags"] = list(set(tags))  # Remove duplicates

    return data


def sort_data(data: List[Dict], sort_by: str, verbose: bool) -> List[Dict]:
    """Sort data by specified field"""
    if verbose:
        click.echo(f"📊 Sorting by: {sort_by}")

    def get_sort_key(item):
        if sort_by == "subdomain":
            return item.get("subdomain") or item.get("domain") or ""
        elif sort_by == "ip":
            ip = item.get("ip", "")
            # Convert IP to sortable format
            try:
                return tuple(int(part) for part in ip.split("."))
            except:
                return (999, 999, 999, 999)
        elif sort_by == "country":
            return item.get("country") or ""
        elif sort_by == "org":
            return item.get("org") or ""
        elif sort_by == "asn":
            asn = item.get("asn", {})
            if isinstance(asn, dict):
                return asn.get("asn", "")
            return str(asn)
        return ""

    return sorted(data, key=get_sort_key)


def group_data(data: List[Dict], group_by: str, verbose: bool) -> Dict[str, List[Dict]]:
    """Group data by specified field"""
    if verbose:
        click.echo(f"📂 Grouping by: {group_by}")

    groups = {}

    for item in data:
        if group_by == "country":
            key = item.get("country") or "Unknown"
        elif group_by == "org":
            key = item.get("org") or "Unknown"
        elif group_by == "asn":
            asn = item.get("asn", {})
            if isinstance(asn, dict):
                key = asn.get("asn", "Unknown")
            else:
                key = str(asn) if asn else "Unknown"
        elif group_by == "ip_range":
            ip = item.get("ip", "")
            if ip:
                # Group by /24 subnet
                parts = ip.split(".")
                if len(parts) >= 3:
                    key = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                else:
                    key = "Unknown"
            else:
                key = "Unknown"
        else:
            key = "All"

        if key not in groups:
            groups[key] = []
        groups[key].append(item)

    return groups


def generate_statistics(data: List[Dict], verbose: bool) -> Dict[str, Any]:
    """Generate comprehensive statistics"""
    if verbose:
        click.echo("📈 Generating statistics...")

    stats = {
        "total_records": len(data),
        "unique_ips": len(set(item.get("ip", "") for item in data if item.get("ip"))),
        "countries": {},
        "organizations": {},
        "asns": {},
        "ip_ranges": {},
        "tags": {},
        "tlds": {},
    }

    for item in data:
        # Country stats
        country = item.get("country")
        if country:
            stats["countries"][country] = stats["countries"].get(country, 0) + 1

        # Organization stats
        org = item.get("org")
        if org:
            stats["organizations"][org] = stats["organizations"].get(org, 0) + 1

        # ASN stats
        asn = item.get("asn", {})
        if isinstance(asn, dict):
            asn_num = asn.get("asn")
        else:
            asn_num = str(asn) if asn else None

        if asn_num:
            stats["asns"][asn_num] = stats["asns"].get(asn_num, 0) + 1

        # IP range stats (/24)
        ip = item.get("ip", "")
        if ip:
            parts = ip.split(".")
            if len(parts) >= 3:
                range_key = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                stats["ip_ranges"][range_key] = stats["ip_ranges"].get(range_key, 0) + 1

        # Tag stats
        for tag in item.get("tags", []):
            stats["tags"][tag] = stats["tags"].get(tag, 0) + 1

        # TLD stats
        domain = item.get("subdomain") or item.get("domain", "")
        if domain and "." in domain:
            tld = domain.split(".")[-1]
            stats["tlds"][tld] = stats["tlds"].get(tld, 0) + 1

    # Sort by count (descending)
    for key in ["countries", "organizations", "asns", "ip_ranges", "tags", "tlds"]:
        stats[key] = dict(sorted(stats[key].items(), key=lambda x: x[1], reverse=True))

    return stats


def generate_timeline(data: List[Dict], verbose: bool) -> Dict[str, Any]:
    """Generate discovery timeline if timestamp data is available"""
    if verbose:
        click.echo("⏰ Generating timeline...")

    # This is a placeholder - in real implementation you'd use actual timestamp data
    timeline = {
        "discovery_start": datetime.now().isoformat(),
        "discovery_end": datetime.now().isoformat(),
        "total_duration": "N/A",
        "phases": [
            {
                "phase": "DNS Enumeration",
                "records": len(data),
                "timestamp": datetime.now().isoformat(),
            },
            {
                "phase": "IP Resolution",
                "records": len([item for item in data if item.get("ip")]),
                "timestamp": datetime.now().isoformat(),
            },
            {
                "phase": "Enrichment",
                "records": len(data),
                "timestamp": datetime.now().isoformat(),
            },
        ],
    }

    return timeline


def generate_security_analysis(data: List[Dict], verbose: bool) -> Dict[str, Any]:
    """Generate security-focused analysis"""
    if verbose:
        click.echo("🔒 Generating security analysis...")

    analysis = {
        "risk_assessment": "medium",
        "findings": [],
        "recommendations": [],
        "sensitive_subdomains": [],
        "cloud_exposure": {},
        "geographic_distribution": {},
    }

    # Identify potentially sensitive subdomains
    sensitive_keywords = [
        "admin",
        "test",
        "dev",
        "staging",
        "internal",
        "private",
        "manage",
        "panel",
        "api",
        "backup",
    ]

    for item in data:
        subdomain = (item.get("subdomain") or item.get("domain", "")).lower()
        for keyword in sensitive_keywords:
            if keyword in subdomain:
                analysis["sensitive_subdomains"].append(
                    {
                        "subdomain": item.get("subdomain") or item.get("domain"),
                        "ip": item.get("ip"),
                        "keyword": keyword,
                        "risk_level": (
                            "high"
                            if keyword in ["admin", "manage", "panel"]
                            else "medium"
                        ),
                    }
                )
                break

    # Cloud exposure analysis
    cloud_providers = {}
    for item in data:
        org = (item.get("org") or "").lower()
        if "amazon" in org or "aws" in org:
            cloud_providers["AWS"] = cloud_providers.get("AWS", 0) + 1
        elif "google" in org:
            cloud_providers["Google Cloud"] = cloud_providers.get("Google Cloud", 0) + 1
        elif "microsoft" in org or "azure" in org:
            cloud_providers["Azure"] = cloud_providers.get("Azure", 0) + 1
        elif "cloudflare" in org:
            cloud_providers["Cloudflare"] = cloud_providers.get("Cloudflare", 0) + 1

    analysis["cloud_exposure"] = cloud_providers

    # Geographic distribution
    countries = {}
    for item in data:
        country = item.get("country")
        if country:
            countries[country] = countries.get(country, 0) + 1

    analysis["geographic_distribution"] = dict(
        sorted(countries.items(), key=lambda x: x[1], reverse=True)
    )

    # Generate findings and recommendations
    if analysis["sensitive_subdomains"]:
        analysis["findings"].append(
            f"Found {len(analysis['sensitive_subdomains'])} potentially sensitive subdomains"
        )
        analysis["recommendations"].append(
            "Review access controls for sensitive subdomains"
        )

    if len(countries) > 5:
        analysis["findings"].append(f"Infrastructure spans {len(countries)} countries")
        analysis["recommendations"].append(
            "Consider geographic compliance requirements"
        )

    if cloud_providers:
        analysis["findings"].append(
            f"Cloud infrastructure detected: {', '.join(cloud_providers.keys())}"
        )
        analysis["recommendations"].append(
            "Ensure cloud security best practices are implemented"
        )

    # Risk assessment
    risk_score = 0
    risk_score += len(analysis["sensitive_subdomains"]) * 2
    risk_score += len(countries) if len(countries) > 3 else 0
    risk_score += len(cloud_providers) * 1

    if risk_score > 10:
        analysis["risk_assessment"] = "high"
    elif risk_score > 5:
        analysis["risk_assessment"] = "medium"
    else:
        analysis["risk_assessment"] = "low"

    return analysis


def generate_mermaid_charts(
    data: List[Dict], grouped_data: Dict[str, List[Dict]], verbose: bool
) -> Dict[str, str]:
    """Generate Mermaid charts for visualization"""
    if verbose:
        click.echo("📊 Generating Mermaid charts...")

    charts = {}

    # Infrastructure overview chart
    charts[
        "infrastructure"
    ] = """
graph TB
    A[Domain] --> B[Subdomains]
    B --> C[IP Addresses]
    C --> D[Geographic Distribution]
    C --> E[Cloud Providers]
    B --> F[Services]
    F --> G[Web Services]
    F --> H[Mail Services]
    F --> I[API Endpoints]
    """

    # Country distribution pie chart
    countries = {}
    for item in data:
        country = item.get("country", "Unknown")
        countries[country] = countries.get(country, 0) + 1

    if len(countries) > 1:
        pie_data = []
        for country, count in sorted(
            countries.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            percentage = (count / len(data)) * 100
            pie_data.append(f'"{country}" : {percentage:.1f}')

        charts["countries"] = f"pie title Country Distribution\n    " + "\n    ".join(
            pie_data
        )

    return charts


def generate_advanced_report(
    domain: str,
    data: Dict[str, List[Dict]],
    template: str,
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    verbose: bool,
    emoji_off: bool = False,
) -> str:
    """Generate advanced markdown report with selected template"""
    if verbose:
        click.echo(f"📝 Generating {template} template report...")

    # Template-specific generators
    if template == "obsidian":
        return generate_obsidian_template(
            domain, data, stats, timeline, security_analysis, charts, emoji_off
        )
    elif template == "github":
        return generate_github_template(
            domain, data, stats, timeline, security_analysis, charts, emoji_off
        )
    elif template == "confluence":
        return generate_confluence_template(
            domain, data, stats, timeline, security_analysis, charts, emoji_off
        )
    elif template == "notion":
        return generate_notion_template(
            domain, data, stats, timeline, security_analysis, charts, emoji_off
        )
    else:  # standard
        return generate_standard_template(
            domain, data, stats, timeline, security_analysis, charts, emoji_off
        )


def generate_obsidian_template(
    domain: str,
    data: Dict[str, List[Dict]],
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    emoji_off: bool = False,
) -> str:
    """Generate Obsidian-optimized markdown template"""
    content = []

    # Obsidian front matter
    content.append("---")
    content.append(f"title: DNS Reconnaissance Report - {domain}")
    content.append(f"date: {datetime.now().strftime('%Y-%m-%d')}")
    content.append("tags:")
    content.append("  - reconnaissance")
    content.append("  - dns")
    content.append("  - cybersecurity")
    content.append(f"  - {domain}")
    content.append("type: security-report")
    content.append("---")
    content.append("")

    # Title and metadata
    content.append(
        format_title(f"# 🔍 DNS Reconnaissance Report: `{domain}`", emoji_off)
    )
    content.append("")
    content.append(format_section_header("## 📊 Report Metadata", emoji_off))
    content.append("")
    content.append(f"- **Target Domain**: `{domain}`")
    content.append(f"- **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append(f"- **Template**: Obsidian")
    content.append(
        f"- **Total Records**: {sum(len(records) for records in data.values())}"
    )
    content.append("")

    # Statistics section
    if stats:
        content.extend(generate_stats_section(stats, "obsidian", emoji_off))

    # Security analysis
    if security_analysis:
        content.extend(
            generate_security_section(security_analysis, "obsidian", emoji_off)
        )

    # Charts
    if charts:
        content.extend(generate_charts_section(charts, "obsidian", emoji_off))

    # Timeline
    if timeline:
        content.extend(generate_timeline_section(timeline, "obsidian"))

    # Data tables
    content.extend(generate_data_sections(data, "obsidian", emoji_off))

    # Obsidian-specific features
    content.append("## 🔗 Related Notes")
    content.append("")
    content.append(f"- [[{domain} - Infrastructure Analysis]]")
    content.append(f"- [[{domain} - Security Assessment]]")
    content.append(f"- [[{domain} - Monitoring Dashboard]]")
    content.append("")

    return "\n".join(content)


def generate_github_template(
    domain: str,
    data: Dict[str, List[Dict]],
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    emoji_off: bool = False,
) -> str:
    """Generate GitHub-optimized markdown template"""
    content = []

    # GitHub-style header with badges
    content.append(format_title(f"# 🔍 DNS Reconnaissance Report: {domain}", emoji_off))
    content.append("")
    content.append(
        "![Security](https://img.shields.io/badge/Security-Reconnaissance-red)"
    )
    content.append("![Status](https://img.shields.io/badge/Status-Complete-green)")
    content.append(
        f"![Records](https://img.shields.io/badge/Records-{sum(len(records) for records in data.values())}-blue)"
    )
    content.append("")

    # Table of contents
    content.append(format_section_header("## 📋 Table of Contents", emoji_off))
    content.append("")
    sections = ["Executive Summary", "Statistics", "Security Analysis", "Data Overview"]
    for i, section in enumerate(sections, 1):
        content.append(f"{i}. [{section}](#{section.lower().replace(' ', '-')})")
    content.append("")

    # Executive summary
    content.append(format_section_header("## 📈 Executive Summary", emoji_off))
    content.append("")
    content.append(
        f"This report contains reconnaissance data for **{domain}** generated on {datetime.now().strftime('%Y-%m-%d')}."
    )
    content.append("")
    total_records = sum(len(records) for records in data.values())
    content.append(f"- **Total Subdomains Discovered**: {total_records}")

    if stats:
        content.append(f"- **Unique IP Addresses**: {stats.get('unique_ips', 0)}")
        content.append(f"- **Countries Detected**: {len(stats.get('countries', {}))}")
        content.append(f"- **Organizations**: {len(stats.get('organizations', {}))}")

    content.append("")

    # Add other sections
    if stats:
        content.extend(generate_stats_section(stats, "github", emoji_off))

    if security_analysis:
        content.extend(
            generate_security_section(security_analysis, "github", emoji_off)
        )

    if charts:
        content.extend(generate_charts_section(charts, "github", emoji_off))

    content.extend(generate_data_sections(data, "github", emoji_off))

    # GitHub-specific footer
    content.append("---")
    content.append("")
    content.append(
        "**⚠️ Disclaimer**: This report is for authorized security testing purposes only."
    )
    content.append("")
    content.append("*Generated by ReconCLI - Advanced Reconnaissance Toolkit*")
    content.append("")

    return "\n".join(content)


def generate_standard_template(
    domain: str,
    data: Dict[str, List[Dict]],
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    emoji_off: bool = False,
) -> str:
    """Generate standard markdown template"""
    content = []

    content.append(f"# DNS Reconnaissance Report for {domain}")
    content.append("")
    content.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append(f"**Domain**: {domain}")
    content.append(
        f"**Total Records**: {sum(len(records) for records in data.values())}"
    )
    content.append("")

    if stats:
        content.extend(generate_stats_section(stats, "standard", emoji_off))

    if security_analysis:
        content.extend(
            generate_security_section(security_analysis, "standard", emoji_off)
        )

    if charts:
        content.extend(generate_charts_section(charts, "standard", emoji_off))

    if timeline:
        content.extend(generate_timeline_section(timeline, "standard"))

    content.extend(generate_data_sections(data, "standard", emoji_off))

    return "\n".join(content)


def generate_confluence_template(
    domain: str,
    data: Dict[str, List[Dict]],
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    emoji_off: bool = False,
) -> str:
    """Generate Confluence-optimized markdown template"""
    # Confluence has specific macro support
    content = []

    content.append(f"h1. DNS Reconnaissance Report: {domain}")
    content.append("")
    content.append("{info}")
    content.append(f"Domain: {domain}")
    content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append(f"Total Records: {sum(len(records) for records in data.values())}")
    content.append("{info}")
    content.append("")

    # Convert to Confluence-style formatting and add macros
    standard_content = generate_standard_template(
        domain, data, stats, timeline, security_analysis, charts
    )

    # Convert markdown headers to Confluence format
    confluence_content = standard_content.replace("## ", "h2. ").replace("### ", "h3. ")

    content.append(confluence_content)

    return "\n".join(content)


def generate_notion_template(
    domain: str,
    data: Dict[str, List[Dict]],
    stats: Optional[Dict],
    timeline: Optional[Dict],
    security_analysis: Optional[Dict],
    charts: Optional[Dict],
    emoji_off: bool = False,
) -> str:
    """Generate Notion-optimized markdown template"""
    content = []

    # Notion supports callouts and databases
    title = format_title(f"🔍 {domain} - DNS Reconnaissance", emoji_off)
    content.append(f"# {title}")
    content.append("")

    # Notion-style callout
    if emoji_off:
        content.append("> **Report Summary**")
    else:
        content.append("> 📊 **Report Summary**")
    content.append(f"> - Domain: `{domain}`")
    content.append(f"> - Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append(f"> - Records: {sum(len(records) for records in data.values())}")
    content.append("")

    if stats:
        content.extend(generate_stats_section(stats, "notion", emoji_off))

    if security_analysis:
        content.extend(
            generate_security_section(security_analysis, "notion", emoji_off)
        )

    if charts:
        content.extend(generate_charts_section(charts, "notion", emoji_off))

    content.extend(generate_data_sections(data, "notion", emoji_off))

    return "\n".join(content)


def generate_stats_section(
    stats: Dict, template: str, emoji_off: bool = False
) -> List[str]:
    """Generate statistics section for any template"""
    content = []

    if template == "obsidian":
        header = format_section_header("📊 Statistics Dashboard", emoji_off)
        content.append(f"## {header}")
    else:
        header = format_section_header("📊 Statistics", emoji_off)
        content.append(f"## {header}")

    content.append("")
    content.append(f"- **Total Records**: {stats['total_records']}")
    content.append(f"- **Unique IP Addresses**: {stats['unique_ips']}")
    content.append(f"- **Countries**: {len(stats['countries'])}")
    content.append(f"- **Organizations**: {len(stats['organizations'])}")
    content.append(f"- **ASNs**: {len(stats['asns'])}")
    content.append("")

    # Top countries
    if stats["countries"]:
        country_header = format_section_header("🌍 Top Countries", emoji_off)
        content.append(f"### {country_header}")
        content.append("")
        for country, count in list(stats["countries"].items())[:5]:
            percentage = (count / stats["total_records"]) * 100
            content.append(f"- **{country}**: {count} ({percentage:.1f}%)")
        content.append("")

    # Top organizations
    if stats["organizations"]:
        org_header = format_section_header("🏢 Top Organizations", emoji_off)
        content.append(f"### {org_header}")
        content.append("")
        for org, count in list(stats["organizations"].items())[:5]:
            percentage = (count / stats["total_records"]) * 100
            content.append(f"- **{org}**: {count} ({percentage:.1f}%)")
        content.append("")

    return content


def generate_security_section(
    security_analysis: Dict, template: str, emoji_off: bool = False
) -> List[str]:
    """Generate security analysis section"""
    content = []

    header = format_section_header("🔒 Security Analysis", emoji_off)
    content.append(f"## {header}")
    content.append("")

    # Risk assessment
    risk = security_analysis["risk_assessment"]
    if emoji_off:
        risk_indicator = f"[{risk.upper()}]"
    else:
        risk_emoji = "🔴" if risk == "high" else "🟡" if risk == "medium" else "🟢"
        risk_indicator = f"{risk_emoji} {risk.upper()}"

    content.append(f"**Overall Risk Level**: {risk_indicator}")
    content.append("")

    # Findings
    if security_analysis["findings"]:
        findings_header = format_section_header("🔍 Key Findings", emoji_off)
        content.append(f"### {findings_header}")
        content.append("")
        for finding in security_analysis["findings"]:
            content.append(f"- {finding}")
        content.append("")

    # Sensitive subdomains
    if security_analysis["sensitive_subdomains"]:
        sensitive_header = format_section_header(
            "⚠️ Potentially Sensitive Subdomains", emoji_off
        )
        content.append(f"### {sensitive_header}")
        content.append("")
        content.append("| Subdomain | IP | Keyword | Risk Level |")
        content.append("|-----------|----|---------| -----------|")
        for item in security_analysis["sensitive_subdomains"][:10]:
            content.append(
                f"| `{item['subdomain']}` | `{item['ip']}` | `{item['keyword']}` | {item['risk_level']} |"
            )
        content.append("")

    # Cloud exposure
    if security_analysis["cloud_exposure"]:
        cloud_header = format_section_header("☁️ Cloud Infrastructure", emoji_off)
        content.append(f"### {cloud_header}")
        content.append("")
        for provider, count in security_analysis["cloud_exposure"].items():
            content.append(f"- **{provider}**: {count} endpoints")
        content.append("")

    # Recommendations
    if security_analysis["recommendations"]:
        rec_header = format_section_header("💡 Security Recommendations", emoji_off)
        content.append(f"### {rec_header}")
        content.append("")
        for rec in security_analysis["recommendations"]:
            content.append(f"- {rec}")
        content.append("")

    return content


def generate_charts_section(
    charts: Dict, template: str, emoji_off: bool = False
) -> List[str]:
    """Generate charts section with Mermaid diagrams"""
    content = []

    header = format_section_header("📊 Visual Analysis", emoji_off)
    content.append(f"## {header}")
    content.append("")

    for chart_name, chart_content in charts.items():
        content.append(f"### {chart_name.title()} Overview")
        content.append("")
        content.append("```mermaid")
        content.append(chart_content.strip())
        content.append("```")
        content.append("")

    return content


def generate_timeline_section(timeline: Dict, template: str) -> List[str]:
    """Generate timeline section"""
    content = []

    content.append("## ⏰ Discovery Timeline")
    content.append("")
    content.append(f"- **Start**: {timeline['discovery_start']}")
    content.append(f"- **End**: {timeline['discovery_end']}")
    content.append(f"- **Duration**: {timeline['total_duration']}")
    content.append("")

    if timeline["phases"]:
        content.append("### Phase Breakdown")
        content.append("")
        for phase in timeline["phases"]:
            content.append(f"- **{phase['phase']}**: {phase['records']} records")
        content.append("")

    return content


def generate_data_sections(
    data: Dict[str, List[Dict]], template: str, emoji_off: bool = False
) -> List[str]:
    """Generate data sections with tables"""
    content = []

    for group_name, records in data.items():
        if group_name == "all":
            header = format_section_header("📋 Complete DNS Data", emoji_off)
            content.append(f"## {header}")
        else:
            header = format_section_header(f"📋 {group_name}", emoji_off)
            content.append(f"## {header}")

        content.append("")
        content.append(f"**Records in this section**: {len(records)}")
        content.append("")

        # Generate table
        content.append("| Subdomain | IP | PTR | ASN | Country | Organization | Tags |")
        content.append("|-----------|----|----|-----|---------|--------------|------|")

        for record in records[:50]:  # Limit to 50 records per section
            subdomain = record.get("subdomain") or record.get("domain", "")
            ip = record.get("ip", "")
            ptr = record.get("ptr", "–")

            asn_raw = record.get("asn", {})
            if isinstance(asn_raw, dict):
                asn = asn_raw.get("asn", "–")
            else:
                asn = str(asn_raw) if asn_raw else "–"

            country = record.get("country", "–")
            org = record.get("org", "–")
            tags = ", ".join(record.get("tags", []))

            # Truncate long fields
            if len(org) > 30:
                org = org[:27] + "..."
            if len(tags) > 40:
                tags = tags[:37] + "..."

            content.append(
                f"| `{subdomain}` | `{ip}` | `{ptr}` | `{asn}` | `{country}` | `{org}` | `{tags}` |"
            )

        if len(records) > 50:
            content.append("")
            content.append(f"*Showing first 50 of {len(records)} records*")

        content.append("")

    return content


def export_to_json(data: List[Dict], output_file: str, verbose: bool):
    """Export filtered data to JSON"""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        if verbose:
            click.echo(f"✅ JSON export saved to {output_file}")
    except Exception as e:
        click.echo(f"❌ Failed to export JSON: {e}")


def export_to_csv(data: List[Dict], output_file: str, verbose: bool):
    """Export filtered data to CSV"""
    try:
        import csv

        if not data:
            return

        # Get all possible field names
        fieldnames = set()
        for record in data:
            fieldnames.update(record.keys())

        # Common fields first
        ordered_fields = [
            "subdomain",
            "domain",
            "ip",
            "ptr",
            "country",
            "org",
            "asn",
            "city",
            "tags",
        ]
        fieldnames = [f for f in ordered_fields if f in fieldnames] + [
            f for f in fieldnames if f not in ordered_fields
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for record in data:
                # Handle complex fields
                row = {}
                for field in fieldnames:
                    value = record.get(field, "")
                    if isinstance(value, (list, dict)):
                        value = str(value)
                    row[field] = value
                writer.writerow(row)

        if verbose:
            click.echo(f"✅ CSV export saved to {output_file}")
    except Exception as e:
        click.echo(f"❌ Failed to export CSV: {e}")


def strip_emoji(text: str, emoji_off: bool) -> str:
    """Remove emoji from text if emoji_off is True"""
    if not emoji_off:
        return text

    # Simple emoji removal - usuwamy najbardziej popularne emoji używane w raportach
    emoji_map = {
        "🔍": "",
        "📊": "",
        "📈": "",
        "🔒": "",
        "⚠️": "",
        "☁️": "",
        "💡": "",
        "🌍": "",
        "🏢": "",
        "🔢": "",
        "📋": "",
        "⏰": "",
        "🔗": "",
        "✅": "",
        "❌": "",
        "🧠": "",
        "📝": "",
        "🎯": "",
        "🚀": "",
        "🛡️": "",
        "🔴": "",
        "🟡": "",
        "🟢": "",
        "📄": "",
        "🏷️": "",
        "🕷️": "",
        "🔹": "",
        "⭐": "",
        "💾": "",
        "🌐": "",
        "🎉": "",
        "⚡": "",
        "🛠️": "",
        "📦": "",
        "🔧": "",
        "💻": "",
        "📁": "",
        "📸": "",
    }

    result = text
    for emoji, replacement in emoji_map.items():
        result = result.replace(emoji, replacement)

    # Czyścimy podwójne spacje
    result = " ".join(result.split())

    return result


def format_title(title: str, emoji_off: bool) -> str:
    """Format title with or without emoji"""
    return strip_emoji(title, emoji_off)


def format_section_header(header: str, emoji_off: bool) -> str:
    """Format section header with or without emoji"""
    return strip_emoji(header, emoji_off)


def flatten_data(enriched_data: Union[Dict, List[Dict]]) -> List[Dict]:
    """Flatten enriched data from dict format to list format"""
    if isinstance(enriched_data, list):
        return enriched_data
    elif isinstance(enriched_data, dict):
        flat_data = []
        for record_type, entries in enriched_data.items():
            for entry in entries:
                if isinstance(entry, dict):
                    # Add record type to entry
                    entry_copy = entry.copy()
                    entry_copy["record_type"] = record_type
                    flat_data.append(entry_copy)
        return flat_data
    else:
        return []


if __name__ == "__main__":
    cli()
