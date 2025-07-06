import click
import subprocess
import os
import json
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from os.path import expanduser, exists as path_exists
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import re


def send_notification(webhook_url, message, service="slack"):
    """Send notification to Slack or Discord webhook."""
    try:
        if "discord" in webhook_url.lower() or service == "discord":
            payload = {"content": message}
        else:  # Slack
            payload = {"text": message}

        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False


def detect_technology(url, custom_headers=None, timeout=30):
    """Detect web technologies for a given URL."""
    try:
        headers = {"User-Agent": "VulnCLI/1.0 ReconCLI Security Scanner"}
        if custom_headers:
            for header in custom_headers.split(","):
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

        response = requests.get(url, headers=headers, timeout=timeout, verify=False)

        tech_stack = []

        # Server header detection
        server = response.headers.get("Server", "").lower()
        if "nginx" in server:
            tech_stack.append("Nginx")
        if "apache" in server:
            tech_stack.append("Apache")
        if "iis" in server:
            tech_stack.append("IIS")
        if "cloudflare" in server:
            tech_stack.append("Cloudflare")

        # X-Powered-By detection
        powered_by = response.headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            tech_stack.append("PHP")
        if "asp.net" in powered_by:
            tech_stack.append("ASP.NET")

        # Content analysis
        content = response.text.lower()
        if "wordpress" in content or "wp-content" in content:
            tech_stack.append("WordPress")
        if "drupal" in content:
            tech_stack.append("Drupal")
        if "joomla" in content:
            tech_stack.append("Joomla")
        if "react" in content:
            tech_stack.append("React")
        if "angular" in content:
            tech_stack.append("Angular")
        if "vue" in content:
            tech_stack.append("Vue.js")

        return {
            "url": url,
            "status_code": response.status_code,
            "technologies": tech_stack,
            "response_size": len(response.content),
            "response_time": response.elapsed.total_seconds(),
        }
    except Exception as e:
        return {"url": url, "status_code": 0, "technologies": [], "error": str(e)}


def check_wayback_machine(url):
    """Check if URL exists in Wayback Machine."""
    try:
        wayback_url = f"http://archive.org/wayback/available?url={url}"
        response = requests.get(wayback_url, timeout=10)
        data = response.json()
        return (
            data.get("archived_snapshots", {})
            .get("closest", {})
            .get("available", False)
        )
    except Exception:
        return False


def generate_json_report(output_dir, stats, scan_results):
    """Generate comprehensive JSON report."""
    report = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "scanner": "VulnCLI",
            "version": "1.0",
        },
        "statistics": stats,
        "scan_results": scan_results,
    }

    json_file = Path(output_dir) / "vulncli_report.json"
    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)
    return json_file


def generate_markdown_report(output_dir, stats, scan_results):
    """Generate comprehensive Markdown report."""
    md_content = f"""# 🎯 VulnCLI Vulnerability Scan Report

## 📊 Scan Statistics

- **🕐 Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **📁 Total URLs Processed**: {stats.get('total_urls', 0)}
- **🔍 Patterns Matched**: {stats.get('patterns_matched', 0)}
- **⚡ Vulnerabilities Found**: {stats.get('vulnerabilities_found', 0)}
- **🌐 Technologies Detected**: {len(stats.get('technologies', []))}

## 🎯 Scan Results by Tool

"""

    if scan_results.get("dalfox"):
        md_content += f"""### 🔥 Dalfox (XSS Scanner)
- **Status**: ✅ Completed
- **Findings**: {scan_results['dalfox'].get('findings', 0)}
- **Output File**: `dalfox.txt`

"""

    if scan_results.get("nuclei"):
        nuclei_data = scan_results["nuclei"]
        ai_info = ""
        if nuclei_data.get("ai_enhanced"):
            ai_info = " 🤖"
            if nuclei_data.get("original_findings"):
                ai_info += f" (AI filtered: {nuclei_data['original_findings']} → {nuclei_data['findings']})"

        md_content += f"""### ⚡ Nuclei (Multi-Vulnerability Scanner){ai_info}
- **Status**: ✅ Completed
- **Templates Used**: {nuclei_data.get('templates', 'Default')}
- **Findings**: {nuclei_data.get('findings', 0)}
- **Output File**: `nuclei.txt`

"""

    if scan_results.get("jaeles"):
        md_content += f"""### 🔧 Jaeles (Signature-based Scanner)
- **Status**: ✅ Completed
- **Signatures Used**: {scan_results['jaeles'].get('signatures', 'Default')}
- **Findings**: {scan_results['jaeles'].get('findings', 0)}
- **Output File**: `jaeles.txt`

"""

    if stats.get("technologies"):
        md_content += f"""## 🛠️ Detected Technologies

| Technology | Count |
|------------|-------|
"""
        for tech, count in stats.get("technologies", {}).items():
            md_content += f"| {tech} | {count} |\n"

    # AI Features section
    if stats.get("ai_features_used"):
        md_content += f"""
## 🤖 AI-Enhanced Analysis

**AI Features Used**: {', '.join(stats['ai_features_used'])}

"""
        if "smart_templates" in stats["ai_features_used"]:
            md_content += "- **Smart Template Selection**: AI analyzed target characteristics to select optimal Nuclei templates\n"
        if "false_positive_reduction" in stats["ai_features_used"]:
            md_content += "- **False Positive Reduction**: AI filtered scan results to reduce noise and improve accuracy\n"
        if "vulnerability_classification" in stats["ai_features_used"]:
            md_content += "- **Vulnerability Classification**: AI classified and scored vulnerabilities for better prioritization\n"
        if "executive_summary" in stats["ai_features_used"]:
            md_content += "- **Executive Summary**: AI generated risk assessment and recommendations\n"

    md_content += f"""
## 📝 Notes

- Scan performed using VulnCLI - Advanced Vulnerability Scanner
- Results may contain false positives - manual verification recommended
- For detailed findings, check individual tool output files

---
**Generated by**: VulnCLI v1.0 | **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    md_file = Path(output_dir) / "vulncli_report.md"
    with open(md_file, "w") as f:
        f.write(md_content)
    return md_file


def ai_classify_vulnerability(finding, tech_stack=None):
    """AI-powered vulnerability classification and risk scoring."""
    try:
        # Extract vulnerability type and severity
        vuln_type = "unknown"
        severity = "info"
        confidence = 0.5
        risk_score = 1.0

        finding_lower = finding.lower()

        # AI-like pattern matching for vulnerability classification
        vuln_patterns = {
            "sql injection": {"severity": "critical", "risk": 9.0, "confidence": 0.9},
            "xss": {"severity": "high", "risk": 7.5, "confidence": 0.8},
            "path traversal": {"severity": "high", "risk": 8.0, "confidence": 0.85},
            "command injection": {
                "severity": "critical",
                "risk": 9.5,
                "confidence": 0.9,
            },
            "authentication bypass": {
                "severity": "critical",
                "risk": 9.0,
                "confidence": 0.8,
            },
            "sensitive disclosure": {
                "severity": "medium",
                "risk": 6.0,
                "confidence": 0.7,
            },
            "misconfiguration": {"severity": "medium", "risk": 5.5, "confidence": 0.6},
            "cve-": {"severity": "high", "risk": 7.0, "confidence": 0.8},
            "exposure": {"severity": "medium", "risk": 5.0, "confidence": 0.6},
        }

        for pattern, attrs in vuln_patterns.items():
            if pattern in finding_lower:
                vuln_type = pattern
                severity = attrs["severity"]
                risk_score = attrs["risk"]
                confidence = attrs["confidence"]
                break

        # Adjust risk based on technology stack
        if tech_stack:
            if "wordpress" in [t.lower() for t in tech_stack]:
                risk_score += 0.5  # WordPress sites often have more attack surface
            if "php" in [t.lower() for t in tech_stack]:
                risk_score += 0.3  # PHP apps may have more injection risks

        # Cap risk score at 10.0
        risk_score = min(risk_score, 10.0)

        return {
            "type": vuln_type,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": confidence,
            "ai_enhanced": True,
        }

    except Exception:
        return {
            "type": "unknown",
            "severity": "info",
            "risk_score": 1.0,
            "confidence": 0.3,
            "ai_enhanced": False,
        }


def ai_reduce_false_positives(findings, tech_stack=None, url_context=None):
    """AI-powered false positive reduction using context analysis."""
    filtered_findings = []

    for finding in findings:
        keep_finding = True
        confidence_adjustment = 0.0

        finding_lower = finding.lower()

        # Common false positive patterns
        false_positive_patterns = [
            "test.html",
            "example.com",
            "localhost",
            "127.0.0.1",
            "demo",
            "placeholder",
        ]

        # Check for false positive indicators
        for fp_pattern in false_positive_patterns:
            if fp_pattern in finding_lower:
                confidence_adjustment -= 0.3

        # Context-based filtering
        if url_context:
            # If finding doesn't match URL context, likely false positive
            if "sql" in finding_lower and not any(
                param in url_context for param in ["id", "search", "query"]
            ):
                confidence_adjustment -= 0.2

        # Technology stack validation
        if tech_stack:
            if "asp.net" in finding_lower and "PHP" in tech_stack:
                confidence_adjustment -= 0.4  # ASP.NET finding on PHP site
            if "wordpress" in finding_lower and "WordPress" not in tech_stack:
                confidence_adjustment -= 0.3

        # Keep finding if confidence is still reasonable
        if confidence_adjustment > -0.5:
            filtered_findings.append(
                {
                    "original": finding,
                    "confidence_adjustment": confidence_adjustment,
                    "likely_valid": True,
                }
            )
        else:
            filtered_findings.append(
                {
                    "original": finding,
                    "confidence_adjustment": confidence_adjustment,
                    "likely_valid": False,
                    "reason": "AI flagged as likely false positive",
                }
            )

    return filtered_findings


def ai_smart_template_selection(url_list, tech_stack=None, target_types=None):
    """AI-powered smart template selection based on target analysis."""
    recommended_templates = []

    # Analyze URL patterns
    url_patterns = {
        "admin": 0,
        "api": 0,
        "login": 0,
        "upload": 0,
        "search": 0,
        "download": 0,
        "file": 0,
        "config": 0,
    }

    # Count pattern occurrences
    for url in url_list[:100]:  # Sample first 100 URLs
        url_lower = url.lower()
        for pattern in url_patterns:
            if pattern in url_lower:
                url_patterns[pattern] += 1

    # Technology-based template recommendations
    tech_templates = {
        "WordPress": ["http/cms/wordpress/", "http/vulnerabilities/wordpress/"],
        "Drupal": ["http/cms/drupal/", "http/vulnerabilities/drupal/"],
        "PHP": ["http/vulnerabilities/php/", "http/file-upload/"],
        "Apache": ["http/misconfiguration/apache/", "http/exposures/configs/"],
        "Nginx": ["http/misconfiguration/nginx/", "http/exposures/configs/"],
        "IIS": ["http/misconfiguration/iis/", "http/vulnerabilities/microsoft/"],
    }

    # Add tech-specific templates
    if tech_stack:
        for tech in tech_stack:
            if tech in tech_templates:
                recommended_templates.extend(tech_templates[tech])

    # Pattern-based template recommendations
    if url_patterns["admin"] > 2:
        recommended_templates.extend(["http/exposures/panels/", "http/default-logins/"])
    if url_patterns["api"] > 3:
        recommended_templates.extend(["http/exposures/apis/", "http/misconfiguration/"])
    if url_patterns["upload"] > 1:
        recommended_templates.extend(
            ["http/file-upload/", "http/vulnerabilities/generic/"]
        )
    if url_patterns["login"] > 1:
        recommended_templates.extend(
            ["http/default-logins/", "http/vulnerabilities/auth/"]
        )

    # Always include safe essentials
    essential_templates = [
        "http/exposures/configs/",
        "http/exposures/files/",
        "http/technologies/",
        "http/misconfiguration/",
    ]
    recommended_templates.extend(essential_templates)

    # Remove duplicates and return
    return list(set(recommended_templates))


def ai_generate_executive_summary(stats, scan_results, tech_stack=None):
    """AI-powered executive summary generation."""
    total_vulns = stats.get("vulnerabilities_found", 0)
    total_urls = stats.get("total_urls", 0)

    # Risk level assessment
    if total_vulns == 0:
        risk_level = "LOW"
        risk_color = "🟢"
    elif total_vulns <= 5:
        risk_level = "MEDIUM"
        risk_color = "🟡"
    elif total_vulns <= 15:
        risk_level = "HIGH"
        risk_color = "🟠"
    else:
        risk_level = "CRITICAL"
        risk_color = "🔴"

    # Generate recommendations
    recommendations = []

    if total_vulns > 0:
        recommendations.append("Immediate manual verification of all findings required")
        recommendations.append("Implement security headers and input validation")

    if tech_stack:
        if "WordPress" in tech_stack:
            recommendations.append("Update WordPress core, themes, and plugins")
        if "PHP" in tech_stack:
            recommendations.append(
                "Review PHP configuration and disable dangerous functions"
            )
        if "Apache" in tech_stack or "Nginx" in tech_stack:
            recommendations.append(
                "Review web server configuration for security misconfigurations"
            )

    if total_vulns > 10:
        recommendations.append("Consider engaging professional security assessment")

    # Coverage assessment
    coverage_score = min((total_urls / 100) * 100, 100)  # Simple coverage metric

    summary = f"""
## 🤖 AI-Powered Executive Summary

### Risk Assessment
- **Overall Risk Level**: {risk_color} **{risk_level}**
- **Vulnerability Density**: {total_vulns}/{total_urls} URLs ({(total_vulns/max(total_urls,1)*100):.1f}%)
- **Coverage Score**: {coverage_score:.0f}%

### Key Findings
- Total vulnerabilities detected: **{total_vulns}**
- Target technologies: {', '.join(tech_stack) if tech_stack else 'Not detected'}
- Scan coverage: {total_urls} URLs processed

### AI Recommendations
"""

    for i, rec in enumerate(recommendations, 1):
        summary += f"{i}. {rec}\n"

    summary += f"""
### Next Steps
1. **Immediate**: Verify high/critical severity findings manually
2. **Short-term**: Implement recommended security controls
3. **Long-term**: Establish regular security testing schedule

*This summary was generated using AI-enhanced analysis of scan results.*
"""

    return summary


@click.command()
@click.option("--input-file", "-i", required=True, help="Input file with URLs.")
@click.option("--output-dir", "-o", required=True, help="Directory to save results.")
@click.option(
    "--patterns", "-p", default="xss,lfi,sqli", help="Comma-separated gf patterns."
)
@click.option(
    "--gf-dir",
    default=os.path.abspath(os.path.join(os.path.dirname(__file__), "gf_patterns")),
    help="Local GF pattern directory.",
)
@click.option(
    "--gf-mode",
    type=click.Choice(["local", "global", "both"]),
    default="local",
    help="Choose gf mode.",
)
@click.option("--run-dalfox", is_flag=True, help="Run Dalfox on xss.txt.")
@click.option("--run-jaeles", is_flag=True, help="Run Jaeles scan.")
@click.option("--run-nuclei", is_flag=True, help="Run Nuclei scan.")
@click.option("--resume", is_flag=True, help="Skip steps if output exists.")
@click.option("--dedup", is_flag=True, help="Deduplicate URLs.")
@click.option(
    "--extract-params", is_flag=True, help="Filter URLs with query parameters."
)
@click.option(
    "--param-filter", help="Comma-separated param names to keep (e.g. id,file,path)"
)
@click.option("--blind", help="Blind XSS listener for Dalfox.")
@click.option("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080).")
@click.option("--jaeles-signatures", help="Path to custom Jaeles signatures.")
@click.option(
    "--jaeles-select",
    help="Jaeles signature selector (e.g., 'fuzz/sqli/.*', 'common/.*', 'sensitive/.*').",
)
@click.option(
    "--jaeles-exclude",
    help="Jaeles signature exclusion selector (e.g., 'experimental/.*').",
)
@click.option(
    "--jaeles-level",
    type=int,
    default=1,
    help="Filter Jaeles signatures by level (1-5).",
)
@click.option("--nuclei-tags", help="Comma-separated tags for Nuclei.")
@click.option("--nuclei-templates", help="Path to custom Nuclei templates.")
@click.option(
    "--nuclei-select",
    help="Nuclei template selector (e.g., 'http/cves/', 'http/exposures/', 'network/').",
)
@click.option(
    "--nuclei-exclude",
    help="Nuclei template exclusion selector (e.g., 'http/fuzzing/').",
)
@click.option(
    "--nuclei-severity", help="Nuclei severity filter (e.g., 'critical,high,medium')."
)
@click.option(
    "--severity-filter",
    help="Comma-separated severities to keep (e.g. critical,high,info)",
)
@click.option("--rl", type=int, help="Rate limit (requests per second).")
@click.option("--concurrency", type=int, help="Number of concurrent threads.")
@click.option("--retry", type=int, help="Retry attempts for supported tools.")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output with progress tracking.",
)
@click.option(
    "--json", "output_json", is_flag=True, help="Generate JSON report with statistics."
)
@click.option(
    "--markdown",
    "output_markdown",
    is_flag=True,
    help="Generate comprehensive Markdown report.",
)
@click.option("--slack-webhook", help="Slack webhook URL for notifications.")
@click.option("--discord-webhook", help="Discord webhook URL for notifications.")
@click.option(
    "--live-stats", is_flag=True, help="Show live statistics during scanning."
)
@click.option(
    "--custom-headers", help="Custom headers for HTTP requests (key:value,key2:value2)."
)
@click.option("--timeout", type=int, default=30, help="HTTP timeout for requests.")
@click.option(
    "--timeout-nuclei",
    type=int,
    default=300,
    help="Timeout for Nuclei scan in seconds.",
)
@click.option(
    "--exclude-extensions",
    help="Comma-separated extensions to exclude (e.g. css,js,png).",
)
@click.option(
    "--include-status-codes",
    help="Comma-separated HTTP status codes to include (e.g. 200,302,403).",
)
@click.option(
    "--technology-detect",
    is_flag=True,
    help="Detect web technologies on discovered URLs.",
)
@click.option(
    "--wayback-filter", is_flag=True, help="Filter URLs by Wayback Machine presence."
)
@click.option(
    "--wordlist-fuzz", help="Wordlist for additional fuzzing (e.g. common endpoints)."
)
@click.option(
    "--ai-mode",
    is_flag=True,
    help="Enable AI-powered vulnerability analysis and template selection.",
)
@click.option(
    "--ai-reduce-fp",
    is_flag=True,
    help="Use AI to reduce false positives in scan results.",
)
@click.option(
    "--ai-smart-templates",
    is_flag=True,
    help="AI-powered smart Nuclei template selection based on target analysis.",
)
@click.option(
    "--ai-executive-summary",
    is_flag=True,
    help="Generate AI-powered executive summary with risk assessment.",
)
@click.option(
    "--ai-confidence-threshold",
    type=float,
    default=0.6,
    help="Minimum confidence threshold for AI findings (0.0-1.0).",
)
def vulncli(
    input_file,
    output_dir,
    patterns,
    gf_dir,
    gf_mode,
    run_dalfox,
    run_jaeles,
    run_nuclei,
    resume,
    dedup,
    extract_params,
    param_filter,
    blind,
    proxy,
    jaeles_signatures,
    jaeles_select,
    jaeles_exclude,
    jaeles_level,
    nuclei_tags,
    nuclei_templates,
    nuclei_select,
    nuclei_exclude,
    nuclei_severity,
    severity_filter,
    rl,
    concurrency,
    retry,
    verbose,
    output_json,
    output_markdown,
    slack_webhook,
    discord_webhook,
    live_stats,
    custom_headers,
    timeout,
    timeout_nuclei,
    exclude_extensions,
    include_status_codes,
    technology_detect,
    wayback_filter,
    wordlist_fuzz,
    ai_mode,
    ai_reduce_fp,
    ai_smart_templates,
    ai_executive_summary,
    ai_confidence_threshold,
):
    """🎯 Advanced vulnerability scanning with GF, Dalfox, Jaeles, and Nuclei

    Comprehensive URL filtering and vulnerability scanning pipeline with:
    • GF pattern matching (XSS, LFI, SQLi, etc.)
    • Parameter extraction and filtering
    • Technology detection and analysis
    • Multi-tool vulnerability scanning with selective template/signature usage
    • Professional reporting (JSON/Markdown)
    • Real-time notifications (Slack/Discord)
    • Resume functionality for large scans
    • 🤖 AI-powered vulnerability analysis and false positive reduction

    AI Features:
    --ai-mode                       # Enable all AI capabilities
    --ai-smart-templates            # AI selects optimal Nuclei templates
    --ai-reduce-fp                  # Reduce false positives using AI
    --ai-executive-summary          # Generate AI-powered executive summary
    --ai-confidence-threshold 0.8   # Set AI confidence threshold

    Jaeles Signature Examples:
    --jaeles-select 'sensitive/.*'     # Only sensitive signatures
    --jaeles-select 'fuzz/sqli/.*'     # Only SQL injection fuzzing
    --jaeles-select 'common/.*'        # Only common vulnerability checks
    --jaeles-exclude 'experimental/.*' # Exclude experimental signatures
    --jaeles-level 2                   # Only level 2+ signatures

    Nuclei Template Examples:
    --nuclei-select 'http/cves/'       # Only CVE templates
    --nuclei-select 'http/exposures/'  # Only exposure templates
    --nuclei-select 'http/cves/,dns/'  # CVE and DNS templates
    --nuclei-exclude 'http/fuzzing/'   # Exclude fuzzing templates
    --nuclei-severity 'critical,high'  # Only critical/high severity
    --nuclei-tags 'exposure,misconfig' # Use specific tags
    """

    # Initialize scan statistics
    start_time = time.time()
    stats = {
        "total_urls": 0,
        "patterns_matched": 0,
        "vulnerabilities_found": 0,
        "technologies": {},
        "scan_tools": [],
        "ai_features_used": [],
    }
    scan_results = {}

    # Track AI features
    if ai_mode:
        stats["ai_features_used"].extend(
            [
                "smart_templates",
                "false_positive_reduction",
                "executive_summary",
                "vulnerability_classification",
            ]
        )
    else:
        if ai_smart_templates:
            stats["ai_features_used"].append("smart_templates")
        if ai_reduce_fp:
            stats["ai_features_used"].append("false_positive_reduction")
        if ai_executive_summary:
            stats["ai_features_used"].append("executive_summary")

    if verbose:
        click.echo(
            f"🎯 [VulnCLI] Starting vulnerability scan at {datetime.now().strftime('%H:%M:%S')}"
        )
        click.echo(f"📁 Input file: {input_file}")
        click.echo(f"📂 Output directory: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)
    patterns = patterns.split(",")
    all_urls = []

    # Check if local GF patterns directory exists and has content
    if not os.path.isdir(gf_dir) or not os.listdir(gf_dir):
        if verbose:
            click.echo(
                f"⚠️ [GF] Local GF patterns not found or empty – falling back to global (~/.gf/)"
            )
        else:
            click.echo(
                "[!] Local GF patterns not found or empty – falling back to global (~/.gf/)"
            )
        gf_mode = "global"

    # Send start notification
    if slack_webhook or discord_webhook:
        start_msg = f"🎯 VulnCLI scan started\\nInput: {input_file}\\nPatterns: {', '.join(patterns)}"
        if slack_webhook:
            send_notification(slack_webhook, start_msg, "slack")
        if discord_webhook:
            send_notification(discord_webhook, start_msg, "discord")

    # === GF FILTERING ===
    if verbose:
        click.echo(f"🔍 [GF] Processing {len(patterns)} patterns...")

    for i, pattern in enumerate(patterns, 1):
        if verbose:
            click.echo(f"🔍 [GF] [{i}/{len(patterns)}] Processing pattern: {pattern}")

        out_path = Path(output_dir) / f"{pattern}.txt"
        combined = ""

        if gf_mode in ["local", "both"]:
            try:
                # Set GF_PATTERNS environment variable for local patterns
                env = os.environ.copy()
                env["GF_PATTERNS"] = gf_dir
                result = subprocess.run(
                    ["gf", pattern],
                    input=open(input_file, "rb").read(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    check=True,
                )
                combined += result.stdout.decode("utf-8", errors="ignore")
                if verbose:
                    click.echo(
                        f"  ✅ Local pattern matched: {len(result.stdout.decode('utf-8', errors='ignore').splitlines())} URLs"
                    )
            except subprocess.CalledProcessError:
                if verbose:
                    click.echo(f"  ❌ Local pattern failed")

        if gf_mode in ["global", "both"]:
            try:
                result = subprocess.run(
                    ["gf", pattern],
                    input=open(input_file, "rb").read(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                combined += result.stdout.decode("utf-8", errors="ignore")
                if verbose:
                    click.echo(
                        f"  ✅ Global pattern matched: {len(result.stdout.decode('utf-8', errors='ignore').splitlines())} URLs"
                    )
            except subprocess.CalledProcessError:
                if verbose:
                    click.echo(f"  ❌ Global pattern failed")

        with open(out_path, "w") as f:
            f.write(combined)
        pattern_urls = combined.splitlines()
        all_urls.extend(pattern_urls)
        stats["patterns_matched"] += len(pattern_urls)

        if verbose:
            click.echo(f"  💾 Saved: {pattern}.txt ({len(pattern_urls)} URLs)")
        else:
            click.echo(f"[+] Saved: {pattern}.txt")

    if dedup:
        original_count = len(all_urls)
        all_urls = list(set(all_urls))
        if verbose:
            click.echo(
                f"🔄 [DEDUP] Removed {original_count - len(all_urls)} duplicates"
            )
        click.echo(f"[✓] Deduplicated: {len(all_urls)} URLs")

    # === ADVANCED URL FILTERING ===
    if exclude_extensions:
        original_count = len(all_urls)
        excluded_exts = exclude_extensions.split(",")
        all_urls = [
            url
            for url in all_urls
            if not any(url.lower().endswith(f".{ext}") for ext in excluded_exts)
        ]
        if verbose:
            click.echo(
                f"🚫 [FILTER] Excluded {original_count - len(all_urls)} URLs with extensions: {exclude_extensions}"
            )

    # === WAYBACK MACHINE FILTERING ===
    if wayback_filter:
        if verbose:
            click.echo(f"🕰️ [WAYBACK] Filtering URLs through Wayback Machine...")
        wayback_filtered = []
        with ThreadPoolExecutor(max_workers=concurrency or 10) as executor:
            future_to_url = {
                executor.submit(check_wayback_machine, url): url
                for url in all_urls[:100]
            }  # Limit for demo
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    if future.result():
                        wayback_filtered.append(url)
                except Exception:
                    pass
        all_urls = wayback_filtered
        if verbose:
            click.echo(
                f"🕰️ [WAYBACK] Kept {len(all_urls)} URLs found in Wayback Machine"
            )

    stats["total_urls"] = len(all_urls)

    # === TECHNOLOGY DETECTION ===
    if technology_detect and all_urls:
        if verbose:
            click.echo(
                f"🛠️ [TECH] Detecting technologies on {min(len(all_urls), 50)} URLs..."
            )

        tech_results = []
        urls_to_check = all_urls[:50]  # Limit for performance

        with ThreadPoolExecutor(max_workers=concurrency or 5) as executor:
            future_to_url = {
                executor.submit(detect_technology, url, custom_headers, timeout): url
                for url in urls_to_check
            }

            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    tech_results.append(result)

                    # Count technologies
                    for tech in result.get("technologies", []):
                        stats["technologies"][tech] = (
                            stats["technologies"].get(tech, 0) + 1
                        )

                    if verbose and result.get("technologies"):
                        click.echo(
                            f"  🛠️ {result['url'][:50]}... → {', '.join(result['technologies'])}"
                        )
                except Exception:
                    pass

        # Save technology detection results
        tech_file = Path(output_dir) / "technology_detection.json"
        with open(tech_file, "w") as f:
            json.dump(tech_results, f, indent=2)

        if verbose:
            click.echo(
                f"🛠️ [TECH] Detected {len(stats['technologies'])} unique technologies"
            )

    # === PARAMETER EXTRACTION ===
    if extract_params:
        param_summary = {}
        param_filter_set = set(param_filter.split(",")) if param_filter else set()
        params_dir = Path(output_dir) / "params"
        params_dir.mkdir(exist_ok=True)
        filtered_urls = []

        with open(params_dir / "params.txt", "w") as pf:
            for url in all_urls:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                matched = False
                for key in qs:
                    pf.write(f"{url} → param: {key}\n")
                    # Sanitize parameter name for filename
                    safe_key = (
                        key.replace("/", "_")
                        .replace("\\", "_")
                        .replace(":", "_")
                        .replace("*", "_")
                        .replace("?", "_")
                        .replace('"', "_")
                        .replace("<", "_")
                        .replace(">", "_")
                        .replace("|", "_")
                    )
                    param_file = params_dir / f"params_{safe_key}.txt"
                    with open(param_file, "a") as single:
                        single.write(url + "\n")
                    if not param_filter_set or key in param_filter_set:
                        matched = True
                        param_summary[key] = param_summary.get(key, 0) + 1
                if matched:
                    filtered_urls.append(url)

        if param_filter_set:
            all_urls = list(set(filtered_urls))
            with open(params_dir / "filtered_params.txt", "w") as ff:
                ff.write("\n".join(all_urls))
            click.echo(f"[✓] Filtered parameters: {len(all_urls)} URLs")

    all_file = Path(output_dir) / "all.txt"
    with open(all_file, "w") as f:
        f.write("\n".join(all_urls))

    # === DALFOX ===
    if run_dalfox:
        stats["scan_tools"].append("Dalfox")
        xss_file = Path(output_dir) / "xss.txt"
        dalfox_out = Path(output_dir) / "dalfox.txt"
        if resume and dalfox_out.exists():
            if verbose:
                click.echo("🔄 [DALFOX] Skipping Dalfox (resume mode)")
            else:
                click.echo("[↻] Skipping Dalfox (resume mode)")
        elif xss_file.exists() and os.path.getsize(xss_file) > 0:
            if verbose:
                click.echo(f"🔥 [DALFOX] Starting XSS scan on {xss_file}...")

            dalfox_cmd = ["dalfox", "file", str(xss_file), "--silence"]
            if proxy:
                dalfox_cmd += ["--proxy", proxy]
            if blind:
                dalfox_cmd += ["--blind", blind]
            if rl:
                dalfox_cmd += ["--delay", str(1 / rl)]
            if concurrency:
                dalfox_cmd += ["--worker", str(concurrency)]
            if retry:
                dalfox_cmd += ["--retry", str(retry)]

            with open(dalfox_out, "w") as out:
                result = subprocess.run(
                    dalfox_cmd, stdout=out, stderr=subprocess.DEVNULL
                )

            # Count findings
            if dalfox_out.exists():
                with open(dalfox_out, "r") as f:
                    findings = len(
                        [line for line in f if "VULN" in line or "POC" in line]
                    )
                scan_results["dalfox"] = {"findings": findings}
                stats["vulnerabilities_found"] += findings

                if verbose:
                    click.echo(
                        f"🔥 [DALFOX] Completed! Found {findings} potential XSS vulnerabilities"
                    )

            click.echo(f"[✓] Dalfox done: {dalfox_out}")
        else:
            if verbose:
                click.echo("⚠️ [DALFOX] No XSS patterns found, skipping Dalfox")

    # === JAELES ===
    if run_jaeles:
        stats["scan_tools"].append("Jaeles")
        jaeles_out = Path(output_dir) / "jaeles.txt"
        if resume and jaeles_out.exists():
            if verbose:
                click.echo("🔄 [JAELES] Skipping Jaeles (resume mode)")
            else:
                click.echo("[↻] Skipping Jaeles (resume mode)")
        else:
            # Determine signature selection
            signature_info = "Default"
            if jaeles_signatures:
                signature_info = f"Custom: {jaeles_signatures}"
            elif jaeles_select:
                signature_info = f"Selected: {jaeles_select}"
                if jaeles_exclude:
                    signature_info += f" (excluding: {jaeles_exclude})"

            if verbose:
                click.echo(f"🔧 [JAELES] Starting signature-based scan...")
                click.echo(f"🔧 [JAELES] Signatures: {signature_info}")

            jaeles_cmd = ["jaeles", "scan", "-u", str(all_file)]

            # Add signature selection
            if jaeles_signatures:
                jaeles_cmd += ["--sig", jaeles_signatures]
            elif jaeles_select:
                jaeles_cmd += ["-s", jaeles_select]
            else:
                # Use professional signatures if available
                pro_signatures = expanduser("~/Documents/pro-signatures/")
                if path_exists(pro_signatures):
                    jaeles_cmd += ["-s", f"{pro_signatures}/sensitive/.*"]
                    signature_info = "Pro: sensitive signatures"
                    if verbose:
                        click.echo(
                            f"🔧 [JAELES] Using pro signatures: {pro_signatures}"
                        )
                else:
                    # Use passive mode for safety when no specific signatures
                    jaeles_cmd += ["--passive"]

            # Add exclusions
            if jaeles_exclude:
                jaeles_cmd += ["-x", jaeles_exclude]

            # Add level filter
            if jaeles_level != 1:
                jaeles_cmd += ["-L", str(jaeles_level)]

            # Add other options
            if proxy:
                jaeles_cmd += ["--proxy", proxy]
            if rl:
                jaeles_cmd += ["--delay", str(1000 / rl)]  # Convert to milliseconds
            if concurrency:
                jaeles_cmd += ["-c", str(concurrency)]
            if retry:
                if verbose:
                    click.echo(
                        "[!] Retry not supported in Jaeles – skipping retry flag."
                    )

            with open(jaeles_out, "w") as out:
                subprocess.run(jaeles_cmd, stdout=out, stderr=subprocess.DEVNULL)

            # Count findings
            if jaeles_out.exists():
                with open(jaeles_out, "r") as f:
                    findings = len(
                        [line for line in f if "[VULN]" in line or "[INFO]" in line]
                    )
                scan_results["jaeles"] = {
                    "findings": findings,
                    "signatures": signature_info,
                }
                stats["vulnerabilities_found"] += findings

                if verbose:
                    click.echo(
                        f"🔧 [JAELES] Completed! Found {findings} potential vulnerabilities"
                    )

            click.echo(f"[✓] Jaeles done: {jaeles_out}")

    # === NUCLEI ===
    if run_nuclei:
        stats["scan_tools"].append("Nuclei")
        nuclei_out = Path(output_dir) / "nuclei.txt"
        if resume and nuclei_out.exists():
            if verbose:
                click.echo("🔄 [NUCLEI] Skipping Nuclei (resume mode)")
            else:
                click.echo("[↻] Skipping Nuclei (resume mode)")
        else:
            # AI-powered smart template selection
            if ai_mode or ai_smart_templates:
                if verbose:
                    click.echo(
                        "🤖 [AI] Analyzing targets for smart template selection..."
                    )

                # Get technology stack for AI analysis
                tech_list = list(stats.get("technologies", {}).keys())
                smart_templates = ai_smart_template_selection(all_urls, tech_list)

                if verbose:
                    click.echo(
                        f"🤖 [AI] Recommended {len(smart_templates)} template categories"
                    )
                    for template in smart_templates[:5]:  # Show first 5
                        click.echo(f"  🎯 {template}")
                    if len(smart_templates) > 5:
                        click.echo(f"  ... and {len(smart_templates) - 5} more")

            # Determine template selection
            template_info = "Default"
            if nuclei_templates:
                template_info = f"Custom: {nuclei_templates}"
            elif nuclei_select:
                template_info = f"Selected: {nuclei_select}"
                if nuclei_exclude:
                    template_info += f" (excluding: {nuclei_exclude})"
            elif nuclei_tags:
                template_info = f"Tags: {nuclei_tags}"
            elif nuclei_severity:
                template_info = f"Severity: {nuclei_severity}"
            elif ai_mode or ai_smart_templates:
                template_info = f"AI-Selected: {len(smart_templates)} categories"

            if verbose:
                click.echo(f"⚡ [NUCLEI] Starting multi-vulnerability scan...")
                click.echo(f"⚡ [NUCLEI] Templates: {template_info}")

            nuclei_cmd = ["nuclei", "-l", str(all_file)]

            # Add template selection
            if nuclei_templates:
                nuclei_cmd += ["-t", nuclei_templates]
            elif nuclei_select:
                # Handle multiple selectors separated by comma
                selectors = nuclei_select.split(",")
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    for selector in selectors:
                        selector = selector.strip()
                        # Remove leading slash if present to avoid double slashes
                        if selector.startswith("/"):
                            selector = selector[1:]
                        template_path = f"{default_tpl.rstrip('/')}/{selector}"
                        if path_exists(template_path):
                            nuclei_cmd += ["-t", template_path]
                            if verbose:
                                click.echo(
                                    f"⚡ [NUCLEI] Added templates: {template_path}"
                                )
                        else:
                            if verbose:
                                click.echo(
                                    f"⚠️ [NUCLEI] Template path not found: {template_path}"
                                )
            elif ai_mode or ai_smart_templates:
                # Use AI-recommended templates
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    templates_added = 0
                    for template in smart_templates:
                        template_path = f"{default_tpl.rstrip('/')}/{template}"
                        if path_exists(template_path):
                            nuclei_cmd += ["-t", template_path]
                            templates_added += 1
                            if verbose:
                                click.echo(f"🤖 [AI] Added template: {template}")

                    if templates_added == 0:
                        # Fallback to safe defaults if AI templates not found
                        safe_defaults = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                        ]
                        for template in safe_defaults:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
            else:
                # Smart defaults based on options
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    if nuclei_tags:
                        # Use tags mode
                        nuclei_cmd += ["-tags", nuclei_tags]
                        template_info = f"Tags: {nuclei_tags}"
                    elif nuclei_severity:
                        # Use severity filtering with safe template categories
                        safe_templates = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                            "http/cves/",
                            "dns/",
                            "ssl/",
                        ]
                        for template in safe_templates:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
                    else:
                        # Conservative default - only safe categories
                        safe_defaults = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                        ]
                        for template in safe_defaults:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
                        template_info = "Safe defaults: exposures, misconfig, tech"

                    if verbose:
                        click.echo(
                            f"⚡ [NUCLEI] Using default templates: {default_tpl}"
                        )

            # Add exclusions
            if nuclei_exclude:
                # Handle multiple exclusions separated by comma
                exclusions = nuclei_exclude.split(",")
                for exclusion in exclusions:
                    nuclei_cmd += ["-exclude-templates", exclusion.strip()]

            # Add severity filtering
            if nuclei_severity:
                nuclei_cmd += ["-severity", nuclei_severity]

            # Add other options
            if proxy:
                nuclei_cmd += ["-proxy", proxy]
            if rl:
                nuclei_cmd += ["-rate-limit", str(rl)]
            if concurrency:
                nuclei_cmd += ["-c", str(concurrency)]
            if retry:
                nuclei_cmd += ["-retries", str(retry)]

            # Add timeout
            nuclei_cmd += ["-timeout", str(timeout_nuclei)]

            with open(nuclei_out, "w") as out:
                subprocess.run(nuclei_cmd, stdout=out, stderr=subprocess.DEVNULL)

            # Count findings and apply AI analysis
            if nuclei_out.exists():
                with open(nuclei_out, "r") as f:
                    raw_findings = [
                        line.strip() for line in f if "[" in line and "]" in line
                    ]

                findings_count = len(raw_findings)
                ai_analyzed_findings = []

                # AI-powered analysis of findings
                if (ai_mode or ai_reduce_fp) and raw_findings:
                    if verbose:
                        click.echo(
                            f"🤖 [AI] Analyzing {findings_count} findings for false positives..."
                        )

                    # Analyze findings with AI
                    tech_list = list(stats.get("technologies", {}).keys())
                    filtered_findings = ai_reduce_false_positives(
                        raw_findings, tech_list, str(all_file)
                    )

                    # Classify vulnerabilities
                    for i, finding_data in enumerate(filtered_findings):
                        if finding_data["likely_valid"]:
                            classification = ai_classify_vulnerability(
                                finding_data["original"], tech_list
                            )
                            ai_analyzed_findings.append(
                                {
                                    "original": finding_data["original"],
                                    "classification": classification,
                                    "confidence": classification["confidence"]
                                    + finding_data["confidence_adjustment"],
                                }
                            )

                    # Filter by confidence threshold
                    high_confidence_findings = [
                        f
                        for f in ai_analyzed_findings
                        if f["confidence"] >= ai_confidence_threshold
                    ]

                    # Save AI analysis results
                    ai_analysis_file = Path(output_dir) / "nuclei_ai_analysis.json"
                    with open(ai_analysis_file, "w") as f:
                        json.dump(
                            {
                                "total_findings": findings_count,
                                "ai_filtered_findings": len(high_confidence_findings),
                                "false_positives_removed": findings_count
                                - len(high_confidence_findings),
                                "confidence_threshold": ai_confidence_threshold,
                                "detailed_analysis": ai_analyzed_findings,
                            },
                            f,
                            indent=2,
                        )

                    if verbose:
                        removed_count = findings_count - len(high_confidence_findings)
                        click.echo(
                            f"🤖 [AI] Removed {removed_count} likely false positives"
                        )
                        click.echo(
                            f"🤖 [AI] {len(high_confidence_findings)} high-confidence findings remain"
                        )

                final_findings = (
                    len(high_confidence_findings)
                    if (ai_mode or ai_reduce_fp) and raw_findings
                    else findings_count
                )

                scan_results["nuclei"] = {
                    "findings": final_findings,
                    "templates": template_info,
                    "ai_enhanced": ai_mode or ai_reduce_fp or ai_smart_templates,
                    "original_findings": (
                        findings_count if (ai_mode or ai_reduce_fp) else None
                    ),
                }
                stats["vulnerabilities_found"] += final_findings

                if verbose:
                    if ai_mode or ai_reduce_fp:
                        click.echo(
                            f"⚡ [NUCLEI] Completed! Found {final_findings} high-confidence vulnerabilities (was {findings_count})"
                        )
                    else:
                        click.echo(
                            f"⚡ [NUCLEI] Completed! Found {final_findings} potential vulnerabilities"
                        )

            click.echo(f"[✓] Nuclei done: {nuclei_out}")

    # === SEVERITY FILTERING ===
    def filter_by_severity(path, out_path, sevs):
        sevs = [s.lower() for s in sevs]
        with open(path, "r") as inp, open(out_path, "w") as out:
            for line in inp:
                if any(f"severity: {s}" in line.lower() for s in sevs):
                    out.write(line)

    if severity_filter:
        sevs = severity_filter.split(",")
        if run_nuclei:
            path = Path(output_dir) / "nuclei.txt"
            out = Path(output_dir) / "nuclei_filtered.txt"
            filter_by_severity(path, out, sevs)
            click.echo(f"[✓] Filtered nuclei → {out}")
        if run_jaeles:
            path = Path(output_dir) / "jaeles.txt"
            out = Path(output_dir) / "jaeles_filtered.txt"
            filter_by_severity(path, out, sevs)
            click.echo(f"[✓] Filtered jaeles → {out}")

    # === FINAL REPORTING AND NOTIFICATIONS ===
    scan_time = time.time() - start_time

    if verbose:
        click.echo(f"\n📊 [SUMMARY] Scan completed in {scan_time:.2f} seconds")
        click.echo(f"📁 Total URLs processed: {stats['total_urls']}")
        click.echo(f"🎯 Patterns matched: {stats['patterns_matched']}")
        click.echo(f"⚡ Vulnerabilities found: {stats['vulnerabilities_found']}")
        click.echo(f"🛠️ Technologies detected: {len(stats['technologies'])}")
        click.echo(f"🔧 Tools used: {', '.join(stats['scan_tools'])}")
        if stats["ai_features_used"]:
            click.echo(f"🤖 AI features: {', '.join(stats['ai_features_used'])}")

    # Generate reports
    if output_json:
        json_file = generate_json_report(output_dir, stats, scan_results)
        if verbose:
            click.echo(f"📄 [JSON] Report saved: {json_file}")

    if output_markdown:
        md_file = generate_markdown_report(output_dir, stats, scan_results)
        if verbose:
            click.echo(f"📝 [MARKDOWN] Report saved: {md_file}")

    # Generate AI-powered executive summary
    if ai_mode or ai_executive_summary:
        if verbose:
            click.echo("🤖 [AI] Generating executive summary...")

        tech_list = list(stats.get("technologies", {}).keys())
        ai_summary = ai_generate_executive_summary(stats, scan_results, tech_list)

        # Save AI summary to file
        ai_summary_file = Path(output_dir) / "ai_executive_summary.md"
        with open(ai_summary_file, "w") as f:
            f.write(f"# 🤖 AI-Enhanced Vulnerability Assessment Report\n")
            f.write(
                f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            f.write(ai_summary)

        if verbose:
            click.echo(f"🤖 [AI] Executive summary saved: {ai_summary_file}")
        else:
            click.echo(f"[🤖] AI summary: {ai_summary_file}")

        # Show brief AI summary in console
        if ai_mode:
            click.echo("\n" + "=" * 60)
            click.echo("🤖 AI EXECUTIVE SUMMARY")
            click.echo("=" * 60)
            # Extract just the risk assessment part
            summary_lines = ai_summary.split("\n")
            for line in summary_lines[3:8]:  # Show risk assessment section
                if line.strip():
                    click.echo(line)
            click.echo("=" * 60)

    # Send completion notification
    if slack_webhook or discord_webhook:
        completion_msg = f"✅ VulnCLI scan completed!\\n"
        completion_msg += f"🕐 Duration: {scan_time:.1f}s\\n"
        completion_msg += f"📁 URLs: {stats['total_urls']}\\n"
        completion_msg += f"⚡ Vulnerabilities: {stats['vulnerabilities_found']}\\n"
        completion_msg += f"🔧 Tools: {', '.join(stats['scan_tools'])}"

        if slack_webhook:
            send_notification(slack_webhook, completion_msg, "slack")
        if discord_webhook:
            send_notification(discord_webhook, completion_msg, "discord")

    # Critical findings notification
    if stats["vulnerabilities_found"] > 10 and (slack_webhook or discord_webhook):
        critical_msg = f"🚨 HIGH VULNERABILITY COUNT DETECTED!\\n"
        critical_msg += (
            f"Found {stats['vulnerabilities_found']} potential vulnerabilities\\n"
        )
        critical_msg += f"Immediate review recommended!"

        if slack_webhook:
            send_notification(slack_webhook, critical_msg, "slack")
        if discord_webhook:
            send_notification(discord_webhook, critical_msg, "discord")

    if verbose:
        click.echo(f"\n🎉 [COMPLETE] VulnCLI scan finished successfully!")
        click.echo(f"📂 All results saved in: {output_dir}")
    else:
        click.echo(f"\n[✓] Scan complete! Results in: {output_dir}")


vulncli.short_help = "🎯 AI-enhanced vulnerability scanning with GF + Dalfox/Jaeles/Nuclei + smart analysis"


if __name__ == "__main__":
    vulncli()
