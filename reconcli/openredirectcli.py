#!/usr/bin/env python3

import os
import json
import time
import click
import requests
import subprocess
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict

# Resume utilities (fallback if not available)
try:
    from reconcli.utils.resume import load_resume, save_resume_state, clear_resume
except ImportError:

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


# DB integration (optional)
try:
    from reconcli.db.operations import store_target, store_vulnerability
except ImportError:
    store_target = None
    store_vulnerability = None


# AI utilities (optional)
try:
    from reconcli.aicli import AIReconAssistant as AIAnalyzer
except ImportError:
    AIAnalyzer = None


# Default payloads for various evasion techniques
DEFAULT_PAYLOADS = [
    "http://evil.com",
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "//evil.com/",
    "https://evil.com/",
    "http://evil.com/",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "http:evil.com",
    "//evil.com\\",
    "http://evil.com\\",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

ADVANCED_PAYLOADS = [
    "http://1.1.1.1",
    "https://127.0.0.1",
    "ftp://evil.com",
    "//google.com@evil.com",
    "http://google.com.evil.com",
    "https://google.com%2eevil.com",
    "//google.com%2eevil.com",
    "https://google.com%252eevil.com",
    "//google%E3%80%82com",
    "http://ⓖⓞⓞⓖⓛⓔ.com",
    "//ⓖⓞⓞⓖⓛⓔ.com",
    "http://google。com",
    "https://google%E3%80%82com",
    "//google%uff0ecom",
    "http://0x7f000001",
    "https://017700000001",
    "//2130706433",
    "http://[::1]",
    "https://[0:0:0:0:0:ffff:7f00:1]",
]

REDIRECT_PARAMS = [
    "url",
    "next",
    "redirect",
    "redir",
    "target",
    "dest",
    "destination",
    "go",
    "goto",
    "link",
    "return",
    "returnTo",
    "continue",
    "forward",
    "location",
    "loc",
    "redirect_url",
    "redirect_to",
    "out",
    "exit",
    "success_url",
    "failure_url",
    "callback",
    "back",
    "r",
    "ref",
]


def send_notification(webhook_url, message, webhook_type="slack"):
    """Send notification to Slack or Discord webhook."""
    try:
        if webhook_type == "slack":
            payload = {"text": message}
        else:  # discord
            payload = {"content": message}

        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass


def run_external_tool(tool_cmd, input_file=None, output_file=None):
    """Run external tools like qsreplace, gf, etc."""
    try:
        if input_file:
            with open(input_file) as f:
                result = subprocess.run(
                    tool_cmd.split(),
                    stdin=f,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
        else:
            result = subprocess.run(
                tool_cmd.split(), capture_output=True, text=True, timeout=300
            )

        if result.returncode == 0:
            if output_file:
                with open(output_file, "w") as f:
                    f.write(result.stdout)
            return result.stdout.strip().split("\n") if result.stdout else []
        return []
    except Exception:
        return []


def run_openredirex(urls_file, output_dir, flags="", verbose=False):
    """Run OpenRedirex tool for advanced open redirect testing."""
    try:
        output_file = os.path.join(output_dir, "openredirex_results.txt")
        cmd = f"openredirex -l {urls_file} -o {output_file} {flags}"

        if verbose:
            click.echo(f"🔧 Running OpenRedirex: {cmd}")

        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=600
        )

        if result.returncode == 0 and os.path.exists(output_file):
            with open(output_file) as f:
                return f.read().strip().split("\n")
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ OpenRedirex error: {str(e)}")
        return []


def run_kxss(urls_file, output_dir, verbose=False):
    """Run kxss to find reflected parameters."""
    try:
        output_file = os.path.join(output_dir, "kxss_results.txt")
        cmd = f"kxss -l {urls_file} -o {output_file}"

        if verbose:
            click.echo(f"🔧 Running kxss: {cmd}")

        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=600
        )

        if result.returncode == 0 and os.path.exists(output_file):
            with open(output_file) as f:
                return f.read().strip().split("\n")
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ kxss error: {str(e)}")
        return []


def run_waybackurls(domain, output_dir, verbose=False):
    """Run waybackurls to get historical URLs."""
    try:
        output_file = os.path.join(output_dir, "waybackurls_results.txt")
        cmd = f"waybackurls {domain}"

        if verbose:
            click.echo(f"🔧 Running waybackurls: {cmd}")

        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=300
        )

        if result.returncode == 0:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            return result.stdout.strip().split("\n") if result.stdout else []
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ waybackurls error: {str(e)}")
        return []


def run_gau(domain, output_dir, verbose=False):
    """Run GAU (GetAllUrls) for URL discovery."""
    try:
        output_file = os.path.join(output_dir, "gau_results.txt")
        cmd = f"gau {domain}"

        if verbose:
            click.echo(f"🔧 Running GAU: {cmd}")

        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=300
        )

        if result.returncode == 0:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            return result.stdout.strip().split("\n") if result.stdout else []
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ GAU error: {str(e)}")
        return []


def run_unfurl(urls_file, output_dir, pattern="", verbose=False):
    """Run unfurl for URL parsing and analysis."""
    try:
        output_file = os.path.join(output_dir, "unfurl_results.txt")
        cmd = f"unfurl -u {pattern}" if pattern else "unfurl -u"

        if verbose:
            click.echo(f"🔧 Running unfurl: {cmd}")

        with open(urls_file) as f:
            result = subprocess.run(
                cmd.split(), stdin=f, capture_output=True, text=True, timeout=300
            )

        if result.returncode == 0:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            return result.stdout.strip().split("\n") if result.stdout else []
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ unfurl error: {str(e)}")
        return []


def run_httpx_probe(urls_file, output_dir, flags="-silent", verbose=False):
    """Run httpx for fast HTTP probing."""
    try:
        output_file = os.path.join(output_dir, "httpx_results.txt")
        cmd = f"httpx -l {urls_file} -o {output_file} {flags}"

        if verbose:
            click.echo(f"🔧 Running httpx: {cmd}")

        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=600
        )

        if result.returncode == 0 and os.path.exists(output_file):
            with open(output_file) as f:
                return f.read().strip().split("\n")
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ httpx error: {str(e)}")
        return []


def generate_ai_payloads(target_url, ai_analyzer=None):
    """Generate AI-powered payloads based on URL analysis."""
    if not ai_analyzer:
        return []

    try:
        # Analyze URL structure for optimal payload generation
        parsed = urlparse(target_url)
        context = {
            "url": target_url,
            "domain": parsed.netloc,
            "path": parsed.path,
            "params": parse_qs(parsed.query),
            "vuln_type": "open_redirect",
        }

        prompt = f"""
        Analyze this URL for open redirect vulnerabilities and generate 10 advanced payloads:
        URL: {target_url}
        Domain: {parsed.netloc}
        Parameters: {list(parse_qs(parsed.query).keys())}
        
        Generate payloads that:
        1. Test different redirect techniques
        2. Use domain-specific evasion methods
        3. Include protocol manipulation
        4. Test parameter pollution
        5. Use encoding bypass techniques
        
        Return only the payload URLs, one per line.
        """

        response = ai_analyzer.ask_ai(prompt, context="payload")
        if response and "payloads" in response:
            return response["payloads"][:10]  # Limit to 10 AI payloads

        return []
    except Exception:
        return []


def ai_analyze_response(response_text, test_url, ai_analyzer=None):
    """AI-powered analysis of HTTP responses for redirect patterns."""
    if not ai_analyzer:
        return {}

    try:
        context = {
            "test_url": test_url,
            "response_length": len(response_text),
            "vuln_type": "open_redirect",
        }

        prompt = f"""
        Analyze this HTTP response for potential open redirect vulnerabilities:
        
        Test URL: {test_url}
        Response (first 1000 chars): {response_text[:1000]}
        
        Look for:
        1. JavaScript redirects (window.location, location.href)
        2. Meta refresh redirects
        3. Form-based redirects
        4. AJAX/fetch redirects
        5. Hidden redirect mechanisms
        
        Return analysis as JSON with fields: redirect_found, method, confidence, location.
        """

        response = ai_analyzer.ask_ai(prompt, context="payload")
        return response if response else {}
    except Exception:
        return {}


def ai_assess_severity(
    original_url, test_url, redirect_location, domain, ai_analyzer=None
):
    """AI-powered severity assessment for open redirect findings."""
    if not ai_analyzer:
        return "medium"

    try:
        context = {
            "original_url": original_url,
            "test_url": test_url,
            "redirect_location": redirect_location,
            "target_domain": domain,
            "vuln_type": "open_redirect",
        }

        prompt = f"""
        Assess the severity of this open redirect vulnerability:
        
        Original URL: {original_url}
        Test URL: {test_url}
        Redirects to: {redirect_location}
        Target domain: {domain}
        
        Consider:
        1. External domain redirect (higher risk)
        2. Protocol changes (HTTP to HTTPS, etc.)
        3. Subdomain vs external domain
        4. Potential for phishing attacks
        5. Business impact
        
        Return severity: critical, high, medium, or low
        """

        response = ai_analyzer.ask_ai(prompt, context="payload")
        if response and "severity" in response:
            return response["severity"]

        return "medium"
    except Exception:
        return "medium"


def ai_generate_report_insights(results, ai_analyzer=None):
    """Generate AI-powered insights for the vulnerability report."""
    if not ai_analyzer or not results:
        return {}

    try:
        # Prepare summary data
        total_findings = len(results)
        external_redirects = len(
            [r for r in results if r.get("redirect_outside", True)]
        )
        severity_counts = {}
        methods_used = set()

        for result in results:
            severity = result.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            methods_used.add(result.get("method", "unknown"))

        context = {
            "total_findings": total_findings,
            "external_redirects": external_redirects,
            "severity_counts": severity_counts,
            "methods_used": list(methods_used),
            "vuln_type": "open_redirect",
        }

        prompt = f"""
        Analyze these open redirect vulnerability findings and provide insights:
        
        Total findings: {total_findings}
        External redirects: {external_redirects}
        Severity breakdown: {severity_counts}
        Detection methods: {list(methods_used)}
        
        Provide:
        1. Risk assessment summary
        2. Remediation priorities
        3. Common patterns found
        4. Business impact analysis
        5. Next steps recommendations
        
        Return as structured analysis.
        """

        response = ai_analyzer.ask_ai(prompt, context="payload")
        return response if response else {}
    except Exception:
        return {}


def check_tool_availability(tool_name):
    """Check if external tool is available."""
    try:
        result = subprocess.run([tool_name, "--help"], capture_output=True, timeout=10)
        return True
    except:
        return False


def encode_payload(payload, encoding_type):
    """Encode payloads using various methods."""
    if not encoding_type:
        return payload

    if encoding_type == "url":
        return quote(payload, safe="")
    elif encoding_type == "double":
        return quote(quote(payload, safe=""), safe="")
    elif encoding_type == "unicode":
        return payload.encode("unicode_escape").decode("ascii")
    elif encoding_type == "html":
        return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    return payload


def check_javascript_redirect(response_text):
    """Check for JavaScript-based redirects."""
    js_patterns = [
        r'window\.location\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\(["\']([^"\']+)["\']\)',
        r'window\.open\(["\']([^"\']+)["\']',
    ]

    for pattern in js_patterns:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        if matches:
            return matches
    return []


def check_meta_refresh(response_text):
    """Check for HTML meta refresh redirects."""
    pattern = r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']'
    matches = re.findall(pattern, response_text, re.IGNORECASE)
    return matches


def generate_markdown_report(results, output_dir, ai_insights=None):
    """Generate a comprehensive Markdown report."""
    report_path = os.path.join(output_dir, "openredirect_report.md")

    with open(report_path, "w") as f:
        f.write("# Open Redirect Vulnerability Report\n\n")
        f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total Findings**: {len(results)}\n\n")

        # AI Insights Section
        if ai_insights:
            f.write("## 🧠 AI-Powered Analysis\n\n")

            if "risk_assessment" in ai_insights:
                f.write("### Risk Assessment\n")
                f.write(f"{ai_insights['risk_assessment']}\n\n")

            if "remediation_priorities" in ai_insights:
                f.write("### Remediation Priorities\n")
                if isinstance(ai_insights["remediation_priorities"], list):
                    for priority in ai_insights["remediation_priorities"]:
                        f.write(f"- {priority}\n")
                else:
                    f.write(f"{ai_insights['remediation_priorities']}\n")
                f.write("\n")

            if "common_patterns" in ai_insights:
                f.write("### Common Attack Patterns\n")
                if isinstance(ai_insights["common_patterns"], list):
                    for pattern in ai_insights["common_patterns"]:
                        f.write(f"- {pattern}\n")
                else:
                    f.write(f"{ai_insights['common_patterns']}\n")
                f.write("\n")

            if "business_impact" in ai_insights:
                f.write("### Business Impact Analysis\n")
                f.write(f"{ai_insights['business_impact']}\n\n")

        if results:
            f.write("## Findings\n\n")
            for i, result in enumerate(results, 1):
                f.write(f"### Finding {i}\n\n")
                f.write(f"- **Original URL**: `{result['original']}`\n")
                f.write(f"- **Test URL**: `{result['test']}`\n")
                f.write(f"- **Status Code**: {result['status']}\n")
                f.write(f"- **Location**: `{result['location']}`\n")
                f.write(
                    f"- **External Redirect**: {result.get('redirect_outside', 'Unknown')}\n"
                )
                if "severity" in result:
                    f.write(f"- **Severity**: {result['severity']}\n")
                if "method" in result:
                    f.write(f"- **Detection Method**: {result['method']}\n")
                if "ai_confidence" in result:
                    f.write(f"- **AI Confidence**: {result['ai_confidence']:.2f}\n")
                f.write("\n")

        f.write("## Recommendations\n\n")
        f.write("1. Implement whitelist-based redirect validation\n")
        f.write("2. Use relative URLs for internal redirects\n")
        f.write("3. Validate redirect destinations against allowed domains\n")
        f.write("4. Implement proper input sanitization\n")
        f.write("5. Use CSRF tokens for sensitive redirect operations\n")
        f.write("6. Monitor and log all redirect activities\n")

        # AI-specific recommendations
        if ai_insights and "next_steps" in ai_insights:
            f.write("\n### AI-Recommended Next Steps\n")
            if isinstance(ai_insights["next_steps"], list):
                for step in ai_insights["next_steps"]:
                    f.write(f"- {step}\n")
            else:
                f.write(f"{ai_insights['next_steps']}\n")

    return report_path


@click.command()
@click.option(
    "--input", "-i", type=click.Path(exists=True), help="File with URLs to test"
)
@click.option("--domain", help="Target domain (filter & DB)")
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (auto-detected if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
@click.option(
    "--payloads", type=click.Path(exists=True), help="Payload list for fuzzing"
)
@click.option(
    "--keyword", default="FUZZ", help="Keyword to replace with payload (default: FUZZ)"
)
@click.option("--threads", default=50, help="Number of concurrent threads")
@click.option(
    "--output-dir", default="output_openredirect", help="Directory for results"
)
@click.option("--check", is_flag=True, help="Enable active redirect testing")
@click.option(
    "--filter-params", is_flag=True, help="Only test URLs with redirect-like parameters"
)
@click.option("--run-dry", is_flag=True, help="Show what would be tested")
@click.option("--resume", is_flag=True, help="Resume from last session")
@click.option("--resume-reset", is_flag=True, help="Clear resume state")
@click.option("--resume-stats", is_flag=True, help="Show resume progress")
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option("--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
@click.option(
    "--user-agent",
    default="Mozilla/5.0 (compatible; openredirectcli)",
    help="Custom User-Agent string",
)
@click.option("--timeout", default=10, help="Request timeout in seconds")
@click.option("--delay", default=0.0, help="Delay between requests in seconds")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--follow-redirects", is_flag=True, help="Follow redirects to detect chains"
)
@click.option("--max-redirects", default=5, help="Maximum redirect depth to follow")
@click.option(
    "--check-javascript", is_flag=True, help="Check for JavaScript-based redirects"
)
@click.option(
    "--check-meta-refresh", is_flag=True, help="Check for HTML meta refresh redirects"
)
@click.option(
    "--check-status-codes",
    default="301,302,303,307,308",
    help="Status codes to check for redirects",
)
@click.option(
    "--filter-external-only", is_flag=True, help="Only report external domain redirects"
)
@click.option("--custom-headers", help="Custom headers as JSON string")
@click.option("--cookie", help="Cookie string to include in requests")
@click.option("--auth", help="Authentication in format username:password")
@click.option("--verify-ssl", is_flag=True, help="Verify SSL certificates")
@click.option(
    "--output-format",
    type=click.Choice(["json", "txt", "csv", "xml"]),
    default="json",
    help="Output format",
)
@click.option(
    "--save-responses", is_flag=True, help="Save full HTTP responses for analysis"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode - minimal output")
@click.option(
    "--use-qsreplace", is_flag=True, help="Use qsreplace for parameter injection"
)
@click.option("--use-gf", is_flag=True, help="Use gf patterns for URL filtering")
@click.option(
    "--gf-pattern", default="redirect", help="GF pattern to use for filtering"
)
@click.option(
    "--use-openredirex", is_flag=True, help="Use OpenRedirex tool for advanced testing"
)
@click.option(
    "--use-kxss", is_flag=True, help="Use kxss for reflected parameter detection"
)
@click.option(
    "--use-waybackurls", is_flag=True, help="Use waybackurls to find historical URLs"
)
@click.option("--use-gau", is_flag=True, help="Use GAU (GetAllUrls) for URL discovery")
@click.option(
    "--use-unfurl", is_flag=True, help="Use unfurl for URL parsing and analysis"
)
@click.option(
    "--openredirex-flags", default="", help="Additional flags for OpenRedirex"
)
@click.option(
    "--burp-suite", is_flag=True, help="Generate Burp Suite compatible output"
)
@click.option(
    "--nuclei-export", is_flag=True, help="Export findings for Nuclei verification"
)
@click.option("--use-httpx", is_flag=True, help="Use httpx for fast HTTP probing")
@click.option(
    "--httpx-flags",
    default="-silent -mc 200,301,302,303,307,308",
    help="HTTPx flags for probing",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity to report",
)
@click.option(
    "--payload-encoding",
    type=click.Choice(["url", "double", "unicode", "html"]),
    help="Payload encoding method",
)
@click.option("--advanced-payloads", is_flag=True, help="Use advanced evasion payloads")
@click.option(
    "--blind-redirect", is_flag=True, help="Test for blind redirect vulnerabilities"
)
@click.option("--markdown", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option(
    "--ai-mode", is_flag=True, help="Enable AI-powered analysis and payload generation"
)
@click.option(
    "--ai-model", default="gpt-3.5-turbo", help="AI model to use for analysis"
)
@click.option(
    "--ai-confidence", default=0.7, help="Minimum AI confidence threshold (0.0-1.0)"
)
def openredirectcli(
    input,
    domain,
    target_domain,
    program,
    payloads,
    keyword,
    threads,
    output_dir,
    check,
    filter_params,
    run_dry,
    resume,
    resume_reset,
    resume_stats,
    store_db,
    proxy,
    user_agent,
    timeout,
    delay,
    retries,
    follow_redirects,
    max_redirects,
    check_javascript,
    check_meta_refresh,
    check_status_codes,
    filter_external_only,
    custom_headers,
    cookie,
    auth,
    verify_ssl,
    output_format,
    save_responses,
    verbose,
    quiet,
    use_qsreplace,
    use_gf,
    gf_pattern,
    use_openredirex,
    use_kxss,
    use_waybackurls,
    use_gau,
    use_unfurl,
    openredirex_flags,
    burp_suite,
    nuclei_export,
    use_httpx,
    httpx_flags,
    severity,
    payload_encoding,
    advanced_payloads,
    blind_redirect,
    markdown,
    slack_webhook,
    discord_webhook,
    ai_mode,
    ai_model,
    ai_confidence,
):
    """🔄 Advanced Open Redirect Vulnerability Scanner

    Detect open redirect vulnerabilities with advanced evasion techniques,
    multiple tool integration, AI-powered analysis, and comprehensive reporting.

    \b
    📋 BASIC USAGE EXAMPLES:

    \b
    🎯 Basic URL Testing:
    reconcli openredirectcli -i urls.txt --verbose

    \b
    🚀 Advanced Testing with AI:
    reconcli openredirectcli -i urls.txt --ai-mode --advanced-payloads --verbose

    \b
    🔍 External Tools Integration:
    reconcli openredirectcli -i urls.txt --use-openredirex --use-kxss --use-waybackurls

    \b
    📊 Database Storage with Program:
    reconcli openredirectcli -i urls.txt --store-db --program "bugcrowd-target" --target-domain example.com

    \b
    📝 Comprehensive Reporting:
    reconcli openredirectcli -i urls.txt --markdown --output-format json --save-responses

    \b
    🎛️ ADVANCED USAGE EXAMPLES:

    \b
    🧠 AI-Powered Analysis:
    reconcli openredirectcli -i urls.txt --ai-mode --ai-model "gpt-4" --ai-confidence 0.8

    \b
    🔧 Custom Payloads & Encoding:
    reconcli openredirectcli -i urls.txt --payloads custom_payloads.txt --payload-encoding url

    \b
    🌐 Proxy & Authentication:
    reconcli openredirectcli -i urls.txt --proxy http://127.0.0.1:8080 --auth user:pass

    \b
    🎯 High-Severity Only:
    reconcli openredirectcli -i urls.txt --severity high --filter-external-only

    \b
    📱 Notifications Setup:
    reconcli openredirectcli -i urls.txt --slack-webhook "https://hooks.slack.com/..."

    \b
    🛠️ WORKFLOW EXAMPLES:

    \b
    🔍 URL Discovery Pipeline:
    reconcli openredirectcli -i targets.txt --use-waybackurls --use-gau --use-httpx --filter-params

    \b
    🚀 Complete Security Assessment:
    reconcli openredirectcli -i urls.txt \\
        --ai-mode \\
        --use-openredirex \\
        --use-kxss \\
        --advanced-payloads \\
        --check-javascript \\
        --check-meta-refresh \\
        --markdown \\
        --store-db \\
        --program "target-name" \\
        --slack-webhook "https://hooks.slack.com/..." \\
        --verbose

    \b
    🔄 Resume & Performance:
    reconcli openredirectcli -i urls.txt --resume --threads 100 --delay 0.5

    \b
    📊 CUSTOM OUTPUT EXAMPLES:

    \b
    💾 Multiple Output Formats:
    reconcli openredirectcli -i urls.txt --output-format json --markdown --burp-suite

    \b
    🎯 Nuclei Integration:
    reconcli openredirectcli -i urls.txt --nuclei-export --output-dir nuclei_targets

    \b
    📈 Status Monitoring:
    reconcli openredirectcli -i urls.txt --resume-stats  # Check progress
    reconcli openredirectcli -i urls.txt --resume        # Continue scan
    reconcli openredirectcli -i urls.txt --resume-reset  # Reset state

    \b
    🔧 TOOL-SPECIFIC EXAMPLES:

    \b
    🚀 OpenRedirex Integration:
    reconcli openredirectcli -i urls.txt --use-openredirex --openredirex-flags "-t 50 -c 20"

    \b
    ⚡ HTTPx Probing:
    reconcli openredirectcli -i urls.txt --use-httpx --httpx-flags "-mc 200,301,302 -fc 404"

    \b
    🎯 GF Pattern Filtering:
    reconcli openredirectcli -i urls.txt --use-gf --gf-pattern "redirect|url|next"

    \b
    📂 INPUT FILE FORMATS:

    \b
    URLs file (urls.txt):
    https://example.com/redirect?url=FUZZ
    https://target.com/goto?next=FUZZ
    https://site.com/login?returnUrl=FUZZ

    \b
    Custom payloads file (payloads.txt):
    http://evil.com
    https://attacker.com
    //malicious.site
    javascript:alert(1)

    \b
    📋 EXAMPLE COMMANDS BY SCENARIO:

    \b
    🎯 Bug Bounty Testing:
    reconcli openredirectcli -i scope_urls.txt --ai-mode --use-waybackurls --store-db --program "hackerone-target" --severity medium --markdown --slack-webhook "$SLACK_URL"

    \b
    🔍 Penetration Testing:
    reconcli openredirectcli -i target_urls.txt --use-openredirex --use-kxss --check-javascript --check-meta-refresh --save-responses --proxy http://127.0.0.1:8080

    \b
    📊 Security Assessment:
    reconcli openredirectcli -i application_urls.txt --ai-mode --advanced-payloads --payload-encoding double --follow-redirects --output-format json --markdown

    \b
    💡 TIP: Use --run-dry first to see what URLs will be tested!
    💡 TIP: Use --verbose for detailed output and debugging
    💡 TIP: Use --ai-mode for intelligent payload generation and analysis
    """

    if not quiet:
        click.echo("🔄 Starting Advanced Open Redirect Scanner")

    # Initialize AI analyzer if requested
    ai_analyzer = None
    if ai_mode:
        if AIAnalyzer:
            try:
                ai_analyzer = AIAnalyzer()
                if verbose:
                    click.echo(f"🧠 AI mode enabled with model: {ai_model}")
            except Exception as e:
                if verbose:
                    click.echo(f"⚠️ AI initialization failed: {str(e)}")
                ai_mode = False
        else:
            click.echo("⚠️ AI mode requested but AIAnalyzer not available")
            ai_mode = False

    # Auto-detect target domain if not provided
    if not target_domain and input:
        with open(input) as f:
            first_url = f.readline().strip()
            if first_url:
                target_domain = urlparse(first_url).netloc

    os.makedirs(output_dir, exist_ok=True)
    resume_data = load_resume(output_dir)

    if resume_stats:
        tested = resume_data.get("tested", [])
        click.echo(f"📊 Resume: {len(tested)} URLs already tested")
        return

    if resume_reset:
        clear_resume(output_dir)
        click.echo("🗑️ Resume state cleared")
        if not resume:
            return

    # Load URLs
    with open(input) as f:
        urls = [line.strip() for line in f if line.strip()]

    if verbose:
        click.echo(f"📂 Loaded {len(urls)} URLs from input file")

    # External tool integrations for URL discovery and enhancement
    additional_urls = []

    # Use waybackurls for historical URL discovery
    if use_waybackurls and target_domain:
        if verbose:
            click.echo("🕰️ Running waybackurls for historical URL discovery...")

        if check_tool_availability("waybackurls"):
            wayback_urls = run_waybackurls(target_domain, output_dir, verbose)
            additional_urls.extend(wayback_urls)
            if verbose:
                click.echo(f"✅ waybackurls found {len(wayback_urls)} URLs")
        else:
            click.echo("⚠️ waybackurls not found - skipping")

    # Use GAU for URL discovery
    if use_gau and target_domain:
        if verbose:
            click.echo("🔍 Running GAU for URL discovery...")

        if check_tool_availability("gau"):
            gau_urls = run_gau(target_domain, output_dir, verbose)
            additional_urls.extend(gau_urls)
            if verbose:
                click.echo(f"✅ GAU found {len(gau_urls)} URLs")
        else:
            click.echo("⚠️ GAU not found - skipping")

    # Add discovered URLs to main list
    if additional_urls:
        original_count = len(urls)
        urls.extend([u for u in additional_urls if u not in urls])
        if verbose:
            click.echo(f"📈 URL discovery: {original_count} -> {len(urls)} URLs")

    # Use httpx for fast HTTP probing if requested
    if use_httpx:
        if verbose:
            click.echo("⚡ Running httpx for HTTP probing...")

        if check_tool_availability("httpx"):
            temp_urls_file = os.path.join(output_dir, "temp_all_urls.txt")
            with open(temp_urls_file, "w") as f:
                f.write("\n".join(urls))

            live_urls = run_httpx_probe(
                temp_urls_file, output_dir, httpx_flags, verbose
            )
            if live_urls:
                urls = [u for u in live_urls if u.strip()]
                if verbose:
                    click.echo(f"✅ httpx filtered to {len(urls)} live URLs")
            os.remove(temp_urls_file)
        else:
            click.echo("⚠️ httpx not found - skipping")

    # Use GF patterns for filtering if requested
    if use_gf:
        if verbose:
            click.echo(f"🔍 Filtering URLs with GF pattern: {gf_pattern}")

        if check_tool_availability("gf"):
            temp_file = os.path.join(output_dir, "temp_urls.txt")
            with open(temp_file, "w") as f:
                f.write("\n".join(urls))

            filtered_urls = run_external_tool(f"gf {gf_pattern}", temp_file)
            if filtered_urls:
                urls = [u for u in filtered_urls if u.strip()]
                if verbose:
                    click.echo(f"✅ GF filtered to {len(urls)} URLs")
            os.remove(temp_file)
        else:
            click.echo("⚠️ gf not found - skipping")

    # Use unfurl for URL analysis
    if use_unfurl:
        if verbose:
            click.echo("🔧 Running unfurl for URL analysis...")

        if check_tool_availability("unfurl"):
            temp_file = os.path.join(output_dir, "temp_urls.txt")
            with open(temp_file, "w") as f:
                f.write("\n".join(urls))

            # Extract URLs with parameters for redirect testing
            unfurl_urls = run_unfurl(temp_file, output_dir, "params", verbose)
            if unfurl_urls:
                urls.extend([u for u in unfurl_urls if u not in urls and u.strip()])
                if verbose:
                    click.echo(f"✅ unfurl added {len(unfurl_urls)} parametrized URLs")
            os.remove(temp_file)
        else:
            click.echo("⚠️ unfurl not found - skipping")

    # Filter for redirect parameters
    if filter_params:
        original_count = len(urls)
        urls = [u for u in urls if any(param in u.lower() for param in REDIRECT_PARAMS)]
        if verbose:
            click.echo(f"🎯 Parameter filtering: {original_count} -> {len(urls)} URLs")

    # Resume functionality
    tested = set(resume_data.get("tested", [])) if resume else set()
    urls = [u for u in urls if u not in tested]

    if verbose:
        click.echo(
            f"🔄 {len(urls)} URLs to test (excluding {len(tested)} already tested)"
        )

    # Load payloads
    payload_list = DEFAULT_PAYLOADS.copy()
    if payloads:
        with open(payloads) as f:
            custom_payloads = [p.strip() for p in f if p.strip()]
            payload_list.extend(custom_payloads)

    if advanced_payloads:
        payload_list.extend(ADVANCED_PAYLOADS)

    # AI-powered payload generation
    if ai_mode and ai_analyzer and urls:
        if verbose:
            click.echo("🧠 Generating AI-powered payloads...")

        ai_payloads = set()
        for url in urls[:10]:  # Analyze first 10 URLs for performance
            ai_generated = generate_ai_payloads(url, ai_analyzer)
            ai_payloads.update(ai_generated)

        if ai_payloads:
            payload_list.extend(list(ai_payloads))
            if verbose:
                click.echo(f"✅ AI generated {len(ai_payloads)} additional payloads")

    if payload_encoding:
        payload_list = [encode_payload(p, payload_encoding) for p in payload_list]

    if verbose:
        click.echo(f"💣 Using {len(payload_list)} payloads total")

    # External tool integration for advanced testing
    external_findings = []

    # Use OpenRedirex for advanced testing
    if use_openredirex:
        if verbose:
            click.echo("🚀 Running OpenRedirex for advanced open redirect testing...")

        if check_tool_availability("openredirex"):
            temp_urls_file = os.path.join(output_dir, "openredirex_input.txt")
            with open(temp_urls_file, "w") as f:
                f.write("\n".join(urls))

            openredirex_results = run_openredirex(
                temp_urls_file, output_dir, openredirex_flags, verbose
            )

            # Parse OpenRedirex results
            for result_line in openredirex_results:
                if result_line.strip() and "VULN" in result_line:
                    parts = result_line.split()
                    if len(parts) >= 2:
                        external_findings.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "original": parts[0] if len(parts) > 0 else "",
                                "test": parts[1] if len(parts) > 1 else parts[0],
                                "payload": "openredirex_detected",
                                "status": 302,
                                "location": parts[2] if len(parts) > 2 else "unknown",
                                "redirect_outside": True,
                                "severity": "high",
                                "method": "openredirex",
                                "tool": "openredirex",
                            }
                        )

            if verbose:
                click.echo(
                    f"✅ OpenRedirex found {len([f for f in external_findings if f.get('tool') == 'openredirex'])} vulnerabilities"
                )

            os.remove(temp_urls_file)
        else:
            click.echo(
                "⚠️ OpenRedirex not found - install from: https://github.com/devanshbatham/OpenRedireX"
            )

    # Use kxss for reflected parameter detection
    if use_kxss:
        if verbose:
            click.echo("🔍 Running kxss for reflected parameter detection...")

        if check_tool_availability("kxss"):
            temp_urls_file = os.path.join(output_dir, "kxss_input.txt")
            with open(temp_urls_file, "w") as f:
                f.write("\n".join(urls))

            kxss_results = run_kxss(temp_urls_file, output_dir, verbose)

            # Parse kxss results for potential redirect parameters
            for result_line in kxss_results:
                if result_line.strip() and "=" in result_line:
                    # kxss finds reflected parameters which might be useful for redirects
                    for redirect_param in REDIRECT_PARAMS:
                        if redirect_param in result_line.lower():
                            external_findings.append(
                                {
                                    "timestamp": datetime.now().isoformat(),
                                    "original": result_line,
                                    "test": result_line,
                                    "payload": "kxss_reflected_param",
                                    "status": 200,
                                    "location": "reflected_parameter",
                                    "redirect_outside": False,
                                    "severity": "medium",
                                    "method": "kxss_reflection",
                                    "tool": "kxss",
                                }
                            )
                            break

            if verbose:
                kxss_count = len(
                    [f for f in external_findings if f.get("tool") == "kxss"]
                )
                click.echo(f"✅ kxss found {kxss_count} reflected redirect parameters")

            os.remove(temp_urls_file)
        else:
            click.echo("⚠️ kxss not found - install from: https://github.com/Emoe/kxss")

    # Parse status codes to check
    valid_status_codes = [int(code.strip()) for code in check_status_codes.split(",")]

    results = external_findings.copy()  # Start with external findings
    session = requests.Session()

    # Configure session
    session.headers.update({"User-Agent": user_agent})
    session.verify = verify_ssl

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    if custom_headers:
        try:
            headers = json.loads(custom_headers)
            session.headers.update(headers)
        except json.JSONDecodeError:
            if verbose:
                click.echo("⚠️ Invalid JSON in custom headers, ignoring")

    if cookie:
        session.headers["Cookie"] = cookie

    if auth:
        username, password = auth.split(":", 1)
        session.auth = (username, password)

    def test_url_advanced(url: str) -> List[Dict]:
        """Advanced URL testing with multiple techniques."""
        findings = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        # Method 1: Keyword replacement
        if keyword in url:
            base = url.replace(keyword, "{}")
            test_urls = [
                base.format(encode_payload(p, payload_encoding)) for p in payload_list
            ]
        else:
            test_urls = []

            # Method 2: Parameter injection
            for param in qs:
                if any(
                    redirect_param in param.lower()
                    for redirect_param in REDIRECT_PARAMS
                ):
                    for payload in payload_list[:10]:  # Limit payloads per param
                        modified_qs = qs.copy()
                        modified_qs[param] = [encode_payload(payload, payload_encoding)]
                        new_query = urlencode(modified_qs, doseq=True)
                        new_parts = parsed._replace(query=new_query)
                        test_urls.append(urlunparse(new_parts))

            # Method 3: qsreplace integration
            if use_qsreplace and payload_list:
                for payload in payload_list[:5]:  # Limit for performance
                    qsreplace_cmd = f"echo '{url}' | qsreplace '{encode_payload(payload, payload_encoding)}'"
                    qsreplace_urls = run_external_tool(qsreplace_cmd)
                    test_urls.extend(qsreplace_urls)

        # Test each generated URL
        for test_url in test_urls[:50]:  # Limit tests per URL
            try:
                if run_dry:
                    click.echo(f"[DRY] {test_url}")
                    continue

                # Make request with retry logic
                for attempt in range(retries + 1):
                    try:
                        response = session.get(
                            test_url, timeout=timeout, allow_redirects=follow_redirects
                        )
                        break
                    except requests.RequestException:
                        if attempt == retries:
                            raise
                        time.sleep(delay)

                # Check response
                location = response.headers.get("Location", "")

                # AI-powered response analysis
                if ai_mode and ai_analyzer and response.text:
                    ai_analysis = ai_analyze_response(
                        response.text, test_url, ai_analyzer
                    )

                    if (
                        ai_analysis.get("redirect_found")
                        and ai_analysis.get("confidence", 0) >= ai_confidence
                    ):
                        ai_location = ai_analysis.get("location", "")
                        if ai_location and any(
                            payload in ai_location for payload in payload_list
                        ):
                            severity_level = determine_severity(
                                url, test_url, ai_location, domain
                            )

                            if severity_priority(severity_level) >= severity_priority(
                                severity
                            ):
                                finding = {
                                    "timestamp": datetime.now().isoformat(),
                                    "original": url,
                                    "test": test_url,
                                    "payload": "ai_detected",
                                    "status": response.status_code,
                                    "location": ai_location,
                                    "redirect_outside": is_external_redirect(
                                        ai_location, domain
                                    ),
                                    "severity": severity_level,
                                    "method": f"ai_{ai_analysis.get('method', 'analysis')}",
                                    "ai_confidence": ai_analysis.get("confidence", 0),
                                }

                                if save_responses:
                                    finding["response_body"] = response.text[:1000]

                                findings.append(finding)

                # Check status code

                # Check status code
                if response.status_code in valid_status_codes:
                    # Check if payload is in location header
                    for payload in payload_list:
                        if payload in location:
                            severity_level = determine_severity(
                                url, test_url, location, domain
                            )

                            if severity_priority(severity_level) >= severity_priority(
                                severity
                            ):
                                finding = {
                                    "timestamp": datetime.now().isoformat(),
                                    "original": url,
                                    "test": test_url,
                                    "payload": payload,
                                    "status": response.status_code,
                                    "location": location,
                                    "redirect_outside": is_external_redirect(
                                        location, domain
                                    ),
                                    "severity": severity_level,
                                    "method": "header_redirect",
                                }

                                if save_responses:
                                    finding["response_body"] = response.text[
                                        :1000
                                    ]  # First 1KB

                                findings.append(finding)

                # Check JavaScript redirects
                if check_javascript:
                    js_redirects = check_javascript_redirect(response.text)
                    for js_redirect in js_redirects:
                        for payload in payload_list:
                            if payload in js_redirect:
                                severity_level = determine_severity(
                                    url, test_url, js_redirect, domain
                                )
                                if severity_priority(
                                    severity_level
                                ) >= severity_priority(severity):
                                    findings.append(
                                        {
                                            "timestamp": datetime.now().isoformat(),
                                            "original": url,
                                            "test": test_url,
                                            "payload": payload,
                                            "status": response.status_code,
                                            "location": js_redirect,
                                            "redirect_outside": is_external_redirect(
                                                js_redirect, domain
                                            ),
                                            "severity": severity_level,
                                            "method": "javascript_redirect",
                                        }
                                    )

                # Check meta refresh redirects
                if check_meta_refresh:
                    meta_redirects = check_meta_refresh(response.text)
                    for meta_redirect in meta_redirects:
                        for payload in payload_list:
                            if payload in meta_redirect:
                                severity_level = determine_severity(
                                    url, test_url, meta_redirect, domain
                                )
                                if severity_priority(
                                    severity_level
                                ) >= severity_priority(severity):
                                    findings.append(
                                        {
                                            "timestamp": datetime.now().isoformat(),
                                            "original": url,
                                            "test": test_url,
                                            "payload": payload,
                                            "status": response.status_code,
                                            "location": meta_redirect,
                                            "redirect_outside": is_external_redirect(
                                                meta_redirect, domain
                                            ),
                                            "severity": severity_level,
                                            "method": "meta_refresh",
                                        }
                                    )

                if delay > 0:
                    time.sleep(delay)

            except Exception as e:
                if verbose:
                    click.echo(f"❌ Error testing {test_url}: {str(e)}")
                continue

        return findings

    def determine_severity(original_url, test_url, redirect_location, target_domain):
        """Determine severity based on redirect characteristics."""
        # Use AI assessment if available
        if ai_mode and ai_analyzer:
            ai_severity = ai_assess_severity(
                original_url, test_url, redirect_location, target_domain, ai_analyzer
            )
            if ai_severity in ["critical", "high", "medium", "low"]:
                return ai_severity

        # Fallback to rule-based assessment
        if not target_domain:
            return "medium"

        parsed_redirect = urlparse(redirect_location)

        # Critical: Redirects to completely different domains
        if parsed_redirect.netloc and target_domain not in parsed_redirect.netloc:
            return "critical"

        # High: Protocol changes or suspicious patterns
        if any(
            pattern in redirect_location.lower()
            for pattern in ["javascript:", "data:", "file:"]
        ):
            return "high"

        # Medium: Same domain but suspicious
        if parsed_redirect.netloc and target_domain in parsed_redirect.netloc:
            return "medium"

        return "low"

    def severity_priority(severity_level):
        """Convert severity to numeric priority."""
        priorities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return priorities.get(severity_level, 0)

    def is_external_redirect(location, target_domain):
        """Check if redirect goes to external domain."""
        if not target_domain or not location:
            return True

        parsed = urlparse(location)
        if not parsed.netloc:
            return False

        return target_domain not in parsed.netloc

    # Main scanning loop
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(test_url_advanced, url): url for url in urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                url_findings = future.result()
                if url_findings:
                    results.extend(url_findings)
                    for finding in url_findings:
                        if not quiet:
                            click.echo(
                                f"🚨 [{finding['severity'].upper()}] {finding['test']} -> {finding['location']}"
                            )

                        # Send notifications for high/critical findings
                        if finding["severity"] in ["high", "critical"]:
                            if slack_webhook:
                                message = f"🚨 Open Redirect Found!\nSeverity: {finding['severity'].upper()}\nURL: {finding['test']}\nRedirects to: {finding['location']}"
                                send_notification(slack_webhook, message, "slack")

                            if discord_webhook:
                                message = f"🚨 Open Redirect Found!\nSeverity: {finding['severity'].upper()}\nURL: {finding['test']}\nRedirects to: {finding['location']}"
                                send_notification(discord_webhook, message, "discord")

                tested.add(url)

            except Exception as e:
                if verbose:
                    click.echo(f"❌ Error processing {url}: {str(e)}")

    # Save resume state
    resume_data["tested"] = list(tested)
    save_resume_state(output_dir, resume_data)

    # Filter external-only if requested
    if filter_external_only:
        original_count = len(results)
        results = [r for r in results if r.get("redirect_outside", True)]
        if verbose:
            click.echo(
                f"🎯 External-only filter: {original_count} -> {len(results)} findings"
            )

    # Generate outputs
    outputs_generated = []

    # Generate AI insights if available
    ai_insights = {}
    if ai_mode and ai_analyzer and results:
        if verbose:
            click.echo("🧠 Generating AI-powered insights...")
        ai_insights = ai_generate_report_insights(results, ai_analyzer)

    # JSON output
    if output_format in ["json", "all"]:
        json_out = os.path.join(output_dir, "openredirect_results.json")
        scan_info = {
            "timestamp": datetime.now().isoformat(),
            "target_domain": target_domain,
            "program": program,
            "total_urls_tested": len(tested),
            "total_findings": len(results),
            "ai_mode": ai_mode,
            "ai_model": ai_model if ai_mode else None,
            "severity_breakdown": {
                "critical": len(
                    [r for r in results if r.get("severity") == "critical"]
                ),
                "high": len([r for r in results if r.get("severity") == "high"]),
                "medium": len([r for r in results if r.get("severity") == "medium"]),
                "low": len([r for r in results if r.get("severity") == "low"]),
            },
        }

        output_data = {"scan_info": scan_info, "findings": results}

        # Add AI insights if available
        if ai_insights:
            output_data["ai_insights"] = ai_insights

        with open(json_out, "w") as f:
            json.dump(output_data, f, indent=2)
        outputs_generated.append(json_out)

    # TXT output
    if output_format in ["txt", "all"]:
        txt_out = os.path.join(output_dir, "openredirect_results.txt")
        with open(txt_out, "w") as f:
            f.write(
                f"Open Redirect Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write("=" * 80 + "\n\n")
            for result in results:
                f.write(f"Original: {result['original']}\n")
                f.write(f"Test URL: {result['test']}\n")
                f.write(f"Redirect: {result['location']}\n")
                f.write(f"Severity: {result.get('severity', 'unknown')}\n")
                f.write(f"Method: {result.get('method', 'unknown')}\n")
                f.write("-" * 40 + "\n")
        outputs_generated.append(txt_out)

    # CSV output
    if output_format in ["csv", "all"]:
        csv_out = os.path.join(output_dir, "openredirect_results.csv")
        with open(csv_out, "w") as f:
            f.write(
                "timestamp,original_url,test_url,payload,status_code,location,external_redirect,severity,method\n"
            )
            for result in results:
                f.write(
                    f"{result.get('timestamp', '')},{result['original']},{result['test']},{result.get('payload', '')},"
                    f"{result['status']},{result['location']},{result.get('redirect_outside', '')},"
                    f"{result.get('severity', '')},{result.get('method', '')}\n"
                )
        outputs_generated.append(csv_out)

    # Markdown report
    if markdown:
        md_report = generate_markdown_report(results, output_dir, ai_insights)
        outputs_generated.append(md_report)

    # Burp Suite output
    if burp_suite:
        burp_out = os.path.join(output_dir, "burp_openredirects.txt")
        with open(burp_out, "w") as f:
            for result in results:
                f.write(f"{result['test']}\n")
        outputs_generated.append(burp_out)

    # Nuclei export
    if nuclei_export:
        nuclei_out = os.path.join(output_dir, "nuclei_targets.txt")
        with open(nuclei_out, "w") as f:
            unique_domains = set()
            for result in results:
                domain = urlparse(result["original"]).netloc
                unique_domains.add(domain)
            for domain in unique_domains:
                f.write(f"https://{domain}\n")
        outputs_generated.append(nuclei_out)

    # Database storage
    if store_db and store_target and store_vulnerability:
        target = (
            target_domain
            or domain
            or (urlparse(results[0]["original"]).netloc if results else None)
        )
        if target:
            try:
                tid = store_target(target, program=program)
                for r in results:
                    vuln_data = {
                        "url": r["original"],
                        "type": "open_redirect",
                        "severity": r.get("severity", "medium"),
                        "title": f"Open Redirect - {r['test']}",
                        "description": f"Open redirect vulnerability found. External redirect to: {r['location']}",
                        "payload": r.get("payload", ""),
                        "evidence": f"Status: {r['status']}, Location: {r['location']}, Method: {r.get('method', 'unknown')}",
                    }
                    store_vulnerability(
                        target, vuln_data, discovery_tool="openredirectcli"
                    )
                if verbose:
                    click.echo(
                        f"💾 Stored {len(results)} vulnerabilities in database for {target}"
                    )
            except Exception as e:
                if verbose:
                    click.echo(f"❌ Database storage error: {str(e)}")

    # Final summary
    if not quiet:
        click.echo("\n" + "=" * 60)
        click.echo("🎯 Scan Summary:")
        click.echo(f"   • URLs tested: {len(tested)}")
        click.echo(f"   • Vulnerabilities found: {len(results)}")

        if ai_mode:
            click.echo(f"   • AI mode: ✅ Enabled ({ai_model})")
            ai_findings = len(
                [r for r in results if r.get("method", "").startswith("ai_")]
            )
            if ai_findings > 0:
                click.echo(f"   • AI-detected findings: {ai_findings}")

        if results:
            severity_counts = {}
            for result in results:
                sev = result.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            click.echo("   • Severity breakdown:")
            for severity, count in sorted(
                severity_counts.items(),
                key=lambda x: severity_priority(x[0]),
                reverse=True,
            ):
                click.echo(f"     - {severity.capitalize()}: {count}")

        click.echo(f"   • Output files: {len(outputs_generated)}")
        for output_file in outputs_generated:
            click.echo(f"     - {output_file}")

        # Display AI insights summary
        if ai_insights and not quiet:
            click.echo("\n🧠 AI Analysis Summary:")
            if "risk_assessment" in ai_insights:
                risk_summary = (
                    ai_insights["risk_assessment"][:100] + "..."
                    if len(ai_insights["risk_assessment"]) > 100
                    else ai_insights["risk_assessment"]
                )
                click.echo(f"   • Risk: {risk_summary}")

            if "remediation_priorities" in ai_insights:
                priorities = ai_insights["remediation_priorities"]
                if isinstance(priorities, list) and priorities:
                    click.echo(f"   • Top Priority: {priorities[0]}")

        if results:
            critical_high = len(
                [r for r in results if r.get("severity") in ["critical", "high"]]
            )
            if critical_high > 0:
                click.echo(
                    f"\n⚠️  {critical_high} high/critical severity findings require immediate attention!"
                )

        click.echo("=" * 60)
        click.echo("✅ Open Redirect scan completed successfully!")

        if ai_mode and ai_insights:
            click.echo("🧠 AI-powered insights available in detailed reports")


if __name__ == "__main__":
    openredirectcli()
