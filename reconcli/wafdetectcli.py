#!/usr/bin/env python3

import click
import subprocess
import json
import httpx
import time
import random
import base64
import urllib.parse
from pathlib import Path
from rich import print
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
from typing import Dict, List, Optional, Tuple


def load_targets_from_file(file_path):
    with open(file_path) as f:
        return list({line.strip() for line in f if line.strip()})


def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def ensure_output_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


COMMON_WAF_SIGNATURES = {
    "Cloudflare": [
        "cf-ray",
        "cf-cache-status",
        "cloudflare",
        "__cfduid",
        "cf-connecting-ip",
    ],
    "Akamai": ["akamai-", "aka_", "x-akamai", "akamai-ghost-ip", "x-cache-key"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-block", "sucuri", "x-sucuri-cache"],
    "AWS WAF": [
        "x-amzn-requestid",
        "x-amz-cf-id",
        "x-amzn-trace-id",
        "x-amzn-errortype",
    ],
    "Imperva": [
        "x-cdn",
        "incapsula",
        "x-iinfo",
        "x-sab-agent",
        "incap_ses",
        "visid_incap",
    ],
    "F5 BIG-IP": [
        "x-waf",
        "x-wa-info",
        "bigip",
        "x-f5-",
        "f5-trace-id",
        "x-f5-backend",
    ],
    "DDoS-Guard": ["ddos-guard", "x-ddos", "server-info"],
    "StackPath": ["stackpath", "x-sdn-traceid", "x-served-by"],
    "Barracuda": ["barracuda", "x-barracuda", "barra"],
    "ModSecurity": ["mod_security", "modsecurity", "x-mod-security"],
    "Nginx": ["x-nginx", "nginx"],
    "Apache": ["x-apache", "apache"],
    "Fortinet": ["fortigate", "fortiweb", "x-fw-debug"],
    "Palo Alto": ["x-pan-", "panos"],
    "Check Point": ["x-checkpoint", "cpx"],
    "SonicWall": ["sonicwall", "x-sonicwall"],
    "Arbor Networks": ["arbor", "x-arbor"],
    "Radware": ["radware", "x-rdwr-"],
    "Citrix": ["citrix", "netscaler", "x-citrix"],
    "Juniper": ["juniper", "x-juniper"],
    "Wallarm": ["wallarm", "x-wallarm"],
    "Signal Sciences": ["sigsci", "x-sigsci"],
    "Edgecast": ["edgecast", "x-ec-"],
    "KeyCDN": ["keycdn", "x-cache"],
    "MaxCDN": ["maxcdn", "x-pulled-from"],
    "Fastly": ["fastly", "x-served-by", "x-cache-hits"],
    "Varnish": ["varnish", "x-varnish", "via"],
}

# Dodatkowe sygnatury dla zaawansowanego wykrywania
ADVANCED_WAF_PATTERNS = {
    "response_codes": [403, 406, 429, 501, 503],
    "blocked_phrases": [
        "access denied",
        "blocked",
        "forbidden",
        "not acceptable",
        "request blocked",
        "security violation",
        "suspicious activity",
        "waf",
        "firewall",
        "protection",
        "rate limit",
        "too many requests",
    ],
    "redirect_patterns": ["/blocked", "/denied", "/error", "/security", "/captcha"],
}

# Payloady do testowania WAF
WAF_TEST_PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
    ],
    "sqli": [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users; --",
        "1' AND 1=1#",
        "admin'--",
        "' OR 1=1 LIMIT 1 -- -+",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "rce": [
        "; ls -la",
        "| whoami",
        "; cat /etc/passwd",
        "`id`",
        "$(whoami)",
    ],
    "generic": [
        "<test>",
        "test'test",
        'test"test',
        "test;test",
        "test|test",
        "test&test",
    ],
}


def detect_waf_headers(headers):
    detected = []
    for waf, sigs in COMMON_WAF_SIGNATURES.items():
        for sig in sigs:
            for header in headers:
                if (
                    sig.lower() in header.lower()
                    or sig.lower() in headers[header].lower()
                ):
                    detected.append(waf)
                    break
    return list(set(detected))


@click.command(
    name="wafdetectcli",
    short_help="🛡 Advanced WAF detection, testing and bypass analysis",
)
@click.option(
    "--input", "-i", type=click.Path(), help="Input file with domains or URLs."
)
@click.option("--target", "-t", help="Single domain or URL to scan.")
@click.option(
    "--output-dir", default="output/wafdetect", help="Directory to save results."
)
@click.option("--output-json", is_flag=True, help="Save result as JSON.")
@click.option("--output-markdown", is_flag=True, help="Save result as Markdown.")
@click.option("--output-html", is_flag=True, help="Save result as HTML.")
@click.option("--full", is_flag=True, help="Include full raw tool output.")
@click.option("--timeout", default=15, help="Timeout per target.")
@click.option(
    "--proxy", help="Proxy (http://127.0.0.1:8080 or socks5://127.0.0.1:9050)."
)
@click.option("--resume", is_flag=True, help="Skip already scanned targets.")
@click.option("--use-whatwaf", is_flag=True, help="Use WhatWaf instead of wafw00f.")
@click.option(
    "--use-gotestwaf", is_flag=True, help="Use GoTestWAF for comprehensive testing."
)
@click.option("--use-nmap", is_flag=True, help="Use Nmap WAF detection scripts.")
@click.option("--test-bypass", is_flag=True, help="Test WAF bypass with payloads.")
@click.option(
    "--max-payloads", default=3, help="Maximum payloads per category to test."
)
@click.option(
    "--header-analysis", is_flag=True, help="Perform advanced header analysis."
)
@click.option("--all-tools", is_flag=True, help="Use all available detection tools.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def wafdetectcli(
    input,
    target,
    output_dir,
    output_json,
    output_markdown,
    output_html,
    full,
    timeout,
    proxy,
    resume,
    use_whatwaf,
    use_gotestwaf,
    use_nmap,
    test_bypass,
    max_payloads,
    header_analysis,
    all_tools,
    verbose,
):
    """
    🛡️ Advanced Web Application Firewall (WAF) Detection & Bypass Testing

    This tool provides comprehensive WAF detection using multiple methods:
    - wafw00f: Classic WAF fingerprinting
    - WhatWaf: Alternative detection engine
    - GoTestWAF: Advanced bypass testing
    - Nmap scripts: Network-level detection
    - Custom payload testing: Manual bypass attempts
    - Header analysis: Deep inspection of HTTP headers

    Examples:        # Basic WAF detection
        reconcli wafdetectcli -t example.com --output-markdown

        # Comprehensive analysis with all tools
        reconcli wafdetectcli -t example.com --all-tools --output-html

        # Bypass testing with payloads
        reconcli wafdetectcli -t example.com --test-bypass --max-payloads 5

        # Bulk scanning with GoTestWAF
        reconcli wafdetectcli -i targets.txt --use-gotestwaf --output-json
    """
    console = Console()

    if not input and not target:
        console.print("[red]❌ You must provide either --input or --target[/red]")
        return

    ensure_output_dir(output_dir)

    # Determine which tools to use
    tools_to_use = {
        "wafw00f": not use_whatwaf,  # Default unless whatwaf specified
        "whatwaf": use_whatwaf,
        "gotestwaf": use_gotestwaf or all_tools,
        "nmap": use_nmap or all_tools,
        "payload_test": test_bypass or all_tools,
        "header_analysis": header_analysis or all_tools,
    }

    if verbose:
        console.print(
            f"[blue]🔧 Tools selected:[/blue] {', '.join([k for k, v in tools_to_use.items() if v])}"
        )

    ts = timestamp()
    json_path = Path(output_dir) / f"wafdetect_advanced_{ts}.json"
    md_path = Path(output_dir) / f"wafdetect_advanced_{ts}.md"
    html_path = Path(output_dir) / f"wafdetect_advanced_{ts}.html"
    results = []
    already_scanned = set()

    # Build list of targets
    if target:
        targets = [target.strip()]
    else:
        targets = load_targets_from_file(input)

    if resume:
        previous = sorted(Path(output_dir).glob("wafdetect_advanced_*.json"))
        if previous:
            try:
                with open(previous[-1]) as f:
                    for entry in json.load(f):
                        already_scanned.add(entry["target"])
                        results.append(entry)
                console.print(
                    f"[yellow]⏩ Resume active, skipping {len(already_scanned)} targets[/yellow]"
                )
            except:
                console.print("[yellow]⚠️ Could not load previous results[/yellow]")

    targets_to_scan = [t for t in targets if t not in already_scanned]

    if verbose:
        console.print(
            f"[blue]📊 Total targets: {len(targets)}, New targets: {len(targets_to_scan)}[/blue]"
        )

    # Scan targets
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:

        task = progress.add_task("Scanning targets...", total=len(targets_to_scan))

        for i, t in enumerate(targets_to_scan):
            progress.update(
                task, description=f"Scanning {t} ({i+1}/{len(targets_to_scan)})"
            )

            if verbose:
                console.print(f"[blue]→ Scanning:[/blue] {t}")

            target_result = {
                "target": t,
                "timestamp": datetime.now().isoformat(),
                "waf_detected": False,
                "detected_wafs": [],
                "tools_used": list(tools_to_use.keys()),
                "scan_duration": 0,
            }

            scan_start = time.time()

            # Run wafw00f or whatwaf
            if tools_to_use["wafw00f"] or tools_to_use["whatwaf"]:
                waf_name = None
                waf_detected = False
                raw_output = ""

                if tools_to_use["whatwaf"]:
                    try:
                        cmd = ["whatwaf", "-u", t, "--ra", "--timeout", str(timeout)]
                        if proxy:
                            cmd += ["--proxy", proxy]
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=timeout
                        )
                        raw_output = result.stdout.strip()
                        for line in raw_output.splitlines():
                            if "identified as" in line.lower():
                                waf_detected = True
                                waf_name = line.split("identified as")[-1].strip()
                                break
                    except Exception as e:
                        raw_output = f"WhatWaf error: {e}"

                    target_result["whatwaf"] = {
                        "detected": waf_detected,
                        "waf": waf_name,
                        "raw_output": raw_output if full else "",
                    }

                else:  # wafw00f
                    try:
                        cmd = ["wafw00f", "-t", str(timeout), t]
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=timeout
                        )
                        raw_output = result.stdout.strip()

                        # Debug: print raw output in verbose mode
                        if verbose:
                            console.print(
                                f"[yellow]Debug wafw00f output:[/yellow]\n{raw_output}"
                            )

                        # Check for different wafw00f detection patterns
                        waf_names = []

                        # Pattern 1: "is behind [WAF NAME] WAF"
                        if "is behind" in raw_output and "WAF" in raw_output:
                            waf_detected = True
                            for line in raw_output.splitlines():
                                if "is behind" in line and "WAF" in line:
                                    if "is behind a" in line:
                                        waf_name = (
                                            line.split("is behind a")[-1]
                                            .strip()
                                            .split(".")[0]
                                        )
                                        waf_names.append(waf_name)
                                    elif "is behind" in line:
                                        # Pattern: "is behind CacheWall (Varnish) WAF"
                                        parts = line.split("is behind")[-1].strip()
                                        waf_name = parts.split("WAF")[0].strip()
                                        if " and/or " in waf_name:
                                            # Multiple WAFs: "CacheWall (Varnish) and/or Kona SiteDefender (Akamai)"
                                            for name in waf_name.split(" and/or "):
                                                waf_names.append(name.strip())
                                        else:
                                            waf_names.append(waf_name)
                                    break

                        # Pattern 2: "seems to be behind a WAF"
                        if "seems to be behind a WAF" in raw_output:
                            waf_detected = True
                            if not waf_names:
                                waf_names.append("Generic WAF")

                        # Set final waf_name
                        if waf_names:
                            waf_name = ", ".join(waf_names)
                    except Exception as e:
                        raw_output = f"Wafw00f error: {e}"

                    target_result["wafw00f"] = {
                        "detected": waf_detected,
                        "waf": waf_name,
                        "raw_output": raw_output if full else "",
                    }

                if waf_detected:
                    target_result["waf_detected"] = True
                    if waf_name:
                        target_result["detected_wafs"].append(waf_name)

            # Run GoTestWAF
            if tools_to_use["gotestwaf"]:
                gotestwaf_result = run_gotestwaf(t, timeout, proxy)
                target_result["gotestwaf"] = gotestwaf_result
                if gotestwaf_result.get("detected"):
                    target_result["waf_detected"] = True
                    if gotestwaf_result.get("waf_name"):
                        target_result["detected_wafs"].append(
                            gotestwaf_result["waf_name"]
                        )

            # Run Nmap scripts
            if tools_to_use["nmap"]:
                nmap_result = run_nmap_waf_scripts(t, timeout)
                target_result["nmap"] = nmap_result
                if nmap_result.get("detected"):
                    target_result["waf_detected"] = True
                    target_result["detected_wafs"].append("Nmap-detected")

            # Test bypass payloads
            if tools_to_use["payload_test"]:
                payload_result = test_waf_bypass_payloads(t, timeout, max_payloads)
                target_result["payload_test"] = payload_result
                if payload_result.get("blocked_count", 0) > 0:
                    target_result["waf_detected"] = True
                    target_result["detected_wafs"].append("Payload-detected")

            # Header analysis
            if tools_to_use["header_analysis"]:
                header_result = advanced_header_analysis(t, timeout)
                target_result["header_analysis"] = header_result
                if header_result.get("waf_indicators"):
                    target_result["waf_detected"] = True
                    target_result["detected_wafs"].extend(
                        header_result["waf_indicators"]
                    )

            # Fallback header detection if no other tools detected
            if not target_result["waf_detected"]:
                try:
                    proxy_dict = proxy if proxy else None
                    with httpx.Client(
                        timeout=timeout, follow_redirects=True, verify=False
                    ) as client:
                        url = t if t.startswith("http") else f"http://{t}"
                        response = client.get(url)
                        fallback_tags = detect_waf_headers(response.headers)
                        if fallback_tags:
                            target_result["waf_detected"] = True
                            target_result["detected_wafs"].extend(fallback_tags)
                            target_result["fallback_headers"] = fallback_tags
                except Exception as e:
                    target_result["fallback_error"] = str(e)

            target_result["scan_duration"] = time.time() - scan_start
            target_result["detected_wafs"] = list(
                set(target_result["detected_wafs"])
            )  # Remove duplicates

            results.append(target_result)
            progress.advance(task)

            if verbose:
                status = (
                    "✅ WAF detected" if target_result["waf_detected"] else "❌ No WAF"
                )
                waf_list = (
                    ", ".join(target_result["detected_wafs"])
                    if target_result["detected_wafs"]
                    else "None"
                )
                console.print(f"  {status}: {waf_list}")

    # Save results
    if output_json or all_tools:
        with open(json_path, "w") as f:
            import json as json_module

            json_module.dump(results, f, indent=2)
        console.print(f"[green]✔ JSON saved:[/green] {json_path}")

    if output_markdown or all_tools:
        generate_comprehensive_report(results, str(md_path), "markdown")
        console.print(f"[green]✔ Markdown saved:[/green] {md_path}")

    if output_html:
        generate_comprehensive_report(results, str(html_path), "html")
        console.print(f"[green]✔ HTML saved:[/green] {html_path}")

    # Summary statistics
    total_targets = len(results)
    detected_count = sum(1 for r in results if r["waf_detected"])

    console.print(f"\n[bold green]✓ Scan Complete![/bold green]")
    console.print(f"[blue]📊 Summary:[/blue]")
    console.print(f"  • Total targets: {total_targets}")
    console.print(f"  • WAF detected: {detected_count}")
    console.print(
        f"  • Detection rate: {(detected_count/total_targets*100):.1f}%"
        if total_targets > 0
        else "  • Detection rate: N/A"
    )

    # Show detected WAFs summary
    all_detected_wafs = {}
    for result in results:
        for waf in result.get("detected_wafs", []):
            all_detected_wafs[waf] = all_detected_wafs.get(waf, 0) + 1

    if all_detected_wafs:
        console.print(f"[blue]🛡️ Detected WAFs:[/blue]")
        for waf, count in sorted(
            all_detected_wafs.items(), key=lambda x: x[1], reverse=True
        ):
            console.print(f"  • {waf}: {count} targets")


def check_tool_availability(tool_name: str) -> bool:
    """Check if a tool is available in PATH"""
    try:
        subprocess.run([tool_name, "--help"], capture_output=True, timeout=5)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def run_gotestwaf(target: str, timeout: int = 30, proxy: Optional[str] = None) -> Dict:
    """Run gotestwaf for comprehensive WAF testing"""
    result = {
        "tool": "gotestwaf",
        "detected": False,
        "waf_name": None,
        "bypass_score": 0,
        "blocked_tests": [],
        "bypassed_tests": [],
        "raw_output": "",
        "error": None,
    }

    if not check_tool_availability("gotestwaf"):
        result["error"] = "gotestwaf not found in PATH"
        return result

    try:
        cmd = [
            "gotestwaf",
            "--url",
            target,
            "--format",
            "json",
            "--timeout",
            str(timeout),
        ]
        if proxy:
            cmd += ["--proxy", proxy]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result["raw_output"] = proc.stdout

        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                if "waf_name" in data:
                    result["detected"] = True
                    result["waf_name"] = data["waf_name"]
                if "bypass_score" in data:
                    result["bypass_score"] = data["bypass_score"]
                if "blocked" in data:
                    result["blocked_tests"] = data["blocked"]
                if "bypassed" in data:
                    result["bypassed_tests"] = data["bypassed"]
            except json.JSONDecodeError:
                pass

    except Exception as e:
        result["error"] = str(e)

    return result


def run_nmap_waf_scripts(target: str, timeout: int = 30) -> Dict:
    """Run Nmap WAF detection scripts"""
    result = {"tool": "nmap", "detected": False, "scripts_output": {}, "error": None}

    if not check_tool_availability("nmap"):
        result["error"] = "nmap not found in PATH"
        return result

    scripts = ["http-waf-detect", "http-waf-fingerprint", "firewalk"]

    try:
        for script in scripts:
            cmd = [
                "nmap",
                "-p",
                "80,443",
                "--script",
                script,
                target,
                "--script-timeout",
                str(timeout),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result["scripts_output"][script] = proc.stdout

            if "WAF" in proc.stdout or "firewall" in proc.stdout.lower():
                result["detected"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def test_waf_bypass_payloads(
    target: str, timeout: int = 15, max_payloads: int = 5
) -> Dict:
    """Test various bypass payloads against target"""
    result = {
        "tool": "payload_test",
        "total_tests": 0,
        "blocked_count": 0,
        "bypassed_count": 0,
        "detection_rate": 0.0,
        "payload_results": [],
        "error": None,
    }

    try:
        url = target if target.startswith("http") else f"http://{target}"

        # Test różne typy payloadów
        for payload_type, payloads in WAF_TEST_PAYLOADS.items():
            for payload in payloads[:max_payloads]:  # Limit payloadów
                try:
                    test_result = {
                        "type": payload_type,
                        "payload": payload,
                        "blocked": False,
                        "status_code": None,
                        "response_time": 0,
                        "detection_indicators": [],
                    }

                    start_time = time.time()

                    # Test GET z payloadem w parametrze
                    test_url = f"{url}?test={urllib.parse.quote(payload)}"

                    with httpx.Client(
                        timeout=timeout, follow_redirects=True, verify=False
                    ) as client:
                        response = client.get(test_url)

                        test_result["status_code"] = response.status_code
                        test_result["response_time"] = time.time() - start_time

                        # Sprawdź czy została zablokowana
                        if (
                            response.status_code
                            in ADVANCED_WAF_PATTERNS["response_codes"]
                        ):
                            test_result["blocked"] = True
                            test_result["detection_indicators"].append(
                                f"HTTP {response.status_code}"
                            )

                        # Sprawdź blocked phrases w response
                        response_text = response.text.lower()
                        for phrase in ADVANCED_WAF_PATTERNS["blocked_phrases"]:
                            if phrase in response_text:
                                test_result["blocked"] = True
                                test_result["detection_indicators"].append(
                                    f"Phrase: {phrase}"
                                )

                        # Sprawdź redirect patterns
                        if response.history:  # Jest redirect
                            final_url = str(response.url).lower()
                            for pattern in ADVANCED_WAF_PATTERNS["redirect_patterns"]:
                                if pattern in final_url:
                                    test_result["blocked"] = True
                                    test_result["detection_indicators"].append(
                                        f"Redirect: {pattern}"
                                    )

                    result["payload_results"].append(test_result)
                    result["total_tests"] += 1

                    if test_result["blocked"]:
                        result["blocked_count"] += 1
                    else:
                        result["bypassed_count"] += 1

                    # Małe opóźnienie między requestami
                    time.sleep(random.uniform(0.5, 1.5))

                except Exception as e:
                    test_result["error"] = str(e)
                    result["payload_results"].append(test_result)

        # Oblicz detection rate
        if result["total_tests"] > 0:
            result["detection_rate"] = (
                result["blocked_count"] / result["total_tests"]
            ) * 100

    except Exception as e:
        result["error"] = str(e)

    return result


def advanced_header_analysis(target: str, timeout: int = 15) -> Dict:
    """Zaawansowana analiza nagłówków HTTP"""
    result = {
        "tool": "header_analysis",
        "security_headers": {},
        "server_info": {},
        "cdn_info": {},
        "waf_indicators": [],
        "fingerprint_score": 0,
        "error": None,
    }

    try:
        url = target if target.startswith("http") else f"http://{target}"

        with httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False
        ) as client:
            # Test różnych metod HTTP
            methods = ["GET", "POST", "OPTIONS", "HEAD"]
            all_headers = {}

            for method in methods:
                try:
                    response = client.request(method, url)
                    for header, value in response.headers.items():
                        if header.lower() not in all_headers:
                            all_headers[header.lower()] = []
                        all_headers[header.lower()].append(value)
                except:
                    continue

            # Analiza security headers
            security_headers = [
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "x-xss-protection",
                "referrer-policy",
                "permissions-policy",
                "expect-ct",
            ]

            for header in security_headers:
                if header in all_headers:
                    result["security_headers"][header] = all_headers[header][0]

            # Analiza informacji o serwerze
            server_headers = [
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-generator",
            ]
            for header in server_headers:
                if header in all_headers:
                    result["server_info"][header] = all_headers[header][0]

            # Detect WAF z nagłówków
            waf_detected = detect_waf_headers(dict(all_headers))
            result["waf_indicators"] = waf_detected

            # Oblicz fingerprint score
            score = 0
            if result["security_headers"]:
                score += len(result["security_headers"]) * 10
            if result["waf_indicators"]:
                score += len(result["waf_indicators"]) * 20
            result["fingerprint_score"] = min(score, 100)

    except Exception as e:
        result["error"] = str(e)

    return result


def generate_comprehensive_report(
    results: List[Dict], output_path: str, format_type: str = "markdown"
):
    """Generate comprehensive WAF analysis report"""
    if format_type == "markdown":
        generate_markdown_report(results, output_path)
    elif format_type == "html":
        generate_html_report(results, output_path)
    elif format_type == "json":
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)


def generate_markdown_report(results: List[Dict], output_path: str):
    """Generate detailed markdown report"""
    with open(output_path, "w") as f:
        f.write("# 🛡️ Advanced WAF Detection & Bypass Report\n\n")
        f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Targets Scanned**: {len(results)}\n\n")

        # Summary table
        f.write("## 📊 Executive Summary\n\n")
        f.write(
            "| Target | WAF Detected | Detection Tools | Bypass Score | Risk Level |\n"
        )
        f.write(
            "|--------|--------------|-----------------|--------------|------------|\n"
        )

        for result in results:
            target = result["target"]
            waf_detected = "✅" if result.get("waf_detected", False) else "❌"
            tools_used = ", ".join(
                [t for t in ["wafw00f", "gotestwaf", "nmap", "headers"] if t in result]
            )
            bypass_score = result.get("gotestwaf", {}).get("bypass_score", "N/A")

            # Calculate risk level
            risk = "🟢 Low"
            if result.get("waf_detected"):
                if isinstance(bypass_score, (int, float)) and bypass_score > 70:
                    risk = "🔴 High"
                elif isinstance(bypass_score, (int, float)) and bypass_score > 30:
                    risk = "🟡 Medium"
                else:
                    risk = "🟢 Low"

            f.write(
                f"| `{target}` | {waf_detected} | {tools_used} | {bypass_score} | {risk} |\n"
            )

        f.write("\n")

        # Detailed results per target
        for result in results:
            f.write(f"## 🎯 Target: {result['target']}\n\n")

            # WAF Detection Results
            if "wafw00f" in result:
                f.write("### 🔍 wafw00f Results\n")
                wafw00f = result["wafw00f"]
                f.write(
                    f"- **Detected**: {'✅' if wafw00f.get('detected') else '❌'}\n"
                )
                f.write(f"- **WAF Name**: {wafw00f.get('waf', 'None')}\n")
                if wafw00f.get("raw_output"):
                    f.write(f"\n```\n{wafw00f['raw_output']}\n```\n")
                f.write("\n")

            # GoTestWAF Results
            if "gotestwaf" in result:
                f.write("### 🧪 GoTestWAF Results\n")
                gtw = result["gotestwaf"]
                f.write(f"- **Detected**: {'✅' if gtw.get('detected') else '❌'}\n")
                f.write(f"- **WAF Name**: {gtw.get('waf_name', 'None')}\n")
                f.write(f"- **Bypass Score**: {gtw.get('bypass_score', 'N/A')}%\n")

                if gtw.get("blocked_tests"):
                    f.write(f"- **Blocked Tests**: {len(gtw['blocked_tests'])}\n")
                if gtw.get("bypassed_tests"):
                    f.write(f"- **Bypassed Tests**: {len(gtw['bypassed_tests'])}\n")
                f.write("\n")

            # Payload Test Results
            if "payload_test" in result:
                f.write("### 💉 Payload Testing Results\n")
                pt = result["payload_test"]
                f.write(f"- **Total Tests**: {pt.get('total_tests', 0)}\n")
                f.write(f"- **Blocked**: {pt.get('blocked_count', 0)}\n")
                f.write(f"- **Bypassed**: {pt.get('bypassed_count', 0)}\n")
                f.write(f"- **Detection Rate**: {pt.get('detection_rate', 0):.1f}%\n\n")

                if pt.get("payload_results"):
                    f.write("#### Payload Details\n\n")
                    f.write("| Type | Payload | Status | Blocked | Indicators |\n")
                    f.write("|------|---------|--------|---------|------------|\n")

                    for pr in pt["payload_results"][:10]:  # Limit to 10 for readability
                        indicators = ", ".join(pr.get("detection_indicators", []))
                        blocked = "✅" if pr.get("blocked") else "❌"
                        f.write(
                            f"| {pr.get('type', 'N/A')} | `{pr.get('payload', '')[:30]}...` | {pr.get('status_code', 'N/A')} | {blocked} | {indicators} |\n"
                        )
                    f.write("\n")

            # Header Analysis
            if "header_analysis" in result:
                f.write("### 📋 Header Analysis\n")
                ha = result["header_analysis"]

                if ha.get("waf_indicators"):
                    f.write(
                        f"- **WAF Indicators**: {', '.join(ha['waf_indicators'])}\n"
                    )
                f.write(
                    f"- **Fingerprint Score**: {ha.get('fingerprint_score', 0)}/100\n"
                )

                if ha.get("security_headers"):
                    f.write("\n#### Security Headers\n")
                    for header, value in ha["security_headers"].items():
                        f.write(f"- **{header}**: `{value}`\n")

                if ha.get("server_info"):
                    f.write("\n#### Server Information\n")
                    for header, value in ha["server_info"].items():
                        f.write(f"- **{header}**: `{value}`\n")
                f.write("\n")

            f.write("---\n\n")


def generate_html_report(results: List[Dict], output_path: str):
    """Generate advanced HTML report with charts and interactive elements"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ WAF Detection & Bypass Report</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #333;
                line-height: 1.6;
            }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ 
                background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); 
                color: white; 
                padding: 30px; 
                border-radius: 15px; 
                text-align: center;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                margin-bottom: 30px;
            }}
            .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
            .header p {{ font-size: 1.2em; opacity: 0.9; }}
            
            .summary {{ 
                background: white; 
                padding: 25px; 
                border-radius: 15px; 
                margin-bottom: 30px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }}
            .summary h2 {{ color: #2c3e50; margin-bottom: 20px; }}
            
            .stats-grid {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                gap: 20px; 
                margin-bottom: 25px;
            }}
            .stat-card {{ 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; 
                padding: 20px; 
                border-radius: 10px; 
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }}
            .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }}
            .stat-label {{ font-size: 1.1em; opacity: 0.9; }}
            
            .summary-table {{ 
                width: 100%; 
                border-collapse: collapse; 
                background: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            .summary-table th {{ 
                background: #34495e; 
                color: white; 
                padding: 15px; 
                text-align: left;
                font-weight: 600;
            }}
            .summary-table td {{ 
                padding: 12px 15px; 
                border-bottom: 1px solid #ecf0f1;
            }}
            .summary-table tr:hover {{ background: #f8f9fa; }}
            
            .target-section {{ 
                background: white; 
                margin: 25px 0; 
                padding: 25px; 
                border-radius: 15px; 
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }}
            .target-section.detected {{ border-left: 5px solid #e74c3c; }}
            .target-section.not-detected {{ border-left: 5px solid #27ae60; }}
            
            .target-header {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid #ecf0f1;
            }}
            .target-title {{ font-size: 1.8em; color: #2c3e50; }}
            .status-badge {{ 
                padding: 8px 15px; 
                border-radius: 20px; 
                color: white; 
                font-weight: bold;
                font-size: 0.9em;
            }}
            .status-detected {{ background: #e74c3c; }}
            .status-not-detected {{ background: #27ae60; }}
            
            .tool-results {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 20px; 
                margin: 20px 0;
            }}
            .tool-card {{ 
                background: #f8f9fa; 
                padding: 20px; 
                border-radius: 10px; 
                border: 1px solid #dee2e6;
            }}
            .tool-card h4 {{ color: #495057; margin-bottom: 15px; font-size: 1.3em; }}
            .tool-card ul {{ list-style: none; }}
            .tool-card li {{ 
                padding: 5px 0; 
                border-bottom: 1px solid #dee2e6;
                display: flex;
                justify-content: space-between;
            }}
            .tool-card li:last-child {{ border-bottom: none; }}
            
            .payload-table {{ 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 15px;
                background: white;
                border-radius: 8px;
                overflow: hidden;
            }}
            .payload-table th {{ 
                background: #6c757d; 
                color: white; 
                padding: 10px; 
                text-align: left;
                font-size: 0.9em;
            }}
            .payload-table td {{ 
                padding: 8px 10px; 
                border-bottom: 1px solid #dee2e6;
                font-size: 0.85em;
            }}
            .payload-table .payload-cell {{ 
                max-width: 200px; 
                overflow: hidden; 
                text-overflow: ellipsis; 
                white-space: nowrap;
                font-family: monospace;
                background: #f8f9fa;
            }}
            
            .risk-high {{ color: #e74c3c; font-weight: bold; }}
            .risk-medium {{ color: #f39c12; font-weight: bold; }}
            .risk-low {{ color: #27ae60; font-weight: bold; }}
            
            .toggle-section {{ 
                background: #e9ecef; 
                padding: 10px 15px; 
                border-radius: 5px; 
                cursor: pointer; 
                margin: 10px 0;
                user-select: none;
            }}
            .toggle-section:hover {{ background: #dee2e6; }}
            .toggle-content {{ 
                display: none; 
                padding: 15px 0;
            }}
            .toggle-content.active {{ display: block; }}
            
            .footer {{ 
                text-align: center; 
                padding: 30px; 
                color: white; 
                font-size: 0.9em;
                opacity: 0.8;
            }}
        </style>
        <script>
            function toggleSection(id) {{
                const content = document.getElementById(id);
                content.classList.toggle('active');
            }}
            
            function filterTable(inputId, tableId) {{
                const input = document.getElementById(inputId);
                const table = document.getElementById(tableId);
                const filter = input.value.toLowerCase();
                const rows = table.getElementsByTagName('tr');
                
                for (let i = 1; i < rows.length; i++) {{
                    const row = rows[i];
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                }}
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ WAF Detection & Bypass Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Comprehensive analysis of {len(results)} targets</p>
            </div>
    """

    # Calculate summary statistics
    total_targets = len(results)
    detected_count = sum(1 for r in results if r.get("waf_detected", False))
    detection_rate = (detected_count / total_targets * 100) if total_targets > 0 else 0

    # Count tool usage
    tool_stats = {}
    all_wafs = {}
    total_payloads = 0
    total_blocked = 0

    for result in results:
        for tool in result.get("tools_used", []):
            tool_stats[tool] = tool_stats.get(tool, 0) + 1

        for waf in result.get("detected_wafs", []):
            all_wafs[waf] = all_wafs.get(waf, 0) + 1

        if "payload_test" in result:
            pt = result["payload_test"]
            total_payloads += pt.get("total_tests", 0)
            total_blocked += pt.get("blocked_count", 0)

    # Summary section
    html_content += f"""
            <div class="summary">
                <h2>📊 Executive Summary</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_targets}</div>
                        <div class="stat-label">Total Targets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{detected_count}</div>
                        <div class="stat-label">WAFs Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{detection_rate:.1f}%</div>
                        <div class="stat-label">Detection Rate</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_payloads}</div>
                        <div class="stat-label">Payloads Tested</div>
                    </div>
                </div>
                
                <input type="text" id="filterInput" placeholder="🔍 Filter targets..." 
                       onkeyup="filterTable('filterInput', 'summaryTable')" 
                       style="width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 5px;">
                
                <table class="summary-table" id="summaryTable">
                    <thead>
                        <tr>
                            <th>🎯 Target</th>
                            <th>🛡️ WAF Status</th>
                            <th>🔧 Tools Used</th>
                            <th>💉 Payloads</th>
                            <th>⚠️ Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    # Summary table rows
    for result in results:
        target = result["target"]
        waf_detected = (
            "✅ Detected" if result.get("waf_detected", False) else "❌ Not Detected"
        )
        tools_used = ", ".join(result.get("tools_used", []))

        payload_info = "N/A"
        if "payload_test" in result:
            pt = result["payload_test"]
            payload_info = (
                f"{pt.get('blocked_count', 0)}/{pt.get('total_tests', 0)} blocked"
            )

        # Risk calculation
        risk_class = "risk-low"
        risk_text = "🟢 Low"
        if result.get("waf_detected"):
            if "payload_test" in result:
                detection_rate = result["payload_test"].get("detection_rate", 0)
                if detection_rate > 70:
                    risk_class = "risk-high"
                    risk_text = "🔴 High"
                elif detection_rate > 30:
                    risk_class = "risk-medium"
                    risk_text = "🟡 Medium"

        html_content += f"""
                        <tr>
                            <td><strong>{target}</strong></td>
                            <td>{waf_detected}</td>
                            <td>{tools_used}</td>
                            <td>{payload_info}</td>
                            <td class="{risk_class}">{risk_text}</td>
                        </tr>
        """

    html_content += """
                    </tbody>
                </table>
            </div>
    """

    # Detailed target sections
    for i, result in enumerate(results):
        detected_class = (
            "detected" if result.get("waf_detected", False) else "not-detected"
        )
        status_class = (
            "status-detected"
            if result.get("waf_detected", False)
            else "status-not-detected"
        )
        status_text = (
            "🔴 WAF Detected" if result.get("waf_detected", False) else "🟢 No WAF"
        )

        html_content += f"""
            <div class="target-section {detected_class}">
                <div class="target-header">
                    <h3 class="target-title">🎯 {result['target']}</h3>
                    <span class="status-badge {status_class}">{status_text}</span>
                </div>
                
                <div class="tool-results">
        """

        # Tool results
        if "wafw00f" in result:
            wafw00f = result["wafw00f"]
            html_content += f"""
                    <div class="tool-card">
                        <h4>🔍 wafw00f Results</h4>
                        <ul>
                            <li><span>Detected:</span> <span>{'✅ Yes' if wafw00f.get('detected') else '❌ No'}</span></li>
                            <li><span>WAF Name:</span> <span>{wafw00f.get('waf', 'None')}</span></li>
                        </ul>
                    </div>
            """

        if "gotestwaf" in result:
            gtw = result["gotestwaf"]
            html_content += f"""
                    <div class="tool-card">
                        <h4>🧪 GoTestWAF Results</h4>
                        <ul>
                            <li><span>Detected:</span> <span>{'✅ Yes' if gtw.get('detected') else '❌ No'}</span></li>
                            <li><span>WAF Name:</span> <span>{gtw.get('waf_name', 'None')}</span></li>
                            <li><span>Bypass Score:</span> <span>{gtw.get('bypass_score', 'N/A')}%</span></li>
                        </ul>
                    </div>
            """

        if "header_analysis" in result:
            ha = result["header_analysis"]
            waf_indicators = ", ".join(ha.get("waf_indicators", [])) or "None"
            html_content += f"""
                    <div class="tool-card">
                        <h4>📋 Header Analysis</h4>
                        <ul>
                            <li><span>WAF Indicators:</span> <span>{waf_indicators}</span></li>
                            <li><span>Fingerprint Score:</span> <span>{ha.get('fingerprint_score', 0)}/100</span></li>
                            <li><span>Security Headers:</span> <span>{len(ha.get('security_headers', {}))}</span></li>
                        </ul>
                    </div>
            """

        html_content += """
                </div>
        """

        # Payload testing results
        if "payload_test" in result:
            pt = result["payload_test"]
            html_content += f"""
                <div class="toggle-section" onclick="toggleSection('payload-{i}')">
                    <strong>💉 Payload Testing Results</strong> - {pt.get('total_tests', 0)} tests, {pt.get('blocked_count', 0)} blocked ({pt.get('detection_rate', 0):.1f}% detection rate)
                </div>
                <div class="toggle-content" id="payload-{i}">
                    <table class="payload-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Payload</th>
                                <th>Status</th>
                                <th>Blocked</th>
                                <th>Indicators</th>
                            </tr>
                        </thead>
                        <tbody>
            """

            for pr in pt.get("payload_results", [])[:15]:  # Limit for performance
                indicators = ", ".join(pr.get("detection_indicators", []))
                blocked = "✅ Yes" if pr.get("blocked") else "❌ No"
                payload_display = pr.get("payload", "")[:50] + (
                    "..." if len(pr.get("payload", "")) > 50 else ""
                )

                html_content += f"""
                            <tr>
                                <td>{pr.get('type', 'N/A')}</td>
                                <td class="payload-cell" title="{pr.get('payload', '')}">{payload_display}</td>
                                <td>{pr.get('status_code', 'N/A')}</td>
                                <td>{blocked}</td>
                                <td>{indicators}</td>
                            </tr>
                """

            html_content += """
                        </tbody>
                    </table>
                </div>
            """

        html_content += "</div>"

    # Footer
    html_content += f"""
            <div class="footer">
                <p>Report generated by ReconCLI WAF Detection Tool</p>
                <p>Advanced WAF analysis with bypass testing capabilities</p>
            </div>
        </div>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
