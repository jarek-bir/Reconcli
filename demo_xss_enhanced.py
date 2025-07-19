#!/usr/bin/env python3
"""
Demo nowych funkcji AI i Tor w XSS CLI - standalone test
"""

from datetime import datetime
import json


def ai_analyze_xss_results_demo(results, query="", target_info=None):
    """Demo wersja AI analysis dla XSS wyników"""
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

    # Recommendations
    analysis.append(f"\n💡 Recommendations:")

    if vulnerable_count > 0:
        analysis.append(f"  🚨 CRITICAL: {vulnerable_count} XSS vulnerabilities found!")
        analysis.append(f"  - Implement proper input validation and output encoding")
        analysis.append(f"  - Use Content Security Policy (CSP) headers")
        analysis.append(f"  - Consider implementing XSS protection headers")

        if any("document.cookie" in str(r.get("payload", "")) for r in results):
            analysis.append(
                f"  - Implement HttpOnly cookie flags to prevent cookie theft"
            )

        if any(
            "script" in str(r.get("payload", "")).lower()
            for r in results
            if r.get("vulnerable")
        ):
            analysis.append(f"  - Review all user input points for script injection")
    else:
        analysis.append(f"  ✅ No XSS vulnerabilities detected in this scan")
        analysis.append(f"  - Continue regular security testing")
        analysis.append(f"  - Consider testing with more advanced payloads")

    # Target-specific insights
    if target_info:
        analysis.append(f"\n🎯 Target-Specific Insights:")
        if target_info.get("tor_used"):
            analysis.append(f"  - All requests made through Tor proxy for anonymity")
        if "waf" in target_info:
            analysis.append(f"  - WAF detected: {target_info['waf']}")
        if "technologies" in target_info:
            analysis.append(
                f"  - Technologies: {', '.join(target_info['technologies'])}"
            )

    return "\n".join(analysis)


def demo_tor_setup():
    """Demo Tor setup functionality"""
    print("🔒 Tor Proxy Setup Demo")
    print("=" * 40)

    print("\n[*] Tor proxy configuration:")
    print("  Default proxy: socks5://127.0.0.1:9050")
    print("  Connection timeout: 15 seconds")
    print("  User-Agent: Firefox/91.0 (anonymized)")

    print("\n[*] Tor connectivity checks:")
    print("  ✅ Check real IP address")
    print("  ✅ Verify Tor proxy connection")
    print("  ✅ Test IP change through Tor")
    print("  ✅ Validate with torproject.org")
    print("  ✅ DNS leak protection test")

    print("\n[*] Security features:")
    print("  🔒 Anonymous HTTP requests")
    print("  🔄 IP rotation per session")
    print("  🛡️  WAF evasion capabilities")
    print("  📊 Request anonymization metrics")


def main():
    """Main demo function"""
    print("🚀 XSS CLI Enhanced Features - AI & Tor Demo")
    print("=" * 60)

    # Demo AI Analysis
    print("\n" + "🤖 AI ANALYSIS DEMO".center(60, "="))

    # Create sample XSS test results
    sample_results = [
        {
            "url": "https://example.com/search?q=<script>alert('XSS')</script>",
            "target": "https://example.com",
            "param": "q",
            "payload": "<script>alert('XSS')</script>",
            "method": "GET",
            "reflected": True,
            "vulnerable": True,
            "response_code": 200,
            "response_length": 1234,
            "timestamp": datetime.now().isoformat(),
            "tor_used": False,
        },
        {
            "url": "https://example.com/contact",
            "target": "https://example.com/contact",
            "param": "message",
            "payload": "<img src=x onerror=alert('XSS')>",
            "method": "POST",
            "reflected": True,
            "vulnerable": True,
            "response_code": 200,
            "response_length": 2456,
            "timestamp": datetime.now().isoformat(),
            "tor_used": True,
        },
        {
            "url": "https://example.com/login?user=<svg onload=alert('XSS')>",
            "target": "https://example.com",
            "param": "user",
            "payload": "<svg onload=alert('XSS')>",
            "method": "GET",
            "reflected": False,
            "vulnerable": False,
            "response_code": 403,
            "response_length": 567,
            "timestamp": datetime.now().isoformat(),
            "tor_used": False,
        },
        {
            "url": "https://example.com/profile?name=javascript:alert('XSS')",
            "target": "https://example.com",
            "param": "name",
            "payload": "javascript:alert('XSS')",
            "method": "GET",
            "reflected": True,
            "vulnerable": True,
            "response_code": 200,
            "response_length": 3456,
            "timestamp": datetime.now().isoformat(),
            "tor_used": True,
        },
        {
            "url": "https://example.com/api/data",
            "target": "https://example.com",
            "param": "input",
            "payload": "document.cookie",
            "method": "POST",
            "reflected": True,
            "vulnerable": True,
            "response_code": 200,
            "response_length": 789,
            "timestamp": datetime.now().isoformat(),
            "tor_used": True,
        },
    ]

    target_info = {
        "tor_used": True,
        "targets_count": 2,
        "payloads_count": 5,
        "waf": "Cloudflare",
        "technologies": ["React", "Node.js", "Express"],
    }

    # Run AI analysis
    ai_result = ai_analyze_xss_results_demo(
        sample_results, "Advanced XSS test on example.com", target_info
    )
    print(ai_result)

    print("\n" + "🔒 TOR PROXY DEMO".center(60, "="))
    demo_tor_setup()

    print("\n" + "🎯 USAGE EXAMPLES".center(60, "="))
    print("\n📋 Command Examples:")
    print("# Basic XSS testing with AI analysis")
    print("reconcli xsscli test-input --input urls.txt --ai")
    print()
    print("# Anonymous XSS testing through Tor")
    print("reconcli xsscli test-input --input urls.txt --tor")
    print()
    print("# Combined AI analysis and Tor scanning")
    print("reconcli xsscli test-input --input urls.txt --ai --tor --delay 2")
    print()
    print("# Manual testing with AI and Tor")
    print("reconcli xsscli manual-test --url https://example.com --ai --tor")
    print()
    print("# Check Tor connectivity")
    print("reconcli xsscli tor-check --tor-proxy socks5://127.0.0.1:9050")
    print()
    print("# Tor setup instructions")
    print("reconcli xsscli tor-setup")
    print()
    print("# Full scan with enhanced features")
    print("reconcli xsscli full-scan --target example.com --ai --tor --threads 10")

    print("\n" + "✅ FEATURES SUMMARY".center(60, "="))
    print("\n🎯 New Capabilities Added:")
    print("1. 🤖 Comprehensive AI-powered XSS analysis")
    print("2. 🔒 Tor proxy support for anonymous testing")
    print("3. 📊 Advanced vulnerability pattern recognition")
    print("4. 🛡️  WAF detection and bypass recommendations")
    print("5. 📈 Statistical analysis of test results")
    print("6. 🎭 IP anonymization and rotation")
    print("7. 🔍 Enhanced security insights and recommendations")

    print("\n🚀 Ready for production use!")


if __name__ == "__main__":
    main()
