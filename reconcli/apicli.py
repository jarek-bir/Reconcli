import click
import subprocess
import os
import json
import time
import yaml
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, quote
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import hashlib
import base64
import jwt
import random
import string
from typing import Dict, List, Any, Optional, Union


def send_notification(webhook_url, message, service="slack"):
    """Send notification to Slack or Discord webhook."""
    try:
        if "discord" in webhook_url.lower() or service == "discord":
            payload = {"content": message}
        else:  # Slack
            payload = {"text": message}

        response = requests.post(webhook_url, json=payload, timeout=3)
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False


def check_api_accessibility(url, timeout=5):
    """Check if API endpoint is accessible."""
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        return {
            "accessible": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_length": len(response.content),
            "response_time": response.elapsed.total_seconds(),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "api_version": response.headers.get("API-Version", "Unknown"),
        }
    except Exception as e:
        return {
            "accessible": False,
            "error": str(e),
            "status_code": 0,
            "server": "Unknown",
            "content_length": 0,
            "response_time": 0,
            "content_type": "Unknown",
            "api_version": "Unknown",
        }


def detect_api_technology(url, timeout=3):
    """Detect API technology stack and framework."""
    try:
        headers = {"User-Agent": "APICLI/1.0 ReconCLI API Scanner"}
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)

        api_indicators = {
            "rest": [
                "application/json",
                "application/hal+json",
                "application/vnd.api+json",
            ],
            "graphql": [
                "application/graphql",
                "graphql",
                "__schema",
                "query",
                "mutation",
            ],
            "soap": ["application/soap+xml", "text/xml", "envelope", "wsdl"],
            "grpc": ["application/grpc", "grpc-status", "grpc-message"],
            "odata": ["application/json;odata", "odata.metadata", "$metadata"],
            "jsonrpc": ["application/json-rpc", "jsonrpc", "method", "params"],
            "fastapi": ["openapi", "docs", "redoc", "swagger"],
            "django": ["django", "csrftoken", "x-frame-options"],
            "flask": ["flask", "werkzeug", "x-ratelimit"],
            "express": ["express", "x-powered-by: express"],
            "spring": ["spring", "x-application-context", "spring-boot"],
            "aspnet": ["asp.net", "x-aspnet-version", "x-powered-by: asp.net"],
            "laravel": ["laravel", "laravel_session", "x-ratelimit-limit"],
            "rails": ["rails", "x-powered-by: rails", "x-csrf-token"],
        }

        detected_tech = []
        response_text = response.text.lower()
        headers_text = str(response.headers).lower()
        content_type = response.headers.get("Content-Type", "").lower()

        for tech, indicators in api_indicators.items():
            for indicator in indicators:
                if (
                    indicator in response_text
                    or indicator in headers_text
                    or indicator in content_type
                ):
                    detected_tech.append(tech)
                    break

        # Additional detection based on response structure
        try:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                json_data = response.json()
                if "data" in json_data and "errors" in json_data:
                    detected_tech.append("graphql")
                elif "swagger" in json_data or "openapi" in json_data:
                    detected_tech.append("openapi")
        except:
            pass

        return {
            "technologies": list(set(detected_tech)),
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "api_version": response.headers.get("API-Version", "Unknown"),
            "cors_enabled": "access-control-allow-origin" in headers_text,
            "rate_limit": response.headers.get("X-RateLimit-Limit", "Unknown"),
        }
    except Exception:
        return {
            "technologies": [],
            "status_code": 0,
            "server": "Unknown",
            "content_type": "Unknown",
            "api_version": "Unknown",
            "cors_enabled": False,
            "rate_limit": "Unknown",
        }


def discover_api_endpoints(base_url, common_paths=None, timeout=3):
    """Discover common API endpoints."""
    if common_paths is None:
        common_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/v1",
            "/v2",
            "/v3",
            "/rest",
            "/graphql",
            "/swagger",
            "/openapi.json",
            "/api-docs",
            "/docs",
            "/redoc",
            "/health",
            "/status",
            "/ping",
            "/version",
            "/info",
            "/metrics",
            "/admin",
            "/users",
            "/auth",
            "/login",
            "/token",
            "/oauth",
            "/api/users",
            "/api/auth",
            "/api/login",
            "/api/admin",
            "/api/health",
            "/api/status",
            "/api/config",
            "/api/settings",
            "/api/data",
            "/api/search",
            "/api/upload",
            "/api/download",
            "/api/files",
            "/api/docs",
            "/api/test",
            "/api/debug",
            "/api/internal",
            "/api/public",
            "/api/private",
            "/api/beta",
            "/api/dev",
            "/api/staging",
            "/api/prod",
            "/api/production",
        ]

    discovered_endpoints = []
    base_url = base_url.rstrip("/")

    def check_endpoint(path):
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=timeout, verify=False)
            return {
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", "Unknown"),
                "response_time": response.elapsed.total_seconds(),
                "accessible": response.status_code < 400,
                "methods": [],
                "auth_required": response.status_code == 401,
                "rate_limited": response.status_code == 429,
            }
        except Exception as e:
            return {
                "url": urljoin(base_url, path),
                "path": path,
                "status_code": 0,
                "content_length": 0,
                "content_type": "Unknown",
                "response_time": 0,
                "accessible": False,
                "methods": [],
                "auth_required": False,
                "rate_limited": False,
                "error": str(e),
            }

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {
            executor.submit(check_endpoint, path): path for path in common_paths
        }
        for future in as_completed(future_to_path):
            result = future.result()
            if result["accessible"] or result["auth_required"]:
                discovered_endpoints.append(result)

    return discovered_endpoints


def test_http_methods(url, timeout=3):
    """Test different HTTP methods on an endpoint."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    results = {}

    for method in methods:
        try:
            response = requests.request(method, url, timeout=timeout, verify=False)
            results[method] = {
                "status_code": response.status_code,
                "allowed": response.status_code not in [404, 405],
                "content_length": len(response.content),
                "response_time": response.elapsed.total_seconds(),
                "headers": dict(response.headers),
            }
        except Exception as e:
            results[method] = {
                "status_code": 0,
                "allowed": False,
                "content_length": 0,
                "response_time": 0,
                "headers": {},
                "error": str(e),
            }

    return results


def test_authentication_bypass(url, timeout=3):
    """Test for authentication bypass vulnerabilities."""
    bypass_tests = []

    # Test different authentication bypass techniques
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Original-URL": "/admin"},
        {"X-Override-URL": "/admin"},
        {"Authorization": "Bearer invalid_token"},
        {"Authorization": "Basic " + base64.b64encode("admin:admin".encode()).decode()},
        {"Authorization": "Basic " + base64.b64encode("test:test".encode()).decode()},
        {"X-User-ID": "1"},
        {"X-User-ID": "admin"},
        {"X-Role": "admin"},
        {"X-Admin": "true"},
        {"X-Authenticated": "true"},
        {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        },
    ]

    for headers in bypass_headers:
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            test_name = f"Header: {list(headers.keys())[0]}"
            bypass_tests.append(
                {
                    "test": test_name,
                    "headers": headers,
                    "status_code": response.status_code,
                    "bypassed": response.status_code not in [401, 403],
                    "content_length": len(response.content),
                    "response_time": response.elapsed.total_seconds(),
                }
            )
        except Exception as e:
            bypass_tests.append(
                {
                    "test": test_name,
                    "headers": headers,
                    "status_code": 0,
                    "bypassed": False,
                    "content_length": 0,
                    "response_time": 0,
                    "error": str(e),
                }
            )

    return bypass_tests


def test_parameter_pollution(url, timeout=3):
    """Test for HTTP Parameter Pollution vulnerabilities."""
    test_params = [
        {"id": ["1", "2"]},  # HPP with same parameter
        {"user": ["admin", "guest"]},
        {"role": ["user", "admin"]},
        {"format": ["json", "xml"]},
        {"version": ["v1", "v2"]},
    ]

    pollution_tests = []

    for params in test_params:
        try:
            # Test with parameter pollution
            response = requests.get(url, params=params, timeout=timeout, verify=False)
            pollution_tests.append(
                {
                    "params": params,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "response_time": response.elapsed.total_seconds(),
                    "potentially_vulnerable": response.status_code == 200,
                }
            )
        except Exception as e:
            pollution_tests.append(
                {
                    "params": params,
                    "status_code": 0,
                    "content_length": 0,
                    "response_time": 0,
                    "potentially_vulnerable": False,
                    "error": str(e),
                }
            )

    return pollution_tests


def test_rate_limiting(url, requests_count=10, timeout=3):
    """Test rate limiting implementation."""
    rate_limit_results = []

    for i in range(requests_count):
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout, verify=False)
            end_time = time.time()

            rate_limit_results.append(
                {
                    "request_number": i + 1,
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "rate_limited": response.status_code == 429,
                    "rate_limit_remaining": response.headers.get(
                        "X-RateLimit-Remaining", "Unknown"
                    ),
                    "rate_limit_reset": response.headers.get(
                        "X-RateLimit-Reset", "Unknown"
                    ),
                    "retry_after": response.headers.get("Retry-After", "Unknown"),
                }
            )

            if response.status_code == 429:
                break

        except Exception as e:
            rate_limit_results.append(
                {
                    "request_number": i + 1,
                    "status_code": 0,
                    "response_time": 0,
                    "rate_limited": False,
                    "rate_limit_remaining": "Unknown",
                    "rate_limit_reset": "Unknown",
                    "retry_after": "Unknown",
                    "error": str(e),
                }
            )

    return rate_limit_results


def test_cors_configuration(url, timeout=3):
    """Test CORS configuration."""
    cors_tests = []

    # Test different origins
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "http://localhost:8080",
        "https://test.com",
        "null",
        "*",
    ]

    for origin in test_origins:
        try:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Custom-Header",
            }

            # Test preflight request
            response = requests.options(
                url, headers=headers, timeout=timeout, verify=False
            )

            cors_tests.append(
                {
                    "origin": origin,
                    "method": "OPTIONS",
                    "status_code": response.status_code,
                    "access_control_allow_origin": response.headers.get(
                        "Access-Control-Allow-Origin", "Not Set"
                    ),
                    "access_control_allow_methods": response.headers.get(
                        "Access-Control-Allow-Methods", "Not Set"
                    ),
                    "access_control_allow_headers": response.headers.get(
                        "Access-Control-Allow-Headers", "Not Set"
                    ),
                    "access_control_allow_credentials": response.headers.get(
                        "Access-Control-Allow-Credentials", "Not Set"
                    ),
                    "vulnerable": response.headers.get("Access-Control-Allow-Origin")
                    == "*"
                    and response.headers.get("Access-Control-Allow-Credentials")
                    == "true",
                }
            )

        except Exception as e:
            cors_tests.append(
                {
                    "origin": origin,
                    "method": "OPTIONS",
                    "status_code": 0,
                    "access_control_allow_origin": "Error",
                    "access_control_allow_methods": "Error",
                    "access_control_allow_headers": "Error",
                    "access_control_allow_credentials": "Error",
                    "vulnerable": False,
                    "error": str(e),
                }
            )

    return cors_tests


def test_injection_vulnerabilities(url, timeout=3):
    """Test for common injection vulnerabilities."""
    injection_payloads = {
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "admin'--",
            "admin' /*",
            "' OR 1=1#",
        ],
        "nosql_injection": [
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "this.username == this.password"}',
            '{"$gt": ""}',
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>",
        ],
        "command_injection": [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
        ],
        "ldap_injection": [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*))(|(objectClass=*",
        ],
        "xml_injection": [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<![CDATA[<script>alert('XSS')</script>]]>",
        ],
    }

    injection_results = {}

    for injection_type, payloads in injection_payloads.items():
        injection_results[injection_type] = []

        for payload in payloads:
            try:
                # Test in URL parameters
                parsed_url = urlparse(url)
                test_url = f"{url}?test={quote(payload)}"

                response = requests.get(test_url, timeout=timeout, verify=False)

                # Check for error patterns that might indicate vulnerability
                error_patterns = [
                    "sql",
                    "mysql",
                    "oracle",
                    "postgresql",
                    "sqlite",
                    "syntax error",
                    "unexpected",
                    "warning",
                    "error",
                    "exception",
                    "stack trace",
                    "debug",
                ]

                response_text = response.text.lower()
                potential_vulnerability = any(
                    pattern in response_text for pattern in error_patterns
                )

                injection_results[injection_type].append(
                    {
                        "payload": payload,
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "potential_vulnerability": potential_vulnerability,
                        "error_indicators": [
                            pattern
                            for pattern in error_patterns
                            if pattern in response_text
                        ],
                    }
                )

            except Exception as e:
                injection_results[injection_type].append(
                    {
                        "payload": payload,
                        "url": f"{url}?test={quote(payload)}",
                        "status_code": 0,
                        "content_length": 0,
                        "response_time": 0,
                        "potential_vulnerability": False,
                        "error_indicators": [],
                        "error": str(e),
                    }
                )

    return injection_results


def analyze_api_security(url, timeout=3):
    """Comprehensive API security analysis."""
    security_analysis = {
        "endpoint": url,
        "timestamp": datetime.now().isoformat(),
        "accessibility": check_api_accessibility(url, timeout),
        "technology": detect_api_technology(url, timeout),
        "http_methods": test_http_methods(url, timeout),
        "authentication_bypass": test_authentication_bypass(url, timeout),
        "parameter_pollution": test_parameter_pollution(url, timeout),
        "rate_limiting": test_rate_limiting(url, timeout=timeout),
        "cors_configuration": test_cors_configuration(url, timeout),
        "injection_tests": test_injection_vulnerabilities(url, timeout),
    }

    return security_analysis


def generate_security_report(analysis_results):
    """Generate a comprehensive security report."""
    report = {
        "summary": {
            "total_endpoints": len(analysis_results),
            "vulnerable_endpoints": 0,
            "high_risk_issues": [],
            "medium_risk_issues": [],
            "low_risk_issues": [],
        },
        "detailed_results": analysis_results,
        "recommendations": [],
        "timestamp": datetime.now().isoformat(),
    }

    for result in analysis_results:
        endpoint = result["endpoint"]

        # Check for high-risk vulnerabilities
        if result.get("cors_configuration"):
            for cors_test in result["cors_configuration"]:
                if cors_test.get("vulnerable"):
                    report["summary"]["high_risk_issues"].append(
                        {
                            "endpoint": endpoint,
                            "issue": "CORS Misconfiguration",
                            "description": f"CORS allows any origin with credentials for {cors_test['origin']}",
                            "severity": "HIGH",
                        }
                    )

        # Check for authentication bypass
        if result.get("authentication_bypass"):
            for bypass_test in result["authentication_bypass"]:
                if bypass_test.get("bypassed"):
                    report["summary"]["high_risk_issues"].append(
                        {
                            "endpoint": endpoint,
                            "issue": "Authentication Bypass",
                            "description": f"Authentication bypassed with {bypass_test['test']}",
                            "severity": "HIGH",
                        }
                    )

        # Check for injection vulnerabilities
        if result.get("injection_tests"):
            for injection_type, tests in result["injection_tests"].items():
                for test in tests:
                    if test.get("potential_vulnerability"):
                        report["summary"]["high_risk_issues"].append(
                            {
                                "endpoint": endpoint,
                                "issue": f"{injection_type.replace('_', ' ').title()} Vulnerability",
                                "description": f"Potential {injection_type} with payload: {test['payload']}",
                                "severity": "HIGH",
                            }
                        )

        # Check for rate limiting issues
        if result.get("rate_limiting"):
            rate_limited = any(
                test.get("rate_limited") for test in result["rate_limiting"]
            )
            if not rate_limited:
                report["summary"]["medium_risk_issues"].append(
                    {
                        "endpoint": endpoint,
                        "issue": "No Rate Limiting",
                        "description": "Endpoint does not implement rate limiting",
                        "severity": "MEDIUM",
                    }
                )

    report["summary"]["vulnerable_endpoints"] = len(
        set(
            issue["endpoint"]
            for issue in report["summary"]["high_risk_issues"]
            + report["summary"]["medium_risk_issues"]
            + report["summary"]["low_risk_issues"]
        )
    )

    # Generate recommendations
    if report["summary"]["high_risk_issues"]:
        report["recommendations"].append(
            "🚨 Immediately address high-risk vulnerabilities"
        )
        report["recommendations"].append(
            "🔒 Implement proper authentication and authorization"
        )
        report["recommendations"].append("🛡️ Configure CORS policies securely")
        report["recommendations"].append("🧼 Sanitize and validate all user inputs")

    if report["summary"]["medium_risk_issues"]:
        report["recommendations"].append("⚠️ Implement rate limiting on all endpoints")
        report["recommendations"].append("📊 Monitor API usage and set up alerting")

    report["recommendations"].extend(
        [
            "🔐 Use HTTPS for all API communications",
            "🎯 Implement proper error handling to avoid information disclosure",
            "📝 Log all API requests for monitoring and debugging",
            "🔄 Regular security testing and vulnerability assessments",
        ]
    )

    return report


def save_results(results, output_dir, format_type="json"):
    """Save scan results to files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_type == "json":
        output_file = output_path / f"apicli_results_{timestamp}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return output_file

    elif format_type == "yaml":
        output_file = output_path / f"apicli_results_{timestamp}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(results, f, default_flow_style=False, allow_unicode=True)
        return output_file

    elif format_type == "markdown":
        output_file = output_path / f"apicli_report_{timestamp}.md"
        with open(output_file, "w") as f:
            f.write("# API Security Analysis Report\n\n")
            f.write(
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            if "summary" in results:
                f.write("## Summary\n\n")
                f.write(
                    f"- **Total Endpoints:** {results['summary']['total_endpoints']}\n"
                )
                f.write(
                    f"- **Vulnerable Endpoints:** {results['summary']['vulnerable_endpoints']}\n"
                )
                f.write(
                    f"- **High Risk Issues:** {len(results['summary']['high_risk_issues'])}\n"
                )
                f.write(
                    f"- **Medium Risk Issues:** {len(results['summary']['medium_risk_issues'])}\n"
                )
                f.write(
                    f"- **Low Risk Issues:** {len(results['summary']['low_risk_issues'])}\n\n"
                )

                if results["summary"]["high_risk_issues"]:
                    f.write("## 🚨 High Risk Issues\n\n")
                    for issue in results["summary"]["high_risk_issues"]:
                        f.write(f"- **{issue['issue']}** at `{issue['endpoint']}`\n")
                        f.write(f"  - {issue['description']}\n\n")

                if results["summary"]["medium_risk_issues"]:
                    f.write("## ⚠️ Medium Risk Issues\n\n")
                    for issue in results["summary"]["medium_risk_issues"]:
                        f.write(f"- **{issue['issue']}** at `{issue['endpoint']}`\n")
                        f.write(f"  - {issue['description']}\n\n")

                if results.get("recommendations"):
                    f.write("## 📋 Recommendations\n\n")
                    for rec in results["recommendations"]:
                        f.write(f"- {rec}\n")
                    f.write("\n")

        return output_file


@click.command()
@click.option("--url", required=True, help="Target API URL or base URL")
@click.option(
    "--endpoints-file",
    type=click.Path(exists=True),
    help="File containing API endpoints (one per line)",
)
@click.option("--discover", is_flag=True, help="Auto-discover API endpoints")
@click.option(
    "--security-test", is_flag=True, help="Perform comprehensive security testing"
)
@click.option("--method-test", is_flag=True, help="Test HTTP methods on endpoints")
@click.option(
    "--auth-bypass", is_flag=True, help="Test authentication bypass techniques"
)
@click.option("--cors-test", is_flag=True, help="Test CORS configuration")
@click.option(
    "--injection-test", is_flag=True, help="Test for injection vulnerabilities"
)
@click.option(
    "--rate-limit-test", is_flag=True, help="Test rate limiting implementation"
)
@click.option(
    "--parameter-pollution", is_flag=True, help="Test HTTP Parameter Pollution"
)
@click.option("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option(
    "--user-agent", default="APICLI/1.0 ReconCLI API Scanner", help="Custom User-Agent"
)
@click.option("--custom-headers", help="Custom headers (key:value,key2:value2)")
@click.option("--timeout", default=5, type=int, help="Request timeout in seconds")
@click.option("--threads", default=10, type=int, help="Number of concurrent threads")
@click.option("--delay", default=0, type=float, help="Delay between requests (seconds)")
@click.option("--output-dir", default="output/apicli", help="Output directory")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--yaml-report", is_flag=True, help="Generate YAML report")
@click.option("--markdown-report", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--tech-detect", is_flag=True, help="Detect API technologies")
@click.option("--verify-ssl", is_flag=True, help="Verify SSL certificates")
@click.option(
    "--max-requests",
    default=100,
    type=int,
    help="Maximum requests for rate limit testing",
)
def main(
    url,
    endpoints_file,
    discover,
    security_test,
    method_test,
    auth_bypass,
    cors_test,
    injection_test,
    rate_limit_test,
    parameter_pollution,
    proxy,
    user_agent,
    custom_headers,
    timeout,
    threads,
    delay,
    output_dir,
    json_report,
    yaml_report,
    markdown_report,
    slack_webhook,
    discord_webhook,
    verbose,
    tech_detect,
    verify_ssl,
    max_requests,
):
    """
    🔍 Advanced API Security Scanner and Analyzer

    Comprehensive API testing tool with security vulnerability detection:
    • API endpoint discovery and enumeration
    • HTTP method testing and analysis
    • Authentication bypass detection
    • CORS configuration testing
    • Injection vulnerability testing (SQL, NoSQL, XSS, Command, LDAP, XML)
    • Rate limiting implementation testing
    • HTTP Parameter Pollution testing
    • Technology stack detection
    • Comprehensive security reporting

    Security Testing Features:
    --security-test              # Full security assessment
    --method-test                # HTTP method analysis
    --auth-bypass                # Authentication bypass testing
    --cors-test                  # CORS configuration testing
    --injection-test             # Injection vulnerability testing
    --rate-limit-test            # Rate limiting testing
    --parameter-pollution        # HTTP Parameter Pollution testing

    Discovery and Analysis:
    --discover                   # Auto-discover API endpoints
    --tech-detect                # Detect API technologies
    --endpoints-file endpoints.txt # Load endpoints from file

    Examples:
    # Basic API discovery
    apicli --url https://api.example.com --discover --tech-detect

    # Comprehensive security testing
    apicli --url https://api.example.com --security-test --json-report --markdown-report

    # Targeted testing
    apicli --url https://api.example.com --method-test --cors-test --auth-bypass

    # Load endpoints from file
    apicli --url https://api.example.com --endpoints-file endpoints.txt --injection-test

    # Full security assessment with reporting
    apicli --url https://api.example.com --security-test --discover --slack-webhook https://hooks.slack.com/... --json-report --markdown-report
    """

    if verbose:
        print("🚀 [START] APICLI - Advanced API Security Scanner")
        print(f"🎯 [TARGET] {url}")

    # Parse custom headers
    headers = {}
    if custom_headers:
        for header in custom_headers.split(","):
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

    # Add User-Agent
    headers["User-Agent"] = user_agent

    # Configure requests session
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    if not verify_ssl:
        session.verify = False
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Prepare endpoints list
    endpoints = []

    # Add base URL
    endpoints.append(url)

    # Load endpoints from file
    if endpoints_file:
        if verbose:
            print(f"📂 [LOAD] Loading endpoints from {endpoints_file}")
        with open(endpoints_file, "r") as f:
            for line in f:
                endpoint = line.strip()
                if endpoint and not endpoint.startswith("#"):
                    if not endpoint.startswith("http"):
                        endpoint = urljoin(url, endpoint)
                    endpoints.append(endpoint)
        if verbose:
            print(f"📝 [LOAD] Loaded {len(endpoints) - 1} endpoints from file")

    # Discover endpoints
    if discover:
        if verbose:
            print("🔍 [DISCOVER] Auto-discovering API endpoints...")
        discovered = discover_api_endpoints(url, timeout=timeout)
        for endpoint in discovered:
            endpoints.append(endpoint["url"])
        if verbose:
            print(f"🔍 [DISCOVER] Found {len(discovered)} endpoints")

    # Remove duplicates
    endpoints = list(set(endpoints))

    if verbose:
        print(f"📊 [TOTAL] Testing {len(endpoints)} endpoints")

    # Test accessibility
    if verbose:
        print("🌐 [CHECK] Testing API accessibility...")
    accessibility = check_api_accessibility(url, timeout)
    if accessibility["accessible"]:
        if verbose:
            print(
                f"✅ [CHECK] API accessible (Status: {accessibility['status_code']}, Server: {accessibility['server']})"
            )
    else:
        print(
            f"❌ [ERROR] API not accessible: {accessibility.get('error', 'Unknown error')}"
        )
        return

    # Technology detection
    if tech_detect:
        if verbose:
            print("🔬 [TECH] Detecting API technologies...")
        tech_info = detect_api_technology(url, timeout)
        if tech_info["technologies"]:
            if verbose:
                print(f"🔬 [TECH] Detected: {', '.join(tech_info['technologies'])}")
        else:
            if verbose:
                print("🔬 [TECH] No specific technologies detected")

    # Initialize results
    all_results = []

    # Process each endpoint
    for i, endpoint in enumerate(endpoints):
        if verbose:
            print(f"🔍 [SCAN] Processing endpoint {i+1}/{len(endpoints)}: {endpoint}")

        endpoint_results = {
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
        }

        # Always check accessibility
        endpoint_results["accessibility"] = check_api_accessibility(endpoint, timeout)

        # Technology detection for each endpoint
        if tech_detect:
            endpoint_results["technology"] = detect_api_technology(endpoint, timeout)

        # HTTP methods testing
        if method_test or security_test:
            if verbose:
                print(f"🔧 [METHODS] Testing HTTP methods on {endpoint}")
            endpoint_results["http_methods"] = test_http_methods(endpoint, timeout)

        # Authentication bypass testing
        if auth_bypass or security_test:
            if verbose:
                print(f"🔐 [AUTH] Testing authentication bypass on {endpoint}")
            endpoint_results["authentication_bypass"] = test_authentication_bypass(
                endpoint, timeout
            )

        # CORS testing
        if cors_test or security_test:
            if verbose:
                print(f"🌐 [CORS] Testing CORS configuration on {endpoint}")
            endpoint_results["cors_configuration"] = test_cors_configuration(
                endpoint, timeout
            )

        # Injection testing
        if injection_test or security_test:
            if verbose:
                print(f"💉 [INJECT] Testing injection vulnerabilities on {endpoint}")
            endpoint_results["injection_tests"] = test_injection_vulnerabilities(
                endpoint, timeout
            )

        # Rate limiting testing
        if rate_limit_test or security_test:
            if verbose:
                print(f"⏱️ [RATE] Testing rate limiting on {endpoint}")
            endpoint_results["rate_limiting"] = test_rate_limiting(
                endpoint, min(max_requests, 10), timeout
            )

        # Parameter pollution testing
        if parameter_pollution or security_test:
            if verbose:
                print(f"🔄 [PARAM] Testing parameter pollution on {endpoint}")
            endpoint_results["parameter_pollution"] = test_parameter_pollution(
                endpoint, timeout
            )

        all_results.append(endpoint_results)

        # Add delay between requests
        if delay > 0:
            time.sleep(delay)

    # Generate security report
    if security_test or any(
        [
            method_test,
            auth_bypass,
            cors_test,
            injection_test,
            rate_limit_test,
            parameter_pollution,
        ]
    ):
        if verbose:
            print("📊 [REPORT] Generating security report...")
        security_report = generate_security_report(all_results)
    else:
        security_report = {
            "summary": {
                "total_endpoints": len(all_results),
                "vulnerable_endpoints": 0,
                "high_risk_issues": [],
                "medium_risk_issues": [],
                "low_risk_issues": [],
            },
            "detailed_results": all_results,
            "recommendations": [],
            "timestamp": datetime.now().isoformat(),
        }

    # Save results
    output_files = []

    if json_report:
        json_file = save_results(security_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] JSON report saved to {json_file}")

    if yaml_report:
        yaml_file = save_results(security_report, output_dir, "yaml")
        output_files.append(yaml_file)
        if verbose:
            print(f"💾 [SAVE] YAML report saved to {yaml_file}")

    if markdown_report:
        md_file = save_results(security_report, output_dir, "markdown")
        output_files.append(md_file)
        if verbose:
            print(f"💾 [SAVE] Markdown report saved to {md_file}")

    # Always save JSON by default
    if not any([json_report, yaml_report, markdown_report]):
        json_file = save_results(security_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] Default JSON report saved to {json_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("📊 [SUMMARY] API Security Analysis Results")
    print("=" * 60)
    print(f"🎯 Target: {url}")
    print(f"📝 Endpoints tested: {security_report['summary']['total_endpoints']}")
    print(
        f"🔴 Vulnerable endpoints: {security_report['summary']['vulnerable_endpoints']}"
    )
    print(f"🚨 High risk issues: {len(security_report['summary']['high_risk_issues'])}")
    print(
        f"⚠️ Medium risk issues: {len(security_report['summary']['medium_risk_issues'])}"
    )
    print(f"📋 Low risk issues: {len(security_report['summary']['low_risk_issues'])}")

    # Display high-risk issues
    if security_report["summary"]["high_risk_issues"]:
        print("\n🚨 [HIGH RISK ISSUES]")
        for issue in security_report["summary"]["high_risk_issues"][:5]:  # Show top 5
            print(f"  • {issue['issue']} at {issue['endpoint']}")
            print(f"    {issue['description']}")

    # Display recommendations
    if security_report["recommendations"]:
        print("\n📋 [RECOMMENDATIONS]")
        for rec in security_report["recommendations"][:5]:  # Show top 5
            print(f"  {rec}")

    # Send notifications
    if slack_webhook or discord_webhook:
        summary_message = f"🔍 API Security Scan Complete\n"
        summary_message += f"Target: {url}\n"
        summary_message += (
            f"Endpoints: {security_report['summary']['total_endpoints']}\n"
        )
        summary_message += (
            f"Vulnerable: {security_report['summary']['vulnerable_endpoints']}\n"
        )
        summary_message += (
            f"High Risk: {len(security_report['summary']['high_risk_issues'])}\n"
        )
        summary_message += (
            f"Medium Risk: {len(security_report['summary']['medium_risk_issues'])}\n"
        )

        if slack_webhook:
            if send_notification(slack_webhook, summary_message, "slack"):
                if verbose:
                    print("✅ [NOTIFY] Slack notification sent")
            else:
                if verbose:
                    print("❌ [NOTIFY] Failed to send Slack notification")

        if discord_webhook:
            if send_notification(discord_webhook, summary_message, "discord"):
                if verbose:
                    print("✅ [NOTIFY] Discord notification sent")
            else:
                if verbose:
                    print("❌ [NOTIFY] Failed to send Discord notification")

    print(f"\n📂 Results saved in: {output_dir}")
    print("🎉 [COMPLETE] APICLI scan finished successfully!")


if __name__ == "__main__":
    main()
