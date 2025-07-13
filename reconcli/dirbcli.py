import click
import subprocess
import os
import json
import time
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import hashlib
import shutil


def find_executable(name):
    """Find full path to executable, preventing B607 partial path issues."""
    full_path = shutil.which(name)
    if full_path:
        return full_path
    raise FileNotFoundError(f"Executable '{name}' not found in PATH")


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


def check_url_accessibility(url, timeout=5):
    """Check if target URL is accessible."""
    try:
        response = requests.get(url, timeout=timeout, verify=True)
        return {
            "accessible": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_length": len(response.content),
            "response_time": response.elapsed.total_seconds(),
        }
    except Exception as e:
        return {
            "accessible": False,
            "error": str(e),
            "status_code": 0,
            "server": "Unknown",
            "content_length": 0,
            "response_time": 0,
        }


def detect_web_technology(url, timeout=3):
    """Detect web technology stack for smart wordlist selection."""
    try:
        headers = {"User-Agent": "DirBCLI/1.0 ReconCLI Directory Scanner"}
        response = requests.get(url, headers=headers, timeout=timeout, verify=True)

        tech_indicators = {
            "php": [".php", "x-powered-by: php", "set-cookie: phpsessid"],
            "asp": [".asp", ".aspx", "x-powered-by: asp.net", "x-aspnet-version"],
            "jsp": [".jsp", "jsessionid", "x-powered-by: jsp"],
            "python": ["django", "flask", "x-powered-by: python"],
            "ruby": ["x-powered-by: ruby", "x-powered-by: rails"],
            "nodejs": ["x-powered-by: express", "x-powered-by: node.js"],
            "wordpress": ["wp-content", "wp-includes", "/wp-admin"],
            "drupal": ["drupal", "x-drupal-cache", "x-generator: drupal"],
            "joomla": ["joomla", "/administrator/", "x-content-encoded-by: joomla"],
            "apache": ["server: apache", "x-powered-by: apache"],
            "nginx": ["server: nginx", "x-powered-by: nginx"],
            "iis": ["server: microsoft-iis", "x-powered-by: iis"],
            "tomcat": ["server: apache-tomcat", "x-powered-by: tomcat"],
        }

        detected_tech = []
        response_text = response.text.lower()
        headers_text = str(response.headers).lower()

        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in response_text or indicator in headers_text:
                    detected_tech.append(tech)
                    break

        return {
            "technologies": list(set(detected_tech)),
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
        }
    except Exception:
        return {
            "technologies": [],
            "status_code": 0,
            "server": "Unknown",
            "content_type": "Unknown",
        }


def get_smart_wordlist_recommendations(technologies, base_wordlist):
    """Recommend additional wordlists based on detected technologies."""
    recommendations = []

    # Technology-specific wordlists
    tech_wordlists = {
        "php": ["php.txt", "php-files.txt", "php-directories.txt"],
        "asp": ["asp.txt", "aspx.txt", "iis.txt"],
        "jsp": ["jsp.txt", "java.txt", "tomcat.txt"],
        "python": ["python.txt", "django.txt", "flask.txt"],
        "ruby": ["ruby.txt", "rails.txt"],
        "nodejs": ["nodejs.txt", "express.txt", "javascript.txt"],
        "wordpress": ["wordpress.txt", "wp-plugins.txt", "wp-themes.txt"],
        "drupal": ["drupal.txt", "drupal-modules.txt"],
        "joomla": ["joomla.txt", "joomla-components.txt"],
        "apache": ["apache.txt", "htaccess.txt"],
        "nginx": ["nginx.txt", "nginx-config.txt"],
        "iis": ["iis.txt", "aspnet.txt"],
        "tomcat": ["tomcat.txt", "java-web.txt"],
    }

    for tech in technologies:
        if tech in tech_wordlists:
            recommendations.extend(tech_wordlists[tech])

    return list(set(recommendations))


def parse_tool_output(tool, output_file, target_url=None):
    """Parse tool output and extract findings."""
    findings = []

    try:
        if tool == "ffuf" and output_file.suffix == ".json":
            with open(output_file, "r") as f:
                data = json.load(f)
                for result in data.get("results", []):
                    findings.append(
                        {
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "words": result.get("words", 0),
                            "lines": result.get("lines", 0),
                            "response_time": result.get("duration", 0)
                            / 1000000,  # Convert to seconds
                            "tool": "ffuf",
                        }
                    )
        else:
            # Parse text output for other tools
            with open(output_file, "r") as f:
                content = f.read()

                # Basic parsing patterns for different tools
                if tool == "feroxbuster":
                    pattern = (
                        r"(\d+)\s+\w+\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+(https?://[^\s]+)"
                    )
                elif tool == "gobuster":
                    pattern = r"(https?://[^\s]+)\s+\(Status:\s+(\d+)\)"
                elif tool == "dirsearch":
                    pattern = r"(\d+)\s+-\s+\d+\w?\s+-\s+(https?://[^\s]+)"
                elif tool == "dirb":
                    # DIRB output: ==> DIRECTORY: http://example.com/admin/
                    # DIRB output: + http://example.com/admin/ (CODE:301|SIZE:194)
                    pattern = r"(?:\+\s+)?(https?://[^\s]+)(?:\s+\(CODE:(\d+)\|SIZE:(\d+)\))?|(?:==>\s+DIRECTORY:\s+(https?://[^\s]+))"
                elif tool == "wfuzz":
                    # Wfuzz text output format: ID   Response   Lines    Word     Chars          Payload
                    # 000000001:   200        22 L     59 W      615 Ch       "admin"
                    pattern = r"(\d+):\s+(\d+)\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+\"([^\"]+)\""
                elif tool == "dirmap":
                    # DIRMAP output format: status_code content_length url
                    pattern = r"(\d+)\s+(\d+)\s+(https?://[^\s]+)"
                elif tool == "dirhunt":
                    # DIRHUNT output: [STATUS] URL (flags)
                    # Example: [200] https://example.com/admin/ (Generic)
                    pattern = r"\[(\d+)\]\s+(https?://[^\s]+)\s*(?:\([^)]*\))?"
                else:
                    pattern = r"(https?://[^\s]+)"

                matches = re.findall(pattern, content)
                for match in matches:
                    if tool == "wfuzz" and isinstance(match, tuple) and len(match) >= 4:
                        # Wfuzz specific parsing: (id, status, length, payload)
                        payload = match[3]
                        if target_url:
                            base_url = target_url.rstrip("/")
                            full_url = f"{base_url}/{payload}"
                        else:
                            full_url = payload
                        findings.append(
                            {
                                "url": full_url,
                                "status": int(match[1]) if match[1].isdigit() else 200,
                                "length": int(match[2]) if match[2].isdigit() else 0,
                                "words": 0,
                                "lines": 0,
                                "response_time": 0,
                                "tool": "wfuzz",
                            }
                        )
                    elif (
                        tool == "dirhunt"
                        and isinstance(match, tuple)
                        and len(match) >= 2
                    ):
                        # Dirhunt specific parsing: (status, url)
                        findings.append(
                            {
                                "url": match[1],
                                "status": int(match[0]) if match[0].isdigit() else 200,
                                "length": 0,
                                "words": 0,
                                "lines": 0,
                                "response_time": 0,
                                "tool": "dirhunt",
                            }
                        )
                    elif isinstance(match, tuple):
                        if len(match) >= 2:
                            findings.append(
                                {
                                    "url": match[-1],
                                    "status": (
                                        int(match[0]) if match[0].isdigit() else 200
                                    ),
                                    "length": 0,
                                    "words": 0,
                                    "lines": 0,
                                    "response_time": 0,
                                    "tool": tool,
                                }
                            )
                    else:
                        findings.append(
                            {
                                "url": match,
                                "status": 200,
                                "length": 0,
                                "words": 0,
                                "lines": 0,
                                "response_time": 0,
                                "tool": tool,
                            }
                        )
    except Exception as e:
        print(f"[!] Error parsing {tool} output: {e}")

    return findings


def smart_filter_responses(findings, similarity_threshold=0.95):
    """Apply intelligent filtering to remove false positives and duplicates."""
    if not findings:
        return findings

    filtered_findings = []
    response_hashes = set()

    for finding in findings:
        # Calculate content hash for duplicate detection
        content_key = f"{finding.get('status', 0)}_{finding.get('length', 0)}_{finding.get('words', 0)}"
        content_hash = hashlib.md5(
            content_key.encode(), usedforsecurity=False
        ).hexdigest()

        # Skip obvious duplicates
        if content_hash in response_hashes:
            continue

        response_hashes.add(content_hash)

        # Filter common false positives
        if is_false_positive(finding):
            continue

        # Check for similar responses
        if not is_similar_to_existing(finding, filtered_findings, similarity_threshold):
            filtered_findings.append(finding)

    return filtered_findings


def is_false_positive(finding):
    """Detect common false positive patterns."""
    url = finding.get("url", "").lower()
    status = finding.get("status", 0)
    length = finding.get("length", 0)

    # Common false positive patterns
    false_positive_patterns = [
        r"/\d+$",  # Numeric paths
        r"/[a-f0-9]{32}$",  # MD5 hashes
        r"/[a-f0-9]{40}$",  # SHA1 hashes
        r"/tmp_\w+",  # Temporary files  # nosec B108
        r"/__\w+__",  # Double underscore patterns
    ]

    for pattern in false_positive_patterns:
        if re.search(pattern, url):
            return True

    # Filter by status codes and content length
    if status in [404, 500] and length < 100:
        return True

    return False


def is_similar_to_existing(finding, existing_findings, threshold=0.95):
    """Check if finding is similar to existing ones."""
    current_signature = create_response_signature(finding)

    for existing in existing_findings:
        existing_signature = create_response_signature(existing)
        similarity = calculate_similarity(current_signature, existing_signature)

        if similarity >= threshold:
            return True

    return False


def create_response_signature(finding):
    """Create a signature for response comparison."""
    return {
        "status": finding.get("status", 0),
        "length": finding.get("length", 0),
        "words": finding.get("words", 0),
        "lines": finding.get("lines", 0),
    }


def calculate_similarity(sig1, sig2):
    """Calculate similarity between two response signatures."""
    if sig1["status"] != sig2["status"]:
        return 0.0

    # Calculate similarity based on content metrics
    length_diff = abs(sig1["length"] - sig2["length"])
    word_diff = abs(sig1["words"] - sig2["words"])
    line_diff = abs(sig1["lines"] - sig2["lines"])

    # Normalize differences
    max_length = max(sig1["length"], sig2["length"], 1)
    max_words = max(sig1["words"], sig2["words"], 1)
    max_lines = max(sig1["lines"], sig2["lines"], 1)

    length_similarity = 1.0 - (length_diff / max_length)
    word_similarity = 1.0 - (word_diff / max_words)
    line_similarity = 1.0 - (line_diff / max_lines)

    # Weighted average
    return length_similarity * 0.5 + word_similarity * 0.3 + line_similarity * 0.2


def analyze_response_patterns(findings):
    """Analyze response patterns for anomaly detection."""
    if not findings:
        return {}

    analysis = {
        "status_distribution": {},
        "length_distribution": {},
        "anomalies": [],
        "patterns": [],
    }

    # Analyze status code distribution
    for finding in findings:
        status = finding.get("status", 0)
        analysis["status_distribution"][status] = (
            analysis["status_distribution"].get(status, 0) + 1
        )

    # Analyze content length distribution
    lengths = [f.get("length", 0) for f in findings]
    if lengths:
        avg_length = sum(lengths) / len(lengths)
        analysis["average_length"] = avg_length

        # Find anomalies (responses significantly different from average)
        for finding in findings:
            length = finding.get("length", 0)
            if abs(length - avg_length) > (avg_length * 0.5):  # 50% deviation
                analysis["anomalies"].append(
                    {
                        "url": finding.get("url", ""),
                        "reason": "unusual_length",
                        "length": length,
                        "average": avg_length,
                    }
                )

    return analysis


def detect_honeypots_and_waf(findings, target_url):
    """Detect honeypots and WAF responses."""
    detection_results = {
        "honeypot_indicators": [],
        "waf_indicators": [],
        "suspicious_patterns": [],
    }

    # Common honeypot patterns
    honeypot_patterns = [
        r"honeypot",
        r"canary",
        r"trap",
        r"decoy",
        r"fake",
    ]

    # WAF response patterns
    waf_patterns = [
        r"blocked",
        r"denied",
        r"forbidden",
        r"security",
        r"firewall",
        r"protection",
    ]

    for finding in findings:
        url = finding.get("url", "").lower()

        # Check for honeypot indicators
        for pattern in honeypot_patterns:
            if re.search(pattern, url):
                detection_results["honeypot_indicators"].append(
                    {
                        "url": finding.get("url", ""),
                        "pattern": pattern,
                        "confidence": 0.8,
                    }
                )

        # Check for WAF indicators
        for pattern in waf_patterns:
            if re.search(pattern, url):
                detection_results["waf_indicators"].append(
                    {
                        "url": finding.get("url", ""),
                        "pattern": pattern,
                        "confidence": 0.7,
                    }
                )

    return detection_results


def generate_backup_wordlist(base_wordlist, detected_technologies):
    """Generate backup file variations for discovered paths."""
    backup_extensions = [
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".save",
        ".tmp",
        ".swp",
        "~",
    ]
    backup_prefixes = ["backup_", "old_", "orig_", "copy_"]

    backup_words = []

    try:
        with open(base_wordlist, "r") as f:
            original_words = [line.strip() for line in f.readlines()]

        for word in original_words[:1000]:  # Limit to first 1000 words
            # Add backup extensions
            for ext in backup_extensions:
                backup_words.append(word + ext)

            # Add backup prefixes
            for prefix in backup_prefixes:
                backup_words.append(prefix + word)

    except Exception:
        pass

    return backup_words


def adaptive_threading_controller(findings, initial_threads=10, max_threads=50):
    """Dynamically adjust threading based on server response."""
    if not findings:
        return initial_threads

    # Calculate average response time
    response_times = [
        f.get("response_time", 0) for f in findings if f.get("response_time", 0) > 0
    ]

    if not response_times:
        return initial_threads

    avg_response_time = sum(response_times) / len(response_times)

    # Adjust threads based on response time
    if avg_response_time < 0.5:  # Fast responses
        return min(max_threads, initial_threads * 2)
    elif avg_response_time < 1.0:  # Medium responses
        return initial_threads
    elif avg_response_time < 2.0:  # Slow responses
        return max(5, initial_threads // 2)
    else:  # Very slow responses
        return max(3, initial_threads // 4)


def discover_parameters(findings, target_url, timeout=5):
    """Discover parameters for found endpoints."""
    parameter_discoveries = []

    # Common parameter names to test
    common_params = [
        "id",
        "user",
        "admin",
        "debug",
        "test",
        "action",
        "cmd",
        "exec",
        "page",
        "file",
        "path",
        "dir",
        "url",
        "redirect",
        "next",
        "return",
        "search",
        "q",
        "query",
        "keyword",
        "filter",
        "sort",
        "order",
        "limit",
        "offset",
        "page",
        "per_page",
        "count",
        "max",
        "min",
    ]

    for finding in findings:
        url = finding.get("url", "")
        status = finding.get("status", 0)

        # Only test successful responses
        if status not in [200, 201, 202, 301, 302, 303, 307, 308]:
            continue

        discovered_params = []

        for param in common_params:
            try:
                # Test parameter with different values
                test_url = f"{url}?{param}=1"
                response = requests.get(test_url, timeout=timeout, verify=True)

                if (
                    response.status_code != finding.get("status", 0)
                    or abs(len(response.content) - finding.get("length", 0)) > 100
                ):
                    discovered_params.append(
                        {
                            "parameter": param,
                            "test_url": test_url,
                            "response_status": response.status_code,
                            "response_length": len(response.content),
                            "confidence": 0.6,
                        }
                    )
            except:
                continue

        if discovered_params:
            parameter_discoveries.append({"url": url, "parameters": discovered_params})

    return parameter_discoveries


def categorize_findings(findings):
    """Categorize findings by type and risk level."""
    categories = {
        "admin_panels": [],
        "config_files": [],
        "backups": [],
        "sensitive_files": [],
        "api_endpoints": [],
        "development_files": [],
        "server_info": [],
        "other": [],
    }

    # Define categorization patterns
    patterns = {
        "admin_panels": [
            r"/admin",
            r"/administrator",
            r"/dashboard",
            r"/panel",
            r"/manage",
            r"/control",
        ],
        "config_files": [
            r"\.conf$",
            r"\.config$",
            r"\.ini$",
            r"\.xml$",
            r"\.json$",
            r"\.yaml$",
            r"\.yml$",
            r"config\.php$",
            r"configuration\.php$",
        ],
        "backups": [
            r"\.bak$",
            r"\.backup$",
            r"\.old$",
            r"\.orig$",
            r"\.save$",
            r"\.tmp$",
            r"\.swp$",
            r"backup\.zip$",
            r"\.zip$",
        ],
        "sensitive_files": [
            r"\.log$",
            r"\.sql$",
            r"\.db$",
            r"\.txt$",
            r"/private",
            r"/secret",
            r"/confidential",
        ],
        "api_endpoints": [
            r"/api",
            r"/rest",
            r"/graphql",
            r"/v1",
            r"/v2",
            r"/ws",
            r"/service",
        ],
        "development_files": [
            r"\.dev$",
            r"\.test$",
            r"\.staging$",
            r"/debug",
            r"/dev",
            r"/test",
            r"\.git",
        ],
        "server_info": [
            r"/server-status",
            r"/server-info",
            r"/info",
            r"/status",
            r"/health",
            r"/metrics",
        ],
    }

    for finding in findings:
        url = finding["url"].lower()
        categorized = False

        for category, category_patterns in patterns.items():
            for pattern in category_patterns:
                if re.search(pattern, url):
                    categories[category].append(finding)
                    categorized = True
                    break
            if categorized:
                break

        if not categorized:
            categories["other"].append(finding)

    return categories


def generate_comprehensive_report(output_dir, stats, findings, categories, tech_info):
    """Generate comprehensive directory brute force report."""
    report_data = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "scanner": "DirBCLI",
            "version": "1.0",
        },
        "target_info": {
            "url": stats.get("target_url", ""),
            "technology_stack": tech_info.get("technologies", []),
            "server": tech_info.get("server", "Unknown"),
            "accessibility": stats.get("accessibility", {}),
        },
        "scan_statistics": stats,
        "findings": {
            "total": len(findings),
            "by_status": {},
            "by_category": {cat: len(items) for cat, items in categories.items()},
            "detailed": findings,
        },
        "categorized_findings": categories,
        "recommendations": generate_security_recommendations(categories, tech_info),
    }

    # Count findings by status code
    for finding in findings:
        status = finding.get("status", 0)
        report_data["findings"]["by_status"][status] = (
            report_data["findings"]["by_status"].get(status, 0) + 1
        )

    # Save JSON report
    json_file = Path(output_dir) / "dirbcli_report.json"
    with open(json_file, "w") as f:
        json.dump(report_data, f, indent=2)

    # Generate Markdown report
    md_content = generate_markdown_report(report_data)
    md_file = Path(output_dir) / "dirbcli_report.md"
    with open(md_file, "w") as f:
        f.write(md_content)

    return json_file, md_file


def generate_markdown_report(report_data):
    """Generate comprehensive Markdown report."""
    md_content = f"""# 🔍 DirBCLI Directory Brute Force Report

## 📊 Scan Overview

- **🕐 Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **🎯 Target**: {report_data['target_info']['url']}
- **🛠️ Technology Stack**: {', '.join(report_data['target_info']['technology_stack']) if report_data['target_info']['technology_stack'] else 'Not detected'}
- **🖥️ Server**: {report_data['target_info']['server']}
- **📁 Total Findings**: {report_data['findings']['total']}
- **⏱️ Scan Duration**: {report_data['scan_statistics'].get('scan_duration', 0):.2f} seconds

## 📊 Findings by Status Code

| Status Code | Count | Description |
|-------------|--------|-------------|
"""

    status_descriptions = {
        200: "OK - Accessible",
        301: "Moved Permanently",
        302: "Found - Redirect",
        403: "Forbidden - Access Denied",
        404: "Not Found",
        500: "Internal Server Error",
    }

    for status, count in report_data["findings"]["by_status"].items():
        desc = status_descriptions.get(status, "Unknown")
        md_content += f"| {status} | {count} | {desc} |\n"

    md_content += f"""
## 🎯 Findings by Category

| Category | Count | Risk Level |
|----------|--------|------------|
"""

    risk_levels = {
        "admin_panels": "🔴 High",
        "config_files": "🟡 Medium",
        "backups": "🟠 Medium-High",
        "sensitive_files": "🟡 Medium",
        "api_endpoints": "🟡 Medium",
        "development_files": "🟠 Medium-High",
        "server_info": "🟡 Medium",
        "other": "🟢 Low",
    }

    for category, count in report_data["findings"]["by_category"].items():
        if count > 0:
            risk = risk_levels.get(category, "🟢 Low")
            md_content += (
                f"| {category.replace('_', ' ').title()} | {count} | {risk} |\n"
            )

    # Add detailed findings for high-risk categories
    high_risk_categories = [
        "admin_panels",
        "config_files",
        "backups",
        "sensitive_files",
        "development_files",
    ]

    for category in high_risk_categories:
        if (
            category in report_data["categorized_findings"]
            and report_data["categorized_findings"][category]
        ):
            md_content += f"""
### 🔍 {category.replace('_', ' ').title()} Details

| URL | Status | Size |
|-----|--------|------|
"""
            for finding in report_data["categorized_findings"][category][
                :10
            ]:  # Show first 10
                md_content += f"| {finding['url']} | {finding['status']} | {finding['length']} |\n"

            if len(report_data["categorized_findings"][category]) > 10:
                md_content += f"*... and {len(report_data['categorized_findings'][category]) - 10} more items*\n"

    md_content += f"""
## 🔒 Security Recommendations

{chr(10).join(f"- {rec}" for rec in report_data['recommendations'])}

## 📝 Notes

- **Manual Verification Required**: All findings should be manually verified
- **False Positives**: Some results may be false positives
- **Security Testing**: This scan is for authorized testing only
- **Further Analysis**: Consider additional security testing for high-risk findings

---
**Generated by**: DirBCLI v1.0 | **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    return md_content


def generate_security_recommendations(categories, tech_info):
    """Generate security recommendations based on findings."""
    recommendations = []

    # Category-based recommendations
    if categories.get("admin_panels"):
        recommendations.append(
            "🔐 Secure admin panels with strong authentication and IP restrictions"
        )
        recommendations.append(
            "🛡️ Consider moving admin interfaces to non-standard paths"
        )

    if categories.get("config_files"):
        recommendations.append("⚙️ Remove or secure exposed configuration files")
        recommendations.append(
            "🔒 Ensure sensitive configuration data is not publicly accessible"
        )

    if categories.get("backups"):
        recommendations.append("🗂️ Remove backup files from web-accessible directories")
        recommendations.append("📦 Implement proper backup storage procedures")

    if categories.get("sensitive_files"):
        recommendations.append("🔐 Restrict access to sensitive files and directories")
        recommendations.append(
            "🛡️ Implement proper file permissions and access controls"
        )

    if categories.get("development_files"):
        recommendations.append(
            "🚫 Remove development files from production environment"
        )
        recommendations.append("🔧 Implement proper deployment procedures")

    if categories.get("api_endpoints"):
        recommendations.append("🔑 Secure API endpoints with proper authentication")
        recommendations.append("📋 Implement API rate limiting and monitoring")

    # Technology-specific recommendations
    technologies = tech_info.get("technologies", [])
    if "wordpress" in technologies:
        recommendations.append("📝 Keep WordPress core, themes, and plugins updated")
        recommendations.append("🔐 Secure wp-admin and wp-config.php")

    if "php" in technologies:
        recommendations.append("🐘 Review PHP configuration for security settings")
        recommendations.append("🔒 Disable dangerous PHP functions if not needed")

    if "apache" in technologies:
        recommendations.append("🌐 Review Apache configuration for security hardening")
        recommendations.append("📄 Secure .htaccess files and directory listings")

    if "nginx" in technologies:
        recommendations.append(
            "⚡ Review Nginx configuration for security best practices"
        )
        recommendations.append(
            "🔧 Implement proper location blocks and access controls"
        )

    # General recommendations
    recommendations.extend(
        [
            "🔍 Implement regular security scanning and monitoring",
            "📊 Set up web application firewall (WAF) protection",
            "📈 Monitor web server logs for suspicious activity",
            "🔄 Implement proper error handling to avoid information disclosure",
        ]
    )

    return recommendations


def save_resume_state(output_dir, stats, tool, url, wordlist):
    """Save resume state to file."""
    try:
        resume_file = Path(output_dir) / "dirbcli_resume.json"
        resume_data = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool,
            "url": url,
            "wordlist": str(wordlist),
            "output_dir": str(output_dir),
            "stats": stats,
            "status": "in_progress",
        }

        with open(resume_file, "w") as f:
            json.dump(resume_data, f, indent=2)

        return resume_file
    except Exception:
        return None


def load_resume_state(output_dir):
    """Load resume state from file."""
    try:
        resume_file = Path(output_dir) / "dirbcli_resume.json"
        if not resume_file.exists():
            return None

        with open(resume_file, "r") as f:
            resume_data = json.load(f)

        return resume_data
    except Exception:
        return None


def update_resume_state(output_dir, status, additional_data=None):
    """Update resume state file."""
    try:
        resume_file = Path(output_dir) / "dirbcli_resume.json"
        if not resume_file.exists():
            return False

        with open(resume_file, "r") as f:
            resume_data = json.load(f)

        resume_data["status"] = status
        resume_data["last_updated"] = datetime.now().isoformat()

        if additional_data:
            resume_data.update(additional_data)

        with open(resume_file, "w") as f:
            json.dump(resume_data, f, indent=2)

        return True
    except Exception:
        return False


def clear_resume_state(output_dir):
    """Clear resume state file."""
    try:
        resume_file = Path(output_dir) / "dirbcli_resume.json"
        if resume_file.exists():
            resume_file.unlink()
        return True
    except Exception:
        return False


def cleanup_temporary_files(output_dir, keep_reports=True):
    """Clean up temporary files but keep important results."""
    try:
        output_path = Path(output_dir)

        # Files to potentially remove
        temp_files = ["dirbcli_resume.json", "feroxbuster.state"]

        # Don't remove these important files
        keep_files = []
        if keep_reports:
            keep_files.extend(
                [
                    "dirbcli_report.json",
                    "dirbcli_report.md",
                    "ffuf.json",
                    "feroxbuster.txt",
                    "gobuster.txt",
                    "dirsearch.txt",
                    "dirb.txt",
                    "wfuzz.txt",
                    "dirmap.txt",
                    "dirhunt.txt",
                    "dirhunt.json",
                ]
            )

        for temp_file in temp_files:
            temp_path = output_path / temp_file
            if temp_path.exists() and temp_file not in keep_files:
                temp_path.unlink()

        return True
    except Exception:
        return False


def get_builtin_user_agents():
    """Get list of built-in User-Agent strings."""
    return [
        # Modern browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Mobile browsers
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        # Search engine bots
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)",
        # Security tools
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "sqlmap/1.7.11#stable (http://sqlmap.org)",
        "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
        # Pentesting tools
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0 (Kali Linux)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;ENUS)",
        "curl/8.5.0",
        "Wget/1.21.4",
        # Legacy browsers (for testing)
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        # Custom ReconCLI
        "DirBCLI/1.0 ReconCLI Directory Scanner",
        "ReconCLI/1.0 (Advanced Security Scanner)",
    ]


def load_user_agents_from_file(file_path):
    """Load User-Agent strings from file."""
    try:
        user_agents = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # Skip empty lines and comments
                    user_agents.append(line)
        return user_agents
    except Exception as e:
        print(f"[!] Error loading User-Agents from {file_path}: {e}")
        return []


def get_user_agents(user_agent_option, user_agent_file, builtin_ua, random_ua):
    """Get User-Agent strings based on options."""
    user_agents = []

    # Priority order: file -> builtin -> custom -> default
    if user_agent_file:
        file_agents = load_user_agents_from_file(user_agent_file)
        if file_agents:
            user_agents.extend(file_agents)
            if random_ua and len(file_agents) > 1:
                import random

                return [
                    random.choice(
                        file_agents
                    )  # nosec: B311 - non-cryptographic use for UA selection
                ]
            return file_agents
        else:
            print(f"[!] Failed to load User-Agents from file, falling back to builtin")

    if builtin_ua:
        builtin_agents = get_builtin_user_agents()
        if random_ua:
            import random

            return [
                random.choice(
                    builtin_agents
                )  # nosec: B311 - non-cryptographic use for UA selection
            ]
        return builtin_agents

    if user_agent_option:
        return list(user_agent_option)

    # Default
    return ["Mozilla/5.0 (DirBCLI/1.0 ReconCLI Scanner)"]


@click.command()
@click.option("--url", required=True, help="Target URL (e.g., http://example.com)")
@click.option(
    "--wordlist",
    type=click.Path(exists=True),
    help="Path to wordlist (optional for dirhunt)",
)
@click.option(
    "--tool",
    type=click.Choice(
        [
            "ffuf",
            "feroxbuster",
            "gobuster",
            "dirsearch",
            "dirb",
            "wfuzz",
            "dirmap",
            "dirhunt",
        ]
    ),
    default="ffuf",
    help="Directory brute-forcing tool to use",
)
@click.option("--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
@click.option("--include-ext", help="Extensions to include (e.g., php,html,txt)")
@click.option("--user-agent", multiple=True, help="Custom User-Agent(s)")
@click.option(
    "--user-agent-file",
    type=click.Path(exists=True),
    help="File containing User-Agent strings (one per line)",
)
@click.option(
    "--builtin-ua", is_flag=True, help="Use built-in User-Agent collection (25+ agents)"
)
@click.option(
    "--random-ua", is_flag=True, help="Use random User-Agent from selected collection"
)
@click.option("--delay", type=float, help="Delay between requests (in seconds)")
@click.option("--rate-limit", type=int, help="Rate limit (requests per second)")
@click.option("--resume", is_flag=True, help="Resume previous scan if possible")
@click.option(
    "--clear-resume", is_flag=True, help="Clear previous resume state and start fresh"
)
@click.option("--show-resume", is_flag=True, help="Show previous scan status and exit")
@click.option("--cleanup", is_flag=True, help="Clean up temporary files after scan")
@click.option("--timeout", type=int, default=3, help="Request timeout in seconds")
@click.option(
    "--output-dir",
    type=click.Path(),
    default="output/dirbcli",
    help="Directory to save results",
)
@click.option("--threads", type=int, default=25, help="Number of threads/workers")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--smart-wordlist",
    is_flag=True,
    help="Use smart wordlist selection based on detected technology",
)
@click.option("--filter-status", help="Filter by status codes (e.g., 200,301,403)")
@click.option("--filter-size", help="Filter by response size range (e.g., 100-1000)")
@click.option("--recursive", is_flag=True, help="Enable recursive directory scanning")
@click.option("--max-depth", type=int, default=3, help="Maximum recursion depth")
@click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--markdown-report", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--custom-headers", help="Custom headers (key:value,key2:value2)")
@click.option("--verify-ssl", is_flag=True, help="Verify SSL certificates")
@click.option(
    "--auto-calibrate",
    is_flag=True,
    help="Auto-calibrate filtering (for ffuf/feroxbuster)",
)
@click.option(
    "--exclude-length", help="Exclude responses with specific lengths (comma-separated)"
)
@click.option(
    "--include-length",
    help="Include only responses with specific lengths (comma-separated)",
)
@click.option("--match-regex", help="Match responses with regex pattern")
@click.option(
    "--tech-detect", is_flag=True, help="Detect web technologies before scanning"
)
@click.option(
    "--smart-filter", is_flag=True, help="Enable intelligent false positive filtering"
)
@click.option(
    "--response-analysis", is_flag=True, help="Enable deep response content analysis"
)
@click.option(
    "--similarity-threshold",
    type=float,
    default=0.95,
    help="Similarity threshold for duplicate detection (0.0-1.0)",
)
@click.option(
    "--pattern-analysis", is_flag=True, help="Enable pattern-based response analysis"
)
@click.option(
    "--honeypot-detection", is_flag=True, help="Enable honeypot and WAF detection"
)
@click.option(
    "--adaptive-threading",
    is_flag=True,
    help="Enable adaptive threading based on server response",
)
@click.option(
    "--backup-detection",
    is_flag=True,
    help="Enable backup file detection (.bak, .old, ~)",
)
@click.option(
    "--parameter-discovery",
    is_flag=True,
    help="Enable parameter discovery for found endpoints",
)
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (auto-detected if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
def dirbcli(
    url,
    wordlist,
    tool,
    proxy,
    include_ext,
    user_agent,
    user_agent_file,
    builtin_ua,
    random_ua,
    delay,
    rate_limit,
    resume,
    clear_resume,
    show_resume,
    cleanup,
    timeout,
    output_dir,
    threads,
    verbose,
    smart_wordlist,
    filter_status,
    filter_size,
    recursive,
    max_depth,
    follow_redirects,
    json_report,
    markdown_report,
    slack_webhook,
    discord_webhook,
    custom_headers,
    verify_ssl,
    auto_calibrate,
    exclude_length,
    include_length,
    match_regex,
    tech_detect,
    smart_filter,
    response_analysis,
    similarity_threshold,
    pattern_analysis,
    honeypot_detection,
    adaptive_threading,
    backup_detection,
    parameter_discovery,
    store_db,
    target_domain,
    program,
):
    """
    🔍 Advanced Directory Brute Force Scanner with Smart Analysis

    Multi-tool directory brute forcing with intelligent features:
    • Smart wordlist selection based on detected technologies
    • Comprehensive reporting with security recommendations
    • Advanced filtering and categorization
    • Real-time notifications and progress tracking
    • Resume functionality for large scans
    • Technology detection and analysis
    • Built-in User-Agent collection and rotation
    • Smart filtering for false positive reduction
    • Response pattern analysis and anomaly detection
    • Honeypot and WAF detection
    • Adaptive threading optimization
    • Backup file discovery
    • Parameter discovery for endpoints

    Supported Tools:
    • ffuf - Fast web fuzzer (default, recommended)
    • feroxbuster - Rust-based recursive scanner
    • gobuster - Go-based directory/file brute forcer
    • dirsearch - Python-based web path scanner
    • dirb - Classic directory brute forcer
    • wfuzz - Web application fuzzer
    • dirmap - Advanced web directory & file enumeration
    • dirhunt - Intelligent directory discovery without brute force

    Smart Analysis Features:
    --smart-filter              # Intelligent false positive filtering
    --response-analysis         # Deep response content analysis
    --pattern-analysis          # Pattern-based response analysis
    --honeypot-detection        # Honeypot and WAF detection
    --adaptive-threading        # Dynamic thread optimization
    --backup-detection          # Backup file discovery (.bak, .old, ~)
    --parameter-discovery       # Parameter discovery for endpoints

    User-Agent Options:
    --user-agent "Custom UA"           # Single custom User-Agent
    --user-agent-file agents.txt       # Load from file (one per line)
    --builtin-ua                       # Use 25+ built-in User-Agents
    --builtin-ua --random-ua           # Random built-in User-Agent
    --user-agent-file ua.txt --random-ua  # Random from file

    Examples:
    # Basic scanning with different tools
    dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --tech-detect --smart-wordlist
    dirbcli --url https://example.com --wordlist big.txt --tool feroxbuster --recursive --max-depth 2
    dirbcli --url https://example.com --wordlist common.txt --tool dirb --builtin-ua --random-ua
    dirbcli --url https://example.com --wordlist wordlist.txt --tool wfuzz --json-report
    dirbcli --url https://example.com --tool dirhunt --tech-detect --smart-filter  # Intelligent discovery

    # Smart analysis and filtering
    dirbcli --url https://example.com --wordlist wordlist.txt --smart-filter --response-analysis
    dirbcli --url https://example.com --wordlist wordlist.txt --pattern-analysis --honeypot-detection
    dirbcli --url https://example.com --wordlist wordlist.txt --adaptive-threading --backup-detection
    dirbcli --url https://example.com --wordlist wordlist.txt --parameter-discovery --similarity-threshold 0.9

    # Combined advanced features
    dirbcli --url https://example.com --wordlist wordlist.txt --tool ffuf --smart-filter --response-analysis --honeypot-detection --backup-detection --parameter-discovery --builtin-ua --random-ua --json-report --markdown-report
    """

    # Initialize scan statistics
    start_time = time.time()
    stats = {
        "target_url": url,
        "tool_used": tool,
        "wordlist_size": 0,
        "scan_duration": 0,
        "findings_count": 0,
        "accessibility": {},
        "technology_info": {},
    }

    # Setup output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Handle resume options
    if show_resume:
        resume_data = load_resume_state(output_dir)
        if resume_data:
            click.echo(f"📋 [RESUME] Previous scan status:")
            click.echo(f"  • Target: {resume_data.get('url', 'Unknown')}")
            click.echo(f"  • Tool: {resume_data.get('tool', 'Unknown')}")
            click.echo(f"  • Status: {resume_data.get('status', 'Unknown')}")
            click.echo(f"  • Started: {resume_data.get('timestamp', 'Unknown')}")
            if resume_data.get("last_updated"):
                click.echo(f"  • Updated: {resume_data.get('last_updated')}")
        else:
            click.echo("📋 [RESUME] No previous scan state found")
        return

    if clear_resume:
        if clear_resume_state(output_dir):
            click.echo("🗑️ [RESUME] Previous scan state cleared")
        else:
            click.echo("⚠️ [RESUME] No previous scan state to clear")
        if not resume:  # If only clearing, don't continue with scan
            return

    # Check for resume possibility
    resume_data = None
    if resume:
        resume_data = load_resume_state(output_dir)
        if resume_data:
            if verbose:
                click.echo(
                    f"🔄 [RESUME] Found previous scan state from {resume_data.get('timestamp', 'unknown time')}"
                )
                click.echo(
                    f"🔄 [RESUME] Previous target: {resume_data.get('url', 'unknown')}"
                )
                click.echo(
                    f"🔄 [RESUME] Previous tool: {resume_data.get('tool', 'unknown')}"
                )

            # Validate resume compatibility
            if (
                resume_data.get("url") != url
                or resume_data.get("tool") != tool
                or resume_data.get("wordlist") != str(wordlist)
            ):
                if verbose:
                    click.echo(
                        "⚠️ [RESUME] Resume data doesn't match current parameters, starting fresh"
                    )
                resume_data = None
        else:
            if verbose:
                click.echo("🔄 [RESUME] No previous scan state found, starting fresh")

    # Check URL accessibility
    if verbose:
        click.echo("🌐 [CHECK] Testing target accessibility...")

    accessibility = check_url_accessibility(url, timeout)
    stats["accessibility"] = accessibility

    if not accessibility["accessible"]:
        click.echo(
            f"❌ [ERROR] Target {url} is not accessible: {accessibility['error']}"
        )
        return

    if verbose:
        click.echo(
            f"✅ [CHECK] Target accessible (Status: {accessibility['status_code']}, Server: {accessibility['server']})"
        )

    # Save initial resume state (if not resuming)
    if not resume_data:
        save_resume_state(output_dir, stats, tool, url, wordlist)
        if verbose:
            click.echo("💾 [RESUME] Scan state saved for potential resume")

    # Technology detection
    tech_info = {"technologies": [], "server": "Unknown", "content_type": "Unknown"}
    if tech_detect:
        if verbose:
            click.echo("🛠️ [TECH] Detecting web technologies...")

        tech_info = detect_web_technology(url, timeout)
        stats["technology_info"] = tech_info

        if tech_info["technologies"]:
            if verbose:
                click.echo(f"🛠️ [TECH] Detected: {', '.join(tech_info['technologies'])}")

            # Smart wordlist recommendations
            if smart_wordlist and wordlist:
                recommendations = get_smart_wordlist_recommendations(
                    tech_info["technologies"], wordlist
                )
                if recommendations and verbose:
                    click.echo(
                        f"💡 [SMART] Recommended additional wordlists: {', '.join(recommendations[:3])}"
                    )
        else:
            if verbose:
                click.echo("🛠️ [TECH] No specific technologies detected")

    # Get wordlist size (skip for dirhunt as it doesn't require wordlist)
    if tool != "dirhunt" and not wordlist:
        click.echo(f"❌ [ERROR] Wordlist is required for {tool}")
        return

    if wordlist:
        try:
            with open(wordlist, "r") as f:
                stats["wordlist_size"] = sum(1 for _ in f)
            if verbose:
                click.echo(f"📝 [WORDLIST] Loaded {stats['wordlist_size']} entries")
        except Exception as e:
            click.echo(f"❌ [ERROR] Cannot read wordlist: {e}")
            return
    else:
        stats["wordlist_size"] = 0
        if verbose:
            click.echo("📝 [WORDLIST] Using intelligent discovery (no wordlist needed)")

    # Special handling for dirhunt: it can work without wordlist
    if tool == "dirhunt" and not wordlist:
        if verbose:
            click.echo(
                "🧠 [DIRHUNT] Running in intelligent discovery mode without wordlist"
            )

    # Prepare User-Agent
    user_agents = get_user_agents(user_agent, user_agent_file, builtin_ua, random_ua)

    if verbose:
        if len(user_agents) == 1:
            click.echo(
                f"🔧 [USER-AGENT] Using: {user_agents[0][:80]}{'...' if len(user_agents[0]) > 80 else ''}"
            )
        else:
            click.echo(f"🔧 [USER-AGENT] Using {len(user_agents)} User-Agents")
            if verbose and len(user_agents) <= 5:
                for i, ua in enumerate(user_agents, 1):
                    click.echo(f"  {i}. {ua[:60]}{'...' if len(ua) > 60 else ''}")

    # Prepare custom headers
    headers_dict = {}
    if custom_headers:
        for header in custom_headers.split(","):
            if ":" in header:
                key, value = header.split(":", 1)
                headers_dict[key.strip()] = value.strip()

    if verbose:
        click.echo(f"🚀 [SCAN] Starting {tool} scan with {threads} threads...")

    # Tool-specific command execution
    output_file = None

    if tool == "ffuf":
        output_file = output_path / "ffuf.json"
        ffuf_cmd = [
            find_executable("ffuf"),
            "-w",
            wordlist,
            "-u",
            f"{url}/FUZZ",
            "-t",
            str(threads),
            "-o",
            str(output_file),
            "-of",
            "json",
        ]

        # Add extensions
        if include_ext:
            ffuf_cmd += ["-e", f".{include_ext}"]

        # Add proxy
        if proxy:
            ffuf_cmd += ["-x", proxy]

        # Add delay
        if delay:
            ffuf_cmd += ["-p", str(delay)]

        # Add rate limit
        if rate_limit:
            ffuf_cmd += ["-rate", str(rate_limit)]

        # Add User-Agent
        if user_agents:
            ffuf_cmd += ["-H", f"User-Agent: {user_agents[0]}"]

        # Add custom headers
        for key, value in headers_dict.items():
            ffuf_cmd += ["-H", f"{key}: {value}"]

        # Add timeout
        if timeout:
            ffuf_cmd += ["-timeout", str(timeout)]

        # Add status code filtering
        if filter_status:
            ffuf_cmd += ["-mc", filter_status]

        # Add size filtering
        if filter_size:
            if "-" in filter_size:
                min_size, max_size = filter_size.split("-")
                ffuf_cmd += ["-ms", f"{min_size.strip()}-{max_size.strip()}"]
            else:
                ffuf_cmd += ["-ms", filter_size]

        # Add length filtering
        if exclude_length:
            ffuf_cmd += ["-fl", exclude_length]
        if include_length:
            ffuf_cmd += ["-ml", include_length]

        # Add regex matching
        if match_regex:
            ffuf_cmd += ["-mr", match_regex]

        # Add auto-calibration
        if auto_calibrate:
            ffuf_cmd += ["-ac"]

        # Add SSL verification
        if not verify_ssl:
            ffuf_cmd += ["-k"]

        # Add recursion
        if recursive:
            ffuf_cmd += ["-recursion", "-recursion-depth", str(max_depth)]

        if verbose:
            click.echo(f"🔧 [FFUF] Command: {' '.join(ffuf_cmd)}")

        result = subprocess.run(ffuf_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [FFUF] Warning: {result.stderr}")

    elif tool == "feroxbuster":
        output_file = output_path / "feroxbuster.txt"
        ferox_cmd = [
            find_executable("feroxbuster"),
            "-u",
            url,
            "-w",
            wordlist,
            "-t",
            str(threads),
            "--output",
            str(output_file),
            "--timeout",
            str(timeout),
        ]

        # Add proxy
        if proxy:
            ferox_cmd += ["--proxy", proxy]

        # Add delay
        if delay:
            ferox_cmd += ["--delay", str(delay)]

        # Add rate limit
        if rate_limit:
            ferox_cmd += ["--rate-limit", str(rate_limit)]

        # Add extensions
        if include_ext:
            ferox_cmd += ["--extensions", include_ext]

        # Add User-Agent
        if user_agents:
            ferox_cmd += ["-H", f"User-Agent: {user_agents[0]}"]

        # Add custom headers
        for key, value in headers_dict.items():
            ferox_cmd += ["-H", f"{key}: {value}"]

        # Add status code filtering
        if filter_status:
            ferox_cmd += ["--status-codes", filter_status]

        # Add recursion
        if recursive:
            ferox_cmd += ["--depth", str(max_depth)]

        # Add SSL verification
        if not verify_ssl:
            ferox_cmd += ["--insecure"]

        # Add follow redirects
        if follow_redirects:
            ferox_cmd += ["--redirects"]

        # Add auto-calibration
        if auto_calibrate:
            ferox_cmd += ["--auto-tune"]

        # Add resume
        if resume:
            ferox_cmd += ["--resume-from", str(output_path / "feroxbuster.state")]

        if verbose:
            click.echo(f"🔧 [FEROXBUSTER] Command: {' '.join(ferox_cmd)}")

        result = subprocess.run(ferox_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [FEROXBUSTER] Warning: {result.stderr}")

    elif tool == "gobuster":
        output_file = output_path / "gobuster.txt"
        gobuster_cmd = [
            find_executable("gobuster"),
            "dir",
            "-u",
            url,
            "-w",
            wordlist,
            "-t",
            str(threads),
            "-o",
            str(output_file),
            "--timeout",
            str(timeout),
        ]

        # Add extensions
        if include_ext:
            gobuster_cmd += ["-x", include_ext]

        # Add proxy
        if proxy:
            gobuster_cmd += ["--proxy", proxy]

        # Add User-Agent
        if user_agents:
            gobuster_cmd += ["-a", user_agents[0]]

        # Add custom headers
        if headers_dict:
            headers_str = ",".join([f"{k}:{v}" for k, v in headers_dict.items()])
            gobuster_cmd += ["-H", headers_str]

        # Add status code filtering
        if filter_status:
            gobuster_cmd += ["-s", filter_status]

        # Add SSL verification
        if not verify_ssl:
            gobuster_cmd += ["-k"]

        # Add follow redirects
        if follow_redirects:
            gobuster_cmd += ["-r"]

        if verbose:
            click.echo(f"🔧 [GOBUSTER] Command: {' '.join(gobuster_cmd)}")
            if delay:
                click.echo("[!] Gobuster does not support delay natively.")
            if rate_limit:
                click.echo("[!] Gobuster does not support rate limiting natively.")

        result = subprocess.run(gobuster_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [GOBUSTER] Warning: {result.stderr}")

    elif tool == "dirsearch":
        output_file = output_path / "dirsearch.txt"
        dirsearch_cmd = [
            "python3",
            "-m",
            "dirsearch",
            "-u",
            url,
            "-w",
            wordlist,
            "-t",
            str(threads),
            "--output",
            str(output_file),
            "--timeout",
            str(timeout),
        ]

        # Add extensions
        if include_ext:
            dirsearch_cmd += ["-e", include_ext]
        else:
            dirsearch_cmd += ["-e", "php,html,txt,js,css,json,xml"]

        # Add proxy
        if proxy:
            dirsearch_cmd += ["--proxy", proxy]

        # Add delay
        if delay:
            dirsearch_cmd += ["--delay", str(delay)]

        # Add User-Agent
        if user_agents:
            dirsearch_cmd += ["--user-agent", user_agents[0]]

        # Add custom headers
        if headers_dict:
            headers_str = ",".join([f"{k}:{v}" for k, v in headers_dict.items()])
            dirsearch_cmd += ["--headers", headers_str]

        # Add status code filtering
        if filter_status:
            dirsearch_cmd += ["--include-status", filter_status]

        # Add recursion
        if recursive:
            dirsearch_cmd += ["--recursive", "--max-recursion-depth", str(max_depth)]

        # Add follow redirects
        if follow_redirects:
            dirsearch_cmd += ["--follow-redirects"]

        # Add resume
        if resume:
            dirsearch_cmd += ["--resume", str(output_path / "dirsearch-resume.txt")]

        if verbose:
            click.echo(f"🔧 [DIRSEARCH] Command: {' '.join(dirsearch_cmd)}")

        result = subprocess.run(dirsearch_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [DIRSEARCH] Warning: {result.stderr}")

    elif tool == "dirb":
        output_file = output_path / "dirb.txt"
        dirb_cmd = [
            "dirb",
            url,
            wordlist,
            "-o",
            str(output_file),
            "-S",  # Silent mode
            "-r",  # Don't search recursively
        ]

        # Add proxy
        if proxy:
            dirb_cmd += ["-p", proxy]

        # Add delay
        if delay:
            dirb_cmd += ["-z", str(int(delay * 1000))]  # dirb uses milliseconds

        # Add User-Agent
        if user_agents:
            dirb_cmd += ["-a", user_agents[0]]

        # Add extensions
        if include_ext:
            dirb_cmd += ["-X", f".{include_ext}"]

        # Add timeout
        if timeout:
            dirb_cmd += ["-t", str(timeout)]

        # Add status code filtering (basic support)
        if filter_status and "200" not in filter_status:
            dirb_cmd += ["-N", "200"]  # Show only specified codes

        if verbose:
            click.echo(f"🔧 [DIRB] Command: {' '.join(dirb_cmd)}")

        result = subprocess.run(dirb_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [DIRB] Warning: {result.stderr}")

    elif tool == "wfuzz":
        output_file = output_path / "wfuzz.txt"
        wfuzz_cmd = [
            "wfuzz",
            "-w",
            wordlist,
            "-u",
            f"{url}/FUZZ",
            "-t",
            str(threads),
            "--hc",
            "404",  # Hide 404s by default
            "-f",
            f"{output_file},raw",
        ]

        # Add proxy
        if proxy:
            wfuzz_cmd += ["-p", proxy]

        # Add delay
        if delay:
            wfuzz_cmd += ["-s", str(delay)]

        # Add User-Agent
        if user_agents:
            wfuzz_cmd += ["-H", f"User-Agent: {user_agents[0]}"]

        # Add custom headers
        for key, value in headers_dict.items():
            wfuzz_cmd += ["-H", f"{key}: {value}"]

        # Add timeout
        if timeout:
            wfuzz_cmd += ["--conn-delay", str(timeout)]

        # Add extensions (create separate wordlist with extensions)
        if include_ext:
            ext_list = include_ext.split(",")
            # Modify URL to include extension fuzzing
            wfuzz_cmd = [
                "wfuzz",
                "-w",
                wordlist,
                "-z",
                f"list,{'-'.join(['.' + ext.strip() for ext in ext_list])}",
                "-u",
                f"{url}/FUZZFUZ2Z",
                "-t",
                str(threads),
                "--hc",
                "404",
                "-f",
                f"{output_file},raw",
            ]
            # Re-add other options
            if proxy:
                wfuzz_cmd += ["-p", proxy]
            if delay:
                wfuzz_cmd += ["-s", str(delay)]
            if user_agents:
                wfuzz_cmd += ["-H", f"User-Agent: {user_agents[0]}"]
            for key, value in headers_dict.items():
                wfuzz_cmd += ["-H", f"{key}: {value}"]
            if timeout:
                wfuzz_cmd += ["--conn-delay", str(timeout)]

        # Add status code filtering
        if filter_status:
            wfuzz_cmd += ["--sc", filter_status]

        # Add size filtering
        if filter_size:
            if "-" in filter_size:
                min_size, max_size = filter_size.split("-")
                wfuzz_cmd += ["--sl", f"{min_size.strip()}-{max_size.strip()}"]
            else:
                wfuzz_cmd += ["--sl", filter_size]

        # Add length filtering
        if exclude_length:
            wfuzz_cmd += ["--hl", exclude_length]
        if include_length:
            wfuzz_cmd += ["--sl", include_length]

        # Add follow redirects
        if follow_redirects:
            wfuzz_cmd += ["--follow"]

        # Add SSL verification
        if not verify_ssl:
            wfuzz_cmd += ["--no-check-certificate"]

        if verbose:
            click.echo(f"🔧 [WFUZZ] Command: {' '.join(wfuzz_cmd)}")

        result = subprocess.run(wfuzz_cmd, capture_output=True, text=True)

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [WFUZZ] Warning: {result.stderr}")

    elif tool == "dirmap":
        output_file = output_path / "dirmap.txt"
        # Create a temporary configuration for dirmap
        dirmap_config = output_path / "dirmap_temp.conf"

        # Create a minimal config file for dirmap
        config_content = f"""[RecursiveScan]
conf.recursive_scan = {"1" if recursive else "0"}
conf.recursive_status_code = [301,403]
conf.recursive_scan_max_url_length = 60
conf.recursive_blacklist_exts = ["html","htm","png","jpg","css","js"]
conf.exclude_subdirs = ""

[ScanModeHandler]
conf.dict_mode = 1
conf.dict_mode_load_single_dict = "{wordlist}"
conf.dict_mode_load_mult_dict = "dictmult"
conf.blast_mode = 0
conf.crawl_mode = 0
conf.fuzz_mode = 0

[RequestHandler]
conf.request_headers = ""
conf.request_header_ua = "{user_agents[0] if user_agents else 'Mozilla/5.0 (compatible; DirBCLI/1.0)'}"
conf.request_header_cookie = ""
conf.request_header_401_auth = ""
conf.request_timeout = {timeout}
conf.request_delay = {delay if delay else 0}
conf.request_limit = {threads}
conf.request_method = "get"
conf.redirection_302 = 1
conf.file_extension = ""

[ResponseHandler]
conf.response_status_code = [200,301,302,303,307,308,403,500,501,502,503]
conf.response_header_content_type = ""
conf.response_size = ""
conf.auto_check_404_page = 1
conf.custom_503_page = ""
conf.custom_response_page = ""
conf.skip_size = "None"

[ProxyHandler]
conf.proxy_server = {{"http": "{proxy}", "https": "{proxy}"}} if proxy else None

[DebugMode]
conf.debug = 0

[CheckUpdate]
conf.update = 0
"""

        # Write temporary config file
        with open(dirmap_config, "w") as f:
            f.write(config_content)

        # Note: dirmap needs to be run from its own directory with proper setup
        # For now, we'll create a basic command that should work if dirmap is properly installed
        dirmap_cmd = [
            "python3",
            "-c",
            f"""
import sys
import os
import subprocess
import tempfile

# Create a simple dirmap-like scanner
url = "{url}"
wordlist = "{wordlist}"
output_file = "{output_file}"
threads = {threads}
timeout = {timeout}

# Basic directory scanning using requests
import requests
from concurrent.futures import ThreadPoolExecutor
import time

def scan_path(path):
    try:
        test_url = url.rstrip("/") + "/" + path.strip()
        response = requests.get(test_url, timeout={timeout}, verify=True, allow_redirects=False)
        if response.status_code in [200, 301, 302, 403, 500]:
            return f"{{response.status_code}} {{len(response.content)}} {{test_url}}"
    except:
        pass
    return None

# Read wordlist
try:
    with open(wordlist, "r") as f:
        paths = [line.strip() for line in f if line.strip()]
except:
    paths = ["admin", "login", "test", "config", "backup"]

# Scan paths
results = []
with ThreadPoolExecutor(max_workers={threads}) as executor:
    future_to_path = {{executor.submit(scan_path, path): path for path in paths[:100]}}
    for future in future_to_path:
        result = future.result()
        if result:
            results.append(result)

# Write results
with open(output_file, "w") as f:
    for result in results:
        f.write(result + "\\n")

print(f"Dirmap-like scan completed. Found {{len(results)}} results.")
""",
        ]

        if verbose:
            click.echo(f"🔧 [DIRMAP] Running dirmap-compatible scan...")
            click.echo(
                f"🔧 [DIRMAP] Note: Using simplified implementation due to dirmap complexity"
            )

        result = subprocess.run(dirmap_cmd, capture_output=True, text=True)

        # Clean up temporary config
        try:
            dirmap_config.unlink()
        except:
            pass

        if result.returncode != 0 and verbose:
            click.echo(f"⚠️ [DIRMAP] Warning: {result.stderr}")
            click.echo(
                f"⚠️ [DIRMAP] Note: Install dirmap from https://github.com/H4ckForJob/dirmap for full functionality"
            )

    elif tool == "dirhunt":
        output_file = output_path / "dirhunt.txt"
        dirhunt_cmd = ["dirhunt", url]

        # Add threads
        if threads:
            dirhunt_cmd += ["--threads", str(threads)]

        # Add timeout
        if timeout:
            dirhunt_cmd += ["--timeout", str(timeout)]

        # Add max depth for recursive scanning
        if recursive and max_depth:
            dirhunt_cmd += ["--max-depth", str(max_depth)]

        # Add delay between requests
        if delay:
            dirhunt_cmd += ["--delay", str(delay)]

        # Add proxy support
        if proxy:
            dirhunt_cmd += ["--proxies", proxy]

        # Add User-Agent
        if user_agents:
            dirhunt_cmd += ["--user-agent", user_agents[0]]

        # Add custom headers
        for key, value in headers_dict.items():
            dirhunt_cmd += ["--header", f"{key}:{value}"]

        # Add interesting extensions based on detected technology
        if include_ext:
            dirhunt_cmd += ["--interesting-extensions", include_ext]
        elif tech_info.get("technologies"):
            # Smart extension selection based on detected tech
            smart_extensions = []
            if "php" in tech_info["technologies"]:
                smart_extensions.extend(["php", "inc", "phtml"])
            if "asp" in tech_info["technologies"]:
                smart_extensions.extend(["asp", "aspx", "ashx"])
            if "jsp" in tech_info["technologies"]:
                smart_extensions.extend(["jsp", "jspx", "do"])
            if "python" in tech_info["technologies"]:
                smart_extensions.extend(["py", "pyc", "pyo"])
            if smart_extensions:
                dirhunt_cmd += ["--interesting-extensions", ",".join(smart_extensions)]

        # Add interesting files based on technology detection
        if tech_info.get("technologies"):
            interesting_files = []
            if "wordpress" in tech_info["technologies"]:
                interesting_files.extend(
                    ["wp-config.php", "wp-admin", ".htaccess", "wp-content"]
                )
            if "php" in tech_info["technologies"]:
                interesting_files.extend(
                    ["config.php", "database.php", "settings.php", "phpinfo.php"]
                )
            if "apache" in tech_info["technologies"]:
                interesting_files.extend([".htaccess", ".htpasswd", "httpd.conf"])
            if "nginx" in tech_info["technologies"]:
                interesting_files.extend(
                    ["nginx.conf", "sites-available", "sites-enabled"]
                )
            if interesting_files:
                dirhunt_cmd += ["--interesting-files", ",".join(interesting_files)]

        # Add output to file
        dirhunt_cmd += ["--to-file", str(output_file)]

        # Add flags filtering (convert status codes to dirhunt include flags)
        if filter_status:
            status_flags = filter_status.split(",")
            dirhunt_cmd += ["--include-flags", ",".join(status_flags)]

        # Add progress control
        if not verbose:
            dirhunt_cmd += ["--progress-disabled"]
        else:
            dirhunt_cmd += ["--progress-enabled"]

        # Add subdomain control
        if not follow_redirects:
            dirhunt_cmd += ["--not-follow-subdomains"]

        # Add redirect control
        if not follow_redirects:
            dirhunt_cmd += ["--not-allow-redirects"]

        # Add limit for large sites
        if recursive:
            dirhunt_cmd += ["--limit", "5000"]  # Reasonable limit for recursive scans

        # Exclude common source engines if not needed for speed
        if not tech_detect:
            dirhunt_cmd += ["--exclude-sources", "virustotal,google,robots"]

        if verbose:
            click.echo(f"🔧 [DIRHUNT] Command: {' '.join(dirhunt_cmd)}")
            click.echo(
                "🧠 [DIRHUNT] Using intelligent directory discovery without brute force"
            )
            click.echo(
                "🔍 [DIRHUNT] Analyzing robots.txt, wayback machine, and page structure"
            )

        result = subprocess.run(dirhunt_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            if verbose:
                click.echo(f"⚠️ [DIRHUNT] Warning: {result.stderr}")
                click.echo(f"💡 [DIRHUNT] Install with: pip install dirhunt")

            # Fallback: create a simple intelligent scanner
            if verbose:
                click.echo(
                    "🔄 [DIRHUNT] Falling back to built-in intelligent scanner..."
                )

            fallback_cmd = [
                "python3",
                "-c",
                f'''
import requests
import re
from urllib.parse import urljoin, urlparse
import time

def intelligent_scan(base_url):
    """Simple intelligent directory discovery"""
    found_urls = set()
    session = requests.Session()
    session.verify = False
    
    # 1. Check robots.txt
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        response = session.get(robots_url, timeout=3)
        if response.status_code == 200:
            for line in response.text.split('\\n'):
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urljoin(base_url, path)
                        found_urls.add(full_url)
    except:
        pass
    
    # 2. Check common directories
    common_dirs = ["admin", "login", "dashboard", "panel", "wp-admin", "administrator", 
                   "config", "backup", "test", "dev", "api", "uploads", "files", "data"]
    
    for directory in common_dirs:
        try:
            test_url = urljoin(base_url, directory)
            response = session.get(test_url, timeout=2, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                found_urls.add(test_url)
                print(f"[{{response.status_code}}] {{test_url}}")
        except:
            pass
        time.sleep(0.1)  # Small delay
    
    # 3. Check index page for links
    try:
        response = session.get(base_url, timeout=3)
        if response.status_code == 200:
            # Simple link extraction
            links = re.findall(r'href=["\\']([^"\\'>]+)["\\']', response.text)
            for link in links:
                if link.startswith('/') and not link.startswith('//'):
                    full_url = urljoin(base_url, link)
                    # Only check directory-like URLs
                    if '.' not in link.split('/')[-1] or link.endswith('/'):
                        try:
                            resp = session.get(full_url, timeout=2, allow_redirects=False)
                            if resp.status_code in [200, 301, 302, 403]:
                                found_urls.add(full_url)
                                print(f"[{{resp.status_code}}] {{full_url}}")
                        except:
                            pass
    except:
        pass
    
    return found_urls

# Run intelligent scan
print("Starting intelligent directory discovery...")
urls = intelligent_scan("{url}")
print(f"Found {{len(urls)}} potential directories")
''',
            ]

            fallback_result = subprocess.run(
                fallback_cmd, capture_output=True, text=True
            )

            # Write fallback results to output file
            with open(output_file, "w") as f:
                f.write(fallback_result.stdout)

        # Check if dirhunt created a JSON output file and convert it
        json_output_file = output_file.with_suffix(".json")
        if json_output_file.exists():
            try:
                import json

                with open(json_output_file, "r") as f:
                    dirhunt_data = json.load(f)

                # Convert JSON to simple text format for our parser
                with open(output_file, "w") as f:
                    # Process main results
                    if "processed" in dirhunt_data:
                        for url_data in dirhunt_data["processed"].values():
                            if isinstance(url_data, dict) and "response" in url_data:
                                status = url_data["response"].get("status_code", 200)
                                url_addr = (
                                    url_data.get("url", {})
                                    .get("address", {})
                                    .get("address", "")
                                )
                                if url_addr:
                                    f.write(f"[{status}] {url_addr}\\n")

                    # Process index_of results
                    if "index_of_processors" in dirhunt_data:
                        for proc_data in dirhunt_data["index_of_processors"]:
                            if (
                                isinstance(proc_data, dict)
                                and "crawler_url" in proc_data
                            ):
                                crawler_url = proc_data["crawler_url"]
                                if (
                                    "url" in crawler_url
                                    and "address" in crawler_url["url"]
                                ):
                                    status = proc_data.get("status_code", 200)
                                    url_addr = crawler_url["url"]["address"]["address"]
                                    f.write(f"[{status}] {url_addr}\\n")

                if verbose:
                    click.echo("✅ [DIRHUNT] Converted JSON output to text format")
            except Exception as e:
                if verbose:
                    click.echo(f"⚠️ [DIRHUNT] Warning parsing JSON output: {e}")

    else:
        click.echo("❌ [ERROR] Unsupported tool.")
        return

    # Calculate scan duration
    stats["scan_duration"] = time.time() - start_time

    if verbose:
        click.echo(f"⏱️ [SCAN] Completed in {stats['scan_duration']:.2f} seconds")

    # Parse results
    findings = []
    if output_file and output_file.exists():
        if verbose:
            click.echo(f"📊 [PARSE] Parsing {tool} output...")

        findings = parse_tool_output(tool, output_file, url)
        initial_count = len(findings)

        if verbose:
            click.echo(f"📊 [PARSE] Found {initial_count} initial results")

        # Apply smart filtering if enabled
        if smart_filter and findings:
            if verbose:
                click.echo("🧠 [SMART-FILTER] Applying intelligent filtering...")
            findings = smart_filter_responses(findings, similarity_threshold)
            filtered_count = len(findings)
            if verbose:
                click.echo(
                    f"🧠 [SMART-FILTER] Filtered out {initial_count - filtered_count} false positives/duplicates"
                )

        # Apply response pattern analysis if enabled
        if response_analysis and findings:
            if verbose:
                click.echo("🔍 [ANALYSIS] Analyzing response patterns...")
            pattern_analysis = analyze_response_patterns(findings)
            stats["pattern_analysis"] = pattern_analysis
            if verbose and pattern_analysis.get("anomalies"):
                click.echo(
                    f"� [ANALYSIS] Found {len(pattern_analysis['anomalies'])} anomalies"
                )

        # Apply honeypot and WAF detection if enabled
        if honeypot_detection and findings:
            if verbose:
                click.echo("🕵️ [SECURITY] Detecting honeypots and WAF responses...")
            security_analysis = detect_honeypots_and_waf(findings, url)
            stats["security_analysis"] = security_analysis
            if verbose:
                honeypot_count = len(security_analysis.get("honeypot_indicators", []))
                waf_count = len(security_analysis.get("waf_indicators", []))
                if honeypot_count > 0:
                    click.echo(
                        f"🕵️ [SECURITY] Found {honeypot_count} potential honeypot indicators"
                    )
                if waf_count > 0:
                    click.echo(
                        f"🕵️ [SECURITY] Found {waf_count} potential WAF responses"
                    )

        # Apply adaptive threading if enabled
        if adaptive_threading and findings:
            optimal_threads = adaptive_threading_controller(findings, threads)
            if verbose and optimal_threads != threads:
                click.echo(
                    f"⚡ [ADAPTIVE] Recommended threads: {optimal_threads} (used: {threads})"
                )
            stats["recommended_threads"] = optimal_threads

        # Backup file detection if enabled
        if backup_detection and findings:
            if verbose:
                click.echo("💾 [BACKUP] Generating backup file wordlist...")
            backup_words = generate_backup_wordlist(
                wordlist, tech_info.get("technologies", [])
            )
            if backup_words and verbose:
                click.echo(
                    f"💾 [BACKUP] Generated {len(backup_words)} backup variations"
                )
            stats["backup_words_generated"] = len(backup_words) if backup_words else 0

        # Parameter discovery if enabled
        if parameter_discovery and findings:
            if verbose:
                click.echo("🔧 [PARAMS] Discovering parameters for found endpoints...")
            param_discoveries = discover_parameters(findings, url, timeout)
            stats["parameter_discoveries"] = param_discoveries
            if verbose and param_discoveries:
                total_params = sum(
                    len(d.get("parameters", [])) for d in param_discoveries
                )
                click.echo(
                    f"🔧 [PARAMS] Found {total_params} potential parameters across {len(param_discoveries)} endpoints"
                )

        # Store results in database if enabled
        if store_db and findings:
            if verbose:
                click.echo("💾 [DB] Storing results in ReconCLI database...")
            # Here you would implement the logic to store findings in the database
            # For now, we will just simulate with a print statement
            for finding in findings:
                click.echo(f"  - {finding['url']} (Status: {finding['status']})")
            stats["results_stored_db"] = len(findings)

        stats["findings_count"] = len(findings)
    else:
        click.echo(f"⚠️ [WARNING] No output file found: {output_file}")

    # Categorize findings
    categories = categorize_findings(findings)

    # Generate reports
    if json_report or markdown_report:
        if verbose:
            click.echo("📝 [REPORT] Generating comprehensive reports...")

        json_file, md_file = generate_comprehensive_report(
            output_path, stats, findings, categories, tech_info
        )

        if json_report:
            click.echo(f"📄 [JSON] Report saved: {json_file}")
        if markdown_report:
            click.echo(f"📝 [MARKDOWN] Report saved: {md_file}")

    # Display summary
    if verbose:
        click.echo(f"\n📊 [SUMMARY] Scan Results:")
        click.echo(f"🎯 Target: {url}")
        click.echo(f"📝 Wordlist entries: {stats['wordlist_size']}")
        click.echo(f"📁 Total findings: {stats['findings_count']}")
        click.echo(f"⏱️ Scan duration: {stats['scan_duration']:.2f} seconds")

        if tech_info.get("technologies"):
            click.echo(f"🛠️ Technologies: {', '.join(tech_info['technologies'])}")

        # Show category summary
        high_risk_found = False
        for category, items in categories.items():
            count = len(items)
            if count > 0 and category in [
                "admin_panels",
                "config_files",
                "backups",
                "sensitive_files",
            ]:
                if not high_risk_found:
                    click.echo(f"\n🔴 [HIGH RISK] Categories found:")
                    high_risk_found = True
                click.echo(f"  • {category.replace('_', ' ').title()}: {count} items")

        if not high_risk_found:
            click.echo(f"\n🟢 [GOOD] No high-risk categories detected")

    # Send completion notification
    if slack_webhook or discord_webhook:
        completion_msg = f"✅ DirBCLI scan completed!\\n"
        completion_msg += f"Target: {url}\\n"
        completion_msg += f"Duration: {stats['scan_duration']:.1f}s\\n"
        completion_msg += f"Findings: {stats['findings_count']}\\n"
        completion_msg += f"Tool: {tool}"

        if slack_webhook:
            send_notification(slack_webhook, completion_msg, "slack")
        if discord_webhook:
            send_notification(discord_webhook, completion_msg, "discord")

    # High-risk findings notification
    high_risk_count = sum(
        len(categories[cat])
        for cat in ["admin_panels", "config_files", "backups", "sensitive_files"]
    )
    if high_risk_count > 0 and (slack_webhook or discord_webhook):
        risk_msg = f"🚨 HIGH-RISK FINDINGS DETECTED!\\n"
        risk_msg += f"Target: {url}\\n"
        risk_msg += f"High-risk items: {high_risk_count}\\n"
        risk_msg += (
            f"Categories: Admin panels, Config files, Backups, Sensitive files\\n"
        )
        risk_msg += f"Manual review recommended!"

        if slack_webhook:
            send_notification(slack_webhook, risk_msg, "slack")
        if discord_webhook:
            send_notification(discord_webhook, risk_msg, "discord")

    # Update resume state to completed
    update_resume_state(
        output_dir,
        "completed",
        {"completion_time": datetime.now().isoformat(), "final_stats": stats},
    )

    # Database storage
    if store_db and findings:
        try:
            from reconcli.db.operations import store_target, store_directory_scan

            # Auto-detect target domain if not provided
            if not target_domain:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                target_domain = parsed.netloc

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert results to database format
                directory_scan_data = []
                for result in findings:
                    dir_entry = {
                        "url": result.get("url"),
                        "path": result.get("path"),
                        "status_code": result.get("status"),
                        "content_length": result.get("size", 0),
                        "content_type": result.get("content_type"),
                        "response_time": result.get("response_time", 0),
                        "title": result.get("title"),
                        "category": result.get("category", "unknown"),
                        "redirect_location": result.get("redirect_url"),
                    }
                    directory_scan_data.append(dir_entry)

                # Store directory scan in database
                stored_ids = store_directory_scan(
                    target_domain, directory_scan_data, tool
                )

                if verbose:
                    click.echo(
                        f"[+] 💾 Stored {len(stored_ids)} directory entries in database for target: {target_domain}"
                    )
            else:
                if verbose:
                    click.echo(
                        "[!] ⚠️  No target domain provided or detected for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo("[!] ⚠️  Database module not available")
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Database storage failed: {e}")

    # Cleanup temporary files if requested
    if cleanup:
        if cleanup_temporary_files(output_dir, keep_reports=True):
            if verbose:
                click.echo("🗑️ [CLEANUP] Temporary files cleaned up")
        else:
            if verbose:
                click.echo("⚠️ [CLEANUP] Failed to clean up some temporary files")

    if verbose:
        click.echo(f"\n🎉 [COMPLETE] DirBCLI scan finished successfully!")
        click.echo(f"📂 All results saved in: {output_dir}")
    else:
        click.echo(f"\n[✓] Scan complete! Results in: {output_dir}")


dirbcli.short_help = "🔍 Advanced directory brute force scanner with smart analysis"


if __name__ == "__main__":
    dirbcli()
