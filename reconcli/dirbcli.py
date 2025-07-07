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


def check_url_accessibility(url, timeout=10):
    """Check if target URL is accessible."""
    try:
        response = requests.get(url, timeout=timeout, verify=False)
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


def detect_web_technology(url, timeout=10):
    """Detect web technology stack for smart wordlist selection."""
    try:
        headers = {"User-Agent": "DirBCLI/1.0 ReconCLI Directory Scanner"}
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)

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


def parse_tool_output(tool, output_file):
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
                else:
                    pattern = r"(https?://[^\s]+)"

                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
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

                return [random.choice(file_agents)]
            return file_agents
        else:
            print(f"[!] Failed to load User-Agents from file, falling back to builtin")

    if builtin_ua:
        builtin_agents = get_builtin_user_agents()
        if random_ua:
            import random

            return [random.choice(builtin_agents)]
        return builtin_agents

    if user_agent_option:
        return list(user_agent_option)

    # Default
    return ["Mozilla/5.0 (DirBCLI/1.0 ReconCLI Scanner)"]


@click.command()
@click.option("--url", required=True, help="Target URL (e.g., http://example.com)")
@click.option(
    "--wordlist", required=True, type=click.Path(exists=True), help="Path to wordlist"
)
@click.option(
    "--tool",
    type=click.Choice(["ffuf", "feroxbuster", "gobuster", "dirsearch"]),
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
@click.option("--timeout", type=int, default=10, help="Request timeout in seconds")
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

    Supported Tools:
    • ffuf - Fast web fuzzer (default, recommended)
    • feroxbuster - Rust-based recursive scanner
    • gobuster - Go-based directory/file brute forcer
    • dirsearch - Python-based web path scanner

    User-Agent Options:
    --user-agent "Custom UA"           # Single custom User-Agent
    --user-agent-file agents.txt       # Load from file (one per line)
    --builtin-ua                       # Use 25+ built-in User-Agents
    --builtin-ua --random-ua           # Random built-in User-Agent
    --user-agent-file ua.txt --random-ua  # Random from file

    Examples:
    dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --tech-detect --smart-wordlist
    dirbcli --url https://example.com --wordlist big.txt --tool feroxbuster --recursive --max-depth 2
    dirbcli --url https://example.com --wordlist common.txt --filter-status 200,301,403 --json-report
    dirbcli --url https://example.com --wordlist /path/to/wordlist.txt --builtin-ua --random-ua
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
            if smart_wordlist:
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

    # Get wordlist size
    try:
        with open(wordlist, "r") as f:
            stats["wordlist_size"] = sum(1 for _ in f)
        if verbose:
            click.echo(f"📝 [WORDLIST] Loaded {stats['wordlist_size']} entries")
    except Exception as e:
        click.echo(f"❌ [ERROR] Cannot read wordlist: {e}")
        return

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
            "ffuf",
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
            "feroxbuster",
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
            "gobuster",
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

        findings = parse_tool_output(tool, output_file)
        stats["findings_count"] = len(findings)

        if verbose:
            click.echo(f"📊 [PARSE] Found {len(findings)} results")
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
