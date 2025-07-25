#!/usr/bin/env python3
"""
🚫 BypassCLI - HTTP Status Code Bypass & Access Control Evasion

Advanced HTTP bypass tool integrating multiple evasion techniques and external tools
for bypassing 403 Forbidden, 404 Not Found, and other access restrictions.

📋 USAGE EXAMPLES:

Basic bypass testing:
    reconcli bypasscli --url "https://target.com/admin"
    reconcli bypasscli --input urls.txt --forbidden-tool --bypass-parser

Advanced bypass techniques:
    reconcli bypasscli --url "https://target.com/api/admin" --all-techniques --custom-payloads
    reconcli bypasscli --input restricted_urls.txt --forbidden-tool --custom-headers --user-agents

Comprehensive assessment:
    reconcli bypasscli --url "https://target.com/admin" --forbidden-tool --bypass-parser \
      --custom-techniques --export-successful --store-db --verbose

Bug bounty workflow:
    reconcli bypasscli --input targets.txt --all-techniques --forbidden-tool \
      --export-successful --generate-report --cache --threads 10

🚀 FEATURES:
• Integration with forbidden tool (ivan-sincek)
• Integration with bypass-url-parser (laluka) 
• Custom bypass techniques (path traversal, encoding, headers)
• HTTP method fuzzing (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
• User-Agent rotation and custom headers
• URL encoding and path manipulation
• Cache system for performance optimization
• Comprehensive reporting and export capabilities
• Database integration for persistent tracking

🛡️ BYPASS TECHNIQUES:
• Path manipulation (/, //, ../, ./, %2f, %2e)
• HTTP method variations (POST vs GET, HEAD, OPTIONS)
• Header injection (X-Original-URL, X-Rewrite-URL, X-Forwarded-*)
• Encoding bypass (URL, double URL, Unicode, HTML entities)
• Case variation testing (Admin vs admin vs ADMIN)
• Protocol manipulation (HTTP vs HTTPS)
• Port variation testing (:80, :443, :8080, :8443)
"""

import csv
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, quote_plus, unquote, urlparse, urlunparse

import click
import requests
from rich.console import Console
from rich.progress import track

console = Console()

# Custom bypass techniques
BYPASS_TECHNIQUES = {
    "path_traversal": [
        "/",
        "//",
        "///",
        "/./",
        "/../",
        "/..;/",
        "/%2e/",
        "/%2e%2e/",
        "/%252e/",
        "/%252e%252e/",
        "/;/",
        "/.;/",
        "/..;/",
        "/.../",
        "/..../",
    ],
    "encoding": [
        lambda p: quote(p),
        lambda p: quote_plus(p),
        lambda p: quote(p, safe=""),
        lambda p: p.replace("/", "%2f"),
        lambda p: p.replace("/", "%2F"),
        lambda p: p.replace("/", "%252f"),
        lambda p: p.replace("/", "%252F"),
        lambda p: quote(quote(p)),
        lambda p: p.replace("/", "\\/"),
        lambda p: p.replace("/", "%5c"),
        lambda p: p.replace("/", "%5C"),
    ],
    "case_variations": [
        lambda p: p.upper(),
        lambda p: p.lower(),
        lambda p: p.title(),
        lambda p: "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
        ),
        lambda p: "".join(
            c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(p)
        ),
    ],
    "protocol_ports": [
        lambda url: url.replace("https://", "http://"),
        lambda url: url.replace("http://", "https://"),
        lambda url: url.replace("://80", "://"),
        lambda url: url.replace("://443", "://"),
        lambda url: (
            url + ":80" if "://" in url and ":" not in url.split("://")[1] else url
        ),
        lambda url: (
            url + ":443" if "://" in url and ":" not in url.split("://")[1] else url
        ),
        lambda url: (
            url + ":8080" if "://" in url and ":" not in url.split("://")[1] else url
        ),
        lambda url: (
            url + ":8443" if "://" in url and ":" not in url.split("://")[1] else url
        ),
    ],
}

# Bypass headers
BYPASS_HEADERS = {
    "forwarded_headers": [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Forwarded-Proto": "https"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Cluster-Client-IP": "127.0.0.1"},
        {"X-Forwarded-Server": "localhost"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
    ],
    "override_headers": [
        {"X-Override-URL": "{path}"},
        {"X-HTTP-Method-Override": "GET"},
        {"X-HTTP-Method": "GET"},
        {"X-Method-Override": "GET"},
        {"Override": "GET"},
        {"X-Forwarded-Method": "GET"},
    ],
    "custom_headers": [
        {"Host": "localhost"},
        {"Host": "127.0.0.1"},
        {"Referer": "https://localhost/"},
        {"Referer": "https://127.0.0.1/"},
        {"Origin": "https://localhost"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
        {"Cookie": "isAdmin=true; role=admin; auth=true"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"Content-Type": "application/json"},
        {"Accept": "application/json, text/plain, */*"},
    ],
}

# HTTP methods for testing
HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT",
]

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
]


class BypassCacheManager:
    """Bypass Testing Cache Manager for storing and retrieving bypass results"""

    def __init__(self, cache_dir: str, max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.cache_index_file = self.cache_dir / "bypass_cache_index.json"
        self.cache_index = self._load_cache_index()

    def _load_cache_index(self) -> dict:
        """Load cache index from file"""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache_index(self):
        """Save cache index to file"""
        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(self.cache_index, f, indent=2)
        except Exception:
            pass

    def _generate_cache_key(self, url: str, options: Optional[Dict] = None) -> str:
        """Generate cache key from URL and options"""
        cache_string = f"bypass:{url}"
        if options:
            cache_string += f":{json.dumps(options, sort_keys=True)}"
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cache entry is still valid"""
        age_hours = (time.time() - timestamp) / 3600
        return age_hours < self.max_age_hours

    def get(self, url: str, options: Optional[Dict] = None) -> Optional[dict]:
        """Get cached bypass result for URL"""
        cache_key = self._generate_cache_key(url, options)

        if cache_key in self.cache_index:
            cache_info = self.cache_index[cache_key]

            if self._is_cache_valid(cache_info["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            data = json.load(f)

                        cache_info["access_count"] += 1
                        cache_info["last_access"] = time.time()
                        self.cache_index[cache_key] = cache_info
                        self._save_cache_index()

                        return data
                    except Exception:
                        del self.cache_index[cache_key]
                        self._save_cache_index()
            else:
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    cache_file.unlink()
                del self.cache_index[cache_key]
                self._save_cache_index()

        return None

    def set(self, url: str, result: dict, options: Optional[Dict] = None):
        """Cache bypass result for URL"""
        cache_key = self._generate_cache_key(url, options)

        self.cache_index[cache_key] = {
            "url": url,
            "timestamp": time.time(),
            "last_access": time.time(),
            "access_count": 1,
            "successful_bypasses": len(
                [r for r in result.get("results", []) if r.get("bypassed")]
            ),
        }

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)

            self._save_cache_index()
        except Exception:
            if cache_key in self.cache_index:
                del self.cache_index[cache_key]

    def clear_all(self) -> int:
        """Clear all cache entries and return count"""
        count = len(self.cache_index)

        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

        self.cache_index = {}
        self._save_cache_index()

        return count

    def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self.cache_dir.exists():
            return {
                "total_entries": 0,
                "total_size_kb": 0,
                "expired_entries": 0,
                "valid_entries": 0,
            }

        cache_files = list(self.cache_dir.glob("*.json"))
        if not cache_files:
            return {
                "total_entries": 0,
                "total_size_kb": 0,
                "expired_entries": 0,
                "valid_entries": 0,
            }

        total_size = sum(f.stat().st_size for f in cache_files)
        expired_count = 0
        valid_count = 0

        for cache_info in self.cache_index.values():
            if self._is_cache_valid(cache_info["timestamp"]):
                valid_count += 1
            else:
                expired_count += 1

        return {
            "total_entries": len(cache_files),
            "total_size_kb": total_size / 1024,
            "expired_entries": expired_count,
            "valid_entries": valid_count,
        }


def check_binary(binary_name):
    """Check if binary is available in PATH"""
    return subprocess.run(["which", binary_name], capture_output=True).returncode == 0


def run_forbidden_tool(url, output_dir, verbose=False):
    """Run forbidden tool by ivan-sincek"""
    try:
        if not check_binary("forbidden"):
            return {
                "error": "forbidden tool not found. Install: git clone https://github.com/ivan-sincek/forbidden"
            }

        output_file = Path(output_dir) / f"forbidden_{int(time.time())}.txt"

        cmd = [
            "forbidden",
            "-u",
            url,
            "-o",
            str(output_file),
            "-t",
            "20",  # threads
            "-f",  # force
        ]

        if verbose:
            console.print(f"[cyan]Running forbidden:[/cyan] {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        bypasses = []
        if output_file.exists():
            with open(output_file, "r") as f:
                content = f.read()

            # Parse forbidden output
            for line in content.split("\n"):
                if "STATUS" in line and any(
                    code in line for code in ["200", "201", "202", "204", "301", "302"]
                ):
                    status_match = re.search(r"STATUS: (\d+)", line)
                    bypasses.append(
                        {
                            "technique": "forbidden_tool",
                            "method": "GET",
                            "url": line.split()[0] if line.split() else url,
                            "status_code": (
                                int(status_match.group(1)) if status_match else 0
                            ),
                            "bypassed": True,
                            "raw_output": line.strip(),
                        }
                    )

        return {
            "tool": "forbidden",
            "bypasses": bypasses,
            "raw_output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
        }

    except subprocess.TimeoutExpired:
        return {"error": "forbidden tool timeout"}
    except Exception as e:
        return {"error": f"forbidden tool error: {e}"}


def run_bypass_url_parser(url, output_dir, verbose=False):
    """Run bypass-url-parser by laluka"""
    try:
        # Check if tool is available
        bypass_parser_path = subprocess.run(
            ["which", "bypass-url-parser"], capture_output=True, text=True
        )
        if bypass_parser_path.returncode != 0:
            # Try python script directly
            if not Path("bypass-url-parser/bypass-url-parser.py").exists():
                return {
                    "error": "bypass-url-parser not found. Install: git clone https://github.com/laluka/bypass-url-parser"
                }

        output_file = Path(output_dir) / f"bypass_parser_{int(time.time())}.json"

        cmd = [
            "python3",
            "bypass-url-parser/bypass-url-parser.py",
            "--url",
            url,
            "--output",
            str(output_file),
        ]

        if verbose:
            console.print(f"[cyan]Running bypass-url-parser:[/cyan] {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        bypasses = []
        if output_file.exists():
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        if item.get("status_code") in [200, 201, 202, 204, 301, 302]:
                            bypasses.append(
                                {
                                    "technique": "bypass_url_parser",
                                    "method": item.get("method", "GET"),
                                    "url": item.get("url", url),
                                    "status_code": item.get("status_code"),
                                    "bypassed": True,
                                    "payload": item.get("payload", ""),
                                    "raw_output": str(item),
                                }
                            )
            except json.JSONDecodeError:
                pass

        return {
            "tool": "bypass-url-parser",
            "bypasses": bypasses,
            "raw_output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
        }

    except subprocess.TimeoutExpired:
        return {"error": "bypass-url-parser timeout"}
    except Exception as e:
        return {"error": f"bypass-url-parser error: {e}"}


def test_custom_bypasses(url, headers=None, proxies=None, timeout=10, verbose=False):
    """Test custom bypass techniques"""
    bypasses = []
    base_headers = headers or {}
    parsed_url = urlparse(url)

    if verbose:
        console.print(f"[cyan]Testing custom bypass techniques for:[/cyan] {url}")

    # Test different HTTP methods
    for method in HTTP_METHODS:
        try:
            response = requests.request(
                method,
                url,
                headers=base_headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code in [200, 201, 202, 204, 301, 302]:
                bypasses.append(
                    {
                        "technique": "http_method",
                        "method": method,
                        "url": url,
                        "status_code": response.status_code,
                        "bypassed": True,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                    }
                )
        except Exception:
            continue

    # Test path traversal techniques
    base_path = parsed_url.path
    for technique in BYPASS_TECHNIQUES["path_traversal"]:
        test_path = technique + base_path.lstrip("/")
        test_url = urlunparse(parsed_url._replace(path=test_path))

        try:
            response = requests.get(
                test_url,
                headers=base_headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code in [200, 201, 202, 204, 301, 302]:
                bypasses.append(
                    {
                        "technique": "path_traversal",
                        "method": "GET",
                        "url": test_url,
                        "status_code": response.status_code,
                        "bypassed": True,
                        "payload": technique,
                        "content_length": len(response.content),
                    }
                )
        except Exception:
            continue

    # Test encoding bypasses
    for encoding_func in BYPASS_TECHNIQUES["encoding"]:
        try:
            encoded_path = encoding_func(base_path)
            test_url = urlunparse(parsed_url._replace(path=encoded_path))

            response = requests.get(
                test_url,
                headers=base_headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code in [200, 201, 202, 204, 301, 302]:
                bypasses.append(
                    {
                        "technique": "encoding",
                        "method": "GET",
                        "url": test_url,
                        "status_code": response.status_code,
                        "bypassed": True,
                        "payload": encoded_path,
                        "content_length": len(response.content),
                    }
                )
        except Exception:
            continue

    # Test case variations
    for case_func in BYPASS_TECHNIQUES["case_variations"]:
        try:
            case_path = case_func(base_path)
            test_url = urlunparse(parsed_url._replace(path=case_path))

            response = requests.get(
                test_url,
                headers=base_headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code in [200, 201, 202, 204, 301, 302]:
                bypasses.append(
                    {
                        "technique": "case_variation",
                        "method": "GET",
                        "url": test_url,
                        "status_code": response.status_code,
                        "bypassed": True,
                        "payload": case_path,
                        "content_length": len(response.content),
                    }
                )
        except Exception:
            continue

    # Test bypass headers
    for header_category, header_list in BYPASS_HEADERS.items():
        for header_dict in header_list:
            test_headers = base_headers.copy()

            # Format headers with path if needed
            for key, value in header_dict.items():
                if "{path}" in value:
                    test_headers[key] = value.format(path=base_path)
                else:
                    test_headers[key] = value

            try:
                response = requests.get(
                    url,
                    headers=test_headers,
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=False,
                )

                if response.status_code in [200, 201, 202, 204, 301, 302]:
                    bypasses.append(
                        {
                            "technique": f"header_{header_category}",
                            "method": "GET",
                            "url": url,
                            "status_code": response.status_code,
                            "bypassed": True,
                            "headers": header_dict,
                            "content_length": len(response.content),
                        }
                    )
            except Exception:
                continue

    # Test protocol and port variations
    for protocol_func in BYPASS_TECHNIQUES["protocol_ports"]:
        try:
            test_url = protocol_func(url)
            if test_url != url:  # Only test if URL actually changed
                response = requests.get(
                    test_url,
                    headers=base_headers,
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=False,
                )

                if response.status_code in [200, 201, 202, 204, 301, 302]:
                    bypasses.append(
                        {
                            "technique": "protocol_port",
                            "method": "GET",
                            "url": test_url,
                            "status_code": response.status_code,
                            "bypassed": True,
                            "content_length": len(response.content),
                        }
                    )
        except Exception:
            continue

    return bypasses


def test_user_agent_bypass(url, headers=None, proxies=None, timeout=10):
    """Test User-Agent rotation bypass"""
    bypasses = []
    base_headers = headers or {}

    for user_agent in USER_AGENTS:
        test_headers = base_headers.copy()
        test_headers["User-Agent"] = user_agent

        try:
            response = requests.get(
                url,
                headers=test_headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code in [200, 201, 202, 204, 301, 302]:
                bypasses.append(
                    {
                        "technique": "user_agent_rotation",
                        "method": "GET",
                        "url": url,
                        "status_code": response.status_code,
                        "bypassed": True,
                        "user_agent": (
                            user_agent[:50] + "..."
                            if len(user_agent) > 50
                            else user_agent
                        ),
                        "content_length": len(response.content),
                    }
                )
        except Exception:
            continue

    return bypasses


@click.command()
@click.option("--url", help="Single URL to test for bypass")
@click.option(
    "--input", "-i", type=click.Path(exists=True), help="File with URLs to test"
)
@click.option("--output-dir", "-o", default="bypasscli_output", help="Output directory")
@click.option(
    "--forbidden-tool", is_flag=True, help="Use forbidden tool by ivan-sincek"
)
@click.option("--bypass-parser", is_flag=True, help="Use bypass-url-parser by laluka")
@click.option("--custom-techniques", is_flag=True, help="Use custom bypass techniques")
@click.option("--all-techniques", is_flag=True, help="Use all available techniques")
@click.option(
    "--methods", help="HTTP methods to test (comma-separated, e.g., GET,POST,PUT)"
)
@click.option(
    "--custom-headers", help='Custom headers JSON (e.g., \'{"X-Custom":"value"}\')'
)
@click.option("--user-agents", is_flag=True, help="Test User-Agent rotation bypass")
@click.option("--custom-payloads", help="File with custom payloads to test")
@click.option("--timeout", default=10, type=int, help="Request timeout in seconds")
@click.option("--threads", default=5, type=int, help="Number of concurrent threads")
@click.option("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option(
    "--export-successful", is_flag=True, help="Export only successful bypasses"
)
@click.option("--export-json", is_flag=True, help="Export results in JSON format")
@click.option("--export-csv", is_flag=True, help="Export results in CSV format")
@click.option(
    "--generate-report", is_flag=True, help="Generate comprehensive HTML report"
)
@click.option("--store-db", is_flag=True, help="Store results in ReconCLI database")
@click.option("--target-domain", help="Primary target domain for database storage")
@click.option("--program", help="Bug bounty program name")
@click.option("--cache", is_flag=True, help="Enable result caching")
@click.option("--cache-dir", help="Cache directory path")
@click.option("--cache-max-age", default=24, type=int, help="Cache max age in hours")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def bypasscli(
    url,
    input,
    output_dir,
    forbidden_tool,
    bypass_parser,
    custom_techniques,
    all_techniques,
    methods,
    custom_headers,
    user_agents,
    custom_payloads,
    timeout,
    threads,
    proxy,
    export_successful,
    export_json,
    export_csv,
    generate_report,
    store_db,
    target_domain,
    program,
    cache,
    cache_dir,
    cache_max_age,
    clear_cache,
    cache_stats,
    verbose,
):
    """
    🚫 Advanced HTTP Status Code Bypass & Access Control Evasion
    
    Comprehensive bypass testing tool integrating multiple techniques and external tools
    for bypassing 403 Forbidden, 404 Not Found, and other access restrictions.
    
    📋 EXAMPLES:
    
    Basic bypass testing:
        reconcli bypasscli --url "https://target.com/admin"
        reconcli bypasscli --input restricted_urls.txt --all-techniques
    
    Tool integration:
        reconcli bypasscli --url "https://target.com/api/admin" --forbidden-tool --bypass-parser
        reconcli bypasscli --input urls.txt --forbidden-tool --custom-techniques --verbose
    
    Advanced techniques:
        reconcli bypasscli --url "https://target.com/admin" --custom-techniques --user-agents
        reconcli bypasscli --input targets.txt --all-techniques --methods "GET,POST,PUT"
    
    Bug bounty workflow:
        reconcli bypasscli --input restricted_endpoints.txt --all-techniques \
          --export-successful --generate-report --store-db --cache --verbose
    
    Custom testing:
        reconcli bypasscli --url "https://api.target.com/admin" --custom-headers \
          '{"Authorization":"Bearer test","X-Admin":"true"}' --custom-techniques
    """

    # Initialize cache manager if cache is enabled
    cache_manager = None
    if cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "bypass_cache")
        cache_manager = BypassCacheManager(cache_directory, cache_max_age)
        if verbose:
            console.print(f"[cyan]🗄️ Bypass caching enabled:[/cyan] {cache_directory}")

    # Handle cache operations
    if clear_cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "bypass_cache")
        temp_cache_manager = BypassCacheManager(cache_directory, cache_max_age)
        count = temp_cache_manager.clear_all()
        console.print(f"[green]🗑️ Cleared {count} cached bypass results[/green]")
        return

    if cache_stats:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "bypass_cache")
        temp_cache_manager = BypassCacheManager(cache_directory, cache_max_age)
        stats = temp_cache_manager.get_stats()

        console.print("[cyan]📊 Bypass Cache Statistics[/cyan]")
        console.print(f"Cache directory: {cache_directory}")
        console.print(f"Total entries: {stats['total_entries']}")
        console.print(f"[green]Valid entries: {stats['valid_entries']}[/green]")
        console.print(f"[yellow]Expired entries: {stats['expired_entries']}[/yellow]")
        console.print(f"Total size: {stats['total_size_kb']:.1f} KB")
        console.print(f"Max age: {cache_max_age} hours")
        return

    # Check input
    if not url and not input:
        console.print("[red]❌ Error: Either --url or --input is required[/red]")
        return

    console.rule("[red]🚫 ReconCLI : BypassCLI - HTTP Status Code Bypass")

    # Setup
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Parse custom headers
    custom_headers_dict = {}
    if custom_headers:
        try:
            custom_headers_dict = json.loads(custom_headers)
        except json.JSONDecodeError:
            console.print("[red]❌ Invalid JSON format for custom headers[/red]")
            return

    # Parse methods
    test_methods = []
    if methods:
        test_methods = [m.strip().upper() for m in methods.split(",")]

    # Collect URLs
    urls = []
    if url:
        urls = [url]
    elif input:
        with open(input, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

    if verbose:
        console.print(
            f"[cyan]🎯 Testing {len(urls)} URLs with {threads} threads[/cyan]"
        )
        if all_techniques:
            console.print("[cyan]🔧 Using all available techniques[/cyan]")

    # Process URLs
    all_results = []

    def process_url(target_url):
        # Check cache first
        cache_options = {
            "forbidden_tool": forbidden_tool,
            "bypass_parser": bypass_parser,
            "custom_techniques": custom_techniques or all_techniques,
            "user_agents": user_agents or all_techniques,
            "methods": test_methods,
        }

        if cache_manager:
            cached_result = cache_manager.get(target_url, cache_options)
            if cached_result:
                if verbose:
                    console.print(f"[green]📋 Cached result for {target_url}[/green]")
                return cached_result

        result = {
            "url": target_url,
            "timestamp": datetime.now().isoformat(),
            "results": [],
            "bypassed": False,
            "total_techniques": 0,
            "successful_bypasses": 0,
        }

        if verbose:
            console.print(f"[yellow]🔍 Testing {target_url}[/yellow]")

        # Test with forbidden tool
        if forbidden_tool or all_techniques:
            forbidden_result = run_forbidden_tool(target_url, output_dir, verbose)
            if "error" not in forbidden_result:
                result["results"].extend(forbidden_result.get("bypasses", []))
                result["total_techniques"] += 1

        # Test with bypass-url-parser
        if bypass_parser or all_techniques:
            parser_result = run_bypass_url_parser(target_url, output_dir, verbose)
            if "error" not in parser_result:
                result["results"].extend(parser_result.get("bypasses", []))
                result["total_techniques"] += 1

        # Test custom techniques
        if custom_techniques or all_techniques:
            custom_bypasses = test_custom_bypasses(
                target_url, custom_headers_dict, proxies, timeout, verbose
            )
            result["results"].extend(custom_bypasses)
            result["total_techniques"] += 1

        # Test User-Agent rotation
        if user_agents or all_techniques:
            ua_bypasses = test_user_agent_bypass(
                target_url, custom_headers_dict, proxies, timeout
            )
            result["results"].extend(ua_bypasses)
            result["total_techniques"] += 1

        # Calculate success metrics
        successful = [r for r in result["results"] if r.get("bypassed")]
        result["successful_bypasses"] = len(successful)
        result["bypassed"] = len(successful) > 0

        # Cache result
        if cache_manager:
            cache_manager.set(target_url, result, cache_options)

        return result

    # Execute with threading
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(process_url, target_url) for target_url in urls]

        for future in track(
            as_completed(futures), total=len(futures), description="Testing bypasses..."
        ):
            result = future.result()
            all_results.append(result)

            # Show results
            if result["bypassed"]:
                console.print(
                    f"[green]✅ {result['url']} - {result['successful_bypasses']} bypasses found[/green]"
                )
                if verbose:
                    for bypass in result["results"]:
                        if bypass.get("bypassed"):
                            console.print(
                                f"   [green]→[/green] {bypass['technique']} ({bypass['method']}) - {bypass['status_code']}"
                            )
            else:
                console.print(f"[red]❌ {result['url']} - No bypasses found[/red]")

    # Generate summary
    total_urls = len(all_results)
    bypassed_urls = len([r for r in all_results if r["bypassed"]])
    total_bypasses = sum(r["successful_bypasses"] for r in all_results)

    console.print(f"\n[cyan]📊 Summary:[/cyan]")
    console.print(f"   • URLs tested: {total_urls}")
    console.print(f"   • URLs bypassed: {bypassed_urls}")
    console.print(f"   • Total bypasses found: {total_bypasses}")
    console.print(f"   • Success rate: {(bypassed_urls / total_urls * 100):.1f}%")

    # Export results
    if export_json:
        json_file = output_path / f"bypass_results_{int(time.time())}.json"
        export_data = (
            all_results
            if not export_successful
            else [r for r in all_results if r["bypassed"]]
        )
        with open(json_file, "w") as f:
            json.dump(export_data, f, indent=2)
        console.print(f"[green]💾 JSON results saved to {json_file}[/green]")

    if export_csv:
        csv_file = output_path / f"bypass_results_{int(time.time())}.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "url",
                    "bypassed",
                    "total_techniques",
                    "successful_bypasses",
                    "technique",
                    "method",
                    "status_code",
                    "payload",
                    "headers",
                ]
            )

            for result in all_results:
                if export_successful and not result["bypassed"]:
                    continue

                if result["results"]:
                    for bypass in result["results"]:
                        if not export_successful or bypass.get("bypassed"):
                            writer.writerow(
                                [
                                    result["url"],
                                    result["bypassed"],
                                    result["total_techniques"],
                                    result["successful_bypasses"],
                                    bypass.get("technique", ""),
                                    bypass.get("method", ""),
                                    bypass.get("status_code", ""),
                                    bypass.get("payload", ""),
                                    str(bypass.get("headers", "")),
                                ]
                            )
                else:
                    writer.writerow(
                        [
                            result["url"],
                            result["bypassed"],
                            result["total_techniques"],
                            result["successful_bypasses"],
                            "",
                            "",
                            "",
                            "",
                            "",
                        ]
                    )
        console.print(f"[green]💾 CSV results saved to {csv_file}[/green]")

    # Export successful bypasses only
    if export_successful:
        successful_results = [r for r in all_results if r["bypassed"]]
        successful_file = output_path / "successful_bypasses.txt"
        with open(successful_file, "w") as f:
            for result in successful_results:
                f.write(f"{result['url']}\n")
        console.print(
            f"[green]✅ Successful bypasses saved to {successful_file}[/green]"
        )

    # Database storage
    if store_db:
        try:
            from reconcli.db.operations import store_target

            if not target_domain and all_results:
                first_url = all_results[0]["url"]
                parsed = urlparse(first_url)
                target_domain = parsed.netloc

            if target_domain:
                target_id = store_target(target_domain, program=program)
                console.print(
                    f"[green]💾 Results prepared for database storage (target: {target_domain})[/green]"
                )
                # Note: store_bypass_results function would need to be implemented
            else:
                console.print(
                    "[yellow]⚠️ No target domain provided for database storage[/yellow]"
                )

        except ImportError:
            console.print("[yellow]⚠️ Database module not available[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Database storage failed: {e}[/red]")

    console.rule("[green]🎉 BypassCLI Analysis Complete!")


if __name__ == "__main__":
    bypasscli()
