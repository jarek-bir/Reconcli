#!/usr/bin/env python3
"""
🌐 CDNCli - Advanced CDN Fingerprinting & Cloud Storage Discovery Tool

Enhanced CDN detection, bypass tool with AI analysis, cloud storage discovery,
and comprehensive reconnaissance capabilities.

Examples:
    # Basic CDN detection
    reconcli cdncli --domain example.com --check-cdn

    # Full passive reconnaissance with cloud storage discovery
    reconcli cdncli --domain example.com --passive-all --ai --cloudhunter

    # Active bypass attempts with nuclei scanning
    reconcli cdncli --domain example.com --bypass-active --nuclei --store-db

    # Cloud storage hunting with custom wordlist
    reconcli cdncli --domain example.com --cloudhunter --permutations-file custom.txt --services aws,azure,google

    # Multi-engine analysis with AI and database storage
    reconcli cdncli --domain example.com --engine metabigor --dnsx --subfinder --ai --program "bug-bounty-2024"

    # Complete reconnaissance workflow
    reconcli cdncli --domain example.com --passive-all --bypass-all --cloudhunter --nuclei --ai --format rich
"""

import json
import os
import shutil
import subprocess  # nosec B404 - Required for external tool integration
import sys
import time
import sqlite3
import pickle  # nosec B403 - Used for secure resume state management
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import re

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

console = Console()


class CDNCacheManager:
    """Intelligent caching system for CDN analysis operations with SHA256-based cache keys."""

    def __init__(
        self,
        cache_dir: str = "cdn_cache",
        ttl_hours: int = 24,
        max_cache_size: int = 500,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.max_cache_size = max_cache_size
        self.cache_index_file = self.cache_dir / "cdn_cache_index.json"
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_files": 0,
            "total_size_mb": 0.0,
        }
        self._load_cache_index()

    def _load_cache_index(self):
        """Load cache index from disk."""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    self.cache_index = json.load(f)
            except:
                self.cache_index = {}
        else:
            self.cache_index = {}

    def _save_cache_index(self):
        """Save cache index to disk."""
        with open(self.cache_index_file, "w") as f:
            json.dump(self.cache_index, f, indent=2)

    def _generate_cache_key(self, domain: str, analysis_type: str, **kwargs) -> str:
        """Generate SHA256 cache key based on domain and analysis parameters."""
        import hashlib

        # Create deterministic cache key from parameters
        cache_data = {
            "domain": domain,
            "analysis_type": analysis_type,
            "subfinder": kwargs.get("subfinder", False),
            "dnsx": kwargs.get("dnsx", False),
            "cdncheck": kwargs.get("cdncheck", False),
            "nuclei": kwargs.get("nuclei", False),
            "metabigor": kwargs.get("metabigor", False),
            "cloudhunter": kwargs.get("cloudhunter", False),
            "services": kwargs.get("services", ""),
            "bypass": kwargs.get("bypass", False),
            "shodan": kwargs.get("shodan", False),
            "fofa": kwargs.get("fofa", False),
        }

        # Sort for consistent ordering
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def get_cached_result(
        self, domain: str, analysis_type: str, **kwargs
    ) -> Optional[Dict]:
        """Retrieve cached result if valid and not expired."""
        self.cache_stats["total_requests"] += 1

        cache_key = self._generate_cache_key(domain, analysis_type, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            self.cache_stats["misses"] += 1
            return None

        try:
            with open(cache_file, "r") as f:
                cached_data = json.load(f)

            # Check if cache is still valid
            cache_time = cached_data.get("cache_metadata", {}).get("timestamp", 0)
            if time.time() - cache_time > self.ttl_seconds:
                cache_file.unlink()  # Remove expired cache
                self.cache_stats["misses"] += 1
                return None

            self.cache_stats["hits"] += 1
            cached_data["cache_metadata"]["cache_hit"] = True
            return cached_data

        except Exception:
            # If cache file is corrupted, remove it
            if cache_file.exists():
                cache_file.unlink()
            self.cache_stats["misses"] += 1
            return None

    def save_result_to_cache(
        self, domain: str, analysis_type: str, result: Dict, **kwargs
    ):
        """Save analysis result to cache with metadata."""
        cache_key = self._generate_cache_key(domain, analysis_type, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add cache metadata
        cached_result = {
            **result,
            "cache_metadata": {
                "timestamp": time.time(),
                "cache_key": cache_key,
                "domain": domain,
                "analysis_type": analysis_type,
                "ttl_seconds": self.ttl_seconds,
                "cache_hit": False,
            },
        }

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(cached_result, f, indent=2)

        # Update cache index
        self.cache_index[cache_key] = {
            "domain": domain,
            "analysis_type": analysis_type,
            "timestamp": time.time(),
            "file": str(cache_file.name),
        }
        self._save_cache_index()

        # Cleanup old cache if needed
        self._cleanup_old_cache()

    def _cleanup_old_cache(self):
        """Remove oldest cache files if cache size exceeds limit."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "cdn_cache_index.json"]

        if len(cache_files) > self.max_cache_size:
            # Sort by modification time and remove oldest
            cache_files.sort(key=lambda x: x.stat().st_mtime)
            files_to_remove = cache_files[: -self.max_cache_size]

            for cache_file in files_to_remove:
                cache_file.unlink()
                # Remove from index
                cache_key = cache_file.stem
                self.cache_index.pop(cache_key, None)

            self._save_cache_index()

    def get_cache_stats(self) -> Dict:
        """Get comprehensive cache statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "cdn_cache_index.json"]

        total_size = sum(f.stat().st_size for f in cache_files)

        hit_rate = (
            (self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100)
            if self.cache_stats["total_requests"] > 0
            else 0
        )

        return {
            **self.cache_stats,
            "hit_rate_percent": round(hit_rate, 1),
            "cache_files": len(cache_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
            "ttl_hours": self.ttl_seconds / 3600,
        }

    def clear_cache(self):
        """Clear all cached results."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

        self.cache_index = {}
        self._save_cache_index()

        # Reset stats
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_files": 0,
            "total_size_mb": 0.0,
        }


# CDN Provider signatures
CDN_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "servers": ["cloudflare"],
        "ips": ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22"],
        "cnames": ["cloudflare.com", "cloudflare.net"],
    },
    "akamai": {
        "headers": ["akamai-origin-hop", "x-akamai-transformed"],
        "servers": ["akamaihd.net", "akamaized.net"],
        "ips": ["23.32.0.0/11", "23.192.0.0/11"],
        "cnames": ["akamai.net", "akamaihd.net"],
    },
    "aws_cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "servers": ["cloudfront"],
        "ips": ["13.32.0.0/15", "13.35.0.0/16"],
        "cnames": ["cloudfront.net"],
    },
    "fastly": {
        "headers": ["fastly-io", "x-served-by"],
        "servers": ["fastly"],
        "ips": ["23.235.32.0/20", "43.249.72.0/22"],
        "cnames": ["fastly.com", "fastlylb.net"],
    },
    "maxcdn": {"headers": ["x-pull"], "servers": ["maxcdn"], "cnames": ["maxcdn.com"]},
}


def ai_analyze_cdn_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """AI-powered analysis of CDN and cloud storage findings."""
    analysis = {
        "risk_assessment": {},
        "findings_summary": {},
        "recommendations": [],
        "attack_vectors": [],
        "cloud_exposure": {},
        "bypass_opportunities": [],
    }

    # Risk Assessment
    risk_score = 0
    risk_factors = []

    if results.get("cdn_detected"):
        risk_factors.append("CDN protection detected")
        risk_score += 2

    if results.get("real_ips"):
        risk_factors.append(f"Real IP addresses discovered: {len(results['real_ips'])}")
        risk_score += 5

    if results.get("cloud_buckets"):
        open_buckets = [b for b in results["cloud_buckets"] if b.get("accessible")]
        if open_buckets:
            risk_factors.append(
                f"Open cloud storage buckets found: {len(open_buckets)}"
            )
            risk_score += 8

    if results.get("subdomains"):
        risk_factors.append(f"Subdomains enumerated: {len(results['subdomains'])}")
        risk_score += 3

    # Risk Level
    if risk_score >= 15:
        risk_level = "CRITICAL"
    elif risk_score >= 10:
        risk_level = "HIGH"
    elif risk_score >= 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    analysis["risk_assessment"] = {
        "score": risk_score,
        "level": risk_level,
        "factors": risk_factors,
    }

    # Findings Summary
    analysis["findings_summary"] = {
        "cdn_provider": results.get("cdn_provider", "None detected"),
        "real_ips_found": len(results.get("real_ips", [])),
        "subdomains_discovered": len(results.get("subdomains", [])),
        "cloud_buckets_found": len(results.get("cloud_buckets", [])),
        "vulnerabilities": len(results.get("vulnerabilities", [])),
    }

    # Attack Vectors
    if results.get("real_ips"):
        analysis["attack_vectors"].append("Direct IP access bypassing CDN")

    if results.get("subdomains"):
        analysis["attack_vectors"].append(
            "Subdomain enumeration for additional attack surface"
        )

    if results.get("cloud_buckets"):
        open_buckets = [b for b in results["cloud_buckets"] if b.get("accessible")]
        if open_buckets:
            analysis["attack_vectors"].append("Open cloud storage bucket access")

    # Cloud Exposure Analysis
    if results.get("cloud_buckets"):
        services = {}
        for bucket in results["cloud_buckets"]:
            service = bucket.get("service", "unknown")
            if service not in services:
                services[service] = {"total": 0, "accessible": 0}
            services[service]["total"] += 1
            if bucket.get("accessible"):
                services[service]["accessible"] += 1

        analysis["cloud_exposure"] = services

    # Recommendations
    recommendations = []

    if results.get("cdn_detected"):
        recommendations.append("Monitor CDN configuration for bypasses")

    if results.get("real_ips"):
        recommendations.append("Ensure real IP addresses are properly firewalled")

    if results.get("cloud_buckets"):
        open_buckets = [b for b in results["cloud_buckets"] if b.get("accessible")]
        if open_buckets:
            recommendations.append("Immediately secure open cloud storage buckets")
            recommendations.append("Implement proper IAM policies for cloud storage")

    if results.get("subdomains"):
        recommendations.append("Review subdomain inventory and disable unused services")

    recommendations.extend(
        [
            "Regular security assessments of CDN configuration",
            "Implement proper access controls on cloud resources",
            "Monitor for subdomain takeover vulnerabilities",
        ]
    )

    analysis["recommendations"] = recommendations

    return analysis


class CDNAnalyzer:
    """Enhanced CDN analysis with multiple detection methods and cloud storage discovery."""

    def _validate_domain_init(self, domain: str) -> bool:
        """Validate domain name during initialization."""
        # Allow only valid domain characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return False

        # Check length
        if len(domain) > 253:
            return False

        # Check for suspicious patterns
        suspicious_patterns = [
            ";",
            "&",
            "|",
            "`",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "<",
            ">",
        ]
        if any(pattern in domain for pattern in suspicious_patterns):
            return False

        return True

    def __init__(
        self,
        domain: str,
        options: Dict[str, Any],
        cache_manager: Optional["CDNCacheManager"] = None,
    ):
        # Validate domain for security
        if not self._validate_domain_init(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        self.domain = domain
        self.options = options
        self.cache_manager = cache_manager
        self.output_dir = Path(options.get("output_dir", "cdncli_output"))
        self.output_dir.mkdir(exist_ok=True)

        # Resume functionality
        self.resume_file = self.output_dir / f"resume_{domain}.pkl"
        self.stats_file = self.output_dir / f"stats_{domain}.json"

        self.results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "cdn_detected": False,
            "cdn_provider": None,
            "bypass_methods": [],
            "real_ips": [],
            "subdomains": [],
            "certificates": [],
            "dns_records": [],
            "vulnerabilities": [],
            "cloud_buckets": [],
            "shodan_results": [],
            "fofa_results": [],
            "ai_analysis": {},
            "tools_used": [],
            "step_completed": {},
            "stats": {
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "duration": 0,
                "steps_completed": 0,
                "steps_total": 0,
                "errors": [],
            },
        }

    def check_binary(self, binary_name: str) -> bool:
        """Check if binary is available."""
        return shutil.which(binary_name) is not None

    def save_resume_state(self):
        """Save current state for resume functionality."""
        try:
            # Only save if resume file is in our controlled output directory
            if not str(self.resume_file).startswith(str(self.output_dir)):
                raise ValueError("Resume file path outside allowed directory")

            with open(self.resume_file, "wb") as f:
                pickle.dump(self.results, f)  # nosec B301 - Controlled internal state
        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Failed to save resume state: {e}[/yellow]")

    def load_resume_state(self) -> bool:
        """Load previous state for resume functionality."""
        try:
            if self.resume_file.exists():
                # Security check: ensure file is in our controlled directory
                if not str(self.resume_file).startswith(str(self.output_dir)):
                    raise ValueError("Resume file path outside allowed directory")

                # Check file size to prevent memory exhaustion
                if self.resume_file.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                    raise ValueError("Resume file too large")

                with open(self.resume_file, "rb") as f:
                    self.results = pickle.load(
                        f
                    )  # nosec B301 - Controlled internal state
                console.print("[green]Resume state loaded successfully[/green]")
                return True
        except Exception as e:
            console.print(f"[yellow]Failed to load resume state: {e}[/yellow]")
        return False

    def clear_resume_state(self):
        """Clear resume state and stats."""
        try:
            if self.resume_file.exists():
                self.resume_file.unlink()
            if self.stats_file.exists():
                self.stats_file.unlink()
            console.print("[green]Resume state cleared[/green]")
        except Exception as e:
            console.print(f"[yellow]Failed to clear resume state: {e}[/yellow]")

    def save_stats(self):
        """Save statistics to file."""
        try:
            self.results["stats"]["end_time"] = datetime.now().isoformat()
            start_time = datetime.fromisoformat(self.results["stats"]["start_time"])
            end_time = datetime.fromisoformat(self.results["stats"]["end_time"])
            self.results["stats"]["duration"] = (end_time - start_time).total_seconds()

            with open(self.stats_file, "w") as f:
                json.dump(self.results["stats"], f, indent=2)
        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Failed to save stats: {e}[/yellow]")

    def display_resume_stats(self):
        """Display resume statistics."""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, "r") as f:
                    stats = json.load(f)

                stats_table = Table(title="📊 Resume Statistics")
                stats_table.add_column("Metric", style="cyan")
                stats_table.add_column("Value", style="green")

                stats_table.add_row("Start Time", stats.get("start_time", "N/A"))
                stats_table.add_row("End Time", stats.get("end_time", "N/A"))
                stats_table.add_row("Duration (seconds)", str(stats.get("duration", 0)))
                stats_table.add_row(
                    "Steps Completed", str(stats.get("steps_completed", 0))
                )
                stats_table.add_row("Steps Total", str(stats.get("steps_total", 0)))
                stats_table.add_row("Errors", str(len(stats.get("errors", []))))

                console.print(stats_table)
            except Exception as e:
                console.print(f"[red]Failed to display stats: {e}[/red]")
        else:
            console.print("[yellow]No resume statistics found[/yellow]")

    def mark_step_completed(self, step_name: str):
        """Mark a step as completed."""
        self.results["step_completed"][step_name] = True
        self.results["stats"]["steps_completed"] += 1
        self.save_resume_state()

    def is_step_completed(self, step_name: str) -> bool:
        """Check if a step was already completed."""
        return self.results["step_completed"].get(step_name, False)

    def run_shodan(self) -> List[Dict[str, Any]]:
        """Query Shodan API for domain information."""
        shodan_results = []

        # Skip if already completed and resuming
        if self.is_step_completed("shodan"):
            console.print("[yellow]Shodan step already completed, skipping[/yellow]")
            return self.results.get("shodan_results", [])

        try:
            # This would integrate with Shodan API
            # For now, simulating with a placeholder
            shodan_api_key = os.getenv("SHODAN_API_KEY")
            if not shodan_api_key:
                console.print(
                    "[yellow]SHODAN_API_KEY not set, skipping Shodan[/yellow]"
                )
                return []

            import shodan

            api = shodan.Shodan(shodan_api_key)

            # Search for domain
            results = api.search(f"hostname:{self.domain}")

            for result in results["matches"]:
                shodan_results.append(
                    {
                        "ip": result.get("ip_str"),
                        "port": result.get("port"),
                        "org": result.get("org"),
                        "location": result.get("location", {}),
                        "data": result.get("data", "")[:500],  # Truncate data
                    }
                )

            self.results["shodan_results"].extend(shodan_results)
            self.results["tools_used"].append("shodan")
            self.mark_step_completed("shodan")

        except ImportError:
            console.print(
                "[yellow]Shodan library not installed. Install with: pip install shodan[/yellow]"
            )
        except Exception as e:
            error_msg = f"Shodan query failed: {e}"
            self.results["stats"]["errors"].append(error_msg)
            if self.options.get("verbose"):
                console.print(f"[yellow]{error_msg}[/yellow]")

        return shodan_results

    def run_fofa(self) -> List[Dict[str, Any]]:
        """Query FOFA API for domain information."""
        fofa_results = []

        # Skip if already completed and resuming
        if self.is_step_completed("fofa"):
            console.print("[yellow]FOFA step already completed, skipping[/yellow]")
            return self.results.get("fofa_results", [])

        try:
            fofa_email = os.getenv("FOFA_EMAIL")
            fofa_key = os.getenv("FOFA_KEY")

            if not fofa_email or not fofa_key:
                console.print(
                    "[yellow]FOFA_EMAIL and FOFA_KEY not set, skipping FOFA[/yellow]"
                )
                return []

            import base64

            # FOFA search query
            query = f'domain="{self.domain}"'
            query_base64 = base64.b64encode(query.encode()).decode()

            url = f"https://fofa.info/api/v1/search/all"
            params = {
                "email": fofa_email,
                "key": fofa_key,
                "qbase64": query_base64,
                "size": 100,
                "fields": "ip,port,title,host,protocol,country",
            }

            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("error") == False:
                    for result in data.get("results", []):
                        if len(result) >= 6:
                            fofa_results.append(
                                {
                                    "ip": result[0],
                                    "port": result[1],
                                    "title": result[2],
                                    "host": result[3],
                                    "protocol": result[4],
                                    "country": result[5],
                                }
                            )

            self.results["fofa_results"].extend(fofa_results)
            self.results["tools_used"].append("fofa")
            self.mark_step_completed("fofa")

        except Exception as e:
            error_msg = f"FOFA query failed: {e}"
            self.results["stats"]["errors"].append(error_msg)
            if self.options.get("verbose"):
                console.print(f"[yellow]{error_msg}[/yellow]")

        return fofa_results

    def analyze_headers(self) -> Dict[str, Any]:
        """Analyze HTTP headers for CDN signatures."""
        # Skip if already completed and resuming
        if self.is_step_completed("headers"):
            console.print(
                "[yellow]Headers analysis already completed, skipping[/yellow]"
            )
            return {
                "provider": self.results.get("cdn_provider"),
                "confidence": "resumed",
                "method": "headers",
            }

        try:
            response = requests.get(f"http://{self.domain}", timeout=10)
            headers = response.headers

            for cdn, signatures in CDN_SIGNATURES.items():
                for header_sig in signatures["headers"]:
                    if any(
                        header_sig.lower() in k.lower()
                        or header_sig.lower() in v.lower()
                        for k, v in headers.items()
                    ):
                        self.results["cdn_detected"] = True
                        self.results["cdn_provider"] = cdn
                        self.mark_step_completed("headers")
                        return {
                            "provider": cdn,
                            "confidence": "high",
                            "method": "headers",
                        }

        except Exception as e:
            error_msg = f"Header analysis failed: {e}"
            self.results["stats"]["errors"].append(error_msg)
            if self.options.get("verbose"):
                console.print(f"[red]{error_msg}[/red]")

        self.mark_step_completed("headers")
        return {"provider": None, "confidence": "none", "method": "headers"}

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name to prevent command injection."""
        # Allow only valid domain characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return False

        # Check length
        if len(domain) > 253:
            return False

        # Check for suspicious patterns
        suspicious_patterns = [";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]"]
        if any(pattern in domain for pattern in suspicious_patterns):
            return False

        return True

    def _safe_subprocess(
        self, cmd: List[str], timeout: int = 30
    ) -> subprocess.CompletedProcess:
        """Safely execute subprocess with validation."""
        # Validate all command arguments
        for arg in cmd:
            if not isinstance(arg, str):
                raise ValueError("All command arguments must be strings")

            # Check for command injection patterns
            if any(char in arg for char in [";", "&", "|", "`", "$", "(", ")"]):
                if arg != self.domain:  # Domain already validated separately
                    raise ValueError(f"Suspicious characters in argument: {arg}")

        # Validate domain if present in command
        if self.domain in cmd and not self._validate_domain(self.domain):
            raise ValueError(f"Invalid domain format: {self.domain}")

        return subprocess.run(  # nosec B603 - Input validated above
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # Explicitly disable shell
        )

    def run_cdncheck(self) -> Dict[str, Any]:
        """Run projectdiscovery/cdncheck for detection."""
        # Skip if already completed and resuming
        if self.is_step_completed("cdncheck"):
            console.print("[yellow]CDNCheck already completed, skipping[/yellow]")
            return {
                "provider": self.results.get("cdn_provider"),
                "confidence": "resumed",
                "method": "cdncheck",
            }

        if not self.check_binary("cdncheck"):
            console.print("[yellow]cdncheck not found, skipping[/yellow]")
            return {"provider": None, "confidence": "none", "method": "cdncheck"}

        try:
            cmd = ["cdncheck", "-i", self.domain, "-json"]
            result = self._safe_subprocess(cmd, timeout=30)

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                if data.get("cdn"):
                    self.results["cdn_detected"] = True
                    self.results["cdn_provider"] = data.get("provider", "unknown")
                    self.results["tools_used"].append("cdncheck")
                    self.mark_step_completed("cdncheck")
                    return {
                        "provider": data.get("provider"),
                        "confidence": "high",
                        "method": "cdncheck",
                    }

        except Exception as e:
            error_msg = f"CDNCheck failed: {e}"
            self.results["stats"]["errors"].append(error_msg)
            if self.options.get("verbose"):
                console.print(f"[yellow]{error_msg}[/yellow]")

        self.mark_step_completed("cdncheck")
        return {"provider": None, "confidence": "none", "method": "cdncheck"}

    def run_subfinder(self) -> List[str]:
        """Run subfinder for subdomain enumeration."""
        # Skip if already completed and resuming
        if self.is_step_completed("subfinder"):
            console.print("[yellow]Subfinder already completed, skipping[/yellow]")
            return self.results.get("subdomains", [])

        if not self.check_binary("subfinder"):
            console.print("[yellow]subfinder not found, skipping[/yellow]")
            self.mark_step_completed("subfinder")
            return []

        subdomains = []
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent"]
            result = self._safe_subprocess(cmd, timeout=120)

            if result.returncode == 0:
                subdomains = [
                    line.strip() for line in result.stdout.split("\n") if line.strip()
                ]
                self.results["subdomains"].extend(subdomains)
                self.results["tools_used"].append("subfinder")

        except Exception as e:
            error_msg = f"Subfinder failed: {e}"
            self.results["stats"]["errors"].append(error_msg)
            if self.options.get("verbose"):
                console.print(f"[yellow]{error_msg}[/yellow]")

        self.mark_step_completed("subfinder")
        return subdomains

    def run_dnsx(self) -> List[Dict[str, Any]]:
        """Run dnsx for DNS resolution."""
        if not self.check_binary("dnsx"):
            console.print("[yellow]dnsx not found, skipping[/yellow]")
            return []

        dns_records = []
        try:
            cmd = [
                "dnsx",
                "-d",
                self.domain,
                "-a",
                "-aaaa",
                "-cname",
                "-mx",
                "-txt",
                "-json",
            ]
            result = self._safe_subprocess(cmd, timeout=30)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.strip():
                        try:
                            record = json.loads(line)
                            dns_records.append(record)
                        except json.JSONDecodeError:
                            continue

                self.results["dns_records"].extend(dns_records)
                self.results["tools_used"].append("dnsx")

        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]DNSX failed: {e}[/yellow]")

        return dns_records

    def run_cloudhunter(self) -> List[Dict[str, Any]]:
        """Run cloudhunter for cloud storage discovery."""
        if not self.check_binary("cloudhunter"):
            console.print("[yellow]cloudhunter not found, skipping[/yellow]")
            return []

        cloud_buckets = []
        try:
            output_file = self.output_dir / f"cloudhunter_{self.domain}.json"

            cmd = ["cloudhunter", self.domain, "-of", str(output_file)]

            # Add optional parameters
            if self.options.get("permutations_file"):
                cmd.extend(["-p", self.options["permutations_file"]])

            if self.options.get("services"):
                cmd.extend(["-s", self.options["services"]])

            if self.options.get("threads"):
                cmd.extend(["-t", str(self.options["threads"])])

            if self.options.get("crawl_deep"):
                cmd.extend(["-c", str(self.options["crawl_deep"])])

            if self.options.get("write_test"):
                cmd.append("-w")

            if self.options.get("base_only"):
                cmd.append("-b")

            if self.options.get("disable_bruteforce"):
                cmd.append("-d")

            if self.options.get("open_only"):
                cmd.append("-o")

            if self.options.get("verbose"):
                cmd.append("-v")

            result = self._safe_subprocess(cmd, timeout=300)

            # Parse cloudhunter output - it outputs findings directly to stdout
            for line in result.stdout.split("\n"):
                if line.strip() and ("http" in line or "https" in line):
                    # Extract bucket info from output line
                    if any(
                        cloud in line
                        for cloud in [
                            "amazonaws",
                            "googleapis",
                            "blob.core",
                            "aliyuncs",
                        ]
                    ):
                        cloud_buckets.append(
                            {
                                "url": line.strip(),
                                "service": self._detect_cloud_service(line),
                                "accessible": True,  # cloudhunter only shows accessible buckets
                                "permissions": (
                                    "read" if "read" in line.lower() else "unknown"
                                ),
                            }
                        )

            self.results["cloud_buckets"].extend(cloud_buckets)
            self.results["tools_used"].append("cloudhunter")

        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]CloudHunter failed: {e}[/yellow]")

        return cloud_buckets

    def _detect_cloud_service(self, url: str) -> str:
        """Detect cloud service from URL."""
        if "amazonaws" in url:
            return "aws"
        elif "googleapis" in url or "storage.cloud.google" in url:
            return "google"
        elif "blob.core.windows" in url:
            return "azure"
        elif "aliyuncs" in url:
            return "alibaba"
        else:
            return "unknown"

    def run_nuclei(self) -> List[Dict[str, Any]]:
        """Run nuclei for vulnerability scanning."""
        if not self.check_binary("nuclei"):
            console.print("[yellow]nuclei not found, skipping[/yellow]")
            return []

        vulnerabilities = []
        try:
            cmd = ["nuclei", "-u", f"https://{self.domain}", "-json", "-silent"]
            result = self._safe_subprocess(cmd, timeout=300)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue

                self.results["vulnerabilities"].extend(vulnerabilities)
                self.results["tools_used"].append("nuclei")

        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Nuclei failed: {e}[/yellow]")

        return vulnerabilities

    def run_metabigor(self) -> Dict[str, Any]:
        """Run metabigor for additional reconnaissance."""
        if not self.check_binary("metabigor"):
            console.print("[yellow]metabigor not found, skipping[/yellow]")
            return {}

        try:
            cmd = ["metabigor", "net", "--org", self.domain]
            result = self._safe_subprocess(cmd, timeout=60)

            if result.returncode == 0:
                self.results["tools_used"].append("metabigor")
                return {"status": "success", "output": result.stdout}

        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Metabigor failed: {e}[/yellow]")

        return {}

    def bypass_cdn_methods(self) -> List[str]:
        """Try various CDN bypass methods."""
        bypass_results = []

        # Method 1: Direct IP access
        try:
            import socket

            ip = socket.gethostbyname(self.domain)
            if ip:
                self.results["real_ips"].append(ip)
                bypass_results.append(f"Direct IP: {ip}")
        except (socket.gaierror, socket.error) as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Direct IP lookup failed: {e}[/yellow]")

        # Method 2: Historical DNS records
        try:
            # This would integrate with SecurityTrails or similar service
            # Placeholder for future implementation
            if self.options.get("verbose"):
                console.print("[yellow]Historical DNS lookup not implemented[/yellow]")
        except Exception as e:
            if self.options.get("verbose"):
                console.print(f"[yellow]Historical DNS lookup failed: {e}[/yellow]")

        # Method 3: Subdomain enumeration for non-CDN subdomains
        if self.results["subdomains"]:
            bypass_results.append(
                f"Subdomains found: {len(self.results['subdomains'])}"
            )

        self.results["bypass_methods"] = bypass_results
        return bypass_results

    def store_to_database(self, program: Optional[str] = None):
        """Store results to SQLite database."""
        try:
            db_path = Path("reconcli_data.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create table if not exists
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cdncli_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    program TEXT,
                    timestamp TEXT,
                    cdn_detected BOOLEAN,
                    cdn_provider TEXT,
                    real_ips_count INTEGER,
                    subdomains_count INTEGER,
                    cloud_buckets_count INTEGER,
                    vulnerabilities_count INTEGER,
                    results_json TEXT
                )
            """
            )

            # Insert results
            cursor.execute(
                """
                INSERT INTO cdncli_results 
                (domain, program, timestamp, cdn_detected, cdn_provider, 
                 real_ips_count, subdomains_count, cloud_buckets_count, 
                 vulnerabilities_count, results_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    self.domain,
                    program,
                    self.results["timestamp"],
                    self.results["cdn_detected"],
                    self.results["cdn_provider"],
                    len(self.results["real_ips"]),
                    len(self.results["subdomains"]),
                    len(self.results["cloud_buckets"]),
                    len(self.results["vulnerabilities"]),
                    json.dumps(self.results),
                ),
            )

            conn.commit()
            conn.close()
            console.print("[green]Results stored to database[/green]")

        except Exception as e:
            console.print(f"[red]Database storage failed: {e}[/red]")

    def run_full_analysis(self):
        """Run comprehensive CDN and cloud storage analysis with intelligent caching."""
        # Check cache first if enabled
        if self.cache_manager:
            cache_params = {
                "subfinder": self.options.get("subfinder", False),
                "dnsx": self.options.get("dnsx", False),
                "cdncheck": self.options.get("cdncheck", True),
                "nuclei": self.options.get("nuclei", False),
                "metabigor": self.options.get("metabigor", False),
                "cloudhunter": self.options.get("cloudhunter", False),
                "services": self.options.get("services", ""),
                "bypass": self.options.get("bypass", False),
                "shodan": self.options.get("shodan", False),
                "fofa": self.options.get("fofa", False),
            }

            cached_result = self.cache_manager.get_cached_result(
                self.domain, "full_analysis", **cache_params
            )

            if cached_result:
                # Use cached results
                self.results = cached_result
                console.print(
                    Panel(
                        f"🚀 Cache Hit! Using cached results for [cyan]{self.domain}[/cyan]\n"
                        f"Cache Key: {cached_result['cache_metadata']['cache_key'][:16]}...\n"
                        f"Cached at: {datetime.fromtimestamp(cached_result['cache_metadata']['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}",
                        title="⚡ CDN Cache Performance",
                        border_style="green",
                    )
                )
                return

        # Calculate total steps
        total_steps = 0
        if self.options.get("cdncheck", True):
            total_steps += 1
        if self.options.get("subfinder", True):
            total_steps += 1
        if self.options.get("dnsx", True):
            total_steps += 1
        if self.options.get("cloudhunter", False):
            total_steps += 1
        if self.options.get("nuclei", False):
            total_steps += 1
        if self.options.get("metabigor", False):
            total_steps += 1
        if self.options.get("bypass", False):
            total_steps += 1
        if self.options.get("ai", False):
            total_steps += 1
        if self.options.get("shodan", False):
            total_steps += 1
        if self.options.get("fofa", False):
            total_steps += 1
        total_steps += 1  # headers analysis

        self.results["stats"]["steps_total"] = total_steps

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            # CDN Detection - Headers
            task1 = progress.add_task(
                "Analyzing headers for CDN signatures...", total=None
            )
            self.analyze_headers()
            progress.remove_task(task1)

            # CDNCheck
            if self.options.get("cdncheck", True):
                task2 = progress.add_task("Running CDNCheck...", total=None)
                self.run_cdncheck()
                progress.remove_task(task2)

            # Shodan
            if self.options.get("shodan", False):
                task_shodan = progress.add_task("Querying Shodan API...", total=None)
                self.run_shodan()
                progress.remove_task(task_shodan)

            # FOFA
            if self.options.get("fofa", False):
                task_fofa = progress.add_task("Querying FOFA API...", total=None)
                self.run_fofa()
                progress.remove_task(task_fofa)

            # Subfinder
            if self.options.get("subfinder", True):
                task3 = progress.add_task("Enumerating subdomains...", total=None)
                self.run_subfinder()
                progress.remove_task(task3)

            # DNSX
            if self.options.get("dnsx", True):
                task4 = progress.add_task("Resolving DNS records...", total=None)
                self.run_dnsx()
                progress.remove_task(task4)

            # CloudHunter
            if self.options.get("cloudhunter", False):
                task5 = progress.add_task(
                    "Hunting cloud storage buckets...", total=None
                )
                self.run_cloudhunter()
                progress.remove_task(task5)

            # Nuclei
            if self.options.get("nuclei", False):
                task6 = progress.add_task("Scanning for vulnerabilities...", total=None)
                self.run_nuclei()
                progress.remove_task(task6)

            # Metabigor
            if self.options.get("metabigor", False):
                task7 = progress.add_task(
                    "Running metabigor reconnaissance...", total=None
                )
                self.run_metabigor()
                progress.remove_task(task7)

            # CDN Bypass attempts
            if self.options.get("bypass", False):
                task8 = progress.add_task(
                    "Attempting CDN bypass methods...", total=None
                )
                self.bypass_cdn_methods()
                progress.remove_task(task8)

            # AI Analysis
            if self.options.get("ai", False):
                task9 = progress.add_task("Running AI analysis...", total=None)
                self.results["ai_analysis"] = ai_analyze_cdn_results(self.results)
                self.mark_step_completed("ai")
                progress.remove_task(task9)

        # Save final stats
        self.save_stats()

        # Save to cache if enabled (excluding cached results)
        if self.cache_manager and not self.results.get("cache_metadata", {}).get(
            "cache_hit", False
        ):
            cache_params = {
                "subfinder": self.options.get("subfinder", False),
                "dnsx": self.options.get("dnsx", False),
                "cdncheck": self.options.get("cdncheck", True),
                "nuclei": self.options.get("nuclei", False),
                "metabigor": self.options.get("metabigor", False),
                "cloudhunter": self.options.get("cloudhunter", False),
                "services": self.options.get("services", ""),
                "bypass": self.options.get("bypass", False),
                "shodan": self.options.get("shodan", False),
                "fofa": self.options.get("fofa", False),
            }

            self.cache_manager.save_result_to_cache(
                self.domain, "full_analysis", self.results, **cache_params
            )


def display_results(results: Dict[str, Any], format_type: str = "rich"):
    """Display results in various formats."""
    if format_type == "rich":
        display_rich_results(results)
    elif format_type == "json":
        console.print(json.dumps(results, indent=2))
    elif format_type == "table":
        display_table_results(results)


def display_rich_results(results: Dict[str, Any]):
    """Display results using Rich formatting."""
    # CDN Detection Panel
    cdn_status = "🔍 DETECTED" if results["cdn_detected"] else "❌ NOT DETECTED"
    cdn_provider = results.get("cdn_provider", "None")

    cdn_panel = Panel(
        f"Status: {cdn_status}\nProvider: {cdn_provider}",
        title="🌐 CDN Detection",
        border_style="blue",
    )
    console.print(cdn_panel)

    # Cloud Storage Panel
    if results.get("cloud_buckets"):
        bucket_count = len(results["cloud_buckets"])
        open_buckets = len([b for b in results["cloud_buckets"] if b.get("accessible")])

        cloud_panel = Panel(
            f"Total Buckets: {bucket_count}\nAccessible: {open_buckets}",
            title="☁️ Cloud Storage Discovery",
            border_style="cyan",
        )
        console.print(cloud_panel)

    # Statistics Table
    stats_table = Table(title="📊 Reconnaissance Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Count", style="green")

    stats_table.add_row("Real IPs Found", str(len(results.get("real_ips", []))))
    stats_table.add_row("Subdomains", str(len(results.get("subdomains", []))))
    stats_table.add_row("DNS Records", str(len(results.get("dns_records", []))))
    stats_table.add_row("Cloud Buckets", str(len(results.get("cloud_buckets", []))))
    stats_table.add_row("Vulnerabilities", str(len(results.get("vulnerabilities", []))))
    stats_table.add_row("Shodan Results", str(len(results.get("shodan_results", []))))
    stats_table.add_row("FOFA Results", str(len(results.get("fofa_results", []))))

    console.print(stats_table)

    # AI Analysis
    if results.get("ai_analysis"):
        ai_analysis = results["ai_analysis"]
        risk_level = ai_analysis.get("risk_assessment", {}).get("level", "UNKNOWN")

        risk_color = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(risk_level, "white")

        ai_panel = Panel(
            f"Risk Level: [{risk_color}]{risk_level}[/{risk_color}]\n"
            f"Attack Vectors: {len(ai_analysis.get('attack_vectors', []))}\n"
            f"Recommendations: {len(ai_analysis.get('recommendations', []))}",
            title="🤖 AI Analysis",
            border_style="magenta",
        )
        console.print(ai_panel)


def display_table_results(results: Dict[str, Any]):
    """Display results in table format."""
    table = Table(title=f"CDNCli Results for {results['domain']}")
    table.add_column("Category", style="cyan")
    table.add_column("Details", style="white")

    table.add_row("CDN Detected", "✅ Yes" if results["cdn_detected"] else "❌ No")
    table.add_row("CDN Provider", results.get("cdn_provider", "None"))
    table.add_row("Real IPs", str(len(results.get("real_ips", []))))
    table.add_row("Subdomains", str(len(results.get("subdomains", []))))
    table.add_row("Cloud Buckets", str(len(results.get("cloud_buckets", []))))
    table.add_row("Vulnerabilities", str(len(results.get("vulnerabilities", []))))
    table.add_row("Shodan Results", str(len(results.get("shodan_results", []))))
    table.add_row("FOFA Results", str(len(results.get("fofa_results", []))))
    table.add_row("Tools Used", ", ".join(results.get("tools_used", [])))

    console.print(table)


@click.command()
@click.option("--domain", help="Target domain to analyze")
@click.option("--ip", help="Target IP address for direct scanning")
@click.option("--check-cdn", is_flag=True, help="Perform CDN detection")
@click.option(
    "--bypass-passive", is_flag=True, help="Attempt passive CDN bypass methods"
)
@click.option("--bypass-active", is_flag=True, help="Attempt active CDN bypass methods")
@click.option("--bypass-all", is_flag=True, help="Attempt all CDN bypass methods")
@click.option("--passive-all", is_flag=True, help="Run all passive reconnaissance")
@click.option("--cloudhunter", is_flag=True, help="Run cloud storage discovery")
@click.option("--permutations-file", help="CloudHunter permutations file")
@click.option(
    "--services", default="aws,google,azure,alibaba", help="CloudHunter target services"
)
@click.option("--write-test", is_flag=True, help="CloudHunter write test")
@click.option("--base-only", is_flag=True, help="CloudHunter base only")
@click.option(
    "--disable-bruteforce", is_flag=True, help="CloudHunter disable bruteforce"
)
@click.option("--open-only", is_flag=True, help="CloudHunter show only open buckets")
@click.option("--crawl-deep", type=int, default=1, help="CloudHunter crawl depth")
@click.option(
    "--subfinder", is_flag=True, help="Run subfinder for subdomain enumeration"
)
@click.option("--dnsx", is_flag=True, help="Run dnsx for DNS resolution")
@click.option("--cdncheck", is_flag=True, help="Run CDNCheck for detection")
@click.option("--nuclei", is_flag=True, help="Run nuclei for vulnerability scanning")
@click.option("--metabigor", is_flag=True, help="Run metabigor for reconnaissance")
@click.option("--shodan", is_flag=True, help="Query Shodan API for intelligence")
@click.option("--fofa", is_flag=True, help="Query FOFA API for intelligence")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis")
@click.option("--threads", type=int, default=50, help="Number of threads")
@click.option(
    "--format",
    "format_type",
    type=click.Choice(["rich", "json", "table"]),
    default="rich",
    help="Output format",
)
@click.option("--save", help="Save results to file")
@click.option("--store-db", is_flag=True, help="Store results in database")
@click.option("--program", help="Program name for database storage")
@click.option("--output-dir", default="cdncli_output", help="Output directory")
@click.option("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
@click.option("--tor", is_flag=True, help="Use Tor proxy")
@click.option("--burp", is_flag=True, help="Use Burp Suite proxy")
@click.option("--verbose", is_flag=True, help="Verbose output")
@click.option("--resume", is_flag=True, help="Resume from previous session")
@click.option("--resume-stats", is_flag=True, help="Display resume statistics")
@click.option("--resume-clear", is_flag=True, help="Clear resume state and exit")
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option("--cache-dir", default="cdn_cache", help="Directory for cache storage")
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
def cdncli(
    domain,
    ip,
    check_cdn,
    bypass_passive,
    bypass_active,
    bypass_all,
    passive_all,
    cloudhunter,
    permutations_file,
    services,
    write_test,
    base_only,
    disable_bruteforce,
    open_only,
    crawl_deep,
    subfinder,
    dnsx,
    cdncheck,
    nuclei,
    metabigor,
    shodan,
    fofa,
    ai,
    threads,
    format_type,
    save,
    store_db,
    program,
    output_dir,
    proxy,
    tor,
    burp,
    verbose,
    resume,
    resume_stats,
    resume_clear,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """🌐 CDNCli - Advanced CDN Fingerprinting & Cloud Storage Discovery Tool"""

    # Initialize cache manager if caching is enabled
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = CDNCacheManager(cache_dir=cache_dir, ttl_hours=cache_max_age)

    # Handle cache operations
    if cache_stats:
        if cache_manager:
            stats = cache_manager.get_cache_stats()
            console.print(
                Panel(
                    f"📊 CDN Cache Statistics\n\n"
                    f"Hit Rate: [green]{stats['hit_rate_percent']}%[/green] "
                    f"({stats['hits']}/{stats['total_requests']} requests)\n"
                    f"Cache Files: {stats['cache_files']}\n"
                    f"Total Size: {stats['total_size_mb']} MB\n"
                    f"Cache Directory: {stats['cache_dir']}\n"
                    f"TTL: {stats['ttl_hours']} hours",
                    title="🚀 CDN Cache Performance",
                    border_style="cyan",
                )
            )
        else:
            console.print(
                "[yellow]Cache not enabled. Use --cache to enable caching.[/yellow]"
            )
        return

    if clear_cache:
        if cache_manager:
            cache_manager.clear_cache()
            console.print("[green]✅ CDN cache cleared successfully[/green]")
        return

    # Domain is required for analysis operations
    if not domain:
        console.print("[red]Error: --domain is required for analysis operations[/red]")
        return

    # Configure proxy
    if tor:
        os.environ["http_proxy"] = "socks5h://127.0.0.1:9050"
        os.environ["https_proxy"] = "socks5h://127.0.0.1:9050"
    elif burp:
        os.environ["http_proxy"] = "http://127.0.0.1:8080"
        os.environ["https_proxy"] = "http://127.0.0.1:8080"
    elif proxy:
        os.environ["http_proxy"] = proxy
        os.environ["https_proxy"] = proxy

    # Build options
    options = {
        "verbose": verbose,
        "output_dir": output_dir,
        "threads": threads,
        "permutations_file": permutations_file,
        "services": services,
        "write_test": write_test,
        "base_only": base_only,
        "disable_bruteforce": disable_bruteforce,
        "open_only": open_only,
        "crawl_deep": crawl_deep,
        "cdncheck": check_cdn or cdncheck or passive_all,
        "subfinder": subfinder or passive_all,
        "dnsx": dnsx or passive_all,
        "cloudhunter": cloudhunter,
        "nuclei": nuclei,
        "metabigor": metabigor,
        "shodan": shodan,
        "fofa": fofa,
        "bypass": bypass_passive or bypass_active or bypass_all,
        "ai": ai,
    }

    # Initialize analyzer
    analyzer = CDNAnalyzer(domain, options, cache_manager)

    # Handle resume operations
    if resume_clear:
        analyzer.clear_resume_state()
        console.print("[green]Resume state cleared successfully[/green]")
        return

    if resume_stats:
        analyzer.display_resume_stats()
        return

    if resume:
        if analyzer.load_resume_state():
            console.print(
                Panel(
                    f"🔄 Resuming CDNCli Analysis for [bold cyan]{domain}[/bold cyan]\n"
                    f"Previous session: {analyzer.results.get('timestamp', 'Unknown')}\n"
                    f"Completed steps: {analyzer.results['stats'].get('steps_completed', 0)}/{analyzer.results['stats'].get('steps_total', 0)}",
                    title="Resume Mode",
                    border_style="yellow",
                )
            )

    # Header
    console.print(
        Panel(
            f"🌐 CDNCli Analysis for [bold cyan]{domain}[/bold cyan]\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Mode: {'Resume' if resume and analyzer.resume_file.exists() else 'Fresh Start'}",
            title="CDN Fingerprinting & Cloud Storage Discovery",
            border_style="blue",
        )
    )

    try:
        # Run analysis
        analyzer.run_full_analysis()

        # Display results
        display_results(analyzer.results, format_type)

        # Save results
        if save:
            save_path = Path(save)
            with open(save_path, "w") as f:
                json.dump(analyzer.results, f, indent=2)
            console.print(f"[green]Results saved to {save_path}[/green]")

        # Store to database
        if store_db:
            analyzer.store_to_database(program)

        # Show summary
        console.print(
            Panel(
                f"✅ Analysis Complete\n"
                f"CDN Detected: {'Yes' if analyzer.results['cdn_detected'] else 'No'}\n"
                f"Cloud Buckets: {len(analyzer.results['cloud_buckets'])}\n"
                f"Subdomains: {len(analyzer.results['subdomains'])}\n"
                f"Tools Used: {', '.join(analyzer.results['tools_used'])}",
                title="Summary",
                border_style="green",
            )
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cdncli()
