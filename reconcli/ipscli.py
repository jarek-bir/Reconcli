#!/usr/bin/env python3
"""
ReconCLI IP Analysis Module

Advanced IP reconnaissance using multiple sources (ipinfo.io, uncover, shodan) with
resume functionality, ASN mapping, geolocation analysis, and professional reporting.
"""

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import click
import requests
from tqdm import tqdm

# CDN and Cloud provider IP ranges for filtering
CDN_RANGES = [
    "104.16.",
    "104.17.",
    "104.18.",
    "104.19.",
    "104.20.",
    "104.21.",
    "172.64.",
    "172.65.",
    "172.66.",
    "172.67.",
    "185.60.",
    "23.21.",
    "23.22.",
    "23.23.",
    "13.32.",
    "13.35.",
]

CLOUD_RANGES = [
    # AWS
    ("13.32.0.0/15", "aws"),
    ("13.35.0.0/16", "aws"),
    ("18.130.0.0/16", "aws"),
    ("52.0.0.0/8", "aws"),
    ("54.0.0.0/8", "aws"),
    # Google Cloud
    ("8.34.208.0/20", "gcp"),
    ("8.35.192.0/20", "gcp"),
    ("23.236.48.0/20", "gcp"),
    ("23.251.128.0/19", "gcp"),
    # Azure
    ("13.64.0.0/11", "azure"),
    ("20.0.0.0/8", "azure"),
    ("40.64.0.0/10", "azure"),
    # DigitalOcean
    ("165.227.0.0/16", "digitalocean"),
    ("157.245.0.0/16", "digitalocean"),
    ("68.183.0.0/16", "digitalocean"),
]


class IPScanCacheManager:
    """Cache manager for IP scan results"""

    def __init__(self, cache_dir="ip_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "ip_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}

    def _generate_cache_key(self, scan_type, ip_list_hash, parameters=""):
        """Generate SHA256 cache key from scan parameters"""
        key_data = f"{scan_type}:{ip_list_hash}:{parameters}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _get_ip_list_hash(self, ip_list):
        """Generate hash from IP list"""
        ip_str = "|".join(sorted(ip_list))
        return hashlib.sha256(ip_str.encode()).hexdigest()

    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, "w") as f:
                json.dump(index, f, indent=2)
        except:
            pass

    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or "timestamp" not in cache_entry:
            return False

        entry_time = cache_entry["timestamp"]
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds

    def get_cached_result(
        self, scan_type, ip_list, parameters="", max_age_seconds=86400
    ):
        """Retrieve cached scan result if available and valid"""
        self.stats["total_requests"] += 1
        ip_hash = self._get_ip_list_hash(ip_list)
        cache_key = self._generate_cache_key(scan_type, ip_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"

        index = self._load_index()

        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, "r") as f:
                        cached_data = json.load(f)

                    self.stats["hits"] += 1
                    return cached_data.get("result")
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass

        self.stats["misses"] += 1
        return None

    def store_result(self, scan_type, ip_list, result, parameters=""):
        """Store scan result in cache"""
        ip_hash = self._get_ip_list_hash(ip_list)
        cache_key = self._generate_cache_key(scan_type, ip_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"

        cache_data = {
            "result": result,
            "scan_type": scan_type,
            "ip_hash": ip_hash,
            "parameters": parameters,
            "timestamp": time.time(),
        }

        try:
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            # Update index
            index = self._load_index()
            index[cache_key] = {
                "timestamp": time.time(),
                "scan_type": scan_type,
                "ip_hash": ip_hash,
                "parameters": parameters,
            }
            self._save_index(index)

        except Exception as e:
            pass  # Fail silently on cache storage errors

    def clear_cache(self):
        """Clear all cached results"""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False

    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size
            for key in index.keys()
            if (self.cache_dir / f"{key}.json").exists()
        )

        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100

        return {
            "total_entries": len(index),
            "cache_size_mb": round(total_size / (1024 * 1024), 2),
            "hit_rate_percent": round(hit_rate, 1),
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "total_requests": self.stats["total_requests"],
        }


class AICacheManager:
    """Cache manager for AI-powered analysis results"""

    def __init__(self, cache_dir="ai_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "ai_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}

    def _generate_cache_key(self, analysis_type, input_data_hash, parameters=""):
        """Generate SHA256 cache key from AI analysis parameters"""
        key_data = f"{analysis_type}:{input_data_hash}:{parameters}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _get_data_hash(self, data):
        """Generate hash from input data"""
        if isinstance(data, (list, tuple)):
            data_str = "|".join(str(item) for item in data)
        else:
            data_str = str(data)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, "w") as f:
                json.dump(index, f, indent=2)
        except:
            pass

    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or "timestamp" not in cache_entry:
            return False

        entry_time = cache_entry["timestamp"]
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds

    def get_cached_analysis(
        self, analysis_type, input_data, parameters="", max_age_seconds=86400
    ):
        """Retrieve cached AI analysis result if available and valid"""
        self.stats["total_requests"] += 1
        input_hash = self._get_data_hash(input_data)
        cache_key = self._generate_cache_key(analysis_type, input_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"

        index = self._load_index()

        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, "r") as f:
                        cached_data = json.load(f)

                    self.stats["hits"] += 1
                    return {
                        "result": cached_data.get("result"),
                        "analysis_type": cached_data.get("analysis_type"),
                        "cached": True,
                        "cache_timestamp": cache_entry["timestamp"],
                    }
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass

        self.stats["misses"] += 1
        return None

    def store_analysis(self, analysis_type, input_data, result, parameters=""):
        """Store AI analysis result in cache"""
        input_hash = self._get_data_hash(input_data)
        cache_key = self._generate_cache_key(analysis_type, input_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"

        cache_data = {
            "result": result,
            "analysis_type": analysis_type,
            "input_hash": input_hash,
            "parameters": parameters,
            "timestamp": time.time(),
        }

        try:
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            # Update index
            index = self._load_index()
            index[cache_key] = {
                "timestamp": time.time(),
                "analysis_type": analysis_type,
                "input_hash": input_hash,
                "parameters": parameters,
            }
            self._save_index(index)

        except Exception as e:
            pass  # Fail silently on cache storage errors

    def clear_cache(self):
        """Clear all cached AI analysis results"""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False

    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size
            for key in index.keys()
            if (self.cache_dir / f"{key}.json").exists()
        )

        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100

        return {
            "total_entries": len(index),
            "cache_size_mb": round(total_size / (1024 * 1024), 2),
            "hit_rate_percent": round(hit_rate, 1),
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "total_requests": self.stats["total_requests"],
        }


CLOUD_RANGES = [
    # AWS
    ("13.32.0.0/15", "aws"),
    ("13.35.0.0/16", "aws"),
    ("18.130.0.0/16", "aws"),
    ("52.0.0.0/8", "aws"),
    ("54.0.0.0/8", "aws"),
    # Google Cloud
    ("8.34.208.0/20", "gcp"),
    ("8.35.192.0/20", "gcp"),
    ("23.236.48.0/20", "gcp"),
    ("23.251.128.0/19", "gcp"),
    # Azure
    ("13.64.0.0/11", "azure"),
    ("20.0.0.0/8", "azure"),
    ("40.64.0.0/10", "azure"),
    # DigitalOcean
    ("165.227.0.0/16", "digitalocean"),
    ("157.245.0.0/16", "digitalocean"),
    ("68.183.0.0/16", "digitalocean"),
]

# Common web and service ports for IP analysis
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    9000,
    9200,
]


def is_cdn_ip(ip):
    """Check if IP belongs to known CDN ranges"""
    return any(ip.startswith(prefix) for prefix in CDN_RANGES)


def get_cloud_provider(ip):
    """Detect cloud provider from IP"""
    try:
        ip_obj = ipaddress.ip_address(ip.split(":")[0])
        for cidr, provider in CLOUD_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                return provider
    except ValueError:
        pass
    return None


def validate_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str.split(":")[0])  # Handle IP:port format
        return True
    except ValueError:
        return False


def expand_cidrs(ip_list):
    """Expand CIDR notation to individual IPs (limited to /24 and larger)"""
    expanded_ips = []
    for item in ip_list:
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                if network.num_addresses > 256:
                    print(
                        f"[!] CIDR {item} too large (>{network.num_addresses} IPs). Use /24 or smaller."
                    )
                    continue
                expanded_ips.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"[!] Invalid CIDR format: {item}")
                if validate_ip(item):
                    expanded_ips.append(item)
        else:
            if validate_ip(item):
                expanded_ips.append(item)
    return expanded_ips


def filter_cdn_ips(ip_list):
    """Filter out known CDN IP addresses"""
    return [ip for ip in ip_list if not is_cdn_ip(ip)]


def detect_asn_from_ip(ip_list):
    """Detect most common ASN from IP list sample"""
    if not ip_list:
        return None

    # Sample first few IPs to detect ASN
    sample_ips = ip_list[: min(5, len(ip_list))]
    asn_counter = Counter()

    for ip in sample_ips:
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                org = data.get("org", "")
                if org and "AS" in org:
                    asn = org.split()[0]  # Extract ASN number
                    asn_counter[asn] += 1
        except Exception:
            continue

    if asn_counter:
        return asn_counter.most_common(1)[0][0]
    return None


def extract_ips_from_uncover_json(json_file, verbose=False):
    """Extract IPs from uncover JSON output"""
    ips = []
    sources = {}

    try:
        with open(json_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    ip = data.get("ip")
                    source = data.get("source", "unknown")
                    if ip and validate_ip(ip):
                        ips.append(ip)
                        sources[ip] = source
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        if verbose:
            print(f"[!] Error reading uncover JSON: {e}")

    return list(set(ips)), sources


def run_uncover(query, engine=None, verbose=False):
    """Run uncover tool with specified query"""
    ips = []
    try:
        cmd = ["uncover", "-q", query, "-silent"]
        if engine:
            cmd.extend(["-e", engine])

        if verbose:
            print(f"[*] Running: {' '.join(cmd)}")

        output = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=60
        ).decode()
        for line in output.strip().splitlines():
            if line.strip() and validate_ip(line.strip()):
                ips.append(line.strip())
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Uncover timeout")
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"[!] Uncover error: {e}")
    except Exception as e:
        if verbose:
            print(f"[!] Uncover unexpected error: {e}")

    return list(set(ips))


def generate_uncover_summary(sources, query, output_dir):
    """Generate summary of uncover results"""
    summary_path = os.path.join(output_dir, "uncover_summary.md")

    engine_counts = Counter(sources.values())

    with open(summary_path, "w") as f:
        f.write("# Uncover Summary\n\n")
        f.write(f"**Query:** `{query}`\n")
        f.write(f"**Total IPs:** {len(sources)}\n")
        f.write(f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n")

        f.write("## Sources\n")
        for engine, count in engine_counts.most_common():
            f.write(f"- **{engine}:** {count} IPs\n")

        f.write("\n## Sample IPs by Source\n")
        for engine in engine_counts.keys():
            engine_ips = [ip for ip, src in sources.items() if src == engine][:5]
            f.write(f"\n### {engine}\n")
            for ip in engine_ips:
                f.write(f"- {ip}\n")


def get_ip_tags(ip_data):
    """Generate tags for IP based on enrichment data"""
    tags = []

    # Basic classification
    if ip_data.get("bogon"):
        tags.append("bogon")

    # Geographic tags
    country = ip_data.get("country")
    if country:
        tags.append(f"country-{country.lower()}")

    region = ip_data.get("region")
    if region:
        tags.append(f"region-{region.lower().replace(' ', '-')}")

    # Organization/ASN tags
    org = ip_data.get("org", "")
    if org:
        org_lower = org.lower()
        if (
            "cloud" in org_lower
            or "amazon" in org_lower
            or "google" in org_lower
            or "microsoft" in org_lower
        ):
            tags.append("cloud")
        if "hosting" in org_lower or "server" in org_lower:
            tags.append("hosting")
        if "telecom" in org_lower or "isp" in org_lower:
            tags.append("isp")
        if "university" in org_lower or "education" in org_lower:
            tags.append("education")
        if "government" in org_lower or "gov" in org_lower:
            tags.append("government")

    # Cloud provider detection
    cloud_provider = get_cloud_provider(ip_data.get("ip", ""))
    if cloud_provider:
        tags.append("cloud")
        tags.append(cloud_provider)

    # CDN detection
    if is_cdn_ip(ip_data.get("ip", "")):
        tags.append("cdn")

    # Hostname patterns
    hostname = ip_data.get("hostname") or ip_data.get("ptr") or ""
    if hostname:
        hostname_lower = hostname.lower()
        if "mail" in hostname_lower or "smtp" in hostname_lower:
            tags.append("mail-server")
        if "web" in hostname_lower or "www" in hostname_lower:
            tags.append("web-server")
        if "db" in hostname_lower or "database" in hostname_lower:
            tags.append("database")
        if "api" in hostname_lower:
            tags.append("api")
        if "vpn" in hostname_lower:
            tags.append("vpn")

    # Security indicators
    if ip_data.get("honeypot"):
        tags.append("honeypot")

    # Privacy/security services
    if ip_data.get("privacy") or "privacy" in org.lower():
        tags.append("privacy")

    return sorted(list(set(tags)))


def ai_analyze_ip_patterns(
    ip_list, enriched_data, ai_cache_manager=None, max_age_seconds=86400
):
    """AI-powered analysis of IP patterns and attack surfaces"""

    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {"ip_count": len(ip_list), "sample_ips": ip_list[:50]}
        cached_result = ai_cache_manager.get_cached_analysis(
            "ip_pattern_analysis", cache_input, "", max_age_seconds
        )

        if cached_result:
            return cached_result["result"]

    # If no cache hit, run actual AI analysis
    analysis = {
        "high_value_targets": [],
        "attack_vectors": [],
        "risk_assessment": {},
        "recommendations": [],
        "patterns_detected": {},
    }

    # Analyze IP patterns
    patterns = {
        "government_ips": 0,
        "educational_ips": 0,
        "cloud_concentration": 0,
        "geographic_spread": set(),
        "suspicious_patterns": [],
        "honeypot_indicators": 0,
    }

    for ip, data in enriched_data.items():
        if not isinstance(data, dict) or "error" in data:
            continue

        # Check for high-value targets
        org = data.get("org", "").lower()
        country = data.get("country", "")
        tags = data.get("tags", [])

        if "government" in tags or "gov" in org:
            patterns["government_ips"] += 1
            analysis["high_value_targets"].append(
                {"ip": ip, "type": "government", "details": data.get("org", "")}
            )

        if "education" in tags or "university" in org:
            patterns["educational_ips"] += 1
            analysis["high_value_targets"].append(
                {"ip": ip, "type": "educational", "details": data.get("org", "")}
            )

        if "cloud" in tags:
            patterns["cloud_concentration"] += 1

        if country:
            patterns["geographic_spread"].add(country)

        if data.get("honeypot"):
            patterns["honeypot_indicators"] += 1
            patterns["suspicious_patterns"].append(f"Potential honeypot: {ip}")

    analysis["patterns_detected"] = patterns
    analysis["patterns_detected"]["geographic_spread"] = list(
        patterns["geographic_spread"]
    )

    # Risk assessment
    total_ips = len(ip_list)
    risk_score = 1.0

    if patterns["government_ips"] > 0:
        risk_score += 2.0
        analysis["attack_vectors"].append("Government infrastructure targets")

    if patterns["educational_ips"] > 0:
        risk_score += 1.5
        analysis["attack_vectors"].append("Educational institution targets")

    if patterns["cloud_concentration"] / total_ips > 0.7:
        risk_score += 1.0
        analysis["attack_vectors"].append("High cloud infrastructure concentration")

    if len(patterns["geographic_spread"]) > 10:
        risk_score += 0.5
        analysis["attack_vectors"].append("Wide geographic distribution")

    if patterns["honeypot_indicators"] > 0:
        risk_score -= 1.0  # Honeypots reduce actual risk
        analysis["recommendations"].append("Avoid detected honeypot IPs")

    analysis["risk_assessment"] = {
        "overall_score": min(risk_score, 10.0),
        "risk_level": (
            "critical"
            if risk_score > 8
            else "high" if risk_score > 6 else "medium" if risk_score > 4 else "low"
        ),
        "total_targets": total_ips,
        "high_value_count": len(analysis["high_value_targets"]),
    }

    # Generate recommendations
    if patterns["government_ips"] > 0:
        analysis["recommendations"].append(
            "Exercise extreme caution with government IPs - ensure proper authorization"
        )
    if patterns["cloud_concentration"] / total_ips > 0.5:
        analysis["recommendations"].append(
            "Consider cloud-specific attack vectors and security measures"
        )
    if len(patterns["geographic_spread"]) > 5:
        analysis["recommendations"].append(
            "Consider regional compliance and legal implications"
        )

    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("ip_pattern_analysis", cache_input, analysis)

    return analysis


def ai_classify_ip_threats(ip_data, ai_cache_manager=None, max_age_seconds=86400):
    """AI-powered threat classification for individual IPs"""

    ip = ip_data.get("ip", "")

    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {
            "ip": ip,
            "org": ip_data.get("org", ""),
            "country": ip_data.get("country", ""),
        }
        cached_result = ai_cache_manager.get_cached_analysis(
            "ip_threat_classification", cache_input, "", max_age_seconds
        )

        if cached_result:
            return cached_result["result"]

    threat_level = "low"
    threat_types = []
    confidence = 0.5

    # Analyze threat indicators
    org = ip_data.get("org", "").lower()
    country = ip_data.get("country", "")
    tags = ip_data.get("tags", [])
    hostname = ip_data.get("hostname", "") or ip_data.get("ptr", "")

    # Government/Critical Infrastructure
    if "government" in tags or any(
        keyword in org for keyword in ["gov", "military", "defense"]
    ):
        threat_level = "critical"
        threat_types.append("government_infrastructure")
        confidence = 0.9

    # Educational Institutions
    elif "education" in tags or any(
        keyword in org for keyword in ["university", "college", "school", ".edu"]
    ):
        threat_level = "high"
        threat_types.append("educational_institution")
        confidence = 0.8

    # Financial Services
    elif any(keyword in org for keyword in ["bank", "financial", "credit", "payment"]):
        threat_level = "high"
        threat_types.append("financial_services")
        confidence = 0.85

    # Healthcare
    elif any(keyword in org for keyword in ["hospital", "health", "medical", "clinic"]):
        threat_level = "high"
        threat_types.append("healthcare")
        confidence = 0.8

    # Cloud Infrastructure
    elif "cloud" in tags:
        threat_level = "medium"
        threat_types.append("cloud_infrastructure")
        confidence = 0.7

    # Hosting/VPS
    elif "hosting" in tags:
        threat_level = "medium"
        threat_types.append("hosting_provider")
        confidence = 0.6

    # CDN
    elif "cdn" in tags:
        threat_level = "low"
        threat_types.append("cdn_service")
        confidence = 0.8

    # Honeypot detection
    if ip_data.get("honeypot"):
        threat_level = "honeypot"
        threat_types.append("honeypot")
        confidence = 0.9

    # Geographic risk factors
    high_risk_countries = ["CN", "RU", "KP", "IR"]  # Example high-risk countries
    if country in high_risk_countries:
        if threat_level == "low":
            threat_level = "medium"
        threat_types.append("high_risk_geography")
        confidence = min(confidence + 0.1, 1.0)

    result = {
        "ip": ip,
        "threat_level": threat_level,
        "threat_types": threat_types,
        "confidence": confidence,
        "reasoning": f"Classification based on organization: {ip_data.get('org', 'Unknown')}, tags: {', '.join(tags)}",
    }

    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("ip_threat_classification", cache_input, result)

    return result


def ai_generate_attack_surface_report(
    ip_analysis, port_data, ai_cache_manager=None, max_age_seconds=86400
):
    """AI-powered attack surface analysis and reporting"""

    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {
            "ip_count": len(ip_analysis.get("high_value_targets", [])),
            "port_summary": len(port_data) if port_data else 0,
        }
        cached_result = ai_cache_manager.get_cached_analysis(
            "attack_surface_report", cache_input, "", max_age_seconds
        )

        if cached_result:
            return cached_result["result"]

    report = {
        "executive_summary": "",
        "key_findings": [],
        "attack_vectors": [],
        "remediation_steps": [],
        "risk_priorities": [],
    }

    # Analyze attack surface
    total_targets = ip_analysis.get("risk_assessment", {}).get("total_targets", 0)
    high_value_count = len(ip_analysis.get("high_value_targets", []))
    risk_level = ip_analysis.get("risk_assessment", {}).get("risk_level", "low")

    # Generate executive summary
    report[
        "executive_summary"
    ] = f"""
    Analysis of {total_targets} IP addresses reveals a {risk_level} risk attack surface. 
    {high_value_count} high-value targets were identified, requiring enhanced security measures.
    The geographic distribution and organizational diversity suggest a complex threat landscape.
    """

    # Key findings
    if high_value_count > 0:
        report["key_findings"].append(
            f"Identified {high_value_count} high-value targets including government and educational institutions"
        )

    patterns = ip_analysis.get("patterns_detected", {})
    if patterns.get("cloud_concentration", 0) / max(total_targets, 1) > 0.5:
        report["key_findings"].append(
            "High concentration of cloud infrastructure presents centralized attack opportunities"
        )

    if len(patterns.get("geographic_spread", [])) > 10:
        report["key_findings"].append(
            "Wide geographic distribution requires multi-jurisdictional security considerations"
        )

    # Attack vectors
    if port_data:
        common_ports = {}
        for ip, ports in port_data.items():
            if isinstance(ports, list):
                for port in ports:
                    common_ports[port] = common_ports.get(port, 0) + 1

        if 22 in common_ports:
            report["attack_vectors"].append(
                f"SSH access available on {common_ports[22]} hosts - potential for credential attacks"
            )
        if 80 in common_ports or 443 in common_ports:
            web_count = common_ports.get(80, 0) + common_ports.get(443, 0)
            report["attack_vectors"].append(
                f"Web services on {web_count} hosts - web application vulnerabilities possible"
            )
        if 3389 in common_ports:
            report["attack_vectors"].append(
                f"RDP services on {common_ports[3389]} hosts - remote access vulnerability"
            )

    # Remediation steps
    report["remediation_steps"] = [
        "Implement network segmentation to isolate high-value targets",
        "Deploy intrusion detection systems on critical infrastructure",
        "Regular security assessments and penetration testing",
        "Monitor for unusual access patterns and geographic anomalies",
    ]

    if patterns.get("honeypot_indicators", 0) > 0:
        report["remediation_steps"].append(
            "Exclude identified honeypots from target lists"
        )

    # Risk priorities
    if patterns.get("government_ips", 0) > 0:
        report["risk_priorities"].append(
            "Government infrastructure - Highest priority for protection"
        )
    if patterns.get("educational_ips", 0) > 0:
        report["risk_priorities"].append(
            "Educational institutions - High priority, sensitive data"
        )

    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("attack_surface_report", cache_input, report)

    return report


def strip_ansi(s):
    """Remove ANSI escape sequences from string"""
    return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", s)


def load_ips(input_file, resolve_from):
    """Load IPs from input file with improved error handling"""
    if not input_file:
        input_file = "subs_resolved.txt" if resolve_from == "subs" else "ips_raw.txt"

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    ips = []
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    line = strip_ansi(line.strip())
                    if not line or line.startswith(
                        "#"
                    ):  # Skip empty lines and comments
                        continue

                    if resolve_from == "subs":
                        match = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", line)
                        for ip in match:
                            try:
                                if ":" in ip:
                                    continue
                                ipaddress.ip_address(ip)
                                ips.append(ip)
                            except Exception:
                                continue
                    else:
                        ip = line.strip()
                        try:
                            if ":" in ip:
                                continue
                            ipaddress.ip_address(ip)
                            ips.append(ip)
                        except Exception:
                            # Skip invalid IP, don't crash
                            continue
                except Exception:
                    # Skip problematic lines, don't crash entire operation
                    continue
    except Exception as e:
        raise Exception(f"Error reading file {input_file}: {e}")

    # Debug output
    try:
        with open("debug_ips_loaded.txt", "w") as dbg:
            dbg.write("\n".join(ips))
    except Exception:
        pass  # Don't fail if debug file can't be written

    return list(set(ips))


def enrich_ips(ip_list, proxy=None):
    """Enrich IPs with geolocation and organization data"""
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    enriched = {}
    errors = []

    def enrich_single(ip):
        try:
            r = session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if r.status_code == 200:
                data = r.json()

                # Add reverse DNS
                ptr = None
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except Exception:
                    ptr = None
                data["ptr"] = ptr

                # Add cloud provider detection
                cloud_provider = get_cloud_provider(ip)
                if cloud_provider:
                    data["cloud_provider"] = cloud_provider

                # Add CDN detection
                data["is_cdn"] = is_cdn_ip(ip)

                # Generate tags
                data["tags"] = get_ip_tags(data)

                # Add scan timestamp
                data["scan_time"] = datetime.utcnow().isoformat()

                return ip, data, None
            else:
                return ip, {"error": f"HTTP {r.status_code}", "ip": ip}, None
        except Exception as e:
            return ip, {"error": str(e), "ip": ip}, str(e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(enrich_single, ip) for ip in ip_list]
        for future in tqdm(
            as_completed(futures), total=len(ip_list), desc="Enriching IPs"
        ):
            ip, data, err = future.result()
            enriched[ip] = data
            if err:
                errors.append(f"{ip}: {err}")

    if errors:
        print(f"[!] {len(errors)} enrichment errors (check errors.log)")
        with open("errors.log", "a") as errlog:
            errlog.write(f"\n--- IP Enrichment Errors {datetime.utcnow()} ---\n")
            for line in errors:
                errlog.write(line + "\n")

    return enriched


def scan_ips(
    ip_list,
    scan_type="rustscan",
    port_list_path=None,
    proxy=None,
    cache_manager=None,
    max_age_seconds=86400,
):
    """Scan IPs for open ports using specified scanner"""

    # Try to get cached result if cache is enabled
    if cache_manager:
        scan_params = f"{scan_type}:{port_list_path or 'default'}:{proxy or 'no_proxy'}"
        cached_result = cache_manager.get_cached_result(
            "port_scan", ip_list, scan_params, max_age_seconds
        )

        if cached_result:
            return cached_result

    # Default web and service ports - focused on common services
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        81,
        110,
        135,
        139,
        143,
        280,
        300,
        443,
        445,
        583,
        591,
        593,
        832,
        981,
        993,
        995,
        1010,
        1099,
        1311,
        1433,
        1521,
        2082,
        2087,
        2095,
        2096,
        2480,
        3000,
        3128,
        3306,
        3333,
        3389,
        4243,
        4444,
        4445,
        4567,
        4711,
        4712,
        4993,
        5000,
        5104,
        5108,
        5280,
        5281,
        5432,
        5601,
        5800,
        5900,
        6379,
        6543,
        7000,
        7001,
        7002,
        7396,
        7474,
        8000,
        8001,
        8008,
        8009,
        8014,
        8042,
        8060,
        8069,
        8080,
        8081,
        8083,
        8088,
        8090,
        8091,
        8095,
        8118,
        8123,
        8172,
        8181,
        8222,
        8243,
        8280,
        8281,
        8333,
        8337,
        8443,
        8500,
        8530,
        8531,
        8834,
        8880,
        8887,
        8888,
        8983,
        9000,
        9001,
        9043,
        9060,
        9080,
        9090,
        9091,
        9092,
        9200,
        9443,
        9502,
        9800,
        9981,
        10000,
        10250,
        10443,
        11371,
        12043,
        12046,
        12443,
        15672,
        16080,
        17778,
        18091,
        18092,
        20720,
        27017,
        28017,
        32000,
        55440,
        55672,
    ]
    if port_list_path:
        try:
            with open(port_list_path) as f:
                ports = [int(line.strip()) for line in f if line.strip().isdigit()]
        except Exception as e:
            print(f"[!] Failed to load custom port list: {e}")

    results = {}
    errors = []

    if scan_type == "simple":

        def scan_single(ip):
            open_ports = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.5)  # zamiast 0.5
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    continue
            return ip, open_ports, None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_single, ip) for ip in ip_list]
            for future in tqdm(
                as_completed(futures), total=len(ip_list), desc="Scanning IPs"
            ):
                ip, open_ports, err = future.result()
                results[ip] = open_ports
                if not open_ports:
                    results[ip] = {"status": "no open ports"}
                if not open_ports:
                    with open("empty_ports.txt", "a") as ef:
                        ef.write(ip + "\n")
                if err:
                    errors.append(f"{ip}: {err}")

    elif scan_type == "rustscan":
        port_arg = ",".join(map(str, ports))
        for ip in tqdm(ip_list, desc="Rustscan IPs"):
            try:
                cmd = [
                    "rustscan",
                    "--ulimit",
                    "5000",
                    "-a",
                    ip,
                    "-p",
                    port_arg,
                    "--no-config",
                ]
                # DEBUG: Logging rustscan output
                with open("debug_scan_output.log", "a") as dbg:
                    dbg.write(f"\n[{ip}]\n")
                output = subprocess.check_output(
                    cmd,
                    stderr=subprocess.DEVNULL,
                ).decode()
                open_ports = []
                for line in output.splitlines():
                    if "Open" in line and ":" in line:
                        match = re.search(r":(\d+)", line)
                        if match:
                            port = int(match.group(1))
                            open_ports.append(port)
                results[ip] = open_ports
                if not open_ports:
                    results[ip] = {"status": "no open ports"}
                if not open_ports:
                    with open("empty_ports.txt", "a") as ef:
                        ef.write(ip + "\n")
            except Exception as e:
                results[ip] = [f"error: {str(e)}"]

    elif scan_type == "masscan":
        port_arg = ",".join(map(str, ports))
        for ip in tqdm(ip_list, desc="Masscan IPs"):
            try:
                cmd = [
                    "masscan",
                    ip,
                    "-p",
                    port_arg,
                    "--rate",
                    "1000",
                    "--wait",
                    "2",
                    "--output-format",
                    "list",
                ]

                # Add proxy support for masscan if available
                if proxy:
                    print(
                        f"[!] Warning: Masscan doesn't support HTTP proxy. Proxy {proxy} ignored."
                    )

                output = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, timeout=300  # 5 minute timeout
                ).decode()

                open_ports = []
                for line in output.splitlines():
                    if "open" in line.lower() and ip in line:
                        # Parse masscan output: "open tcp 80 1.2.3.4"
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                port = int(parts[2])
                                open_ports.append(port)
                            except ValueError:
                                continue

                results[ip] = open_ports
                if not open_ports:
                    results[ip] = {"status": "no open ports"}
                    with open("empty_ports.txt", "a") as ef:
                        ef.write(ip + "\n")

            except subprocess.TimeoutExpired:
                results[ip] = {"error": "scan timeout"}
                errors.append(f"{ip}: scan timeout")
            except subprocess.CalledProcessError as e:
                results[ip] = {"error": f"masscan failed: {e}"}
                errors.append(f"{ip}: masscan failed")
            except Exception as e:
                results[ip] = {"error": str(e)}
                errors.append(f"{ip}: {str(e)}")

    elif scan_type == "nmap":
        port_arg = ",".join(map(str, ports))
        for ip in tqdm(ip_list, desc="Nmap IPs"):
            try:
                cmd = [
                    "nmap",
                    "-p",
                    port_arg,
                    "-T4",
                    "--open",
                    "--host-timeout",
                    "300s",
                    ip,
                ]

                if proxy:
                    print(
                        f"[!] Warning: Nmap proxy support limited. Proxy {proxy} may not work."
                    )

                output = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, timeout=600  # 10 minute timeout
                ).decode()

                open_ports = []
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        # Parse nmap output: "80/tcp   open  http"
                        port_match = re.match(r"(\d+)/tcp", line)
                        if port_match:
                            port = int(port_match.group(1))
                            open_ports.append(port)

                results[ip] = open_ports
                if not open_ports:
                    results[ip] = {"status": "no open ports"}
                    with open("empty_ports.txt", "a") as ef:
                        ef.write(ip + "\n")

            except subprocess.TimeoutExpired:
                results[ip] = {"error": "nmap timeout"}
                errors.append(f"{ip}: nmap timeout")
            except subprocess.CalledProcessError as e:
                results[ip] = {"error": f"nmap failed: {e}"}
                errors.append(f"{ip}: nmap failed")
            except Exception as e:
                results[ip] = {"error": str(e)}
                errors.append(f"{ip}: {str(e)}")

    else:
        results = {"info": f"Scan type '{scan_type}' not implemented."}

    if errors:
        with open("errors.log", "a") as errlog:
            for line in errors:
                errlog.write(line + "\n")

    # Store result in cache if cache is enabled
    if cache_manager:
        scan_params = f"{scan_type}:{port_list_path or 'default'}:{proxy or 'no_proxy'}"
        cache_manager.store_result("port_scan", ip_list, results, scan_params)

    return results


def map_asns(ip_list):
    asn_map = {}
    for ip in ip_list:
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                asn = data.get("org", "unknown")
                if asn not in asn_map:
                    asn_map[asn] = []
                asn_map[asn].append(ip)
        except Exception:
            continue
    return asn_map


def generate_markdown_summary(ip_list, output_dir, ports_data=None):
    """Generate comprehensive markdown summary of IP analysis"""
    summary_path = Path(output_dir) / "ips_summary.md"

    # Collect statistics
    asns = set()
    countries = set()
    cloud_providers = Counter()
    tags_counter = Counter()

    enriched_data = {}
    try:
        enriched_path = os.path.join(output_dir, "ips_enriched.json")
        if os.path.exists(enriched_path):
            with open(enriched_path) as f:
                enriched_data = json.load(f)
                for ip, data in enriched_data.items():
                    if isinstance(data, dict) and "error" not in data:
                        if "org" in data:
                            asns.add(data["org"])
                        if "country" in data:
                            countries.add(data["country"])
                        if "cloud_provider" in data:
                            cloud_providers[data["cloud_provider"]] += 1
                        if "tags" in data:
                            tags_counter.update(data["tags"])
    except Exception as e:
        print(f"[!] Error reading enriched data: {e}")

    # Port statistics
    port_counter = Counter()
    service_counter = Counter()
    if ports_data:
        for ip, open_ports in ports_data.items():
            if isinstance(open_ports, list):
                port_counter.update(open_ports)
                # Basic service detection based on ports
                if 80 in open_ports or 443 in open_ports:
                    service_counter["web-server"] += 1
                if 22 in open_ports:
                    service_counter["ssh"] += 1
                if 3306 in open_ports or 5432 in open_ports:
                    service_counter["database"] += 1
                if 25 in open_ports or 143 in open_ports:
                    service_counter["mail-server"] += 1

    with open(summary_path, "w") as f:
        f.write(
            f"# 🌐 IP Analysis Report – {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # Executive Summary
        f.write("## 📊 Executive Summary\n")
        f.write(f"- **Total IPs Analyzed:** {len(ip_list)}\n")
        f.write(f"- **Unique ASNs:** {len(asns)}\n")
        f.write(f"- **Countries Represented:** {len(countries)}\n")
        f.write(f"- **Cloud Providers:** {len(cloud_providers)}\n")
        if ports_data:
            ips_with_ports = len(
                [
                    ip
                    for ip, ports in ports_data.items()
                    if isinstance(ports, list) and ports
                ]
            )
            f.write(f"- **IPs with Open Ports:** {ips_with_ports}\n")
        f.write(f"- **Generated:** {datetime.utcnow().isoformat()}Z\n\n")

        # Geographic Distribution
        if countries:
            f.write("## 🌍 Geographic Distribution\n")
            country_counter = Counter()
            for ip, data in enriched_data.items():
                if isinstance(data, dict) and "country" in data:
                    country_counter[data["country"]] += 1

            for country, count in country_counter.most_common(10):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{country}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Cloud Infrastructure
        if cloud_providers:
            f.write("## ☁️ Cloud Infrastructure\n")
            for provider, count in cloud_providers.most_common():
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{provider.upper()}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Tag Analysis
        if tags_counter:
            f.write("## 🏷️ IP Classification\n")
            for tag, count in tags_counter.most_common(15):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{tag}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Port Analysis
        if port_counter:
            f.write("## 🔌 Port Analysis\n")
            f.write("### Most Common Open Ports\n")
            for port, count in port_counter.most_common(15):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **Port {port}:** {count} hosts ({percentage:.1f}%)\n")
            f.write("\n")

        # Service Analysis
        if service_counter:
            f.write("### Service Distribution\n")
            for service, count in service_counter.most_common():
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{service}:** {count} hosts ({percentage:.1f}%)\n")
            f.write("\n")

        # Top ASNs
        if asns:
            f.write("## 🏢 Top Organizations (ASNs)\n")
            asn_counter = Counter()
            for ip, data in enriched_data.items():
                if isinstance(data, dict) and "org" in data:
                    asn_counter[data["org"]] += 1

            for asn, count in asn_counter.most_common(10):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{asn}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Sample Data
        f.write("## 📋 Sample IP Data\n")
        sample_ips = list(ip_list)[:10]
        for ip in sample_ips:
            f.write(f"### {ip}\n")
            if ip in enriched_data and isinstance(enriched_data[ip], dict):
                data = enriched_data[ip]
                if "error" not in data:
                    if "city" in data and "country" in data:
                        f.write(
                            f"- **Location:** {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}\n"
                        )
                    if "org" in data:
                        f.write(f"- **Organization:** {data['org']}\n")
                    if "cloud_provider" in data:
                        f.write(
                            f"- **Cloud Provider:** {data['cloud_provider'].upper()}\n"
                        )
                    if "is_cdn" in data and data["is_cdn"]:
                        f.write("- **CDN:** Yes\n")
                    if "tags" in data and data["tags"]:
                        f.write(f"- **Tags:** {', '.join(data['tags'])}\n")
                    if (
                        ports_data
                        and ip in ports_data
                        and isinstance(ports_data[ip], list)
                        and ports_data[ip]
                    ):
                        f.write(
                            f"- **Open Ports:** {', '.join(map(str, ports_data[ip][:10]))}\n"
                        )
            f.write("\n")

        # Security Considerations
        f.write("## 🔒 Security Considerations\n")
        honeypot_count = sum(
            1
            for data in enriched_data.values()
            if isinstance(data, dict) and data.get("honeypot")
        )
        if honeypot_count > 0:
            f.write(f"- **Potential Honeypots:** {honeypot_count} detected\n")

        cdn_count = sum(
            1
            for data in enriched_data.values()
            if isinstance(data, dict) and data.get("is_cdn")
        )
        if cdn_count > 0:
            f.write(f"- **CDN IPs:** {cdn_count} identified\n")

        f.write(
            "- **High-Value Targets:** Look for government, education, or unique ASNs\n"
        )
        f.write("- **Scan Responsibly:** Respect rate limits and terms of service\n")


def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def update_resume(output_dir):
    """Update resume state with timestamp"""
    resume_file = os.path.join(output_dir, "ipscli_resume.json")
    resume_data = {"last_run": datetime.utcnow().isoformat(), "module": "ipscli"}
    with open(resume_file, "w") as f:
        json.dump(resume_data, f, indent=2)


@click.command()
@click.option("--input", "-i", help="Input file with IPs/domains (one per line)")
@click.option(
    "--resolve-from",
    type=click.Choice(["subs", "raw"]),
    default="subs",
    help="Input format: 'subs' for subdomain resolved format, 'raw' for plain IPs",
)
@click.option(
    "--enrich", is_flag=True, help="Enrich IPs with geolocation and organization data"
)
@click.option(
    "--scan",
    type=click.Choice(["naabu", "rustscan", "nmap", "masscan", "zmap", "simple"]),
    help="Port scanner to use for service discovery",
)
@click.option("--asn-map", is_flag=True, help="Generate ASN mapping for IP ranges")
@click.option(
    "--cidr-expand", is_flag=True, help="Expand CIDR ranges to individual IPs"
)
@click.option("--filter-cdn", is_flag=True, help="Filter out known CDN IP ranges")
@click.option(
    "--filter-cloud", help="Filter by cloud provider (aws,gcp,azure,digitalocean)"
)
@click.option("--filter-country", help="Filter IPs by country code (requires --enrich)")
@click.option("--filter-asn", help="Filter IPs by ASN pattern (requires --enrich)")
@click.option("--exclude-tags", help="Exclude IPs with specific tags (comma-separated)")
@click.option(
    "--filter-tags", help="Include only IPs with specific tags (comma-separated)"
)
@click.option(
    "--use-uncover", is_flag=True, help="Use uncover for additional IP discovery"
)
@click.option("--uncover-query", help="Custom uncover query (default: auto-detect ASN)")
@click.option(
    "--uncover-engine", help="Uncover engine to use (shodan,censys,fofa,etc.)"
)
@click.option("--uncover-json", help="Extract IPs from existing uncover JSON output")
# Cache Management Options
@click.option("--ip-cache", is_flag=True, help="Enable caching for IP scan results")
@click.option("--ip-cache-dir", default="ip_cache", help="Directory for IP cache files")
@click.option(
    "--ip-cache-max-age",
    type=int,
    default=86400,
    help="Cache expiration time in seconds (default: 24h)",
)
@click.option("--ip-clear-cache", is_flag=True, help="Clear all IP cached results")
@click.option("--ip-cache-stats", is_flag=True, help="Show IP cache statistics")
@click.option(
    "--ai-cache", is_flag=True, help="Enable caching for AI-powered analysis results"
)
@click.option("--ai-cache-dir", default="ai_cache", help="Directory for AI cache files")
@click.option(
    "--ai-cache-max-age",
    type=int,
    default=86400,
    help="Cache expiration time in seconds (default: 24h)",
)
@click.option("--ai-clear-cache", is_flag=True, help="Clear all AI cached results")
@click.option("--ai-cache-stats", is_flag=True, help="Show AI cache statistics")
# AI Analysis Options
@click.option(
    "--ai-mode",
    is_flag=True,
    help="Enable AI-powered IP analysis and threat assessment",
)
@click.option(
    "--ai-pattern-analysis",
    is_flag=True,
    help="AI-powered pattern analysis of IP infrastructure",
)
@click.option(
    "--ai-threat-classification",
    is_flag=True,
    help="AI-powered threat classification for individual IPs",
)
@click.option(
    "--ai-attack-surface",
    is_flag=True,
    help="Generate AI-powered attack surface analysis report",
)
@click.option(
    "--ai-confidence-threshold",
    type=float,
    default=0.6,
    help="Minimum confidence threshold for AI findings (0.0-1.0)",
)
@click.option(
    "--output-dir",
    default="output/ipscli",
    show_default=True,
    help="Directory to save results",
)
@click.option("--resume", is_flag=True, help="Resume previous incomplete analysis")
@click.option(
    "--clear-resume", is_flag=True, help="Clear previous resume state and exit"
)
@click.option(
    "--show-resume", is_flag=True, help="Show status of previous analysis and exit"
)
@click.option(
    "--proxy", help="HTTP/HTTPS proxy for API requests (e.g., http://127.0.0.1:8080)"
)
@click.option("--config", help="Load configuration from file")
@click.option("--profile", help="Use predefined analysis profile")
@click.option("--port-list", help="Custom port list file for scanning")
@click.option(
    "--threads",
    type=int,
    default=10,
    help="Number of threads for concurrent operations",
)
@click.option(
    "--timeout", type=int, default=10, help="Timeout for API requests (seconds)"
)
@click.option(
    "--verbose", is_flag=True, help="Enable verbose output with detailed progress"
)
@click.option("--json", "json_out", is_flag=True, help="Save results in JSON format")
@click.option("--markdown", is_flag=True, help="Save results in Markdown report format")
@click.option("--honeypot", is_flag=True, help="Enable honeypot detection heuristics")
@click.option("--silent", is_flag=True, help="Suppress all output except errors")
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
def ipscli(
    input,
    resolve_from,
    enrich,
    scan,
    asn_map,
    cidr_expand,
    filter_cdn,
    filter_cloud,
    filter_country,
    filter_asn,
    exclude_tags,
    filter_tags,
    use_uncover,
    uncover_query,
    uncover_engine,
    uncover_json,
    ip_cache,
    ip_cache_dir,
    ip_cache_max_age,
    ip_clear_cache,
    ip_cache_stats,
    ai_cache,
    ai_cache_dir,
    ai_cache_max_age,
    ai_clear_cache,
    ai_cache_stats,
    ai_mode,
    ai_pattern_analysis,
    ai_threat_classification,
    ai_attack_surface,
    ai_confidence_threshold,
    output_dir,
    resume,
    clear_resume,
    show_resume,
    proxy,
    config,
    profile,
    port_list,
    threads,
    timeout,
    verbose,
    json_out,
    markdown,
    honeypot,
    silent,
    store_db,
    target_domain,
    program,
):
    """
    Advanced IP Analysis and Reconnaissance

    Comprehensive IP intelligence gathering using multiple sources with geolocation,
    ASN mapping, cloud detection, port scanning, AI-powered analysis, and professional reporting.

    Examples:
        # Basic IP enrichment and analysis
        reconcli ipscli --input ips.txt --enrich --verbose

        # Full analysis with port scanning, cloud detection, and AI
        reconcli ipscli --input subdomains_resolved.txt --enrich --scan rustscan \
          --filter-cdn --markdown --ai-mode --verbose

        # Masscan port scanning with caching
        reconcli ipscli --input ips.txt --scan masscan --ip-cache \
          --port-list custom_ports.txt

        # AI-powered threat analysis with caching
        reconcli ipscli --input ips.txt --enrich --ai-threat-classification \
          --ai-cache --ai-confidence-threshold 0.8

        # Expand CIDR ranges and analyze with uncover and AI
        reconcli ipscli --input cidrs.txt --cidr-expand --enrich \
          --use-uncover --uncover-engine shodan --ai-attack-surface

        # Filter analysis by geography, cloud providers, and AI patterns
        reconcli ipscli --input ips.txt --enrich --filter-country US \
          --filter-cloud aws,gcp --ai-pattern-analysis --json

        # Resume interrupted analysis with cache
        reconcli ipscli --resume --ip-cache --ai-cache --verbose
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        def vprint(*args, **kwargs):
            if verbose and not silent:
                print(*args, **kwargs, file=sys.stderr)

        # Initialize cache managers
        ip_cache_manager = None
        ai_cache_manager = None

        if ip_cache:
            ip_cache_manager = IPScanCacheManager(ip_cache_dir)
            if verbose:
                vprint(f"[*] IP cache enabled: {ip_cache_dir}")

        if ai_cache:
            ai_cache_manager = AICacheManager(ai_cache_dir)
            if verbose:
                vprint(f"[*] AI cache enabled: {ai_cache_dir}")

        # Handle cache statistics
        if ip_cache_stats:
            if ip_cache_manager:
                stats = ip_cache_manager.get_cache_stats()
                if not silent:
                    click.echo("📊 IP Cache Statistics:")
                    click.echo(f"   Total entries: {stats['total_entries']}")
                    click.echo(f"   Cache size: {stats['cache_size_mb']} MB")
                    click.echo(f"   Hit rate: {stats['hit_rate_percent']}%")
                    click.echo(f"   Hits: {stats['hits']}, Misses: {stats['misses']}")
            else:
                if not silent:
                    click.echo("⚠️ IP cache not enabled. Use --ip-cache to enable.")
            return

        if ai_cache_stats:
            if ai_cache_manager:
                stats = ai_cache_manager.get_cache_stats()
                if not silent:
                    click.echo("🤖 AI Cache Statistics:")
                    click.echo(f"   Total entries: {stats['total_entries']}")
                    click.echo(f"   Cache size: {stats['cache_size_mb']} MB")
                    click.echo(f"   Hit rate: {stats['hit_rate_percent']}%")
                    click.echo(f"   Hits: {stats['hits']}, Misses: {stats['misses']}")
            else:
                if not silent:
                    click.echo("⚠️ AI cache not enabled. Use --ai-cache to enable.")
            return

        # Handle cache clearing
        if ip_clear_cache:
            if ip_cache_manager and ip_cache_manager.clear_cache():
                if not silent:
                    click.echo("[✓] IP cache cleared.")
            else:
                if not silent:
                    click.echo("[ℹ️] No IP cache to clear.")
            return

        if ai_clear_cache:
            if ai_cache_manager and ai_cache_manager.clear_cache():
                if not silent:
                    click.echo("[✓] AI cache cleared.")
            else:
                if not silent:
                    click.echo("[ℹ️] No AI cache to clear.")
            return

        # Handle resume functionality
        resume_path = os.path.join(output_dir, "ipscli_resume.json")

        if clear_resume:
            if os.path.exists(resume_path):
                os.remove(resume_path)
                if not silent:
                    click.echo("[✓] Resume state cleared.")
            else:
                if not silent:
                    click.echo("[ℹ️] No resume state to clear.")
            return

        if show_resume:
            if os.path.exists(resume_path):
                with open(resume_path) as f:
                    data = json.load(f)
                    if not silent:
                        click.echo(
                            f"📄 Resume contains analysis from: {data.get('last_run', 'unknown')}"
                        )
            else:
                if not silent:
                    click.echo("[ℹ️] No resume file found.")
            return

        vprint("[*] Loading IPs...")
        try:
            ip_list = load_ips(input, resolve_from)
            if not ip_list:
                if not silent:
                    click.echo("[!] No valid IPs found in input file", err=True)
                sys.exit(1)
        except FileNotFoundError:
            if not silent:
                click.echo(f"[!] Input file not found: {input}", err=True)
            sys.exit(1)
        except Exception as e:
            if not silent:
                click.echo(f"[!] Error loading IPs: {e}", err=True)
            sys.exit(1)
        uncover_sources = {}

        if cidr_expand:
            vprint("[*] Expanding CIDRs...")
            ip_list = expand_cidrs(ip_list)

        if uncover_json and os.path.exists(uncover_json):
            vprint(f"[*] Extracting IPs from uncover JSON: {uncover_json}")
            uncover_ips, uncover_sources = extract_ips_from_uncover_json(
                uncover_json, verbose
            )
            ip_list.extend(uncover_ips)
            ip_list = list(set(ip_list))
            with open(os.path.join(output_dir, "uncover_ips.txt"), "w") as f:
                for ip in sorted(uncover_ips):
                    f.write(ip + "\n")
            vprint(f"[+] Extracted {len(uncover_ips)} IPs from uncover JSON")

            for engine in ["shodan", "fofa"]:
                engine_ips = [
                    ip for ip, src in uncover_sources.items() if src == engine
                ]
                if engine_ips:
                    with open(
                        os.path.join(output_dir, f"uncover_{engine}.txt"), "w"
                    ) as ef:
                        for ip in sorted(engine_ips):
                            ef.write(ip + "\n")

            generate_uncover_summary(uncover_sources, uncover_query, output_dir)

        elif use_uncover:
            if not uncover_query:
                asn_detected = detect_asn_from_ip(ip_list)
                if asn_detected:
                    uncover_query = f'asn="{asn_detected}"'
                    vprint(
                        f"[+] Detected ASN: {asn_detected} → uncover query: {uncover_query}"
                    )
        # ...existing code...

        else:
            vprint("[!] Could not detect ASN. Skipping uncover.")
            uncover_query = None

        if uncover_query:
            vprint(f"[*] Running uncover with query: {uncover_query}")
            uncover_ips = run_uncover(uncover_query, uncover_engine, verbose)
            ip_list.extend(uncover_ips)
            ip_list = list(set(ip_list))
        else:
            vprint("[!] uncover_query is missing. Skipping uncover step.")

        if filter_cdn:
            vprint("[*] Filtering CDN IPs...")
            ip_list = filter_cdn_ips(ip_list)

        if enrich:
            vprint("[*] Enriching IPs...")
            try:
                enriched_data = enrich_ips(ip_list, proxy)
            except Exception as e:
                if not silent:
                    click.echo(f"[!] Error during IP enrichment: {e}", err=True)
                if verbose:
                    import traceback

                    click.echo(traceback.format_exc(), err=True)
                sys.exit(1)

        # Apply filtering based on enrichment data
        original_count = len(ip_list)

        # Filter by country
        if filter_country:
            vprint(f"[*] Filtering IPs by country: {filter_country}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if isinstance(data, dict)
                and data.get("country", "").lower() == filter_country.lower()
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
            vprint(f"[+] Country filter: {len(ip_list)}/{original_count} IPs remaining")

        # Filter by ASN
        if filter_asn:
            vprint(f"[*] Filtering IPs by ASN: {filter_asn}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if isinstance(data, dict)
                and filter_asn.lower() in str(data.get("org", "")).lower()
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
            vprint(f"[+] ASN filter: {len(ip_list)}/{original_count} IPs remaining")

        # Filter by cloud provider
        if filter_cloud:
            cloud_providers = [p.strip().lower() for p in filter_cloud.split(",")]
            vprint(
                f"[*] Filtering IPs by cloud providers: {', '.join(cloud_providers)}"
            )
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if isinstance(data, dict)
                and data.get("cloud_provider", "").lower() in cloud_providers
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
            vprint(f"[+] Cloud filter: {len(ip_list)}/{original_count} IPs remaining")

        # Filter by tags
        if filter_tags:
            required_tags = [tag.strip().lower() for tag in filter_tags.split(",")]
            vprint(f"[*] Filtering IPs by tags: {', '.join(required_tags)}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if isinstance(data, dict)
                and any(
                    tag in [t.lower() for t in data.get("tags", [])]
                    for tag in required_tags
                )
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
            vprint(f"[+] Tag filter: {len(ip_list)}/{original_count} IPs remaining")

        # Exclude by tags
        if exclude_tags:
            excluded_tags = [tag.strip().lower() for tag in exclude_tags.split(",")]
            vprint(f"[*] Excluding IPs with tags: {', '.join(excluded_tags)}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if isinstance(data, dict)
                and not any(
                    tag in [t.lower() for t in data.get("tags", [])]
                    for tag in excluded_tags
                )
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
            vprint(f"[+] Tag exclusion: {len(ip_list)}/{original_count} IPs remaining")

        # Honeypot detection
        if honeypot:
            vprint("[*] Running honeypot detection...")
            for ip, data in enriched_data.items():
                if isinstance(data, dict):
                    ptr = data.get("ptr", "") or ""
                    hostname = data.get("hostname", "") or ""
                    org = data.get("org", "") or ""

                    # Enhanced honeypot detection heuristics
                    honeypot_indicators = [
                        "honeypot",
                        "trap",
                        "canary",
                        "decoy",
                        "bait",
                        "sensor",
                        "detector",
                        "monitor",
                        "fake",
                    ]

                    is_honeypot = any(
                        indicator in ptr.lower()
                        or indicator in hostname.lower()
                        or indicator in org.lower()
                        for indicator in honeypot_indicators
                    )

                    data["honeypot"] = is_honeypot

            honeypot_count = sum(
                1
                for data in enriched_data.values()
                if isinstance(data, dict) and data.get("honeypot")
            )
            if honeypot_count > 0:
                vprint(f"[!] Detected {honeypot_count} potential honeypots")

        save_json(enriched_data, os.path.join(output_dir, "ips_enriched.json"))

        if scan:
            vprint(f"[*] Scanning IPs (mode: {scan})...")
            try:
                ports_data = scan_ips(
                    ip_list, scan, port_list, proxy, ip_cache_manager, ip_cache_max_age
                )
                save_json(ports_data, os.path.join(output_dir, "ips_ports.json"))
            except Exception as e:
                if not silent:
                    click.echo(f"[!] Error during port scanning: {e}", err=True)
                if verbose:
                    import traceback

                    click.echo(traceback.format_exc(), err=True)
                ports_data = {}
        else:
            ports_data = {}

        # Generate outputs
        try:
            # AI Analysis
            ai_results = {}
            ai_features_used = []

            if ai_mode or ai_pattern_analysis:
                vprint("[*] Running AI pattern analysis...")
                ai_results["pattern_analysis"] = ai_analyze_ip_patterns(
                    ip_list, enriched_data, ai_cache_manager, ai_cache_max_age
                )
                ai_features_used.append("pattern_analysis")
                if verbose:
                    pattern_data = ai_results["pattern_analysis"]
                    vprint(
                        f"[+] AI detected {len(pattern_data.get('high_value_targets', []))} high-value targets"
                    )
                    vprint(
                        f"[+] Risk level: {pattern_data.get('risk_assessment', {}).get('risk_level', 'unknown')}"
                    )

            if ai_mode or ai_threat_classification:
                vprint("[*] Running AI threat classification...")
                threat_classifications = {}
                for ip, data in enriched_data.items():
                    if isinstance(data, dict) and "error" not in data:
                        classification = ai_classify_ip_threats(
                            data, ai_cache_manager, ai_cache_max_age
                        )
                        if classification["confidence"] >= ai_confidence_threshold:
                            threat_classifications[ip] = classification

                ai_results["threat_classification"] = threat_classifications
                ai_features_used.append("threat_classification")
                if verbose:
                    critical_threats = len(
                        [
                            c
                            for c in threat_classifications.values()
                            if c["threat_level"] == "critical"
                        ]
                    )
                    vprint(f"[+] AI classified {critical_threats} critical threats")

            if ai_mode or ai_attack_surface:
                vprint("[*] Generating AI attack surface report...")
                if ai_results.get("pattern_analysis"):
                    ai_results["attack_surface_report"] = (
                        ai_generate_attack_surface_report(
                            ai_results["pattern_analysis"],
                            ports_data,
                            ai_cache_manager,
                            ai_cache_max_age,
                        )
                    )
                    ai_features_used.append("attack_surface_analysis")
                    if verbose:
                        report = ai_results["attack_surface_report"]
                        vprint(
                            f"[+] AI generated attack surface report with {len(report.get('key_findings', []))} key findings"
                        )

            # Save AI results
            if ai_results:
                ai_path = os.path.join(output_dir, "ai_analysis.json")
                save_json(ai_results, ai_path)
                vprint(f"[+] AI analysis saved to: ai_analysis.json")

                # Generate AI summary markdown
                if ai_results.get("attack_surface_report"):
                    ai_md_path = os.path.join(output_dir, "ai_executive_summary.md")
                    with open(ai_md_path, "w") as f:
                        report = ai_results["attack_surface_report"]
                        f.write("# 🤖 AI-Powered Executive Summary\n\n")
                        f.write(
                            f"**Analysis Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
                        )
                        f.write(
                            f"## Executive Summary\n{report.get('executive_summary', '')}\n\n"
                        )

                        if report.get("key_findings"):
                            f.write("## 🔍 Key Findings\n")
                            for finding in report["key_findings"]:
                                f.write(f"- {finding}\n")
                            f.write("\n")

                        if report.get("attack_vectors"):
                            f.write("## ⚡ Attack Vectors\n")
                            for vector in report["attack_vectors"]:
                                f.write(f"- {vector}\n")
                            f.write("\n")

                        if report.get("remediation_steps"):
                            f.write("## 🛡️ Remediation Steps\n")
                            for step in report["remediation_steps"]:
                                f.write(f"- {step}\n")
                            f.write("\n")

                        if report.get("risk_priorities"):
                            f.write("## 🎯 Risk Priorities\n")
                            for priority in report["risk_priorities"]:
                                f.write(f"- {priority}\n")

                    vprint(
                        f"[+] AI executive summary saved to: ai_executive_summary.md"
                    )

            if json_out or not markdown:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                json_path = os.path.join(output_dir, f"ip_analysis_{timestamp}.json")
                analysis_result = {
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "total_ips": len(ip_list),
                        "analysis_options": {
                            "enrichment": enrich,
                            "scanning": scan,
                            "honeypot_detection": honeypot,
                            "ai_enabled": bool(
                                ai_mode
                                or ai_pattern_analysis
                                or ai_threat_classification
                                or ai_attack_surface
                            ),
                            "ai_features_used": ai_features_used if ai_results else [],
                            "filters_applied": bool(
                                filter_country
                                or filter_asn
                                or filter_cloud
                                or filter_tags
                                or exclude_tags
                            ),
                        },
                    },
                    "ip_list": ip_list,
                    "enriched_data": enriched_data if enrich else {},
                    "ports_data": ports_data if scan else {},
                    "ai_analysis": ai_results if ai_results else {},
                }
                save_json(analysis_result, json_path)
                if not silent:
                    vprint(f"[+] JSON results saved to: {json_path}")

            vprint("[*] Generating markdown summary...")
            generate_markdown_summary(ip_list, output_dir, ports_data)
            update_resume(output_dir)

            # Database storage
            if store_db and ip_list:
                try:
                    # Note: Database operations require separate db module
                    # from reconcli.db.operations import store_ip_scan, store_target

                    # Auto-detect target domain if not provided
                    if not target_domain and enriched_data:
                        # Try to extract organization or ASN info for domain detection
                        for ip_data in enriched_data.values():
                            org = ip_data.get("organization", "")
                            if org and "." in org:
                                target_domain = org.lower()
                                break

                    if target_domain:
                        if not silent:
                            vprint(
                                f"[!] ⚠️  Database storage feature requires database module setup"
                            )
                            vprint(f"    Target domain detected: {target_domain}")
                    else:
                        if not silent:
                            vprint(
                                "[!] ⚠️  No target domain provided or detected for database storage"
                            )

                except ImportError:
                    if not silent:
                        vprint("[!] ⚠️  Database module not available")
                except Exception as e:
                    if not silent:
                        vprint(f"[!] ❌ Database storage failed: {e}")

            if not silent:
                vprint(f"[✓] Analysis completed! Results in: {output_dir}")
                if enrich:
                    vprint("    - Enriched data: ips_enriched.json")
                if scan:
                    vprint("    - Port scan data: ips_ports.json")
                if ai_results:
                    vprint("    - AI analysis: ai_analysis.json")
                    if ai_results.get("attack_surface_report"):
                        vprint("    - AI executive summary: ai_executive_summary.md")
                vprint("    - Summary report: ips_summary.md")

                # Cache statistics
                if ip_cache_manager:
                    stats = ip_cache_manager.get_cache_stats()
                    vprint(
                        f"    - IP Cache: {stats['hit_rate_percent']}% hit rate, {stats['total_entries']} entries"
                    )
                if ai_cache_manager:
                    stats = ai_cache_manager.get_cache_stats()
                    vprint(
                        f"    - AI Cache: {stats['hit_rate_percent']}% hit rate, {stats['total_entries']} entries"
                    )

        except Exception as e:
            if not silent:
                click.echo(f"[!] Error generating output files: {e}", err=True)
            if verbose:
                import traceback

                click.echo(traceback.format_exc(), err=True)
            sys.exit(1)

    except Exception as e:
        if not silent:
            click.echo(f"[!] Fatal error in ipscli: {e}", err=True)
        if verbose:
            import traceback

            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


if __name__ == "__main__":
    ipscli()
