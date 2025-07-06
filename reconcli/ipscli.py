#!/usr/bin/env python3
"""
ReconCLI IP Analysis Module

Advanced IP reconnaissance using multiple sources (ipinfo.io, uncover, shodan) with
resume functionality, ASN mapping, geolocation analysis, and professional reporting.
"""

import sys
import os
import json
import click
import subprocess
import socket
import ipaddress
import requests
import re
from datetime import datetime
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import time

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
        f.write(f"# Uncover Summary\n\n")
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
                except Exception as e:
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


def scan_ips(ip_list, scan_type="rustscan", port_list_path=None, proxy=None):
    """Scan IPs for open ports using specified scanner"""
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
    else:
        results = {"info": f"Scan type '{scan_type}' not implemented."}

    if errors:
        with open("errors.log", "a") as errlog:
            for line in errors:
                errlog.write(line + "\n")

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
        f.write(f"## 📊 Executive Summary\n")
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
            f.write(f"## 🌍 Geographic Distribution\n")
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
            f.write(f"## ☁️ Cloud Infrastructure\n")
            for provider, count in cloud_providers.most_common():
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{provider.upper()}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Tag Analysis
        if tags_counter:
            f.write(f"## 🏷️ IP Classification\n")
            for tag, count in tags_counter.most_common(15):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{tag}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Port Analysis
        if port_counter:
            f.write(f"## 🔌 Port Analysis\n")
            f.write(f"### Most Common Open Ports\n")
            for port, count in port_counter.most_common(15):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **Port {port}:** {count} hosts ({percentage:.1f}%)\n")
            f.write("\n")

        # Service Analysis
        if service_counter:
            f.write(f"### Service Distribution\n")
            for service, count in service_counter.most_common():
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{service}:** {count} hosts ({percentage:.1f}%)\n")
            f.write("\n")

        # Top ASNs
        if asns:
            f.write(f"## 🏢 Top Organizations (ASNs)\n")
            asn_counter = Counter()
            for ip, data in enriched_data.items():
                if isinstance(data, dict) and "org" in data:
                    asn_counter[data["org"]] += 1

            for asn, count in asn_counter.most_common(10):
                percentage = (count / len(ip_list)) * 100
                f.write(f"- **{asn}:** {count} IPs ({percentage:.1f}%)\n")
            f.write("\n")

        # Sample Data
        f.write(f"## 📋 Sample IP Data\n")
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
                        f.write(f"- **CDN:** Yes\n")
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
        f.write(f"## 🔒 Security Considerations\n")
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
            f"- **High-Value Targets:** Look for government, education, or unique ASNs\n"
        )
        f.write(f"- **Scan Responsibly:** Respect rate limits and terms of service\n")


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
):
    """
    Advanced IP Analysis and Reconnaissance
    
    Comprehensive IP intelligence gathering using multiple sources with geolocation,
    ASN mapping, cloud detection, port scanning, and professional reporting.
    
    Examples:
        # Basic IP enrichment and analysis
        reconcli ipscli --input ips.txt --enrich --verbose
        
        # Full analysis with port scanning and cloud detection
        reconcli ipscli --input subdomains_resolved.txt --enrich --scan rustscan \
          --filter-cdn --markdown --verbose
        
        # Expand CIDR ranges and analyze with uncover
        reconcli ipscli --input cidrs.txt --cidr-expand --enrich \
          --use-uncover --uncover-engine shodan
        
        # Filter analysis by geography and cloud providers  
        reconcli ipscli --input ips.txt --enrich --filter-country US \
          --filter-cloud aws,gcp --json
        
        # Resume interrupted analysis
        reconcli ipscli --resume --verbose
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        def vprint(*args, **kwargs):
            if verbose and not silent:
                print(*args, **kwargs, file=sys.stderr)

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
                ports_data = scan_ips(ip_list, scan, port_list, proxy)
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
                }
                save_json(analysis_result, json_path)
                if not silent:
                    vprint(f"[+] JSON results saved to: {json_path}")

            vprint("[*] Generating markdown summary...")
            generate_markdown_summary(ip_list, output_dir, ports_data)
            update_resume(output_dir)

            if not silent:
                vprint(f"[✓] Analysis completed! Results in: {output_dir}")
                if enrich:
                    vprint(f"    - Enriched data: ips_enriched.json")
                if scan:
                    vprint(f"    - Port scan data: ips_ports.json")
                vprint(f"    - Summary report: ips_summary.md")

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
