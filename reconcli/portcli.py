#!/usr/bin/env python3
"""
ReconCLI Port Scanning Module

Advanced port scanning using multiple scanners (naabu, rustscan, nmap) with
resume functionality, CDN detection, and professional reporting.
"""

import datetime
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import shutil
from pathlib import Path
from typing import Dict, List, Optional

import click

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
]

# Port tagging system
PORT_TAGS = {
    # Web services
    80: ["http", "web", "tcp"],
    443: ["https", "web", "ssl", "tcp"],
    8080: ["http-alt", "web", "tcp"],
    8443: ["https-alt", "web", "ssl", "tcp"],
    8000: ["http-alt", "web", "dev", "tcp"],
    8008: ["http-alt", "web", "tcp"],
    8888: ["http-alt", "web", "tcp"],
    3000: ["http-alt", "web", "dev", "tcp"],
    5000: ["http-alt", "web", "dev", "tcp"],
    9000: ["http-alt", "web", "tcp"],
    # DNS
    53: ["dns", "udp", "tcp"],
    5353: ["mdns", "dns", "udp"],
    # Email
    25: ["smtp", "mail", "tcp"],
    110: ["pop3", "mail", "tcp"],
    143: ["imap", "mail", "tcp"],
    993: ["imaps", "mail", "ssl", "tcp"],
    995: ["pop3s", "mail", "ssl", "tcp"],
    587: ["smtp", "mail", "submission", "tcp"],
    # Remote access
    22: ["ssh", "remote", "tcp"],
    23: ["telnet", "remote", "tcp"],
    3389: ["rdp", "remote", "tcp"],
    5900: ["vnc", "remote", "tcp"],
    5985: ["winrm", "remote", "tcp"],
    5986: ["winrm", "remote", "ssl", "tcp"],
    # Databases
    3306: ["mysql", "database", "tcp"],
    5432: ["postgresql", "database", "tcp"],
    1433: ["mssql", "database", "tcp"],
    1521: ["oracle", "database", "tcp"],
    6379: ["redis", "database", "tcp"],
    27017: ["mongodb", "database", "tcp"],
    # FTP
    21: ["ftp", "tcp"],
    990: ["ftps", "ftp", "ssl", "tcp"],
    # Cloud services
    6443: ["k8s-api", "cloud", "tcp"],
    2379: ["etcd", "cloud", "tcp"],
    2380: ["etcd", "cloud", "tcp"],
    8001: ["k8s-api", "cloud", "tcp"],
    10250: ["kubelet", "cloud", "tcp"],
    # Security/Management
    161: ["snmp", "mgmt", "udp"],
    162: ["snmp-trap", "mgmt", "udp"],
    623: ["ipmi", "mgmt", "udp"],
    # Other common services
    445: ["smb", "tcp"],
    139: ["netbios", "tcp"],
    135: ["rpc", "tcp"],
    111: ["rpc", "tcp"],
    2049: ["nfs", "tcp"],
    514: ["syslog", "udp"],
    123: ["ntp", "udp"],
    69: ["tftp", "udp"],
    67: ["dhcp", "udp"],
    68: ["dhcp", "udp"],
    # Development & CI/CD
    8080: ["http-alt", "web", "tcp", "jenkins"],  # Jenkins często na 8080
    8090: ["confluence", "web", "tcp"],
    7990: ["bitbucket", "web", "tcp"],
    9000: ["sonarqube", "web", "tcp"],
    8081: ["nexus", "web", "tcp"],
    8086: ["influxdb", "database", "tcp"],
    5601: ["kibana", "web", "tcp"],
    9200: ["elasticsearch", "database", "tcp"],
    9300: ["elasticsearch", "database", "tcp"],
    # Git services
    9418: ["git", "tcp"],
    2222: ["git-ssh", "remote", "tcp"],
    3000: ["gitea", "web", "dev", "tcp"],  # Gitea default
    10080: ["gitlab", "web", "tcp"],
    # Container orchestration
    2375: ["docker", "tcp"],
    2376: ["docker-tls", "ssl", "tcp"],
    4001: ["etcd-client", "cloud", "tcp"],
    10255: ["kubelet-readonly", "cloud", "tcp"],
    10256: ["kube-proxy", "cloud", "tcp"],
    # Monitoring & Observability
    9090: ["prometheus", "monitoring", "tcp"],
    3001: ["grafana", "web", "monitoring", "tcp"],
    9093: ["alertmanager", "monitoring", "tcp"],
    8125: ["statsd", "monitoring", "udp"],
    9100: ["node-exporter", "monitoring", "tcp"],
    9113: ["nginx-exporter", "monitoring", "tcp"],
    # Message queues
    5672: ["rabbitmq", "queue", "tcp"],
    15672: ["rabbitmq-mgmt", "web", "queue", "tcp"],
    9092: ["kafka", "queue", "tcp"],
    2181: ["zookeeper", "queue", "tcp"],
    # Caching & In-memory stores
    11211: ["memcached", "cache", "tcp"],
    6380: ["redis-alt", "database", "tcp"],
    # Web servers & proxies
    8443: ["https-alt", "web", "ssl", "tcp", "tomcat"],
    9443: ["https-alt", "web", "ssl", "tcp"],
    8009: ["ajp", "web", "tcp"],  # Apache JServ Protocol
    # Security & Auth
    389: ["ldap", "auth", "tcp"],
    636: ["ldaps", "auth", "ssl", "tcp"],
    88: ["kerberos", "auth", "tcp"],
    749: ["kerberos-admin", "auth", "tcp"],
    # Backup & File sharing
    873: ["rsync", "tcp"],
    2049: ["nfs", "tcp"],
    548: ["afp", "tcp"],  # Apple Filing Protocol
    # Gaming & Entertainment
    25565: ["minecraft", "game", "tcp"],
    27015: ["steam", "game", "tcp"],
    7777: ["game-server", "game", "tcp"],
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


def is_cdn_ip(ip):
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


def get_port_tags(port):
    """Get tags for a specific port"""
    tags = PORT_TAGS.get(port, ["unknown"])

    # Add production/staging hints based on common patterns
    if port in [80, 443, 8080, 8443]:
        if port in [80, 443]:
            tags.append("prod")
        else:
            tags.append("staging")

    # Add development hints
    if port in [3000, 5000, 8000, 9000]:
        tags.append("dev")

    return tags


def get_service_name(port):
    """Get human-readable service name"""
    service_names = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
        8080: "HTTP-Alt/Jenkins",
        8443: "HTTPS-Alt/Tomcat",
        3000: "HTTP-Dev/Gitea",
        5000: "HTTP-Dev",
        6443: "Kubernetes API",
        2379: "etcd",
        10250: "Kubelet",
        # Development & CI/CD
        8090: "Confluence",
        7990: "Bitbucket",
        9000: "SonarQube",
        8081: "Nexus",
        8086: "InfluxDB",
        5601: "Kibana",
        9200: "Elasticsearch",
        9418: "Git",
        2222: "Git SSH",
        10080: "GitLab",
        # Container & Orchestration
        2375: "Docker",
        2376: "Docker TLS",
        4001: "etcd Client",
        10255: "Kubelet (readonly)",
        10256: "Kube Proxy",
        # Monitoring
        9090: "Prometheus",
        3001: "Grafana",
        9093: "Alertmanager",
        8125: "StatsD",
        9100: "Node Exporter",
        9113: "Nginx Exporter",
        # Message Queues
        5672: "RabbitMQ",
        15672: "RabbitMQ Management",
        9092: "Kafka",
        2181: "Zookeeper",
        # Caching
        11211: "Memcached",
        6380: "Redis Alt",
        # Auth & Security
        389: "LDAP",
        636: "LDAPS",
        88: "Kerberos",
        749: "Kerberos Admin",
        # File sharing
        873: "Rsync",
        548: "AFP",
        # Gaming
        25565: "Minecraft",
        27015: "Steam",
        7777: "Game Server",
    }
    return service_names.get(port, "Unknown")


def detect_service_patterns(open_ports, tags):
    """Detect service patterns from port combinations and tags"""
    detected_services = []
    port_set = set(open_ports)

    # Web application stacks
    if 80 in port_set and 443 in port_set:
        detected_services.append("web-stack")

    # Database clusters
    if any(p in port_set for p in [3306, 5432, 1433, 27017, 6379]):
        detected_services.append("database-server")

    # Kubernetes cluster
    k8s_ports = {6443, 2379, 2380, 10250, 10255, 10256}
    if len(k8s_ports.intersection(port_set)) >= 2:
        detected_services.append("kubernetes-cluster")

    # Jenkins CI/CD
    if 8080 in port_set and any(p in port_set for p in [50000, 8443]):
        detected_services.append("jenkins-server")

    # Elasticsearch stack (ELK)
    elk_ports = {9200, 9300, 5601}
    if len(elk_ports.intersection(port_set)) >= 2:
        detected_services.append("elasticsearch-stack")

    # Redis cluster
    if 6379 in port_set and 6380 in port_set:
        detected_services.append("redis-cluster")

    # Docker host
    if any(p in port_set for p in [2375, 2376]) and 22 in port_set:
        detected_services.append("docker-host")

    # Git server (GitLab/GitHub Enterprise)
    if 22 in port_set and any(p in port_set for p in [80, 443, 10080, 3000]):
        if any(tag in tags for tag in ["git", "gitea", "gitlab"]):
            detected_services.append("git-server")

    # Monitoring stack (Prometheus + Grafana)
    if 9090 in port_set and 3001 in port_set:
        detected_services.append("monitoring-stack")

    # Message queue cluster
    mq_ports = {5672, 15672, 9092, 2181}
    if len(mq_ports.intersection(port_set)) >= 2:
        detected_services.append("message-queue-cluster")

    # Development environment
    dev_ports = {3000, 5000, 8000, 9000}
    if len(dev_ports.intersection(port_set)) >= 2:
        detected_services.append("development-environment")

    # Mail server
    mail_ports = {25, 110, 143, 993, 995, 587}
    if len(mail_ports.intersection(port_set)) >= 2:
        detected_services.append("mail-server")

    # FTP server with SSH
    if 21 in port_set and 22 in port_set:
        detected_services.append("file-server")

    return detected_services


def validate_target(target):
    """Validate target (IP address or domain)"""
    # Check if it's a valid IP
    if validate_ip(target):
        return True

    # Check if it's a valid domain name
    import re

    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    if re.match(domain_pattern, target.split(":")[0]):  # Handle domain:port format
        return True

    return False


def validate_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str.split(":")[0])  # Handle IP:port format
        return True
    except ValueError:
        return False


def check_binary(binary_name):
    """Check if binary is available in PATH"""
    return shutil.which(binary_name) is not None


def validate_scanner(scanner):
    """Validate if selected scanner binary is available"""
    if scanner == "naabu" and not check_binary("naabu"):
        click.echo(f"[!] {scanner} binary not found in PATH")
        return False
    elif scanner == "rustscan" and not check_binary("rustscan"):
        click.echo(f"[!] {scanner} binary not found in PATH")
        return False
    elif scanner == "nmap" and not check_binary("nmap"):
        click.echo(f"[!] {scanner} binary not found in PATH")
        return False
    elif scanner == "masscan" and not check_binary("masscan"):
        click.echo(f"[!] {scanner} binary not found in PATH")
        return False
    elif scanner == "rush" and not check_binary("rush"):
        click.echo(f"[!] {scanner} binary not found in PATH")
        return False
    return True


def expand_cidr(cidr):
    """Expand CIDR notation to individual IPs (limited to /24 and larger)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > 256:
            click.echo(
                f"[!] CIDR {cidr} too large (>{network.num_addresses} IPs). Use /24 or smaller."
            )
            return []
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        click.echo(f"[!] Invalid CIDR format: {cidr}")
        return []


def load_targets(ip, domain, cidr, input_file):
    targets = []

    if ip:
        ip_clean = ip.strip()
        if validate_ip(ip_clean):
            targets.append(ip_clean)
        else:
            click.echo(f"[!] Invalid IP format: {ip_clean}")

    if domain:
        domain_clean = domain.strip()
        if validate_target(domain_clean):
            targets.append(domain_clean)
        else:
            click.echo(f"[!] Invalid domain format: {domain_clean}")

    if cidr:
        expanded = expand_cidr(cidr.strip())
        targets.extend(expanded)

    if input_file and os.path.exists(input_file):
        try:
            with open(input_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "/" in line:  # CIDR
                            expanded = expand_cidr(line)
                            targets.extend(expanded)
                        elif validate_target(line):  # IP or domain
                            targets.append(line)
                        else:
                            click.echo(f"[!] Invalid target on line {line_num}: {line}")
        except Exception as e:
            click.echo(f"[!] Error reading file {input_file}: {e}")

    return list(set(targets))


def write_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def write_markdown(results, path):
    with open(path, "w") as f:
        f.write(
            f"# 🛠️ Port Scan Report – {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # Summary stats
        total_targets = len(results)
        targets_with_ports = len([r for r in results if r.get("open_ports")])
        total_ports = sum(len(r.get("open_ports", [])) for r in results)

        f.write("## 📊 Summary\n")
        f.write(f"- **Total Targets:** {total_targets}\n")
        f.write(f"- **Targets with Open Ports:** {targets_with_ports}\n")
        f.write(f"- **Total Open Ports Found:** {total_ports}\n")
        if total_targets > 0:
            f.write(
                f"- **Success Rate:** {(targets_with_ports / total_targets * 100):.1f}%\n\n"
            )
        else:
            f.write("- **Success Rate:** 0.0%\n\n")

        # Detailed results
        f.write("## 🎯 Detailed Results\n\n")
        for i, result in enumerate(results, 1):
            f.write(f"### [{i}] Target: {result['ip']}\n")
            f.write(f"- 🛰️ **Scanner:** {result['scanner']}\n")
            f.write(f"- 🌐 **CDN:** {'✅ Yes' if result.get('cdn') else '❌ No'}\n")
            f.write(f"- ⏰ **Scan Time:** {result.get('scan_time', 'N/A')}\n")

            if result.get("open_ports"):
                f.write(f"- ✅ **Open Ports ({len(result['open_ports'])}):**\n")

                # Show detailed port information with tags
                if result.get("port_details"):
                    for port_info in result["port_details"]:
                        port = port_info["port"]
                        service = port_info["service"]
                        tags = ", ".join(port_info["tags"])
                        f.write(f"  - **{port}** ({service}) `{tags}`\n")
                else:
                    # Fallback for older format
                    for port in result["open_ports"]:
                        service = get_service_name(port)
                        tags = ", ".join(get_port_tags(port))
                        f.write(f"  - **{port}** ({service}) `{tags}`\n")

                # Show overall tags
                if result.get("tags"):
                    f.write(f"- 🏷️ **Tags:** `{', '.join(result['tags'])}`\n")

                # Show detected services
                if result.get("detected_services"):
                    f.write(
                        f"- 🔍 **Detected Services:** `{', '.join(result['detected_services'])}`\n"
                    )
            else:
                f.write("- ❌ **No open ports found**\n")

            # Cloud provider info
            if result.get("cloud_provider"):
                f.write(f"- ☁️ **Cloud Provider:** {result['cloud_provider'].upper()}\n")

            if result.get("command_used"):
                f.write(f"- 🔧 **Command:** `{result['command_used']}`\n")

            f.write("\n---\n\n")


class PortCacheManager:
    """Port Scanning Cache Manager for storing and retrieving port scan results"""

    def __init__(self, cache_dir: str, max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.cache_index_file = self.cache_dir / "port_cache_index.json"
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

    def _generate_cache_key(
        self,
        ip: str,
        scanner: str,
        ports: Optional[str] = None,
        options: Optional[Dict] = None,
    ) -> str:
        """Generate cache key from IP, scanner, ports, and options"""
        # Create a normalized cache string
        cache_string = f"{scanner}:{ip}"

        # Add ports to cache key if specified
        if ports:
            cache_string += f":ports={ports}"

        # Add relevant options that affect scan results
        if options:
            relevant_opts = ["top_ports", "full", "rate", "timeout"]
            cache_opts = {}
            for opt in relevant_opts:
                if opt in options and options[opt] is not None:
                    cache_opts[opt] = options[opt]
            if cache_opts:
                cache_string += f":opts={json.dumps(cache_opts, sort_keys=True)}"

        return hashlib.sha256(cache_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cache entry is still valid"""
        age_hours = (time.time() - timestamp) / 3600
        return age_hours < self.max_age_hours

    def get(
        self,
        ip: str,
        scanner: str,
        ports: Optional[str] = None,
        options: Optional[Dict] = None,
    ) -> Optional[dict]:
        """Get cached port scan result for IP"""
        cache_key = self._generate_cache_key(ip, scanner, ports, options)

        if cache_key in self.cache_index:
            cache_info = self.cache_index[cache_key]

            # Check if cache is still valid
            if self._is_cache_valid(cache_info["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            data = json.load(f)

                        # Update access count and last access
                        cache_info["access_count"] += 1
                        cache_info["last_access"] = time.time()
                        self.cache_index[cache_key] = cache_info
                        self._save_cache_index()

                        return data
                    except Exception:
                        # Remove invalid cache entry
                        del self.cache_index[cache_key]
                        self._save_cache_index()
            else:
                # Remove expired cache entry
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    cache_file.unlink()
                del self.cache_index[cache_key]
                self._save_cache_index()

        return None

    def set(
        self,
        ip: str,
        result: dict,
        scanner: str,
        ports: Optional[str] = None,
        options: Optional[Dict] = None,
    ):
        """Cache port scan result for IP"""
        cache_key = self._generate_cache_key(ip, scanner, ports, options)

        # Update cache index
        self.cache_index[cache_key] = {
            "ip": ip,
            "scanner": scanner,
            "ports": ports,
            "timestamp": time.time(),
            "last_access": time.time(),
            "access_count": 1,
            "open_ports": len(result.get("open_ports", [])),
        }

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Save cache file
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)

            self._save_cache_index()
        except Exception:
            # If save fails, remove from index
            if cache_key in self.cache_index:
                del self.cache_index[cache_key]

    def cleanup_expired(self) -> int:
        """Remove expired cache entries and return count"""
        removed_count = 0
        expired_keys = []

        for cache_key, cache_info in self.cache_index.items():
            if not self._is_cache_valid(cache_info["timestamp"]):
                expired_keys.append(cache_key)

        for cache_key in expired_keys:
            cache_file = self.cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                cache_file.unlink()
            del self.cache_index[cache_key]
            removed_count += 1

        if removed_count > 0:
            self._save_cache_index()

        return removed_count

    def clear_all(self) -> int:
        """Clear all cache entries and return count"""
        count = len(self.cache_index)

        # Remove all cache files
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

        # Clear index
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


@click.command()
@click.option(
    "--ip", help="Single IP address to scan (e.g., 192.168.1.1 or 192.168.1.1:8080)"
)
@click.option("--domain", help="Single domain to scan (e.g., example.com)")
@click.option("--cidr", help="CIDR block to scan (e.g., 192.168.1.0/24)")
@click.option("--input", help="File with list of IPs/CIDRs/domains (one per line)")
@click.option(
    "--scanner",
    type=click.Choice(["naabu", "rustscan", "nmap", "masscan", "rush"]),
    default="naabu",
    show_default=True,
    help="Port scanner to use",
)
@click.option("--ports", help="Comma-separated list of ports (e.g., 80,443,8080)")
@click.option("--top-ports", type=int, help="Scan top N most common ports")
@click.option("--full", is_flag=True, help="Scan full port range 1-65535 (slow!)")
@click.option("--exclude-cdn", is_flag=True, help="Exclude known CDN IP ranges")
@click.option(
    "--only-web", is_flag=True, help="Only scan common web ports (80,443,8080,etc.)"
)
@click.option(
    "--filter-tags",
    help="Only show results with specific tags (comma-separated, e.g., 'web,prod')",
)
@click.option(
    "--exclude-tags", help="Exclude results with specific tags (comma-separated)"
)
@click.option(
    "--filter-services",
    help="Only show results with detected services (comma-separated, e.g., 'web-stack,jenkins-server')",
)
@click.option("--rate", type=int, help="Rate limit for scanner (packets/sec)")
@click.option("--timeout", type=int, help="Timeout in milliseconds")
@click.option("--nmap-flags", help='Additional flags for Nmap (e.g., "-sS -O")')
@click.option(
    "--output-dir",
    default="output/portcli",
    show_default=True,
    help="Directory to save results",
)
@click.option("--resume", is_flag=True, help="Resume previous incomplete scan")
@click.option(
    "--clear-resume", is_flag=True, help="Clear previous resume state and exit"
)
@click.option(
    "--show-resume", is_flag=True, help="Show status of previous scans and exit"
)
@click.option("--json", "json_out", is_flag=True, help="Save results in JSON format")
@click.option("--markdown", is_flag=True, help="Save results in Markdown report format")
@click.option("--silent", is_flag=True, help="Suppress all output except errors")
@click.option(
    "--verbose", is_flag=True, help="Enable verbose output with command details"
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
@click.option("--cache", is_flag=True, help="Enable port scan result caching")
@click.option("--cache-dir", help="Cache directory path")
@click.option("--cache-max-age", default=24, type=int, help="Cache max age in hours")
@click.option("--clear-cache", is_flag=True, help="Clear all cached port scan results")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics")
@click.option(
    "--ai", is_flag=True, help="Enable AI-powered analysis of port scan results"
)
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider for analysis",
)
@click.option("--ai-model", help="Specific AI model to use for analysis")
@click.option("--ai-context", help="Additional context for AI analysis")
@click.option("--ai-cache", is_flag=True, help="Enable AI analysis result caching")
@click.option("--ai-cache-dir", default="ai_cache", help="AI cache directory")
@click.option(
    "--masscan-rate", type=int, default=1000, help="Masscan rate limit (packets/sec)"
)
@click.option("--masscan-interface", help="Masscan network interface to use")
@click.option("--masscan-exclude", help="Masscan exclude file or IP ranges")
@click.option("--rush-jobs", type=int, default=12, help="Rush parallel jobs count")
@click.option("--rush-timeout", type=int, help="Rush timeout per job in seconds")
@click.option(
    "--rush-retries", type=int, default=0, help="Rush maximum retries per job"
)
@click.option(
    "--rush-base-scanner",
    type=click.Choice(["nmap", "naabu", "rustscan", "masscan"]),
    default="nmap",
    help="Base scanner to use with rush",
)
def portcli(
    ip,
    domain,
    cidr,
    input,
    scanner,
    ports,
    top_ports,
    full,
    exclude_cdn,
    only_web,
    filter_tags,
    exclude_tags,
    filter_services,
    rate,
    timeout,
    nmap_flags,
    output_dir,
    resume,
    clear_resume,
    show_resume,
    json_out,
    markdown,
    silent,
    verbose,
    store_db,
    target_domain,
    program,
    cache,
    cache_dir,
    cache_max_age,
    clear_cache,
    cache_stats,
    ai,
    ai_provider,
    ai_model,
    ai_context,
    ai_cache,
    ai_cache_dir,
    masscan_rate,
    masscan_interface,
    masscan_exclude,
    rush_jobs,
    rush_timeout,
    rush_retries,
    rush_base_scanner,
):
    """
    Advanced Port Scanning and Service Enumeration

    Perform comprehensive port scans using multiple scanners with resume functionality,
    CDN detection, automatic tagging, and professional reporting. Supports single IPs,
    CIDR ranges, and batch processing.

    Examples:
        # Basic single IP scan with automatic tagging
        reconcli portcli --ip 192.168.1.100

        # Single domain scan
        reconcli portcli --domain example.com

        # Domain with specific ports
        reconcli portcli --domain example.com --ports "80,443,8080"

        # Scan CIDR with top 1000 ports and cloud detection
        reconcli portcli --cidr 192.168.1.0/24 --top-ports 1000

        # Batch scan showing only web services
        reconcli portcli --input targets.txt --filter-tags web --json

        # Find production services excluding development ports
        reconcli portcli --input targets.txt --filter-tags prod --exclude-tags dev

        # Find specific service types (Jenkins, Kubernetes, etc.)
        reconcli portcli --input targets.txt --filter-services web-stack,jenkins-server

        # Full scan excluding cloud and CDN IPs
        reconcli portcli --ip 10.0.0.1 --scanner nmap --full --exclude-cdn

        # Parallel scanning using rush with nmap
        reconcli portcli --input targets.txt --scanner rush --rush-base-scanner nmap --rush-jobs 20

        # Rush with masscan for fast scanning
        reconcli portcli --input targets.txt --scanner rush --rush-base-scanner masscan --rush-jobs 10 --rush-timeout 30

        # Domain scan with rush and AI analysis
        reconcli portcli --domain target.com --scanner rush --rush-base-scanner naabu --ai

        # Resume previous scan and generate tagged report
        reconcli portcli --resume --markdown --verbose

    Port Cache Examples:
        # Enable port scan caching
        reconcli portcli --ip 192.168.1.100 --cache

        # Custom cache directory
        reconcli portcli --ip 192.168.1.100 --cache --cache-dir /tmp/port_cache

        # Set cache expiry
        reconcli portcli --ip 192.168.1.100 --cache --cache-max-age 12

        # Clear cache
        reconcli portcli --clear-cache

        # Show cache stats
        reconcli portcli --cache-stats
    """

    # Validate scanner binary
    if not validate_scanner(scanner):
        click.echo(f"[!] Scanner '{scanner}' not available. Please install it first.")
        exit(1)

    # Additional validation for rush - check base scanner
    if scanner == "rush":
        if not validate_scanner(rush_base_scanner):
            click.echo(
                f"[!] Base scanner '{rush_base_scanner}' for rush not available. Please install it first."
            )
            exit(1)

    # Initialize cache manager if cache is enabled
    cache_manager = None
    if cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "port_cache")
        cache_manager = PortCacheManager(cache_directory, cache_max_age)
        if verbose:
            print(f"[+] 🗄️ Port scan caching enabled: {cache_directory}")

    # Handle cache operations
    if clear_cache:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "port_cache")
        temp_cache_manager = PortCacheManager(cache_directory, cache_max_age)
        count = temp_cache_manager.clear_all()
        print(f"🗑️ Cleared {count} cached port scan results from {cache_directory}")
        return

    if cache_stats:
        cache_directory = cache_dir or str(Path.home() / ".reconcli" / "port_cache")
        temp_cache_manager = PortCacheManager(cache_directory, cache_max_age)
        stats = temp_cache_manager.get_stats()

        print("📊 Port Scan Cache Statistics")
        print(f"Cache directory: {cache_directory}")
        print(f"Total entries: {stats['total_entries']}")
        print(f"Valid entries: {stats['valid_entries']}")
        print(f"Expired entries: {stats['expired_entries']}")
        print(f"Total size: {stats['total_size_kb']:.1f} KB")
        print(f"Max age: {cache_max_age} hours")
        return

    os.makedirs(output_dir, exist_ok=True)
    resume_path = os.path.join(output_dir, "portcli_resume.json")
    results = []

    if clear_resume:
        if os.path.exists(resume_path):
            os.remove(resume_path)
            click.echo("[✓] Resume state cleared.")
        else:
            click.echo("[ℹ️] No resume state to clear.")
        return

    if show_resume:
        if os.path.exists(resume_path):
            with open(resume_path) as f:
                data = json.load(f)
                click.echo(f"📄 Resume contains {len(data)} scanned IP(s):")
                for entry in data:
                    ports_str = ",".join(str(p) for p in entry.get("open_ports", []))
                    click.echo(f"- {entry['ip']} → {ports_str or 'no open ports'}")
        else:
            click.echo("[ℹ️] No resume file found.")
        return

    if resume and os.path.exists(resume_path):
        with open(resume_path) as f:
            results = json.load(f)
            if verbose:
                click.echo(f"[+] Loaded {len(results)} resumed results")

    already_scanned = {r["ip"] for r in results}
    targets = load_targets(ip, domain, cidr, input)
    if exclude_cdn:
        targets = [t for t in targets if not is_cdn_ip(t)]

    if not targets:
        click.echo("[!] No targets found.")
        return

    to_scan = [t for t in targets if t not in already_scanned]
    if not silent:
        click.echo(f"⚙️  Starting scan on {len(to_scan)} new targets...")
        if len(to_scan) > 10:
            click.echo("📊 Progress will be shown every 10 targets...")

    successful_scans = 0
    failed_scans = 0

    for i, target in enumerate(to_scan, 1):
        # Check cache first
        scan_options = {
            "top_ports": top_ports,
            "full": full,
            "rate": rate,
            "timeout": timeout,
            "only_web": only_web,
        }

        if cache_manager:
            cached_result = cache_manager.get(target, scanner, ports, scan_options)
            if cached_result:
                results.append(cached_result)
                successful_scans += 1
                if not silent:
                    port_count = len(cached_result.get("open_ports", []))
                    if verbose:
                        click.echo(f"    ✓ Found {port_count} open ports (cached)")
                    else:
                        click.echo(f"    ✓ Found {port_count} open ports")
                continue

        if not silent:
            if len(to_scan) > 1:
                click.echo(
                    f"[{i}/{len(to_scan)}] 🔍 Scanning {target} using {scanner}..."
                )
            else:
                click.echo(f"🔍 Scanning {target} using {scanner}...")

        cmd = []
        if scanner == "naabu":
            cmd = ["naabu", "-host", target, "-silent"]
            if ports:
                cmd += ["-p", ports]
            elif top_ports:
                cmd += ["-top-ports", str(top_ports)]
            elif full:
                cmd += ["-p", "1-65535"]
            if rate:
                cmd += ["-rate", str(rate)]
            if timeout:
                cmd += ["-timeout", str(timeout)]
        elif scanner == "rustscan":
            cmd = ["rustscan", "-a", target, "--ulimit", "5000"]
            if ports:
                cmd += ["-p", ports]
            elif full:
                cmd += ["-r", "1-65535"]
        elif scanner == "nmap":
            cmd = ["nmap", "-Pn", target]
            if ports:
                cmd += ["-p", ports]
            elif full:
                cmd += [
                    "-p-",
                ]
            if nmap_flags:
                cmd += nmap_flags.split()
        elif scanner == "masscan":
            cmd = ["masscan", target, "--wait", "1"]
            if ports:
                cmd += ["-p", ports]
            elif top_ports:
                # Convert top_ports to common ports for masscan
                if top_ports <= 100:
                    cmd += [
                        "-p",
                        "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
                    ]
                elif top_ports <= 1000:
                    cmd += ["-p", "1-1000"]
                else:
                    cmd += ["-p", "1-65535"]
            elif full:
                cmd += ["-p", "1-65535"]

            # Add masscan specific options
            if masscan_rate:
                cmd += ["--rate", str(masscan_rate)]
            if masscan_interface:
                cmd += ["-e", masscan_interface]
            if masscan_exclude:
                cmd += ["--exclude", masscan_exclude]
        elif scanner == "rush":
            # Rush is a parallel job executor - we'll use it to run the base scanner
            base_scanner = rush_base_scanner

            # Build base scanner command
            base_cmd = []
            if base_scanner == "nmap":
                base_cmd = [
                    "nmap",
                    "-Pn",
                    "{}",
                ]  # {} will be replaced by rush with the target
                if ports:
                    base_cmd += ["-p", ports]
                elif full:
                    base_cmd += ["-p-"]
                if nmap_flags:
                    base_cmd += nmap_flags.split()
            elif base_scanner == "naabu":
                base_cmd = ["naabu", "-host", "{}", "-silent"]
                if ports:
                    base_cmd += ["-p", ports]
                elif top_ports:
                    base_cmd += ["-top-ports", str(top_ports)]
                elif full:
                    base_cmd += ["-p", "1-65535"]
                if rate:
                    base_cmd += ["-rate", str(rate)]
                if timeout:
                    base_cmd += ["-timeout", str(timeout)]
            elif base_scanner == "rustscan":
                base_cmd = ["rustscan", "-a", "{}", "--ulimit", "5000"]
                if ports:
                    base_cmd += ["-p", ports]
                elif full:
                    base_cmd += ["-r", "1-65535"]
            elif base_scanner == "masscan":
                base_cmd = ["masscan", "{}", "--wait", "1"]
                if ports:
                    base_cmd += ["-p", ports]
                elif top_ports:
                    if top_ports <= 100:
                        base_cmd += [
                            "-p",
                            "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
                        ]
                    elif top_ports <= 1000:
                        base_cmd += ["-p", "1-1000"]
                    else:
                        base_cmd += ["-p", "1-65535"]
                elif full:
                    base_cmd += ["-p", "1-65535"]
                if masscan_rate:
                    base_cmd += ["--rate", str(masscan_rate)]
                if masscan_interface:
                    base_cmd += ["-e", masscan_interface]
                if masscan_exclude:
                    base_cmd += ["--exclude", masscan_exclude]

            # Build rush command
            cmd = ["echo", target, "|", "rush"]
            cmd += ["-j", str(rush_jobs)]  # parallel jobs
            cmd += ["-k"]  # keep order

            if rush_timeout:
                cmd += ["-t", str(rush_timeout)]
            if rush_retries:
                cmd += ["-r", str(rush_retries)]

            # Add the base scanner command in quotes
            base_cmd_str = " ".join(base_cmd)
            cmd.append(f"'{base_cmd_str}'")

        try:
            if verbose:
                click.echo(f"    Command: {' '.join(cmd)}")

            # For rush, we need to handle the pipe differently
            if scanner == "rush":
                # Execute with shell=True to handle pipes
                output = subprocess.check_output(
                    " ".join(cmd), shell=True, stderr=subprocess.DEVNULL, timeout=120
                ).decode()
            else:
                output = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, timeout=120
                ).decode()
            open_ports = []

            if scanner == "naabu":
                open_ports = [
                    int(line.split(":")[-1])
                    for line in output.strip().splitlines()
                    if line
                ]
            elif scanner == "rustscan":
                # Parse rustscan output - look for "Open IP:PORT" format
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("Open ") and ":" in line:
                        # Format: "Open 93.184.216.34:80"
                        try:
                            ip_port = line.split("Open ")[-1]
                            if ":" in ip_port:
                                port_str = ip_port.split(":")[-1]
                                if port_str.isdigit():
                                    port = int(port_str)
                                    if 1 <= port <= 65535:
                                        open_ports.append(port)
                        except (ValueError, IndexError):
                            continue
            elif scanner == "nmap":
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        if port.isdigit():
                            open_ports.append(int(port))
            elif scanner == "masscan":
                # Parse masscan output format: "Discovered open port PORT/tcp on IP"
                for line in output.strip().splitlines():
                    if "Discovered open port" in line and "/tcp on" in line:
                        # Extract port from format: "Discovered open port 443/tcp on IP"
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "port" and i + 1 < len(parts):
                                port_part = parts[i + 1]
                                if "/tcp" in port_part:
                                    port_num = port_part.split("/")[0]
                                    if port_num.isdigit():
                                        open_ports.append(int(port_num))
                                break
            elif scanner == "rush":
                # Parse output based on the base scanner used
                if rush_base_scanner == "naabu":
                    open_ports = [
                        int(line.split(":")[-1])
                        for line in output.strip().splitlines()
                        if line and ":" in line
                    ]
                elif rush_base_scanner == "rustscan":
                    # Parse rustscan output - look for "Open IP:PORT" format
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith("Open ") and ":" in line:
                            # Format: "Open 8.8.8.8:53"
                            try:
                                ip_port = line.split("Open ")[-1]
                                if ":" in ip_port:
                                    port_str = ip_port.split(":")[-1]
                                    if port_str.isdigit():
                                        port = int(port_str)
                                        if 1 <= port <= 65535:
                                            open_ports.append(port)
                            except (ValueError, IndexError):
                                continue
                elif rush_base_scanner == "nmap":
                    for line in output.splitlines():
                        if "/tcp" in line and "open" in line:
                            port = line.split("/")[0].strip()
                            if port.isdigit():
                                open_ports.append(int(port))
                elif rush_base_scanner == "masscan":
                    for line in output.strip().splitlines():
                        if "Discovered open port" in line and "/tcp on" in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == "port" and i + 1 < len(parts):
                                    port_part = parts[i + 1]
                                    if "/tcp" in port_part:
                                        port_num = port_part.split("/")[0]
                                        if port_num.isdigit():
                                            open_ports.append(int(port_num))
                                    break

            if only_web:
                web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000]
                open_ports = [p for p in open_ports if p in web_ports]

            # Generate port details with tags
            port_details = []
            all_tags = set()
            for port in sorted(open_ports):
                tags = get_port_tags(port)
                service = get_service_name(port)
                port_details.append({"port": port, "service": service, "tags": tags})
                all_tags.update(tags)

            # Detect cloud provider
            cloud_provider = get_cloud_provider(target)
            if cloud_provider:
                all_tags.add("cloud")
                all_tags.add(cloud_provider)

            # Detect service patterns
            detected_services = detect_service_patterns(open_ports, list(all_tags))
            all_tags.update(detected_services)

            result = {
                "ip": target,
                "scanner": scanner,
                "open_ports": sorted(open_ports),
                "port_details": port_details,
                "tags": sorted(list(all_tags)),
                "detected_services": detected_services,
                "cdn": is_cdn_ip(target),
                "cloud_provider": cloud_provider,
                "scan_time": datetime.datetime.now().isoformat(),
                "command_used": " ".join(cmd),
            }

            # Cache successful result
            if cache_manager:
                cache_manager.set(target, result, scanner, ports, scan_options)

            results.append(result)
            successful_scans += 1

            if not silent:
                if open_ports:
                    ports_str = ", ".join(map(str, open_ports))
                    click.echo(
                        f"    ✅ Found {len(open_ports)} open ports: {ports_str}"
                    )

                    # Show tags
                    if result["tags"]:
                        tags_str = ", ".join(result["tags"])
                        click.echo(f"    🏷️  Tags: {tags_str}")

                    # Show detected services
                    if result.get("detected_services"):
                        services_str = ", ".join(result["detected_services"])
                        click.echo(f"    🔍 Detected: {services_str}")

                    if result["cdn"]:
                        click.echo("    ☁️  CDN detected")

                    if result["cloud_provider"]:
                        click.echo(f"    ☁️  Cloud: {result['cloud_provider'].upper()}")
                else:
                    click.echo("    ❌ No open ports found")

        except subprocess.TimeoutExpired:
            failed_scans += 1
            if not silent:
                click.echo(f"    ⏱️  Timeout scanning {target}")
        except subprocess.CalledProcessError as e:
            failed_scans += 1
            if not silent:
                click.echo(f"    ❌ Scanner error for {target}: {e}")
        except Exception as e:
            failed_scans += 1
            if not silent:
                click.echo(f"    ❌ Unexpected error for {target}: {e}")

        # Progress update for large scans
        if not silent and len(to_scan) > 10 and i % 10 == 0:
            click.echo(
                f"📊 Progress: {i}/{len(to_scan)} ({(i / len(to_scan) * 100):.1f}%) - Success: {successful_scans}, Failed: {failed_scans}"
            )

    # Save results and final summary
    write_json(results, resume_path)

    # Apply tag filtering if specified
    filtered_results = results
    if filter_tags or exclude_tags or filter_services:
        original_count = len(filtered_results)

        if filter_tags:
            required_tags = [tag.strip() for tag in filter_tags.split(",")]
            filtered_results = [
                r
                for r in filtered_results
                if any(tag in r.get("tags", []) for tag in required_tags)
            ]
            if not silent:
                click.echo(
                    f"🔍 Filtered by tags '{filter_tags}': {len(filtered_results)}/{original_count} results"
                )

        if exclude_tags:
            excluded_tags = [tag.strip() for tag in exclude_tags.split(",")]
            filtered_results = [
                r
                for r in filtered_results
                if not any(tag in r.get("tags", []) for tag in excluded_tags)
            ]
            if not silent:
                click.echo(
                    f"🚫 Excluded tags '{exclude_tags}': {len(filtered_results)}/{original_count} results"
                )

        if filter_services:
            required_services = [
                service.strip() for service in filter_services.split(",")
            ]
            filtered_results = [
                r
                for r in filtered_results
                if any(
                    service in r.get("detected_services", [])
                    for service in required_services
                )
            ]
            if not silent:
                click.echo(
                    f"🔍 Filtered by services '{filter_services}': {len(filtered_results)}/{original_count} results"
                )

    if not silent and len(to_scan) > 0:
        total_open_ports = sum(
            len(r["open_ports"]) for r in results if "open_ports" in r
        )
        click.echo("\n📊 Final Summary:")
        click.echo(f"   • Targets scanned: {len(to_scan)}")
        click.echo(f"   • Successful: {successful_scans}")
        click.echo(f"   • Failed: {failed_scans}")
        click.echo(f"   • Total open ports found: {total_open_ports}")
        if successful_scans > 0:
            click.echo(
                f"   • Success rate: {(successful_scans / (successful_scans + failed_scans) * 100):.1f}%"
            )

    if json_out:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(output_dir, f"portscan_{timestamp}.json")
        write_json(filtered_results, json_path)
        if not silent:
            click.echo(f"💾 JSON results saved to: {json_path}")

    if markdown:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(output_dir, f"portscan_summary_{timestamp}.md")
        write_markdown(filtered_results, md_path)
        if not silent:
            click.echo(f"📝 Markdown report saved to: {md_path}")

    # Database storage
    if store_db:
        try:
            from reconcli.db.operations import store_port_scan, store_target

            # Auto-detect target domain if not provided
            if not target_domain and filtered_results:
                # Try to extract domain from first result's IP or use IP directly
                first_result = filtered_results[0]
                target_ip = first_result.get("ip")
                if target_ip:
                    target_domain = target_ip

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert results to database format
                port_scan_data = []
                for result in filtered_results:
                    ip = result.get("ip")
                    # Use port_details if available, otherwise fall back to open_ports
                    port_details = result.get("port_details", [])
                    if not port_details and result.get("open_ports"):
                        # Convert simple port list to detailed format
                        for port in result.get("open_ports", []):
                            port_details.append({"port": port, "service": "unknown"})

                    for port_info in port_details:
                        port_entry = {
                            "ip": ip,
                            "port": port_info.get("port"),
                            "protocol": port_info.get("protocol", "tcp"),
                            "status": port_info.get("status", "open"),
                            "service": port_info.get("service"),
                            "version": port_info.get("version"),
                            "banner": port_info.get("banner"),
                            "response_time": port_info.get("response_time"),
                        }
                        port_scan_data.append(port_entry)

                # Store port scans in database
                if port_scan_data:
                    stored_ids = store_port_scan(target_domain, port_scan_data, scanner)
                    if not silent:
                        click.echo(
                            f"🗄️ Stored {len(stored_ids)} port scan results in database for {target_domain}"
                        )
                        if program:
                            click.echo(f"   Program: {program}")
                        click.echo(f"   Scanner: {scanner}")
                else:
                    if not silent:
                        click.echo("⚠️ No port scan results to store in database")
            else:
                if not silent:
                    click.echo(
                        "⚠️ Could not determine target domain for database storage"
                    )

        except ImportError:
            if not silent:
                click.echo(
                    "⚠️ Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if not silent:
                click.echo(f"❌ Error storing to database: {e}")

    # AI Analysis
    if ai and filtered_results:
        if not silent:
            click.echo("\n🤖 Running AI analysis...")

        try:
            analysis = analyze_with_ai(
                filtered_results,
                ai_provider=ai_provider,
                ai_model=ai_model,
                ai_context=ai_context,
            )

            if analysis:
                if not silent:
                    click.echo("\n📋 AI Analysis Results:")
                    click.echo(
                        f"   • Total targets analyzed: {analysis['summary']['total_targets']}"
                    )
                    click.echo(
                        f"   • Total open ports: {analysis['summary']['total_open_ports']}"
                    )
                    click.echo(
                        f"   • Unique ports: {analysis['summary']['unique_ports']}"
                    )

                    if analysis["recommendations"]:
                        click.echo("\n💡 Recommendations:")
                        for rec in analysis["recommendations"]:
                            click.echo(f"   • {rec}")

                    if analysis["security_insights"]:
                        click.echo("\n🔐 Security Insights:")
                        for insight in analysis["security_insights"]:
                            click.echo(f"   • {insight}")

                # Save AI analysis if caching enabled
                if ai_cache and ai_cache_dir:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    ai_cache_path = Path(ai_cache_dir)
                    ai_cache_path.mkdir(exist_ok=True)
                    analysis_file = ai_cache_path / f"ai_analysis_{timestamp}.json"

                    with open(analysis_file, "w") as f:
                        json.dump(analysis, f, indent=2, default=str)

                    if not silent:
                        click.echo(f"💾 AI analysis saved to: {analysis_file}")

        except Exception as e:
            if not silent:
                click.echo(f"❌ AI analysis failed: {e}")


def analyze_with_ai(results, ai_provider=None, ai_model=None, ai_context=None):
    """
    Analyze port scan results using AI
    """
    try:
        if ai_provider == "openai":
            return analyze_with_openai(results, ai_model, ai_context)
        elif ai_provider == "anthropic":
            return analyze_with_anthropic(results, ai_model, ai_context)
        elif ai_provider == "gemini":
            return analyze_with_gemini(results, ai_model, ai_context)
        else:
            # Default to basic analysis
            return analyze_basic(results)
    except Exception as e:
        click.echo(f"[!] AI analysis failed: {e}")
        return None


def analyze_basic(results):
    """
    Basic AI-like analysis without external APIs
    """
    analysis = {
        "summary": {},
        "recommendations": [],
        "security_insights": [],
        "service_analysis": [],
    }

    all_ports = []
    all_tags = set()

    for result in results:
        # Check both formats: open_ports and port_details
        if "open_ports" in result:
            all_ports.extend(result["open_ports"])
        if "port_details" in result:
            for port_info in result["port_details"]:
                all_tags.update(port_info.get("tags", []))
        if "tags" in result:
            all_tags.update(result["tags"])

    # Summary
    analysis["summary"] = {
        "total_targets": len(results),
        "total_open_ports": len(all_ports),
        "unique_ports": len(set(all_ports)),
        "common_tags": list(all_tags),
    }

    # Basic recommendations
    if 22 in all_ports:
        analysis["recommendations"].append(
            "SSH service detected - ensure key-based authentication"
        )
    if 80 in all_ports or 443 in all_ports:
        analysis["recommendations"].append(
            "Web services detected - consider security headers analysis"
        )
    if 3389 in all_ports:
        analysis["recommendations"].append(
            "RDP detected - ensure strong authentication and network restrictions"
        )

    # Security insights
    if "database" in all_tags:
        analysis["security_insights"].append(
            "Database services exposed - verify access controls"
        )
    if "cloud" in all_tags:
        analysis["security_insights"].append(
            "Cloud infrastructure detected - review security groups"
        )

    return analysis


def analyze_with_openai(results, model=None, context=None):
    """
    Analyze with OpenAI API (placeholder - requires API key)
    """
    # This would integrate with OpenAI API
    click.echo("[!] OpenAI integration requires API key configuration")
    return analyze_basic(results)


def analyze_with_anthropic(results, model=None, context=None):
    """
    Analyze with Anthropic API (placeholder - requires API key)
    """
    # This would integrate with Anthropic API
    click.echo("[!] Anthropic integration requires API key configuration")
    return analyze_basic(results)


def analyze_with_gemini(results, model=None, context=None):
    """
    Analyze with Google Gemini API (placeholder - requires API key)
    """
    # This would integrate with Gemini API
    click.echo("[!] Gemini integration requires API key configuration")
    return analyze_basic(results)


if __name__ == "__main__":
    portcli()
