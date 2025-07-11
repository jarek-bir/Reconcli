#!/usr/bin/env python3
"""
ReconCLI Port Scanning Module

Advanced port scanning using multiple scanners (naabu, rustscan, nmap) with
resume functionality, CDN detection, and professional reporting.
"""

import click
import subprocess
import os
import json
import datetime
import ipaddress
import sys

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


def validate_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str.split(":")[0])  # Handle IP:port format
        return True
    except ValueError:
        return False


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


def load_targets(ip, cidr, input_file):
    targets = []

    if ip:
        ip_clean = ip.strip()
        if validate_ip(ip_clean):
            targets.append(ip_clean)
        else:
            click.echo(f"[!] Invalid IP format: {ip_clean}")

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
                        elif validate_ip(line):
                            targets.append(line)
                        else:
                            click.echo(f"[!] Invalid IP on line {line_num}: {line}")
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

        f.write(f"## 📊 Summary\n")
        f.write(f"- **Total Targets:** {total_targets}\n")
        f.write(f"- **Targets with Open Ports:** {targets_with_ports}\n")
        f.write(f"- **Total Open Ports Found:** {total_ports}\n")
        if total_targets > 0:
            f.write(
                f"- **Success Rate:** {(targets_with_ports/total_targets*100):.1f}%\n\n"
            )
        else:
            f.write(f"- **Success Rate:** 0.0%\n\n")

        # Detailed results
        f.write(f"## 🎯 Detailed Results\n\n")
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
                f.write(f"- ❌ **No open ports found**\n")

            # Cloud provider info
            if result.get("cloud_provider"):
                f.write(f"- ☁️ **Cloud Provider:** {result['cloud_provider'].upper()}\n")

            if result.get("command_used"):
                f.write(f"- 🔧 **Command:** `{result['command_used']}`\n")

            f.write("\n---\n\n")


@click.command()
@click.option(
    "--ip", help="Single IP address to scan (e.g., 192.168.1.1 or 192.168.1.1:8080)"
)
@click.option("--cidr", help="CIDR block to scan (e.g., 192.168.1.0/24)")
@click.option("--input", help="File with list of IPs/CIDRs (one per line)")
@click.option(
    "--scanner",
    type=click.Choice(["naabu", "rustscan", "nmap"]),
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
def portcli(
    ip,
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
):
    """
    Advanced Port Scanning and Service Enumeration

    Perform comprehensive port scans using multiple scanners with resume functionality,
    CDN detection, automatic tagging, and professional reporting. Supports single IPs,
    CIDR ranges, and batch processing.

    Examples:
        # Basic single IP scan with automatic tagging
        reconcli portcli --ip 192.168.1.100

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

        # Resume previous scan and generate tagged report
        reconcli portcli --resume --markdown --verbose
    """

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
    targets = load_targets(ip, cidr, input)
    if exclude_cdn:
        targets = [t for t in targets if not is_cdn_ip(t)]

    if not targets:
        click.echo("[!] No targets found.")
        return

    to_scan = [t for t in targets if t not in already_scanned]
    if not silent:
        click.echo(f"⚙️  Starting scan on {len(to_scan)} new targets...")
        if len(to_scan) > 10:
            click.echo(f"📊 Progress will be shown every 10 targets...")

    successful_scans = 0
    failed_scans = 0

    for i, target in enumerate(to_scan, 1):
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

        try:
            if verbose:
                click.echo(f"    Command: {' '.join(cmd)}")

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
                open_ports = [
                    int(p.strip()) for p in output.split() if p.strip().isdigit()
                ]
            elif scanner == "nmap":
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        if port.isdigit():
                            open_ports.append(int(port))

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
                        click.echo(f"    ☁️  CDN detected")

                    if result["cloud_provider"]:
                        click.echo(f"    ☁️  Cloud: {result['cloud_provider'].upper()}")
                else:
                    click.echo(f"    ❌ No open ports found")

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
                f"📊 Progress: {i}/{len(to_scan)} ({(i/len(to_scan)*100):.1f}%) - Success: {successful_scans}, Failed: {failed_scans}"
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
        click.echo(f"\n📊 Final Summary:")
        click.echo(f"   • Targets scanned: {len(to_scan)}")
        click.echo(f"   • Successful: {successful_scans}")
        click.echo(f"   • Failed: {failed_scans}")
        click.echo(f"   • Total open ports found: {total_open_ports}")
        if successful_scans > 0:
            click.echo(
                f"   • Success rate: {(successful_scans/(successful_scans+failed_scans)*100):.1f}%"
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
            from reconcli.db.operations import store_target, store_port_scan

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
                        click.echo(f"⚠️ No port scan results to store in database")
            else:
                if not silent:
                    click.echo(
                        f"⚠️ Could not determine target domain for database storage"
                    )

        except ImportError:
            if not silent:
                click.echo(
                    f"⚠️ Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if not silent:
                click.echo(f"❌ Error storing to database: {e}")


if __name__ == "__main__":
    portcli()
