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

RESUME_FILE = "resume.cfg"


def strip_ansi(s):
    return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", s)


def load_ips(input_file, resolve_from):
    if not input_file:
        input_file = "subs_resolved.txt" if resolve_from == "subs" else "ips_raw.txt"
    ips = []
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = strip_ansi(line.strip())
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
                ip = line
                try:
                    if ":" in ip:
                        continue
                    ipaddress.ip_address(ip)
                    ips.append(ip)
                except Exception:
                    continue
    with open("debug_ips_loaded.txt", "w") as dbg:
        dbg.write("\n".join(ips))
    return list(set(ips))


def enrich_ips(ip_list, proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    enriched = {}
    errors = []

    def enrich_single(ip):
        try:
            r = session.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                ptr = None
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except Exception:
                    ptr = None
                data["ptr"] = ptr
                return ip, data, None
            else:
                return ip, {"error": f"HTTP {r.status_code}"}, None
        except Exception as e:
            return ip, {"error": str(e)}, str(e)

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
        with open("errors.log", "a") as errlog:
            for line in errors:
                errlog.write(line + "\n")

    return enriched


def scan_ips(ip_list, scan_type="rustscan", port_list_path=None, proxy=None):
    ports = [
        21,
        22,
        80,
        81,
        280,
        300,
        443,
        583,
        591,
        593,
        832,
        981,
        1010,
        1099,
        1311,
        2082,
        2087,
        2095,
        2096,
        2480,
        3000,
        3128,
        3333,
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
        5601,
        5800,
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
    summary_path = Path(output_dir) / "ips_summary.md"
    asns = set()
    countries = set()
    try:
        with open(os.path.join(output_dir, "ips_enriched.json")) as f:
            enriched = json.load(f)
            for ip, data in enriched.items():
                if "org" in data:
                    asns.add(data["org"])
                if "country" in data:
                    countries.add(data["country"])
    except Exception:
        pass
    # Podsumowanie portów
    port_counter = Counter()
    if ports_data:
        for open_ports in ports_data.values():
            if isinstance(open_ports, list):
                port_counter.update(open_ports)
    with open(summary_path, "w") as f:
        f.write(f"# IP Summary\n\n")
        f.write(f"Total IPs: {len(ip_list)}\n")
        f.write(f"Unique ASN: {len(asns)}\n")
        f.write(f"Unique countries: {len(countries)}\n")
        f.write(f"Generated: {datetime.utcnow()} UTC\n\n")
        if port_counter:
            f.write("## Most common open ports\n")
            for port, count in port_counter.most_common(10):
                f.write(f"- Port {port}: {count} hosts\n")
            f.write("\n")
        f.write("## Sample IPs\n")
        for ip in ip_list[:10]:
            f.write(f"- {ip}\n")


def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def update_resume():
    with open(RESUME_FILE, "a") as f:
        f.write(f"[ipscli] last_run={datetime.utcnow()}\n")


@click.command()
@click.option("--input", "-i", help="Input file with IPs (one per line)")
@click.option("--resolve-from", type=click.Choice(["subs", "raw"]), default="subs")
@click.option("--enrich", is_flag=True)
@click.option(
    "--scan",
    type=click.Choice(["naabu", "rustscan", "nmap", "masscan", "zmap", "simple"]),
)
@click.option("--asn-map", is_flag=True)
@click.option("--cidr-expand", is_flag=True)
@click.option("--filter-cdn", is_flag=True)
@click.option("--use-uncover", is_flag=True)
@click.option("--uncover-query")
@click.option("--uncover-engine")
@click.option("--uncover-json")
@click.option("--output-dir", default="output_ips")
@click.option("--resume", is_flag=True)
@click.option("--proxy")
@click.option("--config")
@click.option("--profile")
@click.option("--port-list")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--country", help="Filter IPs by country code (requires --enrich)")
@click.option("--asn", help="Filter IPs by ASN (requires --enrich)")
@click.option(
    "--honeypot", is_flag=True, help="Try to detect honeypots (dummy heuristics)"
)
def ipscli(
    input,
    resolve_from,
    enrich,
    scan,
    asn_map,
    cidr_expand,
    filter_cdn,
    use_uncover,
    uncover_query,
    uncover_engine,
    uncover_json,
    output_dir,
    resume,
    proxy,
    config,
    profile,
    port_list,
    verbose,
    country,
    asn,
    honeypot,
):
    os.makedirs(output_dir, exist_ok=True)

    def vprint(*args, **kwargs):
        if verbose:
            print(*args, **kwargs, file=sys.stderr)

    vprint("[*] Loading IPs...")
    ip_list = load_ips(input, resolve_from)
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
            engine_ips = [ip for ip, src in uncover_sources.items() if src == engine]
            if engine_ips:
                with open(os.path.join(output_dir, f"uncover_{engine}.txt"), "w") as ef:
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
        enriched_data = enrich_ips(ip_list, proxy)
        # Filtrowanie po kraju
        if country:
            vprint(f"[*] Filtering IPs by country: {country}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if data.get("country", "").lower() == country.lower()
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
        # Filtrowanie po ASN
        if asn:
            vprint(f"[*] Filtering IPs by ASN: {asn}")
            ip_list = [
                ip
                for ip, data in enriched_data.items()
                if asn.lower() in str(data.get("org", "")).lower()
            ]
            enriched_data = {
                ip: data for ip, data in enriched_data.items() if ip in ip_list
            }
        # Heurystyka honeypotów
        if honeypot:
            vprint("[*] Marking honeypots (dummy)...")
            for ip, data in enriched_data.items():
                ptr = data.get("ptr", "") or ""
                if "honeypot" in ptr.lower() or "trap" in ptr.lower():
                    data["honeypot"] = True
                else:
                    data["honeypot"] = False
        save_json(enriched_data, os.path.join(output_dir, "ips_enriched.json"))

    if scan:
        vprint(f"[*] Scanning IPs (mode: {scan})...")
        ports_data = scan_ips(ip_list, scan, proxy, port_list)
        save_json(ports_data, os.path.join(output_dir, "ips_ports.json"))
    else:
        ports_data = {}

    vprint("[*] Generating markdown summary...")
    generate_markdown_summary(ip_list, output_dir, ports_data)
    update_resume()
    vprint("[*] Done.")


if __name__ == "__main__":
    ipscli()
