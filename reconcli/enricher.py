#!/usr/bin/env python3
"""
🔍 IP Enricher - Advanced IP Intelligence and Geolocation Analysis

A comprehensive IP enrichment tool that provides PTR records, geolocation data,
ASN information, and threat intelligence for IP addresses.

Features:
- PTR (reverse DNS) lookups
- Geolocation data from multiple providers
- ASN and network ownership information
- Threat intelligence integration
- Caching for improved performance
- Rich CLI interface with progress tracking

Author: ReconCLI Team
Version: 2.0
"""

import argparse
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import requests
from ipwhois import IPWhois
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.logging import RichHandler
from rich.table import Table
import click

# Configure rich console and logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger("enricher")


@dataclass
class GeoInfo:
    """Geolocation information container"""

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    zip_code: Optional[str] = None


@dataclass
class ASNInfo:
    """ASN information container"""

    asn: Optional[str] = None
    asn_description: Optional[str] = None
    network: Optional[str] = None
    cidr: Optional[str] = None
    country: Optional[str] = None


@dataclass
class ThreatInfo:
    """Threat intelligence container"""

    is_malicious: bool = False
    threat_types: Optional[List[str]] = None
    confidence: Optional[int] = None
    last_seen: Optional[str] = None
    source: Optional[str] = None

    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []


@dataclass
class EnrichedIP:
    """Complete IP enrichment data container"""

    ip: str
    ptr: Optional[str] = None
    geo: Optional[GeoInfo] = None
    asn: Optional[ASNInfo] = None
    threat: Optional[ThreatInfo] = None
    timestamp: Optional[str] = None
    enrichment_time: Optional[float] = None


class IPEnricher:
    """Advanced IP enrichment class with multiple data sources"""

    def __init__(
        self, timeout: int = 10, max_workers: int = 5, enable_cache: bool = True
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_cache = enable_cache
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "ReconCLI-Enricher/2.0 (Security Research Tool)"}
        )

        # Cache for storing results
        self._cache: Dict[str, EnrichedIP] = {}

    def get_ptr(self, ip: str) -> Optional[str]:
        """Perform PTR (reverse DNS) lookup"""
        try:
            start_time = time.time()
            result = socket.gethostbyaddr(ip)[0]
            logger.debug(
                f"PTR lookup for {ip}: {result} ({time.time() - start_time:.2f}s)"
            )
            return result
        except socket.herror as e:
            logger.debug(f"PTR lookup failed for {ip}: {e}")
            return None
        except Exception as e:
            logger.warning(f"PTR lookup error for {ip}: {e}")
            return None

    def get_geo_ipapi(self, ip: str) -> Optional[GeoInfo]:
        """Get geolocation data from ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,query"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return GeoInfo(
                        country=data.get("country"),
                        country_code=data.get("countryCode"),
                        city=data.get("city"),
                        region=data.get("regionName"),
                        latitude=data.get("lat"),
                        longitude=data.get("lon"),
                        timezone=data.get("timezone"),
                        org=data.get("org"),
                        isp=data.get("isp"),
                        zip_code=data.get("zip"),
                    )
                else:
                    logger.debug(
                        f"IP-API error for {ip}: {data.get('message', 'Unknown error')}"
                    )
        except requests.RequestException as e:
            logger.debug(f"IP-API request failed for {ip}: {e}")
        except Exception as e:
            logger.warning(f"IP-API lookup error for {ip}: {e}")

        return None

    def get_asn(self, ip: str) -> Optional[ASNInfo]:
        """Get ASN information using IPWhois"""
        try:
            start_time = time.time()
            whois = IPWhois(ip, timeout=self.timeout)
            result = whois.lookup_rdap()

            network_info = result.get("network", {})
            asn_info = result.get("asn", "")

            logger.debug(
                f"ASN lookup for {ip} completed ({time.time() - start_time:.2f}s)"
            )

            return ASNInfo(
                asn=asn_info,
                asn_description=result.get("asn_description"),
                network=network_info.get("name"),
                cidr=network_info.get("cidr"),
                country=result.get("asn_country_code"),
            )
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip}: {e}")
            return None

            return None

    def get_threat_intel(self, ip: str) -> Optional[ThreatInfo]:
        """Get threat intelligence data (placeholder for future implementation)"""
        # This could integrate with services like:
        # - VirusTotal API
        # - AbuseIPDB
        # - IBM X-Force
        # - Shodan
        # For now, return empty threat info
        return ThreatInfo()

    def enrich_ip(self, ip: str) -> EnrichedIP:
        """Enrich a single IP address with all available data"""
        start_time = time.time()

        # Check cache first
        if self.enable_cache and ip in self._cache:
            logger.debug(f"Using cached data for {ip}")
            return self._cache[ip]

        # Perform enrichment
        enriched = EnrichedIP(
            ip=ip,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            ptr=self.get_ptr(ip),
            geo=self.get_geo_ipapi(ip),
            asn=self.get_asn(ip),
            threat=self.get_threat_intel(ip),
            enrichment_time=time.time() - start_time,
        )

        # Cache result
        if self.enable_cache:
            self._cache[ip] = enriched

        return enriched

    def enrich_bulk(
        self, ip_list: List[str], show_progress: bool = True
    ) -> List[EnrichedIP]:
        """Enrich multiple IP addresses concurrently"""
        results = []

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Enriching {len(ip_list)} IP addresses...", total=len(ip_list)
                )

                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_ip = {
                        executor.submit(self.enrich_ip, ip): ip for ip in ip_list
                    }

                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            result = future.result()
                            results.append(result)
                        except Exception as e:
                            logger.error(f"Failed to enrich {ip}: {e}")
                            # Create empty result for failed IPs
                            results.append(
                                EnrichedIP(
                                    ip=ip, timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                            )
                        finally:
                            progress.advance(task)
        else:
            # Silent processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {
                    executor.submit(self.enrich_ip, ip): ip for ip in ip_list
                }
                for future in as_completed(future_to_ip):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        ip = future_to_ip[future]
                        logger.error(f"Failed to enrich {ip}: {e}")
                        results.append(
                            EnrichedIP(
                                ip=ip, timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                            )
                        )

        return results


def extract_ips_from_data(data: Union[List[Dict[str, Any]], List[str]]) -> List[str]:
    """Extract IP addresses from input data"""
    ips = []
    for entry in data:
        if isinstance(entry, dict):
            ip = entry.get("ip")
            if ip:
                ips.append(ip)
        elif isinstance(entry, str):
            # Assume the string is an IP
            ips.append(entry)
    return list(set(ips))  # Remove duplicates


def display_enrichment_summary(results: List[EnrichedIP]) -> None:
    """Display a summary table of enrichment results"""
    table = Table(title="🔍 IP Enrichment Summary")
    table.add_column("IP Address", style="cyan")
    table.add_column("Country", style="green")
    table.add_column("City", style="blue")
    table.add_column("ASN", style="magenta")
    table.add_column("Organization", style="yellow")
    table.add_column("PTR", style="white")

    for result in results[:10]:  # Show first 10 results
        geo = result.geo or GeoInfo()
        asn = result.asn or ASNInfo()

        table.add_row(
            result.ip,
            geo.country or "N/A",
            geo.city or "N/A",
            asn.asn or "N/A",
            geo.org or "N/A",
            result.ptr or "N/A",
        )

    if len(results) > 10:
        table.add_row("...", "...", "...", "...", "...", "...")
        table.add_row(
            f"[dim]Showing 10 of {len(results)} results[/dim]", "", "", "", "", ""
        )

    console.print(table)


def save_results(
    results: List[EnrichedIP], output_path: str, format_type: str = "json"
) -> None:
    """Save enrichment results to file"""
    output_file = Path(output_path)

    if format_type.lower() == "json":
        # Convert dataclasses to dict for JSON serialization
        json_data = []
        for result in results:
            result_dict = asdict(result)
            # Remove None values for cleaner JSON
            result_dict = {k: v for k, v in result_dict.items() if v is not None}
            json_data.append(result_dict)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

    elif format_type.lower() == "csv":
        import csv

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(
                [
                    "IP",
                    "PTR",
                    "Country",
                    "City",
                    "ASN",
                    "ASN_Description",
                    "Organization",
                    "ISP",
                    "Timestamp",
                ]
            )
            # Write data
            for result in results:
                geo = result.geo or GeoInfo()
                asn = result.asn or ASNInfo()
                writer.writerow(
                    [
                        result.ip,
                        result.ptr or "",
                        geo.country or "",
                        geo.city or "",
                        asn.asn or "",
                        asn.asn_description or "",
                        geo.org or "",
                        geo.isp or "",
                        result.timestamp or "",
                    ]
                )

    logger.info(f"Results saved to: {output_file}")


@click.command()
@click.option(
    "--input", "-i", required=True, help="Input file containing IPs or IP data (JSON)"
)
@click.option("--output", "-o", required=True, help="Output file for enriched data")
@click.option(
    "--format",
    "-f",
    default="json",
    type=click.Choice(["json", "csv"]),
    help="Output format",
)
@click.option(
    "--timeout", "-t", default=10, help="Timeout for network requests (seconds)"
)
@click.option("--workers", "-w", default=5, help="Number of concurrent workers")
@click.option("--no-cache", is_flag=True, help="Disable result caching")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress display")
def main(
    input: str,
    output: str,
    format: str,
    timeout: int,
    workers: int,
    no_cache: bool,
    verbose: bool,
    quiet: bool,
):
    """
    🔍 IP Enricher - Advanced IP Intelligence and Geolocation Analysis

    Enrich IP addresses with PTR records, geolocation, ASN data, and threat intelligence.

    Examples:
        enricher --input ips.json --output enriched.json
        enricher --input ips.txt --output results.csv --format csv
        enricher --input data.json --output output.json --workers 10 --timeout 15
    """

    # Configure logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)

    console.rule("[bold blue]🔍 IP Enricher - Starting Analysis")

    try:
        # Load input data
        input_path = Path(input)
        if not input_path.exists():
            console.print(f"[red]Error: Input file '{input}' not found[/red]")
            sys.exit(1)

        with open(input_path, "r", encoding="utf-8") as f:
            if input_path.suffix.lower() == ".json":
                data = json.load(f)
            else:
                # Treat as text file with one IP per line
                data = [line.strip() for line in f if line.strip()]

        # Extract IPs
        if isinstance(data, list) and data:
            if isinstance(data[0], dict):
                ip_list = extract_ips_from_data(data)
            else:
                ip_list = [str(item) for item in data if str(item).strip()]
        else:
            console.print("[red]Error: Invalid input data format[/red]")
            sys.exit(1)

        if not ip_list:
            console.print("[red]Error: No IP addresses found in input data[/red]")
            sys.exit(1)

        console.print(
            f"[green]Found {len(ip_list)} unique IP addresses to enrich[/green]"
        )

        # Initialize enricher
        enricher = IPEnricher(
            timeout=timeout, max_workers=workers, enable_cache=not no_cache
        )

        # Perform enrichment
        results = enricher.enrich_bulk(ip_list, show_progress=not quiet)

        # Display summary
        if not quiet:
            display_enrichment_summary(results)

        # Save results
        save_results(results, output, format)

        # Final statistics
        successful = sum(
            1
            for r in results
            if r.geo is not None or r.asn is not None or r.ptr is not None
        )
        console.print(f"\n[green]✅ Enrichment completed successfully![/green]")
        console.print(f"📊 Results: {successful}/{len(results)} IPs enriched with data")
        console.print(f"💾 Output saved to: {output}")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


# Legacy function for backward compatibility
def enrich(data):
    """Legacy function for backward compatibility"""
    logger.warning(
        "Using legacy enrich() function. Consider upgrading to the new IPEnricher class."
    )

    enricher = IPEnricher()
    enriched = []

    for entry in data:
        ip = entry.get("ip")
        if not ip:
            continue

        result = enricher.enrich_ip(ip)

        # Convert back to old format
        entry_copy = entry.copy()
        entry_copy["ptr"] = result.ptr
        entry_copy["geo"] = asdict(result.geo) if result.geo else {}
        entry_copy["asn"] = asdict(result.asn) if result.asn else {}
        enriched.append(entry_copy)

    return enriched


if __name__ == "__main__":
    main()
