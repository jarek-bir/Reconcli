#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🌐 SHODAN CLI - ReconCLI Elite Edition
Advanced Shodan integration with multiple output formats and enhanced features

Examples:
    # Basic search
    reconcli shodancli -q "apache" -c 50

    # IP lookup with detailed output
    reconcli shodancli -ip 8.8.8.8 --format table

    # Export to multiple formats
    reconcli shodancli -q "port:22" --format csv --save results.csv

    # Advanced search with filters
    reconcli shodancli -q "nginx" --country US --org "Google" --format json

    # ASN enumeration
    reconcli shodancli -asn AS15169 --format table --save google_ips.json

    # Exploit search
    reconcli shodancli --exploit "apache" --severity high --format table

    # Facet analysis
    reconcli shodancli -q "port:80" --facets "country,org" --format json

    # AI-powered analysis
    reconcli shodancli -q "mongodb" --ai --format rich

    # Combined operations
    reconcli shodancli -q "IIS" --country US --ports 80,443 --format rich
"""

import os
import sys
import json
import argparse
import shodan
import csv
import datetime
import sqlite3
import time
import click
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ShodanCLI:
    """Enhanced Shodan CLI with advanced output formatting and filtering"""

    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.api_key = self.get_api_key()
        self.api = shodan.Shodan(self.api_key)

    def get_api_key(self) -> str:
        """Get Shodan API key from environment"""
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            self.error("[!] SHODAN_API_KEY nie ustawiony w zmiennych środowiskowych.")
            sys.exit(1)
        return key

    def error(self, message: str):
        """Print error message"""
        if self.console:
            self.console.print(f"[red]{message}[/red]")
        else:
            print(message)

    def success(self, message: str):
        """Print success message"""
        if self.console:
            self.console.print(f"[green]{message}[/green]")
        else:
            print(message)

    def info(self, message: str):
        """Print info message"""
        if self.console:
            self.console.print(f"[blue]{message}[/blue]")
        else:
            print(message)

    def init_database(self) -> str:
        """Initialize SQLite database for storing results"""
        db_path = Path.home() / ".reconcli" / "shodan_results.db"
        db_path.parent.mkdir(exist_ok=True)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS shodan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                query TEXT,
                ip_str TEXT,
                port INTEGER,
                product TEXT,
                version TEXT,
                organization TEXT,
                country TEXT,
                asn TEXT,
                data TEXT,
                raw_json TEXT
            )
        """
        )

        conn.commit()
        conn.close()
        return str(db_path)

    def store_to_database(self, data: Any, query: Optional[str] = None):
        """Store results to SQLite database"""
        db_path = self.init_database()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        timestamp = datetime.datetime.now().isoformat()

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    cursor.execute(
                        """
                        INSERT INTO shodan_results 
                        (timestamp, query, ip_str, port, product, version, organization, 
                         country, asn, data, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            timestamp,
                            query,
                            item.get("ip_str", ""),
                            item.get("port"),
                            item.get("product", ""),
                            item.get("version", ""),
                            item.get("org", ""),
                            item.get("location", {}).get("country_name", ""),
                            item.get("asn", ""),
                            item.get("data", ""),
                            json.dumps(item),
                        ),
                    )

        conn.commit()
        conn.close()
        self.success(f"[+] Zapisano wyniki do bazy danych: {db_path}")

    def retry_api_call(self, func, *args, max_retries: int = 1, **kwargs):
        """Retry API calls with exponential backoff"""
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == max_retries:
                    raise e

                wait_time = 2**attempt  # Exponential backoff
                self.info(
                    f"[!] API error (attempt {attempt + 1}/{max_retries + 1}): {e}"
                )
                self.info(f"[!] Retrying in {wait_time} seconds...")
                time.sleep(wait_time)

    def ai_analyze_results(self, data: Any, query: str = "") -> str:
        """AI-powered analysis of Shodan results"""
        if not data:
            return "No data to analyze"

        analysis = []
        analysis.append(f"🤖 AI Analysis for query: '{query}'")
        analysis.append("=" * 50)

        if isinstance(data, list):
            total_results = len(data)
            analysis.append(f"📊 Total results: {total_results}")

            # Analyze countries
            countries = {}
            ports = {}
            products = {}
            orgs = {}

            for item in data:
                # Country analysis
                country = item.get("location", {}).get("country_name", "Unknown")
                countries[country] = countries.get(country, 0) + 1

                # Port analysis
                port = str(item.get("port", "Unknown"))
                ports[port] = ports.get(port, 0) + 1

                # Product analysis
                product = item.get("product", "Unknown")
                products[product] = products.get(product, 0) + 1

                # Organization analysis
                org = item.get("org", "Unknown")
                orgs[org] = orgs.get(org, 0) + 1

            # Top countries
            analysis.append("\n🌍 Geographic Distribution:")
            top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[
                :5
            ]
            for country, count in top_countries:
                percentage = (count / total_results) * 100
                analysis.append(f"  {country}: {count} ({percentage:.1f}%)")

            # Top ports
            analysis.append("\n🔌 Port Distribution:")
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]
            for port, count in top_ports:
                percentage = (count / total_results) * 100
                analysis.append(f"  Port {port}: {count} ({percentage:.1f}%)")

            # Top products
            analysis.append("\n📦 Product Distribution:")
            top_products = sorted(products.items(), key=lambda x: x[1], reverse=True)[
                :5
            ]
            for product, count in top_products:
                if product != "Unknown":
                    percentage = (count / total_results) * 100
                    analysis.append(f"  {product}: {count} ({percentage:.1f}%)")

            # Security insights
            analysis.append("\n🔒 Security Insights:")

            # Check for common vulnerable services
            vulnerable_services = {
                "telnet": 23,
                "ftp": 21,
                "ssh": 22,
                "rdp": 3389,
                "vnc": 5900,
                "mongodb": 27017,
                "elasticsearch": 9200,
                "redis": 6379,
            }

            found_vulnerable = []
            for item in data:
                port = item.get("port")
                product = item.get("product", "").lower()

                for service, default_port in vulnerable_services.items():
                    if port == default_port or service in product:
                        found_vulnerable.append(service)

            if found_vulnerable:
                unique_vulnerable = list(set(found_vulnerable))
                analysis.append(
                    f"  ⚠️  Found potentially vulnerable services: {', '.join(unique_vulnerable)}"
                )
            else:
                analysis.append("  ✅ No commonly vulnerable services detected")

            # Check for default ports
            default_ports = [21, 23, 135, 445, 1433, 3389, 5432, 27017, 9200, 6379]
            risky_ports = [
                port
                for port in ports.keys()
                if port.isdigit() and int(port) in default_ports
            ]

            if risky_ports:
                analysis.append(
                    f"  ⚠️  Services on default ports detected: {', '.join(risky_ports)}"
                )

            # Recommendations
            analysis.append("\n💡 Recommendations:")
            if "mongodb" in str(data).lower():
                analysis.append(
                    "  - MongoDB instances found - verify authentication is enabled"
                )
            if "elasticsearch" in str(data).lower():
                analysis.append(
                    "  - Elasticsearch instances found - check for public access"
                )
            if any(int(p) in [21, 23] for p in ports.keys() if p.isdigit()):
                analysis.append(
                    "  - Legacy protocols (FTP/Telnet) found - consider secure alternatives"
                )
            if any(int(p) == 3389 for p in ports.keys() if p.isdigit()):
                analysis.append(
                    "  - RDP services found - ensure strong authentication and VPN access"
                )

        elif isinstance(data, dict):
            # Single host analysis
            if "ip_str" in data:
                analysis.append(f"🎯 Target: {data.get('ip_str')}")
                analysis.append(f"🏢 Organization: {data.get('org', 'Unknown')}")
                analysis.append(
                    f"🌍 Country: {data.get('location', {}).get('country_name', 'Unknown')}"
                )

                if "vulns" in data:
                    vulns = data["vulns"]
                    analysis.append(f"\n🚨 Vulnerabilities: {len(vulns)} found")
                    if isinstance(vulns, dict):
                        for cve in list(vulns.keys())[:5]:  # Show first 5 CVEs
                            analysis.append(f"  - {cve}")
                    elif isinstance(vulns, list):
                        for cve in vulns[:5]:  # Show first 5 CVEs
                            analysis.append(f"  - {cve}")

        return "\n".join(analysis)

    def format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        value = float(bytes_value)
        for unit in ["B", "KB", "MB", "GB"]:
            if value < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} TB"

    def save_to_file(self, data: Any, filename: str, format_type: str):
        """Save data to file in specified format"""
        try:
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)

            if format_type == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif format_type == "csv":
                self.save_to_csv(data, filename)
            elif format_type == "txt":
                with open(filename, "w", encoding="utf-8") as f:
                    if isinstance(data, list):
                        for item in data:
                            f.write(
                                f"{item.get('ip_str', item.get('ip', str(item)))}\n"
                            )
                    else:
                        f.write(str(data))

            self.success(f"[+] Zapisano do {filename}")
        except Exception as e:
            self.error(f"[!] Błąd zapisu do pliku: {e}")

    def save_to_csv(self, data: Any, filename: str):
        """Save data to CSV format"""
        if not data:
            return

        # Flatten nested dictionaries for CSV
        def flatten_dict(d, parent_key="", sep="_"):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key, sep=sep).items())
                elif isinstance(v, list):
                    items.append((new_key, ", ".join(map(str, v))))
                else:
                    items.append((new_key, v))
            return dict(items)

        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return

        flattened_data = [
            flatten_dict(item) if isinstance(item, dict) else item for item in data
        ]

        if not flattened_data:
            return

        # Get all possible keys
        all_keys = set()
        for item in flattened_data:
            if isinstance(item, dict):
                all_keys.update(item.keys())

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()
            for item in flattened_data:
                if isinstance(item, dict):
                    row = {k: str(v) if v is not None else "" for k, v in item.items()}
                    writer.writerow(row)

    def print_table_output(self, data: Any, title: str = "Shodan Results"):
        """Print data in rich table format"""
        if not RICH_AVAILABLE:
            self.print_json_output(data)
            return

        if not data:
            self.error("Brak danych do wyświetlenia")
            return

        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            self.error("Nieprawidłowy format danych")
            return

        table = Table(title=title)

        # Add columns based on first item
        if data:
            first_item = data[0]
            if isinstance(first_item, dict):
                # Common columns for search results
                if "ip_str" in first_item:
                    table.add_column("IP", style="cyan")
                    table.add_column("Port", style="magenta")
                    table.add_column("Product", style="green")
                    table.add_column("Version", style="yellow")
                    table.add_column("Country", style="blue")
                    table.add_column("Organization", style="white")

                    for item in data:
                        table.add_row(
                            item.get("ip_str", ""),
                            str(item.get("port", "")),
                            item.get("product", ""),
                            item.get("version", ""),
                            item.get("location", {}).get("country_name", ""),
                            item.get("org", ""),
                        )
                else:
                    # Generic table for other data
                    columns = list(first_item.keys())[:6]  # Limit columns
                    for col in columns:
                        table.add_column(col.title(), style="cyan")

                    for item in data:
                        row = []
                        for col in columns:
                            value = item.get(col, "")
                            if isinstance(value, (dict, list)):
                                value = (
                                    str(value)[:50] + "..."
                                    if len(str(value)) > 50
                                    else str(value)
                                )
                            row.append(str(value))
                        table.add_row(*row)

        if self.console:
            self.console.print(table)
        else:
            print("Tabela wyników (rich nie dostępne)")
            for item in data:
                print(f"IP: {item.get('ip_str', '')}, Port: {item.get('port', '')}")

    def print_rich_output(self, data: Any):
        """Print data in rich format with panels and styling"""
        if not RICH_AVAILABLE or not self.console:
            self.print_json_output(data)
            return

        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            self.print_json_output(data)
            return

        for i, item in enumerate(data, 1):
            if isinstance(item, dict):
                # Create panels for each result
                content = []

                # Basic info
                if "ip_str" in item:
                    content.append(f"🌐 IP: {item.get('ip_str', 'N/A')}")
                    content.append(f"🔌 Port: {item.get('port', 'N/A')}")
                    content.append(f"📦 Product: {item.get('product', 'N/A')}")
                    content.append(f"🏷️ Version: {item.get('version', 'N/A')}")

                    # Location info
                    location = item.get("location", {})
                    if location:
                        content.append(
                            f"🌍 Country: {location.get('country_name', 'N/A')}"
                        )
                        content.append(f"🏙️ City: {location.get('city', 'N/A')}")

                    content.append(f"🏢 Organization: {item.get('org', 'N/A')}")
                    content.append(f"🕐 Last Update: {item.get('timestamp', 'N/A')}")

                panel_content = "\n".join(content)
                panel = Panel(panel_content, title=f"Result {i}", border_style="blue")
                if self.console:
                    self.console.print(panel)

                if i % 5 == 0 and i < len(data):  # Pause every 5 results
                    input("\nPress Enter to continue...")

    def print_json_output(self, data: Any):
        """Print data in JSON format"""
        if RICH_AVAILABLE and self.console:
            syntax = Syntax(
                json.dumps(data, indent=2, ensure_ascii=False), "json", theme="monokai"
            )
            self.console.print(syntax)
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))

    def print_silent_output(self, data: Any):
        """Print only IPs in silent mode"""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get("ip_str") or item.get("ip")
                    if ip:
                        print(ip)
        elif isinstance(data, dict):
            ip = data.get("ip_str") or data.get("ip")
            if ip:
                print(ip)

    def print_txt_output(self, data: Any):
        """Print IPs in txt format"""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get("ip_str") or item.get("ip")
                    if ip:
                        print(ip)
        elif isinstance(data, dict):
            ip = data.get("ip_str") or data.get("ip")
            if ip:
                print(ip)

    def print_output(self, data: Any, args):
        """Main output handler"""
        if not data:
            self.error("Brak wyników")
            return

        # AI Analysis first if enabled
        if hasattr(args, "ai") and args.ai:
            query_str = (
                getattr(args, "query", "")
                or getattr(args, "host", "")
                or getattr(args, "exploit", "")
                or getattr(args, "asn", "")
            )
            ai_analysis = self.ai_analyze_results(data, query_str)
            self.info(ai_analysis)
            print()  # Add spacing

        if hasattr(args, "silent") and args.silent:
            self.print_silent_output(data)
            return

        if hasattr(args, "save") and args.save:
            format_type = (
                args.format
                if hasattr(args, "format") and args.format in ["json", "csv", "txt"]
                else "json"
            )
            if args.save.endswith(".csv"):
                format_type = "csv"
            elif args.save.endswith(".txt"):
                format_type = "txt"
            self.save_to_file(data, args.save, format_type)

        # Print to console
        format_attr = getattr(args, "format", "rich")
        if format_attr == "json":
            self.print_json_output(data)
        elif format_attr == "table":
            self.print_table_output(data)
        elif format_attr == "rich":
            self.print_rich_output(data)
        elif format_attr == "txt":
            self.print_txt_output(data)
        elif format_attr == "csv":
            # For CSV format, save to file and show summary
            filename = (
                getattr(args, "save", None)
                or f"shodan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            self.save_to_csv(data, filename)
            if isinstance(data, list):
                self.success(f"[+] Zapisano {len(data)} wyników do {filename}")
            else:
                self.success(f"[+] Zapisano wyniki do {filename}")
        else:
            self.print_json_output(data)

    def search_advanced(self, query: str, args) -> Any:
        """Advanced search with filters and facets"""
        try:
            # Build query with filters
            search_query = query

            if args.country:
                search_query += f" country:{args.country}"
            if args.org:
                search_query += f' org:"{args.org}"'
            if args.ports:
                ports = args.ports.split(",")
                port_query = " OR ".join([f"port:{port.strip()}" for port in ports])
                search_query += f" ({port_query})"
            if args.product:
                search_query += f' product:"{args.product}"'
            if args.os:
                search_query += f' os:"{args.os}"'

            self.info(f"🔍 Searching: {search_query}")

            # Search with facets if requested
            if args.facets:
                facets = args.facets.split(",")
                results = self.retry_api_call(
                    self.api.search,
                    search_query,
                    limit=args.count,
                    facets=facets,
                    max_retries=getattr(args, "retry", 1),
                )
                data = {
                    "matches": results["matches"],
                    "facets": results.get("facets", {}),
                    "total": results.get("total", 0),
                }
            else:
                results = self.retry_api_call(
                    self.api.search,
                    search_query,
                    limit=args.count,
                    max_retries=getattr(args, "retry", 1),
                )
                data = results["matches"]

            # Store to database if requested
            if getattr(args, "store_db", False):
                self.store_to_database(data, search_query)

            return data
        except Exception as e:
            self.error(f"[!] Błąd Shodan API: {e}")
            sys.exit(1)

    def search_exploits(self, query: str, args) -> List[Dict]:
        """Search for exploits with severity filtering"""
        try:
            results = self.api.exploits.search(query)
            exploits = results.get("matches", [])

            # Filter by severity if specified
            if args.severity:
                severity_map = {
                    "low": [1, 2, 3],
                    "medium": [4, 5, 6],
                    "high": [7, 8, 9, 10],
                }
                if args.severity in severity_map:
                    exploits = [
                        e
                        for e in exploits
                        if e.get("cvss", 0) in severity_map[args.severity]
                    ]

            return exploits[: args.count]
        except shodan.exception.APIError as e:
            self.error(f"[!] Błąd Shodan API (exploit): {e}")
            sys.exit(1)

    def get_host_info(self, ip: str) -> Dict:
        """Get detailed host information"""
        try:
            return self.api.host(ip)
        except shodan.exception.APIError as e:
            self.error(f"[!] Błąd Shodan API: {e}")
            sys.exit(1)

    def search_asn(self, asn: str, args) -> Any:
        """Search by ASN"""
        query = f"asn:{asn}"
        return self.search_advanced(query, args)

    def get_account_info(self) -> Dict:
        """Get account information"""
        try:
            return self.api.info()
        except shodan.exception.APIError as e:
            self.error(f"[!] Błąd Shodan API: {e}")
            sys.exit(1)

    def stream_alerts(self):
        """Stream Shodan alerts (requires subscription)"""
        try:
            for alert in self.api.stream.alerts():
                self.info(f"🚨 Alert: {alert}")
        except shodan.exception.APIError as e:
            self.error(f"[!] Błąd Shodan Streaming API: {e}")


# Legacy functions for compatibility
def shodan_search(api, query, count):
    results = []
    try:
        for result in api.search_cursor(query):
            results.append(result)
            if len(results) >= count:
                break
    except shodan.exception.APIError as e:
        print(f"[!] Błąd Shodan API: {e}")
        sys.exit(1)
    return results


def shodan_host(api, ip):
    try:
        return api.host(ip)
    except shodan.exception.APIError as e:
        print(f"[!] Błąd Shodan API: {e}")
        sys.exit(1)


def shodan_exploits(api, query, count):
    try:
        results = api.exploits.search(query)
        return results["matches"][:count]
    except shodan.exception.APIError as e:
        print(f"[!] Błąd Shodan API (exploit): {e}")
        sys.exit(1)


def shodan_asn(api, asn, count):
    query = f"asn:{asn}"
    return shodan_search(api, query, count)


def create_parser():
    """Create argument parser with all options"""
    parser = argparse.ArgumentParser(
        description="🌐 Shodan CLI - ReconCLI Elite Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -q "apache" -c 50 --format table
  %(prog)s -ip 8.8.8.8 --format rich
  %(prog)s -q "nginx" --country US --format csv --save results.csv
  %(prog)s --exploit "apache" --severity high --format table
  %(prog)s -asn AS15169 --format json --save google.json
  %(prog)s -q "port:22" --facets "country,org" --format json
        """,
    )

    # Main actions
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-q", "--query", help="Shodan search query")
    action_group.add_argument("-ip", "--host", help="IP address to look up")
    action_group.add_argument("--exploit", help="Search for exploits")
    action_group.add_argument("-asn", help="Search by ASN (e.g., AS15169)")
    action_group.add_argument(
        "--account", action="store_true", help="Show account information"
    )
    action_group.add_argument(
        "--stream", action="store_true", help="Stream alerts (requires subscription)"
    )

    # Search options
    search_group = parser.add_argument_group("Search Options")
    search_group.add_argument(
        "-c", "--count", type=int, default=20, help="Maximum results (default: 20)"
    )
    search_group.add_argument("--country", help="Filter by country code (e.g., US, PL)")
    search_group.add_argument("--org", help="Filter by organization")
    search_group.add_argument(
        "--ports", help="Filter by ports (comma-separated: 80,443)"
    )
    search_group.add_argument("--product", help="Filter by product name")
    search_group.add_argument("--os", help="Filter by operating system")
    search_group.add_argument(
        "--facets", help="Facet analysis (comma-separated: country,org,port)"
    )
    search_group.add_argument(
        "--store-db",
        action="store_true",
        help="Store results in local database for analysis",
    )
    search_group.add_argument(
        "--retry",
        type=int,
        default=1,
        metavar="N",
        help="Number of retry attempts on API errors (default: 1)",
    )

    # Exploit options
    exploit_group = parser.add_argument_group("Exploit Options")
    exploit_group.add_argument(
        "--severity",
        choices=["low", "medium", "high"],
        help="Filter exploits by CVSS severity",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--format",
        choices=["json", "csv", "table", "rich", "txt"],
        default="json",
        help="Output format (default: json)",
    )
    output_group.add_argument("--save", help="Save output to file")
    output_group.add_argument(
        "--silent", action="store_true", help="Only print IPs/results"
    )
    output_group.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args(sys.argv[2:])  # skip "reconcli shodancli"

    # Initialize ShodanCLI
    cli = ShodanCLI()

    # Disable colors if requested
    if args.no_color and cli.console:
        cli.console = None

    # Execute commands
    try:
        if args.query:
            results = cli.search_advanced(args.query, args)
            cli.print_output(results, args)

        elif args.host:
            result = cli.get_host_info(args.host)
            cli.print_output(result, args)

        elif args.exploit:
            results = cli.search_exploits(args.exploit, args)
            cli.print_output(results, args)

        elif args.asn:
            results = cli.search_asn(args.asn, args)
            cli.print_output(results, args)

        elif args.account:
            info = cli.get_account_info()
            cli.print_output(info, args)

        elif args.stream:
            cli.info("🔄 Starting alert stream... (Ctrl+C to stop)")
            cli.stream_alerts()

        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        cli.info("\n👋 Przerwano przez użytkownika")
        sys.exit(0)
    except Exception as e:
        cli.error(f"[!] Nieoczekiwany błąd: {e}")
        sys.exit(1)


@click.command("shodancli")
@click.option("-q", "--query", help="Shodan search query")
@click.option("-ip", "--host", help="IP address to look up")
@click.option("--exploit", help="Search for exploits")
@click.option("-asn", help="Search by ASN (e.g., AS15169)")
@click.option("--account", is_flag=True, help="Show account information")
@click.option("--stream", is_flag=True, help="Stream alerts (requires subscription)")
@click.option(
    "-c", "--count", type=int, default=20, help="Maximum results (default: 20)"
)
@click.option("--country", help="Filter by country code (e.g., US, PL)")
@click.option("--org", help="Filter by organization")
@click.option("--ports", help="Filter by ports (comma-separated: 80,443)")
@click.option("--product", help="Filter by product name")
@click.option("--os", help="Filter by operating system")
@click.option("--facets", help="Facet analysis (comma-separated: country,org,port)")
@click.option(
    "--store-db", is_flag=True, help="Store results in local database for analysis"
)
@click.option(
    "--retry",
    type=int,
    default=1,
    help="Number of retry attempts on API errors (default: 1)",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high"]),
    help="Filter exploits by CVSS severity",
)
@click.option(
    "--format",
    type=click.Choice(["json", "csv", "table", "rich", "txt"]),
    default="json",
    help="Output format (default: json)",
)
@click.option("--save", help="Save output to file")
@click.option("--silent", is_flag=True, help="Only print IPs/results")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis of results")
def shodancli(**kwargs):
    """🌐 Shodan CLI - ReconCLI Elite Edition

    Advanced Shodan integration with multiple output formats and enhanced features

    Examples:
        reconcli shodancli -q "apache" -c 50 --format table
        reconcli shodancli -ip 8.8.8.8 --format rich
        reconcli shodancli -q "nginx" --country US --format csv --save results.csv
        reconcli shodancli --exploit "apache" --severity high --format table
        reconcli shodancli -asn AS15169 --format json --save google.json
        reconcli shodancli -q "mongodb" --ai --format rich
        reconcli shodancli -q "elasticsearch" --ai --save results.json
    """

    # Convert click arguments to argparse-compatible namespace
    class Args:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    args = Args(**kwargs)

    # Validate that at least one action is specified
    actions = [args.query, args.host, args.exploit, args.asn, args.account, args.stream]
    if not any(actions):
        click.echo(
            "❌ Error: You must specify one of: -q, -ip, --exploit, -asn, --account, or --stream"
        )
        return

    # Initialize ShodanCLI
    try:
        cli = ShodanCLI()

        # Disable colors if requested
        if args.no_color and cli.console:
            cli.console = None

        # Execute commands
        if args.query:
            results = cli.search_advanced(args.query, args)
            cli.print_output(results, args)

        elif args.host:
            result = cli.get_host_info(args.host)
            cli.print_output(result, args)

        elif args.exploit:
            results = cli.search_exploits(args.exploit, args)
            cli.print_output(results, args)

        elif args.asn:
            results = cli.search_asn(args.asn, args)
            cli.print_output(results, args)

        elif args.account:
            info = cli.get_account_info()
            cli.print_output(info, args)

        elif args.stream:
            cli.info("🔄 Starting alert stream... (Ctrl+C to stop)")
            cli.stream_alerts()

    except KeyboardInterrupt:
        click.echo("\n👋 Przerwano przez użytkownika")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Nieoczekiwany błąd: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
