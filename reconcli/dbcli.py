#!/usr/bin/env python3
"""
Database CLI for ReconCLI

Simple command-line interface for managing the ReconCLI database.
Provides basic operations like initialization, backup, and statistics.
"""

import click
import json
import subprocess
import os
import shutil
from typing import Optional
from pathlib import Path


def find_executable(name):
    """Find full path to executable, preventing B607 partial path issues."""
    full_path = shutil.which(name)
    if full_path:
        return full_path
    raise FileNotFoundError(f"Executable '{name}' not found in PATH")


@click.group()
def dbcli():
    """ReconCLI Database Management

    Manage reconnaissance data storage and retrieval.
    """
    pass


@dbcli.command()
@click.option(
    "--db-path", "-d", help="Database file path (default: ~/.reconcli/reconcli.db)"
)
def init(db_path: Optional[str]):
    """Initialize ReconCLI database"""
    try:
        from reconcli.db import get_db_manager

        db = get_db_manager(db_path)
        info = db.get_database_info()

        click.echo("✅ Database initialized successfully!")
        click.echo(f"📁 Database path: {info['database_path']}")
        click.echo(f"💾 Database size: {info['database_size_mb']:.2f} MB")

        if "tables" in info:
            click.echo("\n📊 Table counts:")
            for table, count in info["tables"].items():
                click.echo(f"  {table}: {count}")
    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        click.echo("Install SQLAlchemy first: pip install sqlalchemy>=2.0.0")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error initializing database: {e}")
        exit(1)


@dbcli.command()
@click.option("--backup-path", "-b", help="Backup file path (default: auto-generated)")
def backup(backup_path: Optional[str]):
    """Create database backup"""
    try:
        from reconcli.db import get_db_manager

        db = get_db_manager()
        backup_file = db.backup_database(backup_path)
        click.echo(f"✅ Database backed up to: {backup_file}")
    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error creating backup: {e}")
        exit(1)


@dbcli.command()
@click.argument("backup_path")
def restore(backup_path: str):
    """Restore database from backup"""
    try:
        from reconcli.db import get_db_manager

        db = get_db_manager()
        db.restore_database(backup_path)
        click.echo(f"✅ Database restored from: {backup_path}")
    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error restoring database: {e}")
        exit(1)


@dbcli.command()
def stats():
    """Show database statistics"""
    try:
        from reconcli.db import get_db_manager
        from reconcli.db.models import Vulnerability, VulnSeverity, VulnType

        db = get_db_manager()
        info = db.get_database_info()

        click.echo("📊 ReconCLI Database Statistics")
        click.echo("=" * 40)
        click.echo(f"Database: {info['database_path']}")
        click.echo(f"Size: {info['database_size_mb']:.2f} MB")

        if "tables" in info:
            click.echo("\nTable Counts:")
            for table, count in info["tables"].items():
                click.echo(f"  {table.ljust(15)}: {count:,}")

        # Detailed vulnerability statistics
        if info["tables"].get("vulnerabilities", 0) > 0:
            with db.get_session() as session:
                click.echo("\n🐛 Vulnerability Breakdown:")

                # By severity
                click.echo("\n📊 By Severity:")
                for severity in VulnSeverity:
                    count = (
                        session.query(Vulnerability)
                        .filter_by(severity=severity)
                        .count()
                    )
                    if count > 0:
                        severity_icon = {
                            VulnSeverity.CRITICAL: "🔥",
                            VulnSeverity.HIGH: "⚠️",
                            VulnSeverity.MEDIUM: "🟡",
                            VulnSeverity.LOW: "🔵",
                            VulnSeverity.INFO: "ℹ️",
                        }.get(severity, "⚪")
                        click.echo(
                            f"  {severity_icon} {severity.value.upper().ljust(8)}: {count:,}"
                        )

                # By type
                click.echo("\n🔍 By Type:")
                for vuln_type in VulnType:
                    count = (
                        session.query(Vulnerability)
                        .filter_by(vuln_type=vuln_type)
                        .count()
                    )
                    if count > 0:
                        type_icon = {
                            VulnType.XSS: "🚨",
                            VulnType.SQLI: "💉",
                            VulnType.SSRF: "🌐",
                            VulnType.LFI: "📁",
                            VulnType.RFI: "🔗",
                            VulnType.RCE: "💥",
                            VulnType.IDOR: "🔑",
                            VulnType.BROKEN_AUTH: "🔐",
                            VulnType.SENSITIVE_DATA: "📊",
                            VulnType.XXE: "📋",
                            VulnType.CSRF: "🎭",
                            VulnType.OPEN_REDIRECT: "↗️",
                        }.get(vuln_type, "🔍")
                        type_name = vuln_type.value.replace("_", " ").title()
                        click.echo(f"  {type_icon} {type_name.ljust(15)}: {count:,}")

                # Recent findings
                from datetime import datetime, timedelta

                recent_date = datetime.now() - timedelta(days=7)
                recent_count = (
                    session.query(Vulnerability)
                    .filter(Vulnerability.discovered_date >= recent_date)
                    .count()
                )
                if recent_count > 0:
                    click.echo(f"\n🕒 Recent (7 days): {recent_count:,}")

                # Top targets with vulnerabilities
                from reconcli.db.models import Target
                from sqlalchemy import func

                click.echo("\n🎯 Top Affected Targets:")
                top_targets = (
                    session.query(
                        Target.domain, func.count(Vulnerability.id).label("vuln_count")
                    )
                    .join(Vulnerability)
                    .group_by(Target.domain)
                    .order_by(func.count(Vulnerability.id).desc())
                    .limit(5)
                    .all()
                )

                for target, count in top_targets:
                    click.echo(f"  🔴 {target.ljust(20)}: {count:,} vulnerabilities")

    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error getting statistics: {e}")
        exit(1)


@dbcli.command()
@click.argument("domain")
@click.option("--program", "-p", help="Bug bounty program name")
@click.option(
    "--scope",
    "-s",
    default="unknown",
    help="Target scope (in_scope/out_of_scope/unknown)",
)
@click.option(
    "--priority", default="medium", help="Priority (critical/high/medium/low)"
)
def add_target(domain: str, program: Optional[str], scope: str, priority: str):
    """Add a new reconnaissance target"""
    try:
        from reconcli.db.operations import store_target

        target_id = store_target(domain, program, scope, priority)
        click.echo(f"✅ Target added: {domain} (ID: {target_id})")
        if program:
            click.echo(f"   Program: {program}")
        click.echo(f"   Scope: {scope}")
        click.echo(f"   Priority: {priority}")
    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error adding target: {e}")
        exit(1)


@dbcli.command()
@click.argument("domain")
def show_target(domain: str):
    """Show target information and statistics"""
    try:
        from reconcli.db.operations import get_target, get_subdomains

        target_info = get_target(domain)
        if not target_info:
            click.echo(f"❌ Target not found: {domain}")
            return

        click.echo(f"🎯 Target: {domain}")
        click.echo("=" * 40)
        click.echo(f"Program: {target_info.get('program', 'N/A')}")
        click.echo(f"Scope: {target_info['scope']}")
        click.echo(f"Priority: {target_info['priority']}")
        click.echo(f"Added: {target_info['added_date']}")
        if target_info["last_scan"]:
            click.echo(f"Last scan: {target_info['last_scan']}")

        # Get subdomains
        subdomains = get_subdomains(domain, limit=10)
        if subdomains:
            click.echo(f"\n🔍 Recent Subdomains ({len(subdomains)}):")
            for sub in subdomains[:5]:
                click.echo(f"  {sub['subdomain']} ({sub['discovery_method']})")
            if len(subdomains) > 5:
                click.echo(f"  ... and {len(subdomains) - 5} more")

    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error showing target: {e}")
        exit(1)


@dbcli.command()
@click.option("--days", "-d", default=7, help="Number of days to look back")
def recent(days: int):
    """Show recent discoveries"""
    try:
        from reconcli.db.operations import get_recent_discoveries

        discoveries = get_recent_discoveries(days)

        click.echo(f"🔥 Recent Discoveries (last {days} days)")
        click.echo("=" * 50)

        if discoveries["subdomains"]:
            click.echo(f"\n🌐 Subdomains ({len(discoveries['subdomains'])}):")
            for sub in discoveries["subdomains"][:10]:
                click.echo(
                    f"  {sub['subdomain']} ({sub['target_domain']}) - {sub['discovery_method']}"
                )

        if discoveries["vulnerabilities"]:
            click.echo(f"\n🐛 Vulnerabilities ({len(discoveries['vulnerabilities'])}):")
            for vuln in discoveries["vulnerabilities"][:10]:
                severity_icon = {
                    "critical": "🔥",
                    "high": "⚠️",
                    "medium": "🟡",
                    "low": "🔵",
                }.get(vuln["severity"], "⚪")
                click.echo(
                    f"  {severity_icon} {vuln['title']} ({vuln['target_domain']}) - {vuln['type']}"
                )

        if not discoveries["subdomains"] and not discoveries["vulnerabilities"]:
            click.echo("No recent discoveries found.")

    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error getting recent discoveries: {e}")
        exit(1)


@dbcli.command()
@click.option(
    "--table",
    "-t",
    type=click.Choice(
        [
            "subdomains",
            "targets",
            "whois_findings",
            "vulnerabilities",
            "port_scans",
            "scan_sessions",
        ]
    ),
    help="Table to export",
)
@click.option(
    "--output-dir", "-o", default="output/exports", help="Output directory for exports"
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["csv", "json", "pretty"]),
    default="csv",
    help="Export format",
)
@click.option(
    "--analysis", "-a", is_flag=True, help="Run csvtk analysis on exported data"
)
@click.option("--stats", is_flag=True, help="Show statistics with csvtk")
@click.option("--filter", help="SQLite WHERE clause filter")
@click.option(
    "--join-targets", is_flag=True, help="Join with targets table for domain info"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def export(table, output_dir, format, analysis, stats, filter, join_targets, verbose):
    """Export database data with optional csvtk analysis"""
    try:
        from reconcli.db import get_db_manager

        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Get database path
        db = get_db_manager()
        info = db.get_database_info()
        db_path = info["database_path"]

        if verbose:
            click.echo(f"📂 Database: {db_path}")
            click.echo(f"📁 Output directory: {output_dir}")

        # Export data based on table selection
        if table:
            export_file = os.path.join(output_dir, f"{table}_export.csv")
            _export_table(db_path, table, export_file, filter, join_targets, verbose)

            if analysis:
                _run_csvtk_analysis(export_file, verbose)
            elif stats:
                _run_csvtk_stats(export_file, verbose)
        else:
            # Export all tables
            click.echo("📊 Exporting all tables...")
            exported_files = []

            tables = [
                "subdomains",
                "targets",
                "whois_findings",
                "vulnerabilities",
                "port_scans",
            ]
            for tbl in tables:
                export_file = os.path.join(output_dir, f"{tbl}_export.csv")
                try:
                    _export_table(
                        db_path, tbl, export_file, filter, join_targets, verbose
                    )
                    exported_files.append(export_file)
                except Exception as e:
                    if verbose:
                        click.echo(f"⚠️ Could not export {tbl}: {e}")

            if analysis and exported_files:
                for file in exported_files:
                    click.echo(f"\n📈 Analysis for {os.path.basename(file)}:")
                    _run_csvtk_analysis(file, verbose)

    except ImportError as e:
        click.echo(f"❌ Database module not available: {e}")
        exit(1)
    except Exception as e:
        click.echo(f"❌ Error during export: {e}")
        exit(1)


def _export_table(db_path, table, output_file, filter_clause, join_targets, verbose):
    """Export specific table to CSV"""
    if join_targets and table == "subdomains":
        query = """
        SELECT s.subdomain, s.ip_address, s.discovery_method, s.discovered_date, 
               s.status, s.http_status, s.http_title, t.domain
        FROM subdomains s 
        JOIN targets t ON s.target_id = t.id
        """
    elif join_targets and table == "whois_findings":
        query = """
        SELECT w.domain, w.registrar, w.creation_date, w.expiration_date, 
               w.name_servers, w.status, t.domain as target_domain
        FROM whois_findings w 
        JOIN targets t ON w.target_id = t.id
        """
    else:
        # Validate table name to prevent SQL injection
        valid_tables = {
            "targets",
            "subdomains",
            "dns_records",
            "http_responses",
            "vulnerabilities",
            "whois_findings",
            "crawl_results",
            "port_scan_results",
            "ssl_info",
            "directory_results",
        }
        if table not in valid_tables:
            click.echo(f"❌ Invalid table name: {table}")
            click.echo(f"Valid tables: {', '.join(sorted(valid_tables))}")
            return

        # Safe table name insertion (validated above)
        query = f"SELECT * FROM {table}"  # nosec: B608 - table name validated above

    if filter_clause:
        query += f" WHERE {filter_clause}"

    # Export using sqlite3 command safely
    if verbose:
        click.echo(f"🔄 Exporting {table}...")

    with open(output_file, "w") as f:
        result = subprocess.run(
            [find_executable("sqlite3"), db_path, "-header", "-csv", query],
            stdout=f,
            capture_output=False,
            text=True,
        )

    if result.returncode == 0:
        # Check if file has data
        with open(output_file, "r") as f:
            lines = f.readlines()
            if len(lines) > 1:  # More than just header
                click.echo(f"✅ Exported {len(lines)-1} records to {output_file}")
            else:
                click.echo(f"⚠️ No data found in {table}")
    else:
        raise Exception(f"Export failed: {result.stderr}")


def _run_csvtk_analysis(csv_file, verbose):
    """Run comprehensive csvtk analysis on exported data"""
    if not _check_csvtk():
        return

    try:
        # Basic stats
        click.echo("📊 Basic Statistics:")
        subprocess.run([find_executable("csvtk"), "stats", csv_file], check=True)

        # Pretty view (first 10 rows)
        click.echo("\n📋 Sample Data:")
        proc1 = subprocess.Popen(
            [find_executable("csvtk"), "head", "-n", "10", csv_file],
            stdout=subprocess.PIPE,
            text=True,
        )
        subprocess.run(
            [find_executable("csvtk"), "pretty"], stdin=proc1.stdout, check=True
        )
        if proc1.stdout:
            proc1.stdout.close()
        proc1.wait()

        # Column frequency analysis for key fields
        result = subprocess.run(
            [find_executable("csvtk"), "headers", csv_file],
            capture_output=True,
            text=True,
            check=True,
        )
        headers = result.stdout.strip().split("\n")

        for header in headers:
            if any(
                keyword in header.lower()
                for keyword in ["domain", "method", "status", "registrar"]
            ):
                click.echo(f"\n🔍 Frequency analysis for '{header}':")
                subprocess.run(
                    [find_executable("csvtk"), "freq", "-f", header, csv_file],
                    check=True,
                )

    except subprocess.CalledProcessError as e:
        if verbose:
            click.echo(f"⚠️ Analysis error: {e}")
    except Exception as e:
        if verbose:
            click.echo(f"⚠️ Unexpected error: {e}")


def _run_csvtk_stats(csv_file, verbose):
    """Run basic csvtk statistics"""
    if not _check_csvtk():
        return

    try:
        click.echo("📊 CSV Statistics:")
        subprocess.run([find_executable("csvtk"), "nrow", csv_file], check=True)
        subprocess.run([find_executable("csvtk"), "ncol", csv_file], check=True)
        subprocess.run([find_executable("csvtk"), "headers", csv_file], check=True)

    except subprocess.CalledProcessError as e:
        if verbose:
            click.echo(f"⚠️ Stats error: {e}")


def _check_csvtk():
    """Check if csvtk is available"""
    try:
        subprocess.run(
            [find_executable("csvtk"), "--version"], capture_output=True, check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo(
            "⚠️ csvtk not found. Install it from: https://github.com/shenwei356/csvtk"
        )
        click.echo("   or run: conda install -c bioconda csvtk")
        return False


@dbcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option(
    "--analysis-type",
    "-t",
    type=click.Choice(["freq", "stats", "pretty", "grep", "summary"]),
    default="summary",
    help="Type of analysis to run",
)
@click.option("--field", "-f", help="Field name for frequency/grep analysis")
@click.option("--pattern", "-p", help="Pattern for grep analysis")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(csv_file, analysis_type, field, pattern, verbose):
    """Analyze CSV data using csvtk

    Examples:
    python -m reconcli.dbcli analyze subdomains.csv -t freq -f discovery_method
    python -m reconcli.dbcli analyze subdomains.csv -t grep -f subdomain -p "api"
    """
    if not _check_csvtk():
        return

    try:
        click.echo(f"🔍 Running {analysis_type} analysis on {csv_file}")

        if analysis_type == "summary":
            # Comprehensive summary
            click.echo("📊 File Summary:")
            subprocess.run([find_executable("csvtk"), "nrow", csv_file], check=True)
            subprocess.run([find_executable("csvtk"), "ncol", csv_file], check=True)
            subprocess.run([find_executable("csvtk"), "headers", csv_file], check=True)

            click.echo("\n📋 Sample Data:")
            proc1 = subprocess.Popen(
                [find_executable("csvtk"), "head", "-n", "5", csv_file],
                stdout=subprocess.PIPE,
                text=True,
            )
            subprocess.run(
                [find_executable("csvtk"), "pretty"], stdin=proc1.stdout, check=True
            )
            if proc1.stdout:
                proc1.stdout.close()
            proc1.wait()

        elif analysis_type == "freq" and field:
            subprocess.run(
                [find_executable("csvtk"), "freq", "-f", field, csv_file], check=True
            )

        elif analysis_type == "grep" and field and pattern:
            proc1 = subprocess.Popen(
                [
                    find_executable("csvtk"),
                    "grep",
                    "-f",
                    field,
                    "-p",
                    pattern,
                    csv_file,
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            subprocess.run(
                [find_executable("csvtk"), "pretty"], stdin=proc1.stdout, check=True
            )
            if proc1.stdout:
                proc1.stdout.close()
            proc1.wait()

        elif analysis_type == "stats":
            subprocess.run([find_executable("csvtk"), "stats", csv_file], check=True)

        elif analysis_type == "pretty":
            subprocess.run([find_executable("csvtk"), "pretty", csv_file], check=True)

        else:
            click.echo("❌ Invalid combination of parameters")

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Analysis failed: {e}")
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}")
