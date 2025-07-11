#!/usr/bin/env python3
"""
Database CLI for ReconCLI

Simple command-line interface for managing the ReconCLI database.
Provides basic operations like initialization, backup, and statistics.
"""

import click
import json
from typing import Optional


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


if __name__ == "__main__":
    dbcli()
