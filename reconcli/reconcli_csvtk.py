#!/usr/bin/env python3
"""
ReconCLI with CSVTK Integration - Minimal Entry Point

Entry point that includes csvtkcli without problematic dependencies.
"""

import click

# Safe imports
try:
    from reconcli.dnscli import cli as dns_cli

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from reconcli.subdocli import subdocli

    SUBDOCLI_AVAILABLE = True
except ImportError:
    SUBDOCLI_AVAILABLE = False

try:
    from reconcli.csvtkcli import csvtkcli

    CSVTK_AVAILABLE = True
except ImportError:
    CSVTK_AVAILABLE = False

try:
    from reconcli.tagger import cli as tagger_cli

    TAGGER_AVAILABLE = True
except ImportError:
    TAGGER_AVAILABLE = False

try:
    from reconcli.mdreport import cli as mdreport_cli

    MDREPORT_AVAILABLE = True
except ImportError:
    MDREPORT_AVAILABLE = False

# Git operations
try:
    from reconcli.gitcli import gitcli

    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

# Database management (optional)
try:
    from reconcli.dbcli import dbcli

    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


@click.group()
def cli():
    """ReconCLI with CSVTK Integration

    Minimal entry point focusing on data analysis capabilities.
    Includes csvtk integration for advanced CSV data manipulation.
    """
    pass


# Add available commands
if DNS_AVAILABLE:
    cli.add_command(dns_cli, name="dnscli")
    dns_cli.short_help = "Enhanced DNS resolution and subdomain enumeration"

if SUBDOCLI_AVAILABLE:
    cli.add_command(subdocli, name="subdocli")
    subdocli.short_help = "Comprehensive subdomain enumeration using multiple sources"

if TAGGER_AVAILABLE:
    cli.add_command(tagger_cli, name="taggercli")
    tagger_cli.short_help = "🏷️ Advanced subdomain tagging and classification"

if MDREPORT_AVAILABLE:
    cli.add_command(mdreport_cli, name="mdreportcli")
    mdreport_cli.short_help = (
        "📊 Advanced markdown reports with templates, stats & security analysis"
    )

if CSVTK_AVAILABLE:
    cli.add_command(csvtkcli, name="csvtkcli")
    csvtkcli.short_help = "📊 Advanced CSV data analysis and manipulation using csvtk"

if GIT_AVAILABLE:
    cli.add_command(gitcli, name="gitcli")
    gitcli.short_help = "🔧 Git operations and repository management"

if DATABASE_AVAILABLE:
    cli.add_command(dbcli, name="dbcli")
    dbcli.short_help = "🗄️ Database management for reconnaissance data storage"


# Status information
@cli.command()
def status():
    """Show available modules and their status"""
    click.echo("📊 ReconCLI Module Status:")
    click.echo("=" * 40)
    click.echo(f"🔍 DNS CLI: {'✅ Available' if DNS_AVAILABLE else '❌ Not available'}")
    click.echo(
        f"🌐 Subdomain CLI: {'✅ Available' if SUBDOCLI_AVAILABLE else '❌ Not available'}"
    )
    click.echo(
        f"🏷️ Tagger CLI: {'✅ Available' if TAGGER_AVAILABLE else '❌ Not available'}"
    )
    click.echo(
        f"📊 Markdown Report: {'✅ Available' if MDREPORT_AVAILABLE else '❌ Not available'}"
    )
    click.echo(
        f"📈 CSVTK Integration: {'✅ Available' if CSVTK_AVAILABLE else '❌ Not available'}"
    )
    click.echo(
        f"� Git CLI: {'✅ Available' if GIT_AVAILABLE else '❌ Not available'}"
    )
    click.echo(
        f"�🗄️ Database CLI: {'✅ Available' if DATABASE_AVAILABLE else '❌ Not available'}"
    )

    if CSVTK_AVAILABLE:
        click.echo("\n🚀 CSVTK Commands Available:")
        click.echo("  • reconcli-csvtk csvtkcli analyze <file.csv>")
        click.echo("  • reconcli-csvtk csvtkcli security-report <file.csv>")
        click.echo("  • reconcli-csvtk csvtkcli search <file.csv> -f field -p pattern")
        click.echo("  • reconcli-csvtk csvtkcli freq <file.csv> -f field")


if __name__ == "__main__":
    cli()
