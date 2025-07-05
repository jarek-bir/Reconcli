#!/usr/bin/env python3
"""
TLD Reconnaissance CLI (Optimized) - Integration Module for ReconCLI

This module provides a clean interface to integrate the optimized TLD reconnaissance
functionality into the main ReconCLI suite.
"""

import sys
import click

# Import the optimized CLI function
try:
    from reconcli.tldrcli_optimized import cli as optimized_cli
except ImportError:
    optimized_cli = None


@click.command()
@click.option("--domain", "-d", help="Base domain name (without TLD)")
@click.option(
    "--output-dir", default="output_tldrcli", help="Directory to save results"
)
@click.option(
    "--tld-list",
    type=click.Path(exists=True),
    help="Custom TLD list file (one per line)",
)
@click.option(
    "--categories",
    default="popular,country",
    help="TLD categories: popular,country,new_generic,business,crypto_blockchain,emerging_tech,geographic,industry_specific,specialized,all",
)
@click.option(
    "--concurrent", default=100, help="Number of concurrent async tasks (default: 100)"
)
@click.option("--timeout", default=5, help="DNS/HTTP timeout in seconds")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--dns-only", is_flag=True, help="Only perform DNS resolution (no HTTP probing)"
)
@click.option("--http-check", is_flag=True, help="Perform HTTP/HTTPS status checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option(
    "--filter-active",
    is_flag=True,
    help="Only show domains that resolve or respond to HTTP",
)
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option(
    "--whois-check", is_flag=True, help="Perform basic WHOIS availability check"
)
@click.option(
    "--exclude-wildcards",
    is_flag=True,
    help="Exclude domains that appear to be wildcards",
)
@click.option(
    "--show-categories", is_flag=True, help="Show available TLD categories and exit"
)
@click.option("--benchmark", is_flag=True, help="Run performance benchmark test")
def cli(
    domain,
    output_dir,
    tld_list,
    categories,
    concurrent,
    timeout,
    retries,
    dns_only,
    http_check,
    verbose,
    save_json,
    save_markdown,
    resume,
    clear_resume,
    show_resume,
    filter_active,
    slack_webhook,
    discord_webhook,
    whois_check,
    exclude_wildcards,
    show_categories,
    benchmark,
):
    """🚀 OPTIMIZED TLD Reconnaissance - High-performance domain discovery

    Advanced async-powered TLD reconnaissance with 11x performance improvement.
    Discover domains across thousands of TLDs using concurrent DNS resolution,
    HTTP probing, and intelligent caching.

    PERFORMANCE FEATURES:
    ✅ Async DNS resolution with aiodns (290+ TLDs/sec)
    ✅ HTTP connection pooling with aiohttp
    ✅ Intelligent DNS caching
    ✅ Concurrent processing (100+ simultaneous)
    ✅ Memory-efficient batch processing

    Examples:
        reconcli tldrcli-opti -d example --categories popular --concurrent 150 -v
        reconcli tldrcli-opti -d mycompany --categories all --http-check --concurrent 200
        reconcli tldrcli-opti -d startup --categories business,new_generic --filter-active --save-json
        reconcli tldrcli-opti --benchmark
    """

    # Check if optimized CLI is available
    if optimized_cli is None:
        click.echo("❌ Optimized TLD CLI not available!")
        click.echo("📦 Install dependencies: pip install aiodns aiohttp")
        click.echo("🔄 Or use standard version: reconcli tldr")
        sys.exit(1)

    # Check for required dependencies
    try:
        import aiodns
        import aiohttp
    except ImportError:
        click.echo("❌ Missing required dependencies for optimized version!")
        click.echo("📦 Install with: pip install aiodns aiohttp")
        click.echo("🔄 Or use the standard version: reconcli tldr")
        sys.exit(1)

    # Create context and invoke the optimized CLI
    ctx = click.Context(optimized_cli)
    ctx.params = {
        "domain": domain,
        "output_dir": output_dir,
        "tld_list": tld_list,
        "categories": categories,
        "concurrent": concurrent,
        "timeout": timeout,
        "retries": retries,
        "dns_only": dns_only,
        "http_check": http_check,
        "verbose": verbose,
        "save_json": save_json,
        "save_markdown": save_markdown,
        "resume": resume,
        "clear_resume": clear_resume,
        "show_resume": show_resume,
        "filter_active": filter_active,
        "slack_webhook": slack_webhook,
        "discord_webhook": discord_webhook,
        "whois_check": whois_check,
        "exclude_wildcards": exclude_wildcards,
        "show_categories": show_categories,
        "benchmark": benchmark,
    }

    # Invoke the optimized CLI with all parameters
    optimized_cli.invoke(ctx)


if __name__ == "__main__":
    cli()
