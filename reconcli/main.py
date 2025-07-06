import click

from reconcli.dnscli import cli as dns_cli
from reconcli.urlcli import main as url_cli
from reconcli.vhostcli import cli as vhost_cli  # ← poprawiona linia
from reconcli.vhostcheckcli import vhostcheckcli
from reconcli.urlsorter import cli as urlsort_cli
from reconcli.jscli import main as js_cli
from reconcli.httpcli import httpcli
from reconcli.ipscli import ipscli
from reconcli.one_shot import cli as one_shot_cli
from reconcli.zonewalkcli import cli as zonewalk_cli
from reconcli.takeovercli import takeovercli
from reconcli.whoisfreakscli import cli as whoisfreaks_cli
from reconcli.subdocli import subdocli
from reconcli.tldrcli import cli as tldr_cli
from reconcli.tldrcli_optimized_module import cli as tldr_opti_cli
from reconcli.cloudcli import cloudcli
from reconcli.portcli import portcli
from reconcli.cnamecli import cnamecli  # CNAME Record Analysis and Takeover Detection
from reconcli.vulncli import vulncli


@click.group()
def cli():
    """ReconCLI – Advanced modular reconnaissance toolkit

    A comprehensive suite of reconnaissance tools for security professionals and bug hunters.
    Each module provides specialized functionality with advanced features like resume support,
    professional reporting, and notification integrations.
    """
    pass


# DNS Resolution and Analysis
cli.add_command(dns_cli, name="dns")
dns_cli.short_help = "Enhanced DNS resolution and subdomain enumeration"

# URL Discovery and Analysis
cli.add_command(url_cli, name="urlcli")
url_cli.short_help = "Advanced URL discovery using Katana with filtering"

# Virtual Host Discovery
cli.add_command(vhost_cli, name="vhostcli")
vhost_cli.short_help = "Virtual host discovery and enumeration"

# Virtual Host Check
cli.add_command(vhostcheckcli, name="vhostcheck")
vhostcheckcli.short_help = "Advanced virtual host discovery and validation"

# URL Sorting and Organization
cli.add_command(urlsort_cli, name="urlsort")
urlsort_cli.short_help = "Advanced URL sorting and categorization"

# JavaScript Analysis
cli.add_command(js_cli, name="jscli")
js_cli.short_help = "JavaScript file discovery and analysis"

# HTTP Client Testing
cli.add_command(httpcli, name="httpcli")
httpcli.short_help = "HTTP client for web application testing"

# IP Address Analysis
cli.add_command(ipscli, name="ipscli")
ipscli.short_help = "IP address analysis and geolocation"

# One-Shot Reconnaissance
cli.add_command(one_shot_cli, name="oneshot")
one_shot_cli.short_help = "Quick one-shot reconnaissance scans"

# DNS Zone Walking
cli.add_command(zonewalk_cli, name="zonewalkcli")
zonewalk_cli.short_help = "DNS zone walking and enumeration"

# Subdomain Takeover Detection
cli.add_command(takeovercli, name="takeover")
takeovercli.short_help = "Subdomain takeover vulnerability detection"

# WHOIS Analysis
cli.add_command(whoisfreaks_cli, name="whoisfreaks")
whoisfreaks_cli.short_help = "Advanced WHOIS data analysis and enrichment"

# Subdomain Enumeration
cli.add_command(subdocli, name="subdocli")
subdocli.short_help = "Comprehensive subdomain enumeration using multiple sources"

# TLD Reconnaissance
cli.add_command(tldr_cli, name="tldr")
tldr_cli.short_help = "Alternative TLD reconnaissance and domain discovery"

# TLD Reconnaissance (Optimized)
cli.add_command(tldr_opti_cli, name="tldrcli-opti")
tldr_opti_cli.short_help = "🚀 HIGH-PERFORMANCE TLD reconnaissance (11x faster)"

# Cloud Service Discovery
cli.add_command(cloudcli, name="cloudcli")
cloudcli.short_help = "Cloud service discovery and enumeration"

# Port Scanning and Service Enumeration
cli.add_command(portcli, name="portcli")
portcli.short_help = "Port scanning and service enumeration"

# CNAME Record Analysis and Takeover Detection
cli.add_command(cnamecli, name="cnamecli")
cnamecli.short_help = "Detects dangling CNAMEs and takeover candidates"

# Vulnerability Scanning with Jaeles and Nuclei
cli.add_command(vulncli, name="vulncli")
vulncli.short_help = "Scan URLs using GF, Dalfox, Jaeles, and Nuclei with filters"

if __name__ == "__main__":
    cli()
