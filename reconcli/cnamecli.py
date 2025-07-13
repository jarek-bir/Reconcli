import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import click
import dns.resolver
import requests

# Known vulnerable CNAME patterns and providers
TAKEOVER_PATTERNS = {
    "heroku": {
        "patterns": ["herokuapp.com", "herokussl.com"],
        "error_messages": ["no such app", "not found"],
        "status_codes": [404],
        "description": "Heroku App",
    },
    "github": {
        "patterns": ["github.io", "githubusercontent.com"],
        "error_messages": ["there isn't a github pages site here", "404"],
        "status_codes": [404],
        "description": "GitHub Pages",
    },
    "aws-s3": {
        "patterns": ["amazonaws.com", "s3.amazonaws.com", "s3-website"],
        "error_messages": ["nosuchbucket", "the specified bucket does not exist"],
        "status_codes": [404],
        "description": "AWS S3 Bucket",
    },
    "azure": {
        "patterns": ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"],
        "error_messages": ["not found", "web app doesn't exist"],
        "status_codes": [404],
        "description": "Microsoft Azure",
    },
    "cloudfront": {
        "patterns": ["cloudfront.net"],
        "error_messages": ["bad request", "the request could not be satisfied"],
        "status_codes": [403, 404],
        "description": "AWS CloudFront",
    },
    "fastly": {
        "patterns": ["fastly.com", "fastlylb.net"],
        "error_messages": ["fastly error: unknown domain"],
        "status_codes": [404],
        "description": "Fastly CDN",
    },
    "netlify": {
        "patterns": ["netlify.app", "netlify.com"],
        "error_messages": ["not found", "site not found"],
        "status_codes": [404],
        "description": "Netlify",
    },
    "pantheon": {
        "patterns": ["pantheonsite.io", "pantheon.io"],
        "error_messages": ["the gods are wise"],
        "status_codes": [404],
        "description": "Pantheon",
    },
    "surge": {
        "patterns": ["surge.sh"],
        "error_messages": ["project not found"],
        "status_codes": [404],
        "description": "Surge.sh",
    },
    "bitbucket": {
        "patterns": ["bitbucket.io"],
        "error_messages": ["repository not found"],
        "status_codes": [404],
        "description": "Bitbucket Pages",
    },
    "shopify": {
        "patterns": ["myshopify.com"],
        "error_messages": ["sorry, this shop is currently unavailable"],
        "status_codes": [404],
        "description": "Shopify",
    },
    "unbounce": {
        "patterns": ["unbouncepages.com"],
        "error_messages": ["the requested url was not found"],
        "status_codes": [404],
        "description": "Unbounce",
    },
    "wordpress": {
        "patterns": ["wordpress.com"],
        "error_messages": ["do you want to register"],
        "status_codes": [404],
        "description": "WordPress.com",
    },
    "squarespace": {
        "patterns": ["squarespace.com"],
        "error_messages": ["no such account"],
        "status_codes": [404],
        "description": "Squarespace",
    },
    "tumblr": {
        "patterns": ["tumblr.com"],
        "error_messages": ["whatever you were looking for doesn't currently exist"],
        "status_codes": [404],
        "description": "Tumblr",
    },
    "webflow": {
        "patterns": ["webflow.io"],
        "error_messages": ["the page you are looking for doesn't exist"],
        "status_codes": [404],
        "description": "Webflow",
    },
    "ghost": {
        "patterns": ["ghost.io"],
        "error_messages": ["the thing you were looking for is no longer here"],
        "status_codes": [404],
        "description": "Ghost.io",
    },
    "helpjuice": {
        "patterns": ["helpjuice.com"],
        "error_messages": ["we could not find what you're looking for"],
        "status_codes": [404],
        "description": "HelpJuice",
    },
    "helpscout": {
        "patterns": ["helpscoutdocs.com"],
        "error_messages": ["no help site found"],
        "status_codes": [404],
        "description": "Help Scout",
    },
    "cargocollective": {
        "patterns": ["cargocollective.com"],
        "error_messages": ["404 not found"],
        "status_codes": [404],
        "description": "Cargo Collective",
    },
    "statuspage": {
        "patterns": ["statuspage.io"],
        "error_messages": ["you are being redirected"],
        "status_codes": [404],
        "description": "StatusPage",
    },
    "uservoice": {
        "patterns": ["uservoice.com"],
        "error_messages": ["this uservoice subdomain is currently available"],
        "status_codes": [404],
        "description": "UserVoice",
    },
    "zendesk": {
        "patterns": ["zendesk.com"],
        "error_messages": ["help center closed"],
        "status_codes": [404],
        "description": "Zendesk",
    },
}


def resolve_cname(domain, verbose=False):
    """Resolve CNAME record for domain"""
    try:
        # Use query method for dnspython < 2.0 compatibility
        answers = dns.resolver.query(domain, "CNAME")
        cname_target = str(answers[0]).rstrip(".")
        if verbose:
            print(f"[CNAME] {domain} -> {cname_target}")
        return cname_target
    except dns.resolver.NXDOMAIN:
        if verbose:
            print(f"[NXDOMAIN] {domain}")
        return None
    except dns.resolver.NoAnswer:
        if verbose:
            print(f"[NO_CNAME] {domain}")
        return None
    except Exception as e:
        if verbose:
            print(f"[ERROR] {domain}: {e}")
        return None


def resolve_direct_records(domain, verbose=False):
    """Resolve A and AAAA records for domain"""
    records = {"A": [], "AAAA": []}

    try:
        # Resolve A records
        try:
            answers = dns.resolver.query(domain, "A")
            for rdata in answers:
                records["A"].append(str(rdata))
            if verbose:
                print(f"[A] {domain} -> {', '.join(records['A'])}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

        # Resolve AAAA records
        try:
            answers = dns.resolver.query(domain, "AAAA")
            for rdata in answers:
                records["AAAA"].append(str(rdata))
            if verbose:
                print(f"[AAAA] {domain} -> {', '.join(records['AAAA'])}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

    except Exception as e:
        if verbose:
            print(f"[ERROR] {domain} direct records: {e}")

    return records


def identify_provider(cname_target):
    """Identify service provider from CNAME target"""
    if not cname_target:
        return None, "Unknown"

    cname_lower = cname_target.lower()
    for provider, config in TAKEOVER_PATTERNS.items():
        for pattern in config["patterns"]:
            if pattern in cname_lower:
                return provider, config["description"]

    # Additional provider patterns
    if "cloudflare" in cname_lower:
        return "cloudflare", "Cloudflare CDN"
    elif "akamai" in cname_lower:
        return "akamai", "Akamai CDN"
    elif "edgecast" in cname_lower:
        return "edgecast", "Edgecast CDN"
    elif "maxcdn" in cname_lower:
        return "maxcdn", "MaxCDN"
    elif "incapsula" in cname_lower:
        return "incapsula", "Incapsula"
    elif "sucuri" in cname_lower:
        return "sucuri", "Sucuri CDN"
    elif "keycdn" in cname_lower:
        return "keycdn", "KeyCDN"
    elif "stackpath" in cname_lower:
        return "stackpath", "StackPath CDN"
    elif "jsdelivr" in cname_lower:
        return "jsdelivr", "jsDelivr CDN"
    elif "bunnycdn" in cname_lower:
        return "bunnycdn", "BunnyCDN"
    elif "googleusercontent" in cname_lower:
        return "google-cloud", "Google Cloud"
    elif "azure" in cname_lower or "windows.net" in cname_lower:
        return "azure", "Microsoft Azure"
    elif "digitalocean" in cname_lower:
        return "digitalocean", "DigitalOcean"
    elif "linode" in cname_lower:
        return "linode", "Linode"
    elif "vultr" in cname_lower:
        return "vultr", "Vultr"
    elif "ovh" in cname_lower:
        return "ovh", "OVH"

    return None, "Unknown Provider"


def identify_provider_from_ip(ip_address):
    """Identify cloud provider from IP address using known IP ranges"""
    if not ip_address:
        return None, "Unknown"

    # AWS IP ranges (sample - in practice you'd want comprehensive lists)
    aws_ranges = [
        "52.",
        "54.",
        "3.",
        "13.",
        "18.",
        "34.",
        "35.",
        "50.",
        "52.",
        "54.",
        "99.",
        "107.",
    ]

    # Google Cloud IP ranges (sample)
    gcp_ranges = [
        "104.154.",
        "104.196.",
        "104.197.",
        "104.198.",
        "104.199.",
        "35.184.",
        "35.185.",
        "35.186.",
        "35.187.",
        "35.188.",
        "35.189.",
        "35.190.",
        "35.191.",
        "35.192.",
        "35.193.",
        "35.194.",
        "35.195.",
        "35.196.",
        "35.197.",
        "35.198.",
        "35.199.",
        "35.200.",
        "35.201.",
        "35.202.",
        "35.203.",
        "35.204.",
        "35.205.",
        "35.206.",
        "35.207.",
        "35.208.",
        "35.209.",
        "35.210.",
        "35.211.",
        "35.212.",
        "35.213.",
        "35.214.",
        "35.215.",
        "35.216.",
        "35.217.",
        "35.218.",
        "35.219.",
        "35.220.",
        "35.221.",
        "35.222.",
        "35.223.",
        "35.224.",
        "35.225.",
        "35.226.",
        "35.227.",
        "35.228.",
        "35.229.",
        "35.230.",
        "35.231.",
        "35.232.",
        "35.233.",
        "35.234.",
        "35.235.",
        "35.236.",
        "35.237.",
        "35.238.",
        "35.239.",
        "35.240.",
        "35.241.",
        "35.242.",
        "35.243.",
        "35.244.",
        "35.245.",
        "35.246.",
        "35.247.",
        "35.248.",
    ]

    # Azure IP ranges (sample)
    azure_ranges = [
        "13.",
        "20.",
        "23.",
        "40.",
        "52.",
        "104.",
        "137.",
        "138.",
        "191.",
        "168.",
    ]

    # DigitalOcean ranges
    do_ranges = [
        "67.205.",
        "104.131.",
        "104.236.",
        "107.170.",
        "138.197.",
        "159.203.",
        "159.89.",
        "162.243.",
        "178.62.",
        "188.166.",
        "192.241.",
        "198.199.",
    ]

    # Cloudflare ranges
    cf_ranges = [
        "104.16.",
        "104.17.",
        "104.18.",
        "104.19.",
        "104.20.",
        "104.21.",
        "104.22.",
        "104.23.",
        "104.24.",
        "104.25.",
        "104.26.",
        "104.27.",
        "104.28.",
        "104.29.",
        "104.30.",
        "104.31.",
        "172.64.",
        "172.65.",
        "172.66.",
        "172.67.",
        "172.68.",
        "172.69.",
        "172.70.",
        "172.71.",
    ]

    # Check against known ranges
    for prefix in aws_ranges:
        if ip_address.startswith(prefix):
            return "aws", "Amazon Web Services"

    for prefix in gcp_ranges:
        if ip_address.startswith(prefix):
            return "google-cloud", "Google Cloud Platform"

    for prefix in azure_ranges:
        if ip_address.startswith(prefix):
            return "azure", "Microsoft Azure"

    for prefix in do_ranges:
        if ip_address.startswith(prefix):
            return "digitalocean", "DigitalOcean"

    for prefix in cf_ranges:
        if ip_address.startswith(prefix):
            return "cloudflare", "Cloudflare"

    return None, "Unknown Provider"


def check_takeover_vulnerability(domain, cname_target, provider_id, verbose=False):
    """Check if domain is vulnerable to subdomain takeover"""
    if not cname_target or not provider_id:
        return False, "No CNAME or provider detected"

    if provider_id not in TAKEOVER_PATTERNS:
        return False, "Provider not in vulnerability database"

    config = TAKEOVER_PATTERNS[provider_id]

    try:
        # Try HTTP request
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, allow_redirects=True)

                # Check status codes
                if response.status_code in config["status_codes"]:
                    content = response.text.lower()

                    # Check error messages
                    for error_msg in config["error_messages"]:
                        if error_msg.lower() in content:
                            if verbose:
                                print(
                                    f"[VULNERABLE] {domain} - Found error: '{error_msg}'"
                                )
                            return (
                                True,
                                f"Vulnerable - Found error pattern: '{error_msg}'",
                            )

                if verbose:
                    print(f"[CHECK] {domain} - HTTP {response.status_code}")
                break

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"[ERROR] {domain} - Request failed: {e}")
                continue

        return False, "No vulnerability indicators found"

    except Exception as e:
        return False, f"Check failed: {str(e)}"


def analyze_domain(
    domain,
    check_resolution=True,
    check_takeover=True,
    include_direct=False,
    webhook_url=None,
    verbose=False,
):
    """Comprehensive CNAME analysis for a single domain"""
    result = {
        "domain": domain,
        "cname": None,
        "provider_id": None,
        "provider_name": "Unknown",
        "resolves": None,
        "vulnerable": False,
        "vulnerability_details": None,
        "timestamp": datetime.utcnow().isoformat(),
        "risk_level": "low",
        "status": "unknown",
    }

    # Step 1: Resolve CNAME
    cname_target = resolve_cname(domain, verbose)
    result["cname"] = cname_target

    if not cname_target:
        result["vulnerability_details"] = "No CNAME record found"
        result["status"] = "no_cname"

        # Check if domain resolves directly (A/AAAA record)
        if check_resolution:
            try:
                socket.gethostbyname(domain)
                result["resolves"] = True
                result["status"] = "no_cname"  # Direct A record resolution
            except socket.gaierror:
                result["resolves"] = False
                result["status"] = "dead"  # Doesn't resolve at all

        return result

    # Step 2: Identify provider
    provider_id, provider_name = identify_provider(cname_target)
    result["provider_id"] = provider_id
    result["provider_name"] = provider_name

    # Step 3: Check if domain resolves
    if check_resolution:
        try:
            socket.gethostbyname(domain)
            result["resolves"] = True
        except socket.gaierror:
            result["resolves"] = False

    # Step 4: Determine status based on resolution and provider
    if result["resolves"] is True:
        if provider_id in TAKEOVER_PATTERNS:
            result["status"] = (
                "resolves_ok"  # CNAME resolves but points to potentially vulnerable service
            )
        else:
            result["status"] = "resolves_ok"  # CNAME resolves normally
    elif result["resolves"] is False:
        if provider_id in TAKEOVER_PATTERNS:
            result["status"] = (
                "potential_takeover"  # Dangerous: CNAME to vulnerable service but doesn't resolve
            )
        else:
            result["status"] = "not_resolving"  # CNAME doesn't resolve
    else:
        result["status"] = "unknown"

    # Step 5: Check for takeover vulnerability
    if check_takeover and provider_id:
        is_vulnerable, details = check_takeover_vulnerability(
            domain, cname_target, provider_id, verbose
        )
        result["vulnerable"] = is_vulnerable
        result["vulnerability_details"] = details

        # Override status if confirmed vulnerable
        if is_vulnerable:
            result["status"] = "potential_takeover"
            result["risk_level"] = "critical"

            # Send immediate notification for confirmed vulnerabilities
            if webhook_url:
                send_notification(
                    webhook_url, domain, cname_target, provider_name, details, verbose
                )

        elif result["status"] == "potential_takeover":
            result["risk_level"] = "high"
        elif provider_id in TAKEOVER_PATTERNS and result["resolves"]:
            result["risk_level"] = "medium"

        # Special case: if domain is dead (no CNAME, no A record)
        if not cname_target and result["resolves"] is False:
            result["status"] = "dead"
            result["risk_level"] = "low"

    # Step 6: Resolve direct A/AAAA records and check provider
    if include_direct:
        direct_records = resolve_direct_records(domain, verbose)
        result["direct_a"] = direct_records["A"]
        result["direct_aaaa"] = direct_records["AAAA"]

        # Identify provider from first A record IP
        if direct_records["A"]:
            ip_provider_id, ip_provider_name = identify_provider_from_ip(
                direct_records["A"][0]
            )
            result["ip_provider_id"] = ip_provider_id
            result["ip_provider_name"] = ip_provider_name

    return result


def generate_markdown_report(results, output_path):
    """Generate detailed markdown report"""
    with open(output_path, "w") as f:
        f.write("# 🔍 CNAME Analysis Report\n\n")
        f.write(
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        )
        f.write(f"**Total Domains:** {len(results)}\n\n")

        # Statistics
        vulnerable_count = sum(1 for r in results if r["vulnerable"])
        critical_count = sum(1 for r in results if r["risk_level"] == "critical")
        high_count = sum(1 for r in results if r["risk_level"] == "high")

        # Status statistics
        status_counts = {}
        for result in results:
            status = result.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        f.write("## 📊 Summary Statistics\n")
        f.write(f"- **🚨 Critical Risk:** {critical_count} domains\n")
        f.write(f"- **⚠️ High Risk:** {high_count} domains\n")
        f.write(f"- **🔓 Confirmed Vulnerable:** {vulnerable_count} domains\n")
        f.write(f"- **📈 Total Analyzed:** {len(results)} domains\n\n")

        # Status breakdown
        f.write("## 📈 Status Breakdown\n")
        status_emojis = {
            "no_cname": "🔵",
            "resolves_ok": "✅",
            "not_resolving": "❌",
            "potential_takeover": "🚨",
            "dead": "💀",
            "error": "⚠️",
            "unknown": "❓",
        }

        for status, count in status_counts.items():
            emoji = status_emojis.get(status, "❓")
            f.write(
                f"- **{emoji} {status.replace('_', ' ').title()}:** {count} domains\n"
            )
        f.write("\n")

        # Vulnerable domains first
        if vulnerable_count > 0:
            f.write("## 🚨 Critical Vulnerabilities\n\n")
            for result in results:
                if result["vulnerable"]:
                    f.write(f"### 🔴 {result['domain']}\n")
                    f.write(f"- **CNAME Target:** `{result['cname']}`\n")
                    f.write(f"- **Provider:** {result['provider_name']}\n")
                    f.write("- **Status:** ⚠️ **VULNERABLE TO TAKEOVER**\n")
                    f.write(f"- **Details:** {result['vulnerability_details']}\n")
                    f.write(
                        f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No'}\n\n"
                    )

        # High risk domains
        high_risk = [
            r for r in results if r["risk_level"] == "high" and not r["vulnerable"]
        ]
        if high_risk:
            f.write("## ⚠️ High Risk Domains\n\n")
            for result in high_risk:
                f.write(f"### 🟡 {result['domain']}\n")
                f.write(f"- **CNAME Target:** `{result['cname']}`\n")
                f.write(f"- **Provider:** {result['provider_name']}\n")
                f.write(
                    f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No'}\n"
                )
                f.write(
                    "- **Risk:** Domain points to potentially vulnerable service\n\n"
                )

        # All results
        f.write("## 📋 Complete Analysis Results\n\n")
        for result in results:
            risk_emoji = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🟢"}
            status_emojis = {
                "no_cname": "🔵",
                "resolves_ok": "✅",
                "not_resolving": "❌",
                "potential_takeover": "🚨",
                "dead": "💀",
                "error": "⚠️",
                "unknown": "❓",
            }

            risk_emoji_char = risk_emoji.get(result["risk_level"], "⚪")
            status_emoji_char = status_emojis.get(result.get("status", "unknown"), "❓")

            f.write(f"### {risk_emoji_char} {result['domain']} {status_emoji_char}\n")
            f.write(f"- **CNAME:** `{result['cname'] or 'None'}`\n")
            f.write(f"- **Provider:** {result['provider_name']}\n")
            f.write(
                f"- **Status:** {result.get('status', 'unknown').replace('_', ' ').title()}\n"
            )
            f.write(
                f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No' if result['resolves'] is False else '❓ Unknown'}\n"
            )
            f.write(f"- **Risk Level:** {result['risk_level'].title()}\n")

            # Include direct A/AAAA records if available
            if result.get("direct_a") or result.get("direct_aaaa"):
                f.write("- **Direct Records:**\n")
                if result.get("direct_a"):
                    f.write(f"  - **A Records:** {', '.join(result['direct_a'])}\n")
                if result.get("direct_aaaa"):
                    f.write(
                        f"  - **AAAA Records:** {', '.join(result['direct_aaaa'])}\n"
                    )
                if result.get("ip_provider_name"):
                    f.write(f"  - **IP Provider:** {result['ip_provider_name']}\n")

            if result["vulnerability_details"]:
                f.write(f"- **Details:** {result['vulnerability_details']}\n")
            f.write("\n")


# Notification functions
def send_discord_notification(
    webhook_url, domain, cname, provider, details, verbose=False
):
    """Send Discord notification for critical takeover findings"""
    try:
        embed = {
            "title": "🚨 Subdomain Takeover Alert",
            "description": "**Critical vulnerability detected!**",
            "color": 16711680,  # Red color
            "fields": [
                {"name": "🎯 Domain", "value": f"`{domain}`", "inline": True},
                {"name": "🔗 CNAME Target", "value": f"`{cname}`", "inline": True},
                {"name": "☁️ Provider", "value": provider, "inline": True},
                {"name": "⚠️ Details", "value": details, "inline": False},
                {
                    "name": "🕐 Detected",
                    "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "inline": True,
                },
            ],
            "footer": {"text": "ReconCLI CNAME Analysis"},
        }

        payload = {
            "embeds": [embed],
            "username": "ReconCLI",
            "avatar_url": "https://cdn.discordapp.com/attachments/123456789/alert.png",
        }

        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()

        if verbose:
            print(f"✅ Discord notification sent for {domain}")
        return True

    except Exception as e:
        if verbose:
            print(f"❌ Discord notification failed for {domain}: {e}")
        return False


def send_slack_notification(
    webhook_url, domain, cname, provider, details, verbose=False
):
    """Send Slack notification for critical takeover findings"""
    try:
        payload = {
            "text": "🚨 Subdomain Takeover Alert",
            "attachments": [
                {
                    "color": "danger",
                    "title": "Critical Vulnerability Detected",
                    "fields": [
                        {"title": "🎯 Domain", "value": f"`{domain}`", "short": True},
                        {
                            "title": "🔗 CNAME Target",
                            "value": f"`{cname}`",
                            "short": True,
                        },
                        {"title": "☁️ Provider", "value": provider, "short": True},
                        {
                            "title": "🕐 Detected",
                            "value": datetime.utcnow().strftime(
                                "%Y-%m-%d %H:%M:%S UTC"
                            ),
                            "short": True,
                        },
                        {"title": "⚠️ Details", "value": details, "short": False},
                    ],
                    "footer": "ReconCLI CNAME Analysis",
                }
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()

        if verbose:
            print(f"✅ Slack notification sent for {domain}")
        return True

    except Exception as e:
        if verbose:
            print(f"❌ Slack notification failed for {domain}: {e}")
        return False


def send_notification(webhook_url, domain, cname, provider, details, verbose=False):
    """Send notification to Discord or Slack based on webhook URL"""
    if not webhook_url:
        return False

    try:
        if "discord.com" in webhook_url or "discordapp.com" in webhook_url:
            return send_discord_notification(
                webhook_url, domain, cname, provider, details, verbose
            )
        elif "slack.com" in webhook_url:
            return send_slack_notification(
                webhook_url, domain, cname, provider, details, verbose
            )
        else:
            if verbose:
                print(f"⚠️ Unknown webhook provider for {webhook_url}")
            return False
    except Exception as e:
        if verbose:
            print(f"❌ Notification failed: {e}")
        return False


# CNAME Record Analysis and Takeover Detection
@click.command()
@click.option(
    "--domains", type=click.Path(exists=True), help="Path to file with list of domains"
)
@click.option("--check", is_flag=True, help="Check if CNAME resolves")
@click.option(
    "--provider-tags", is_flag=True, help="Attempt to identify cloud/service provider"
)
@click.option(
    "--takeover-check",
    is_flag=True,
    help="Check for subdomain takeover vulnerabilities",
)
@click.option(
    "--include-direct",
    is_flag=True,
    help="Include analysis of direct A/AAAA records (not just CNAMEs)",
)
@click.option(
    "--notify",
    help="Discord/Slack webhook URL for takeover alerts (alias for --webhook-url)",
)
@click.option(
    "--status-filter",
    type=click.Choice(
        [
            "no_cname",
            "resolves_ok",
            "not_resolving",
            "potential_takeover",
            "dead",
            "error",
        ]
    ),
    help="Filter results by status type",
)
@click.option(
    "--json", "json_output", is_flag=True, help="Output results in JSON format"
)
@click.option("--markdown", is_flag=True, help="Output results in Markdown format")
@click.option(
    "--output-dir", default="output/cnamecli", help="Directory to store output files"
)
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear resume state")
@click.option("--show-resume", is_flag=True, help="Show resume status")
@click.option("--threads", type=int, default=10, help="Number of concurrent threads")
@click.option("--timeout", type=int, default=10, help="Request timeout in seconds")
@click.option("--verbose", is_flag=True, help="Verbose output")
@click.option(
    "--webhook-url",
    help="Discord or Slack webhook URL for notifications (deprecated, use --notify)",
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
def cnamecli(
    domains,
    check,
    provider_tags,
    takeover_check,
    include_direct,
    notify,
    status_filter,
    json_output,
    markdown,
    output_dir,
    resume,
    clear_resume,
    show_resume,
    threads,
    timeout,
    verbose,
    webhook_url,
    store_db,
    target_domain,
    program,
):
    """
    🔍 Advanced CNAME Analysis and Subdomain Takeover Detection

    Analyzes CNAME records for potential subdomain takeover vulnerabilities by:
    - Resolving CNAME targets
    - Identifying service providers (Heroku, GitHub, AWS S3, Azure, etc.)
    - Checking for vulnerable configurations
    - Testing for takeover indicators
    - Optionally analyzing direct A/AAAA records when --include-direct is used

    Status Types:
    - no_cname: Domain has no CNAME record (direct A/AAAA)
    - resolves_ok: CNAME exists and resolves properly
    - not_resolving: CNAME exists but doesn't resolve
    - potential_takeover: CNAME points to vulnerable service and doesn't resolve
    - dead: Domain doesn't resolve at all (no DNS records)
    - error: Analysis failed due to technical issues

    Examples:
        # Basic CNAME analysis
        reconcli cnamecli --domains subdomains.txt --provider-tags

        # Include direct A/AAAA record analysis
        reconcli cnamecli --domains targets.txt --include-direct --provider-tags

        # Full vulnerability scan with Discord notifications
        reconcli cnamecli --domains targets.txt --check --takeover-check --notify "https://discord.com/api/webhooks/..." --markdown

        # Slack notifications for critical findings with direct records
        reconcli cnamecli --domains targets.txt --takeover-check --include-direct --notify "https://hooks.slack.com/services/..." --json

        # Filter only potential takeover candidates
        reconcli cnamecli --domains targets.txt --takeover-check --status-filter potential_takeover

        # High-performance concurrent scan with notifications
        reconcli cnamecli --domains large_list.txt --takeover-check --threads 20 --notify "https://discord.com/api/webhooks/..." --json
    """
    os.makedirs(output_dir, exist_ok=True)

    # Handle webhook URL - prioritize --notify over --webhook-url
    notification_webhook = notify or webhook_url
    if notification_webhook and verbose:
        webhook_type = (
            "Discord"
            if "discord" in notification_webhook.lower()
            else "Slack"
            if "slack" in notification_webhook.lower()
            else "Unknown"
        )
        click.echo(f"🔔 Notifications enabled: {webhook_type} webhook")

    # Resume functionality placeholders
    resume_file = os.path.join(output_dir, "cnamecli_resume.json")

    if clear_resume:
        if os.path.exists(resume_file):
            os.remove(resume_file)
            click.echo("🧹 Resume state cleared.")
        else:
            click.echo("ℹ️ No resume state to clear.")
        return

    if show_resume:
        if os.path.exists(resume_file):
            with open(resume_file) as f:
                data = json.load(f)
                click.echo(
                    f"📄 Resume state: Last run {data.get('timestamp', 'unknown')}"
                )
        else:
            click.echo("ℹ️ No resume file found.")
        return

    # Load domains
    if not domains:
        click.echo("❌ Error: --domains file is required")
        return

    try:
        with open(domains) as f:
            domain_list = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    except Exception as e:
        click.echo(f"❌ Error reading domains file: {e}")
        return

    if not domain_list:
        click.echo("❌ No domains found in input file")
        return

    click.echo(f"🎯 Analyzing {len(domain_list)} domains...")
    if include_direct:
        click.echo("🔍 Including direct A/AAAA record analysis")
    if verbose:
        click.echo(f"📁 Output directory: {output_dir}")
        click.echo(f"🧵 Threads: {threads}")
        if include_direct:
            click.echo("📋 Direct record analysis: Enabled")

    # Analyze domains concurrently
    results = []

    def analyze_single_domain(domain):
        return analyze_domain(
            domain,
            check_resolution=check,
            check_takeover=takeover_check,
            include_direct=include_direct,
            webhook_url=notification_webhook,
            verbose=verbose,
        )

    # Use ThreadPoolExecutor for concurrent analysis
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {
            executor.submit(analyze_single_domain, domain): domain
            for domain in domain_list
        }

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)

                # Progress output
                if verbose:
                    risk_emoji = {
                        "critical": "🔴",
                        "high": "🟡",
                        "medium": "🟠",
                        "low": "🟢",
                    }
                    status_emojis = {
                        "no_cname": "🔵",
                        "resolves_ok": "✅",
                        "not_resolving": "❌",
                        "potential_takeover": "🚨",
                        "dead": "💀",
                        "error": "⚠️",
                        "unknown": "❓",
                    }

                    risk_emoji_char = risk_emoji.get(result["risk_level"], "⚪")
                    status_emoji_char = status_emojis.get(
                        result.get("status", "unknown"), "❓"
                    )
                    cname_info = f" -> {result['cname']}" if result["cname"] else ""

                    # Add direct record info if available
                    direct_info = ""
                    if result.get("direct_a") or result.get("direct_aaaa"):
                        direct_parts = []
                        if result.get("direct_a"):
                            direct_parts.append(
                                f"A:{','.join(result['direct_a'][:2])}"
                            )  # Show first 2 IPs
                        if result.get("direct_aaaa"):
                            direct_parts.append(f"AAAA:{len(result['direct_aaaa'])}")
                        if (
                            result.get("ip_provider_name")
                            and result["ip_provider_name"] != "Unknown Provider"
                        ):
                            direct_parts.append(f"({result['ip_provider_name']})")
                        if direct_parts:
                            direct_info = f" | {' '.join(direct_parts)}"

                    status_info = f" [{result.get('status', 'unknown').replace('_', ' ').title()}]"

                    click.echo(
                        f"{risk_emoji_char}{status_emoji_char} {domain}{cname_info}{direct_info}{status_info}"
                    )
                else:
                    # Simple progress for non-verbose mode
                    status_emojis = {
                        "no_cname": "🔵",
                        "resolves_ok": "✅",
                        "not_resolving": "❌",
                        "potential_takeover": "🚨",
                        "dead": "💀",
                        "error": "⚠️",
                        "unknown": "❓",
                    }
                    status_emoji_char = status_emojis.get(
                        result.get("status", "unknown"), "❓"
                    )
                    click.echo(f"{status_emoji_char} {domain}", nl=False)
                    if len(results) % 10 == 0:  # New line every 10 domains
                        click.echo("")

            except Exception as e:
                if verbose:
                    click.echo(f"❌ Error analyzing {domain}: {e}")
                # Add error result
                results.append(
                    {
                        "domain": domain,
                        "cname": None,
                        "provider_id": None,
                        "provider_name": "Error",
                        "resolves": None,
                        "vulnerable": False,
                        "vulnerability_details": f"Analysis failed: {str(e)}",
                        "timestamp": datetime.utcnow().isoformat(),
                        "risk_level": "low",
                        "status": "error",
                    }
                )

    # Apply status filter if specified
    if status_filter:
        original_count = len(results)
        results = [r for r in results if r.get("status") == status_filter]
        filtered_count = len(results)
        if verbose:
            click.echo(
                f"🔍 Filtered by status '{status_filter}': {filtered_count}/{original_count} domains"
            )

    # Generate outputs
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = (
        os.path.splitext(os.path.basename(domains))[0] if domains else "cname_scan"
    )

    # Statistics
    vulnerable_count = sum(1 for r in results if r["vulnerable"])
    critical_count = sum(1 for r in results if r["risk_level"] == "critical")
    high_count = sum(1 for r in results if r["risk_level"] == "high")

    # Save JSON output
    if json_output:
        json_path = os.path.join(output_dir, f"{base_name}_cname_{timestamp}.json")
        analysis_data = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "total_domains": len(results),
                "vulnerable_count": vulnerable_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "scan_options": {
                    "check_resolution": check,
                    "provider_identification": provider_tags,
                    "takeover_check": takeover_check,
                    "include_direct": include_direct,
                },
            },
            "results": results,
        }

        with open(json_path, "w") as jf:
            json.dump(analysis_data, jf, indent=2)
        click.echo(f"📄 JSON results saved to: {json_path}")

    # Save Markdown report
    if markdown:
        md_path = os.path.join(output_dir, f"{base_name}_cname_{timestamp}.md")
        generate_markdown_report(results, md_path)
        click.echo(f"📝 Markdown report saved to: {md_path}")

    # Save resume state
    resume_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "domains_analyzed": len(results),
        "last_domain": domain_list[-1] if domain_list else None,
    }
    with open(resume_file, "w") as rf:
        json.dump(resume_data, rf, indent=2)

    # Database storage
    if store_db and results:
        try:
            from reconcli.db.operations import store_cname_scan, store_target

            # Auto-detect target domain if not provided
            if not target_domain and results:
                # Try to extract domain from first result
                first_domain = results[0].get("domain") if results else None
                if first_domain:
                    # Extract root domain from subdomain
                    parts = first_domain.split(".")
                    if len(parts) >= 2:
                        target_domain = ".".join(parts[-2:])

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Convert results to database format
                cname_scan_data = []
                for result in results:
                    cname_entry = {
                        "domain": result.get("domain"),
                        "cname": result.get("cname"),
                        "status": result.get("status"),
                        "provider_name": result.get("provider_name"),
                        "provider_tags": result.get("provider_tags", []),
                        "vulnerable": result.get("vulnerable", False),
                        "vulnerability_details": result.get("vulnerability_details"),
                        "resolved_ips": result.get("resolved_ips", []),
                        "http_status": result.get("http_status"),
                        "error": result.get("error"),
                        "last_checked": datetime.utcnow().isoformat(),
                    }
                    cname_scan_data.append(cname_entry)

                # Store CNAME scan in database
                stored_ids = store_cname_scan(target_domain, cname_scan_data)

                if verbose:
                    click.echo(
                        f"[+] 💾 Stored {len(stored_ids)} CNAME analysis results in database for target: {target_domain}"
                    )
            else:
                if verbose:
                    click.echo(
                        "[!] ⚠️  No target domain provided or detected for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo("[!] ⚠️  Database module not available")
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Database storage failed: {e}")

    # Final summary
    click.echo("\n✅ CNAME Analysis Complete!")
    click.echo(f"📊 Total domains analyzed: {len(results)}")
    if vulnerable_count > 0:
        click.echo(f"🚨 Critical vulnerabilities found: {vulnerable_count}")
    if high_count > 0:
        click.echo(f"⚠️ High-risk domains: {high_count}")
    click.echo(f"� Results saved to: {output_dir}")

    if vulnerable_count > 0:
        click.echo(
            f"\n🔥 ATTENTION: {vulnerable_count} domains may be vulnerable to subdomain takeover!"
        )

    # Send notifications for critical vulnerabilities
    if webhook_url and critical_count > 0:
        click.echo("📢 Sending notifications for critical vulnerabilities...")
        for result in results:
            if result["vulnerable"]:
                send_notification(
                    webhook_url,
                    result["domain"],
                    result["cname"],
                    result["provider_name"],
                    result["vulnerability_details"],
                    verbose,
                )


if __name__ == "__main__":
    cnamecli()
