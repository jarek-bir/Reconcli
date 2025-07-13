#!/usr/bin/env python3
"""
WhoisFreaks CLI for Reconcli Toolkit
Advanced WHOIS analysis and domain intelligence gathering
"""

import concurrent.futures
import json
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

import click
import requests
from tqdm import tqdm

# Database imports
try:
    from reconcli.db.operations import store_target, store_whois_findings
except ImportError:
    store_target = None
    store_whois_findings = None

# Import notifications
try:
    from reconcli.utils.notifications import NotificationManager, send_notification
except ImportError:
    send_notification = None
    NotificationManager = None

# Import resume utilities
try:
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
except ImportError:

    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def clear_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            os.remove(path)


# Risk assessment patterns
RISK_PATTERNS = {
    "suspicious_registrars": [
        "namecheap",
        "godaddy",
        "enom",
        "1&1",
        "tucows",
        "network solutions",
        "register.com",
        "domains by proxy",
    ],
    "privacy_services": [
        "whoisguard",
        "privacy protection",
        "domains by proxy",
        "perfect privacy",
        "contact privacy inc",
        "whois privacy corp",
    ],
    "short_lived_domains": 30,  # days
    "expiring_soon": 90,  # days
    "suspicious_tlds": [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".top",
        ".click",
        ".download",
        ".space",
        ".website",
        ".online",
        ".site",
        ".store",
    ],
}


@click.group()
def cli():
    """WhoisFreaks CLI - Advanced WHOIS analysis and domain intelligence"""
    pass


@cli.command()
@click.option(
    "--input",
    type=click.Path(exists=True),
    help="Path to file with domains",
)
@click.option(
    "--domain",
    help="Single domain to analyze (alternative to --input)",
)
@click.option(
    "--output-dir", default="output_whoisfreaks", help="Directory to save results"
)
@click.option(
    "--api-key", help="WhoisFreaks API key (or set WHOISFREAKS_API_KEY env var)"
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--threads", default=10, help="Number of concurrent API requests")
@click.option("--delay", default=1.0, help="Delay between API requests (seconds)")
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
@click.option("--resume", is_flag=True, help="Resume scan from previous run")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state",
)
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--risk-analysis", is_flag=True, help="Perform risk analysis on domains")
@click.option("--expire-check", type=int, help="Flag domains expiring within N days")
@click.option("--store-db", is_flag=True, help="Store results in ReconCLI database")
@click.option("--target-domain", help="Primary target domain for database storage")
@click.option("--program", help="Bug bounty program name for database classification")
def lookup(
    input,
    domain,
    output_dir,
    api_key,
    verbose,
    threads,
    delay,
    save_json,
    save_markdown,
    resume,
    clear_resume_flag,
    show_resume,
    slack_webhook,
    discord_webhook,
    risk_analysis,
    expire_check,
    store_db,
    target_domain,
    program,
):
    """Perform bulk WHOIS lookups with advanced analysis"""

    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir, "whoisfreaks")
        return

    if clear_resume_flag:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Validate input options
    if not input and not domain:
        click.echo("❌ Error: Either --input or --domain must be specified")
        sys.exit(1)

    if input and domain:
        click.echo("❌ Error: Cannot specify both --input and --domain")
        sys.exit(1)

    # Get API key
    if not api_key:
        api_key = os.getenv("WHOISFREAKS_API_KEY")

    if not api_key:
        click.echo(
            "❌ Error: WhoisFreaks API key required. Use --api-key or set WHOISFREAKS_API_KEY env var"
        )
        sys.exit(1)

    # Initialize database storage if enabled
    if store_db:
        if not target_domain:
            click.echo("❌ Error: --store-db requires --target-domain to be specified")
            sys.exit(1)
        if not program:
            click.echo("❌ Error: --store-db requires --program to be specified")
            sys.exit(1)

        if store_target is None:
            click.echo(
                "❌ Error: Database operations not available. Install database dependencies."
            )
            sys.exit(1)

        # Store target info
        try:
            store_target(target_domain, program)
            if verbose:
                click.echo(
                    f"[+] 🗄️ Target {target_domain} stored in database for program {program}"
                )
        except Exception as e:
            click.echo(f"❌ Error storing target: {e}")
            if verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    # Load domains
    if input:
        with open(input) as f:
            domains = [line.strip() for line in f if line.strip()]
        input_source = input
    else:
        domains = [domain.strip()]
        input_source = f"single domain: {domain}"

    if verbose:
        click.echo("[+] 🚀 Starting WhoisFreaks bulk lookup")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏰ Delay: {delay}s")
        click.echo(f"[+] 📋 Loaded {len(domains)} domain(s) from {input_source}")

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"whoisfreaks_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_state = load_resume(output_dir)

    if resume and resume_state:
        if verbose:
            click.echo(
                f"[+] 📁 Loading resume state with {len(resume_state)} previous scan(s)"
            )
        # Find the most recent incomplete scan
        for key, data in sorted(
            resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True
        ):
            if key.startswith("whoisfreaks_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "input_source": input_source,
            "input_file": input if input else None,
            "single_domain": domain if domain else None,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "processed_count": 0,
            "success_count": 0,
            "failed_count": 0,
            "configuration": {
                "threads": threads,
                "delay": delay,
                "risk_analysis": risk_analysis,
                "expire_check": expire_check,
            },
        }
        save_resume_state(output_dir, resume_state)

    current_scan = resume_state[scan_key]
    processed_count = current_scan.get("processed_count", 0)

    if verbose and processed_count > 0:
        click.echo(f"[+] 📁 Resume: {processed_count} domains already processed")

    start_time = time.time()

    # Perform bulk WHOIS lookup
    results = bulk_whois_lookup(
        domains[processed_count:], api_key, threads, delay, verbose
    )

    # Update counts
    success_count = len([r for r in results if r.get("status") == "success"])
    failed_count = len(results) - success_count

    current_scan["processed_count"] = len(domains)
    current_scan["success_count"] = current_scan.get("success_count", 0) + success_count
    current_scan["failed_count"] = current_scan.get("failed_count", 0) + failed_count
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()

    save_resume_state(output_dir, resume_state)

    # Store results in database if enabled
    if store_db and store_whois_findings and results:
        if verbose:
            click.echo(f"[+] 🗄️ Storing {len(results)} WHOIS results in database...")

        try:
            for result in results:
                if result.get("status") == "success":
                    # Extract useful WHOIS data for database
                    whois_data = result.get("whois_data", {})
                    finding_data = {
                        "domain": result["domain"],
                        "whois_data": whois_data,
                        "timestamp": result.get("timestamp"),
                        "source": "whoisfreaks",
                    }

                    # Add risk analysis if available
                    if "risk_analysis" in result:
                        finding_data["risk_analysis"] = result["risk_analysis"]

                    store_whois_findings(target_domain, finding_data)

            if verbose:
                successful_results = [
                    r for r in results if r.get("status") == "success"
                ]
                click.echo(
                    f"[+] ✅ Stored {len(successful_results)} successful WHOIS results in database"
                )

        except Exception as e:
            click.echo(f"❌ Error storing WHOIS results: {e}")
            if verbose:
                import traceback

                traceback.print_exc()

    # Perform risk analysis if requested
    if risk_analysis:
        if verbose:
            click.echo("[+] 🔍 Performing risk analysis...")
        results = perform_risk_analysis(results, verbose)

    # Check expiring domains if requested
    if expire_check:
        if verbose:
            click.echo(
                f"[+] ⏰ Checking for domains expiring within {expire_check} days..."
            )
        results = check_expiring_domains(results, expire_check, verbose)

    # Save outputs
    save_whois_outputs(results, output_dir, save_json, save_markdown, verbose)

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo("\n[+] 📊 Scan Summary:")
        click.echo(f"   - Total domains: {len(domains)}")
        click.echo(f"   - Successfully analyzed: {success_count}")
        click.echo(f"   - Failed to analyze: {failed_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(
            f"   - Success rate: {success_count / len(domains) * 100:.1f}%"
            if len(domains) > 0
            else "   - Success rate: 0.0%"
        )

    # Generate analysis statistics
    analysis_stats = generate_analysis_statistics(results, verbose)

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        send_whoisfreaks_notifications(
            results,
            analysis_stats,
            len(domains),
            success_count,
            failed_count,
            elapsed,
            slack_webhook,
            discord_webhook,
            verbose,
        )

    click.echo("\n[+] ✅ WhoisFreaks analysis completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


@cli.command()
@click.option(
    "--input",
    type=click.Path(exists=True),
    required=True,
    help="Path to JSON file with WHOIS data",
)
@click.option(
    "--output-dir",
    default="output_whois_analysis",
    help="Directory to save analysis results",
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--expire-days", default=90, help="Flag domains expiring within N days")
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
def analyze(input, output_dir, verbose, expire_days, save_json, save_markdown):
    """Analyze existing WHOIS data for security insights"""

    if verbose:
        click.echo("[+] 🔍 Starting WHOIS data analysis")
        click.echo(f"[+] 📁 Input file: {input}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")

    # Load existing WHOIS data
    with open(input, "r") as f:
        whois_data = json.load(f)

    if verbose:
        click.echo(
            f"[+] 📊 Loaded {len(whois_data) if isinstance(whois_data, list) else 'unknown'} WHOIS records"
        )

    os.makedirs(output_dir, exist_ok=True)

    # Convert to standard format if needed
    if isinstance(whois_data, dict):
        # Check if it's our format (domain -> whois_data)
        results = []
        for domain, data in whois_data.items():
            if isinstance(data, dict) and "domain_name" in data:
                results.append(
                    {"domain": domain, "status": "success", "whois_data": data}
                )
        if not results and "results" in whois_data:
            results = whois_data["results"]
    elif isinstance(whois_data, list):
        results = whois_data
    else:
        results = [whois_data]

    # Perform comprehensive analysis
    analysis_results = {
        "registrar_analysis": analyze_registrars(results, verbose),
        "expiration_analysis": analyze_expirations(results, expire_days, verbose),
        "privacy_analysis": analyze_privacy_services(results, verbose),
        "risk_analysis": analyze_security_risks(results, verbose),
        "nameserver_analysis": analyze_nameservers(results, verbose),
        "creation_date_analysis": analyze_creation_dates(results, verbose),
    }

    # Save analysis results
    save_analysis_outputs(
        analysis_results, output_dir, save_json, save_markdown, verbose
    )

    if verbose:
        click.echo("\n[+] ✅ WHOIS analysis completed!")
        click.echo(f"[+] 📁 Analysis results saved to: {output_dir}")


def bulk_whois_lookup(
    domains: List[str], api_key: str, threads: int, delay: float, verbose: bool
) -> List[Dict]:
    """Perform bulk WHOIS lookups using WhoisFreaks API"""
    results = []

    def lookup_domain(domain: str) -> Dict:
        """Lookup WHOIS data for a single domain"""
        try:
            time.sleep(delay)  # Rate limiting

            # WhoisFreaks API endpoint
            url = "https://api.whoisfreaks.com/v1.0/whois"
            params = {"apiKey": api_key, "whois": "live", "domainName": domain.strip()}

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                whois_data = response.json()
                return {
                    "domain": domain,
                    "status": "success",
                    "whois_data": whois_data,
                    "timestamp": datetime.now().isoformat(),
                }
            else:
                return {
                    "domain": domain,
                    "status": "error",
                    "error": f"HTTP {response.status_code}: {response.text}",
                    "timestamp": datetime.now().isoformat(),
                }

        except Exception as e:
            return {
                "domain": domain,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    # Use ThreadPoolExecutor for concurrent lookups
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        with tqdm(
            total=len(domains), desc="🔍 WHOIS Lookup", disable=not verbose, ncols=100
        ) as pbar:
            # Submit all tasks
            future_to_domain = {
                executor.submit(lookup_domain, domain): domain for domain in domains
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_domain):
                result = future.result()
                results.append(result)
                pbar.update(1)

                # Update progress bar with stats
                success = len([r for r in results if r.get("status") == "success"])
                pbar.set_postfix(success=success, failed=len(results) - success)

    return results


def perform_risk_analysis(results: List[Dict], verbose: bool) -> List[Dict]:
    """Perform security risk analysis on WHOIS data"""

    for result in results:
        if result.get("status") != "success":
            continue

        whois_data = result.get("whois_data", {})
        risk_factors = []
        risk_score = 0

        # Check registrar reputation
        registrar = (
            whois_data.get("registrarName")
            or whois_data.get("domain_registrar", {}).get("registrar_name")
            or ""
        ).lower()
        if any(susp in registrar for susp in RISK_PATTERNS["suspicious_registrars"]):
            risk_factors.append("suspicious_registrar")
            risk_score += 20

        # Check privacy service usage
        registrant_org = whois_data.get("registrantOrganization", "").lower()
        admin_org = whois_data.get("adminOrganization", "").lower()
        if any(
            privacy in f"{registrant_org} {admin_org}"
            for privacy in RISK_PATTERNS["privacy_services"]
        ):
            risk_factors.append("privacy_service")
            risk_score += 15

        # Check domain age
        creation_date = (
            whois_data.get("createdDate")
            or whois_data.get("create_date")
            or whois_data.get("creation_date")
        )
        if creation_date:
            try:
                created = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                age_days = (
                    datetime.now().replace(tzinfo=created.tzinfo) - created
                ).days
                if age_days < RISK_PATTERNS["short_lived_domains"]:
                    risk_factors.append("new_domain")
                    risk_score += 25
            except:
                pass

        # Check TLD
        domain = result.get("domain", "")
        tld = f".{domain.split('.')[-1]}" if "." in domain else ""
        if tld in RISK_PATTERNS["suspicious_tlds"]:
            risk_factors.append("suspicious_tld")
            risk_score += 10

        # Assign risk level
        if risk_score >= 40:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "NONE"

        result["risk_analysis"] = {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
        }

    if verbose:
        high_risk = len(
            [
                r
                for r in results
                if r.get("risk_analysis", {}).get("risk_level") == "HIGH"
            ]
        )
        medium_risk = len(
            [
                r
                for r in results
                if r.get("risk_analysis", {}).get("risk_level") == "MEDIUM"
            ]
        )
        click.echo(
            f"[+] 🚨 Risk Analysis: {high_risk} HIGH risk, {medium_risk} MEDIUM risk domains found"
        )

    return results


def check_expiring_domains(
    results: List[Dict], expire_days: int, verbose: bool
) -> List[Dict]:
    """Check for domains expiring soon"""

    cutoff_date = datetime.now() + timedelta(days=expire_days)
    expiring_count = 0

    for result in results:
        if result.get("status") != "success":
            continue

        whois_data = result.get("whois_data", {})
        expiry_date = (
            whois_data.get("expiresDate")
            or whois_data.get("expiry_date")
            or whois_data.get("expires_date")
        )

        if expiry_date:
            try:
                expires = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
                days_until_expiry = (
                    expires - datetime.now().replace(tzinfo=expires.tzinfo)
                ).days

                if days_until_expiry <= expire_days:
                    result["expiring_soon"] = {
                        "days_until_expiry": days_until_expiry,
                        "expiry_date": expiry_date,
                        "status": "EXPIRING" if days_until_expiry > 0 else "EXPIRED",
                    }
                    expiring_count += 1

            except:
                pass

    if verbose:
        click.echo(
            f"[+] ⏰ Found {expiring_count} domains expiring within {expire_days} days"
        )

    return results


# Analysis functions for the analyze command
def analyze_registrars(results: List[Dict], verbose: bool) -> Dict:
    """Analyze registrar distribution"""
    registrar_counts = {}

    for result in results:
        whois_data = result.get("whois_data", {})
        # Support multiple field names
        registrar = (
            whois_data.get("registrar")
            or whois_data.get("registrarName")
            or whois_data.get("registrar_name")
            or "Unknown"
        )
        registrar_counts[registrar] = registrar_counts.get(registrar, 0) + 1

    # Sort by count
    sorted_registrars = sorted(
        registrar_counts.items(), key=lambda x: x[1], reverse=True
    )

    if verbose:
        click.echo("[+] 📊 Top 5 Registrars:")
        for registrar, count in sorted_registrars[:5]:
            click.echo(f"   - {registrar}: {count}")

    return {
        "total_registrars": len(registrar_counts),
        "top_registrars": dict(sorted_registrars[:10]),
        "registrar_distribution": registrar_counts,
    }


def analyze_expirations(results: List[Dict], expire_days: int, verbose: bool) -> Dict:
    """Analyze domain expiration patterns"""
    now = datetime.now()
    expiring_soon = []
    expired = []
    expiry_years = {}

    for result in results:
        whois_data = result.get("whois_data", {})
        # Support multiple field names
        expiry_date = (
            whois_data.get("expiration_date")
            or whois_data.get("expiresDate")
            or whois_data.get("expires_date")
        )

        if expiry_date:
            try:
                # Handle different date formats
                if "T" in expiry_date:
                    expires = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
                else:
                    expires = datetime.strptime(expiry_date, "%Y-%m-%d")

                days_until_expiry = (
                    expires
                    - now.replace(tzinfo=expires.tzinfo if expires.tzinfo else None)
                ).days

                if days_until_expiry <= 0:
                    expired.append(result.get("domain"))
                elif days_until_expiry <= expire_days:
                    expiring_soon.append(
                        {
                            "domain": result.get("domain"),
                            "days_until_expiry": days_until_expiry,
                            "expiry_date": expiry_date,
                        }
                    )

                # Track expiry years
                year = expires.year
                expiry_years[year] = expiry_years.get(year, 0) + 1

            except:
                pass

    if verbose:
        click.echo("[+] ⏰ Expiration Analysis:")
        click.echo(f"   - Expiring within {expire_days} days: {len(expiring_soon)}")
        click.echo(f"   - Already expired: {len(expired)}")

    return {
        "expiring_soon": expiring_soon,
        "expired_domains": expired,
        "expiry_year_distribution": expiry_years,
        "total_expiring": len(expiring_soon),
        "total_expired": len(expired),
    }


def analyze_privacy_services(results: List[Dict], verbose: bool) -> Dict:
    """Analyze privacy service usage"""
    privacy_services = {}
    privacy_count = 0

    for result in results:
        whois_data = result.get("whois_data", {})
        # Support multiple field names
        registrant_org = (
            whois_data.get("registrant_organization")
            or whois_data.get("registrantOrganization")
            or ""
        ).lower()
        admin_org = (
            whois_data.get("admin_organization")
            or whois_data.get("adminOrganization")
            or ""
        ).lower()

        for privacy_service in RISK_PATTERNS["privacy_services"]:
            if privacy_service in f"{registrant_org} {admin_org}":
                privacy_services[privacy_service] = (
                    privacy_services.get(privacy_service, 0) + 1
                )
                privacy_count += 1
                break

    if verbose:
        click.echo(
            f"[+] 🔒 Privacy Services: {privacy_count} domains using privacy protection"
        )

    return {
        "total_with_privacy": privacy_count,
        "privacy_service_distribution": privacy_services,
        "privacy_percentage": (privacy_count / len(results) * 100) if results else 0,
    }


def analyze_security_risks(results: List[Dict], verbose: bool) -> Dict:
    """Analyze security risks across all domains"""
    risk_distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    risk_factors = {}

    for result in results:
        risk_analysis = result.get("risk_analysis", {})
        risk_level = risk_analysis.get("risk_level", "NONE")
        risk_distribution[risk_level] += 1

        for factor in risk_analysis.get("risk_factors", []):
            risk_factors[factor] = risk_factors.get(factor, 0) + 1

    if verbose:
        click.echo("[+] 🚨 Security Risk Distribution:")
        for level, count in risk_distribution.items():
            if count > 0:
                click.echo(f"   - {level}: {count}")

    return {
        "risk_distribution": risk_distribution,
        "common_risk_factors": risk_factors,
        "high_risk_count": risk_distribution["HIGH"],
        "total_at_risk": risk_distribution["HIGH"] + risk_distribution["MEDIUM"],
    }


def analyze_nameservers(results: List[Dict], verbose: bool) -> Dict:
    """Analyze nameserver patterns"""
    nameserver_counts = {}

    for result in results:
        whois_data = result.get("whois_data", {})
        # Support multiple field names
        nameservers = (
            whois_data.get("nameservers")
            or whois_data.get("nameServers")
            or whois_data.get("name_servers")
            or []
        )

        if isinstance(nameservers, list):
            for ns in nameservers:
                # Extract provider from nameserver
                ns_lower = ns.lower()
                if "cloudflare" in ns_lower:
                    provider = "Cloudflare"
                elif "amazonaws" in ns_lower or "aws" in ns_lower:
                    provider = "AWS"
                elif "google" in ns_lower:
                    provider = "Google"
                elif "azure" in ns_lower or "microsoft" in ns_lower:
                    provider = "Microsoft"
                else:
                    provider = ns.split(".")[0] if "." in ns else ns

                nameserver_counts[provider] = nameserver_counts.get(provider, 0) + 1

    sorted_ns = sorted(nameserver_counts.items(), key=lambda x: x[1], reverse=True)

    if verbose:
        click.echo("[+] 🌐 Top 5 Nameserver Providers:")
        for provider, count in sorted_ns[:5]:
            click.echo(f"   - {provider}: {count}")

    return {
        "total_providers": len(nameserver_counts),
        "top_providers": dict(sorted_ns[:10]),
        "provider_distribution": nameserver_counts,
    }


def analyze_creation_dates(results: List[Dict], verbose: bool) -> Dict:
    """Analyze domain creation date patterns"""
    creation_years = {}
    recent_domains = []
    now = datetime.now()

    for result in results:
        whois_data = result.get("whois_data", {})
        # Support multiple field names
        creation_date = (
            whois_data.get("creation_date")
            or whois_data.get("createdDate")
            or whois_data.get("created_date")
        )

        if creation_date:
            try:
                # Handle different date formats
                if "T" in creation_date:
                    created = datetime.fromisoformat(
                        creation_date.replace("Z", "+00:00")
                    )
                else:
                    created = datetime.strptime(creation_date, "%Y-%m-%d")

                year = created.year
                creation_years[year] = creation_years.get(year, 0) + 1

                # Check for recent domains (last 30 days)
                days_old = (
                    now.replace(tzinfo=created.tzinfo if created.tzinfo else None)
                    - created
                ).days
                if days_old <= 30:
                    recent_domains.append(
                        {
                            "domain": result.get("domain"),
                            "created_date": creation_date,
                            "days_old": days_old,
                        }
                    )

            except:
                pass

    if verbose:
        click.echo(
            f"[+] 📅 Found {len(recent_domains)} domains created in last 30 days"
        )

    return {
        "creation_year_distribution": creation_years,
        "recent_domains": recent_domains,
        "total_recent": len(recent_domains),
    }


def save_whois_outputs(
    results: List[Dict],
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
):
    """Save WHOIS results in multiple formats"""

    # Standard text output
    txt_path = os.path.join(output_dir, "whoisfreaks_results.txt")
    with open(txt_path, "w") as f:
        for result in results:
            domain = result.get("domain", "unknown")
            status = result.get("status", "unknown")

            if status == "success":
                whois_data = result.get("whois_data", {})
                # Handle different field structures from WhoisFreaks API
                registrar = (
                    whois_data.get("registrarName")
                    or whois_data.get("domain_registrar", {}).get("registrar_name")
                    or "Unknown"
                )
                expiry = (
                    whois_data.get("expiresDate")
                    or whois_data.get("expiry_date")
                    or "Unknown"
                )

                # Risk analysis
                risk_info = ""
                if "risk_analysis" in result:
                    risk_level = result["risk_analysis"]["risk_level"]
                    risk_score = result["risk_analysis"]["risk_score"]
                    risk_info = f" | RISK: {risk_level} ({risk_score})"

                # Expiry warning
                expiry_info = ""
                if "expiring_soon" in result:
                    days = result["expiring_soon"]["days_until_expiry"]
                    expiry_info = f" | EXPIRES: {days} days"

                f.write(
                    f"{domain} | REG: {registrar} | EXPIRY: {expiry}{risk_info}{expiry_info}\n"
                )
            else:
                error = result.get("error", "Unknown error")
                f.write(f"{domain} | ERROR: {error}\n")

    if verbose:
        click.echo(f"[+] 💾 Saved results to {txt_path}")

    # JSON output
    if save_json:
        json_output = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_domains": len(results),
                "success_count": len(
                    [r for r in results if r.get("status") == "success"]
                ),
                "tool": "whoisfreakscli",
            },
            "results": results,
        }

        json_path = os.path.join(output_dir, "whoisfreaks_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

    # Markdown output
    if save_markdown:
        md_path = os.path.join(output_dir, "whoisfreaks_results.md")
        with open(md_path, "w") as f:
            f.write("# WhoisFreaks Analysis Results\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total Domains:** {len(results)}\n")
            f.write(
                f"**Successful Lookups:** {len([r for r in results if r.get('status') == 'success'])}\n\n"
            )

            f.write("## Results\n\n")
            f.write("| Domain | Registrar | Expiry Date | Risk Level | Status |\n")
            f.write("|--------|-----------|-------------|------------|--------|\n")

            for result in results:
                domain = result.get("domain", "unknown")
                if result.get("status") == "success":
                    whois_data = result.get("whois_data", {})
                    # Handle different field structures from WhoisFreaks API
                    registrar = (
                        whois_data.get("registrarName")
                        or whois_data.get("domain_registrar", {}).get("registrar_name")
                        or "Unknown"
                    )
                    expiry = (
                        whois_data.get("expiresDate")
                        or whois_data.get("expiry_date")
                        or "Unknown"
                    )
                    risk_level = result.get("risk_analysis", {}).get(
                        "risk_level", "N/A"
                    )
                    status = "✅ Success"
                else:
                    registrar = "-"
                    expiry = "-"
                    risk_level = "-"
                    status = f"❌ {result.get('error', 'Error')}"

                f.write(
                    f"| {domain} | {registrar} | {expiry} | {risk_level} | {status} |\n"
                )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")


def save_analysis_outputs(
    analysis_results: Dict,
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
):
    """Save analysis results in multiple formats"""

    # JSON output
    if save_json:
        json_path = os.path.join(output_dir, "whois_analysis.json")
        with open(json_path, "w") as f:
            json.dump(
                {
                    "analysis_metadata": {
                        "timestamp": datetime.now().isoformat(),
                        "tool": "whoisfreakscli-analyze",
                    },
                    "analysis_results": analysis_results,
                },
                f,
                indent=2,
            )

        if verbose:
            click.echo(f"[+] 📄 Saved analysis JSON to {json_path}")

    # Markdown report
    if save_markdown:
        md_path = os.path.join(output_dir, "whois_analysis_report.md")
        with open(md_path, "w") as f:
            f.write("# WHOIS Analysis Report\n\n")
            f.write(
                f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            # Registrar analysis
            f.write("## Registrar Analysis\n\n")
            reg_analysis = analysis_results.get("registrar_analysis", {})
            f.write(
                f"**Total Registrars:** {reg_analysis.get('total_registrars', 0)}\n\n"
            )
            f.write("### Top Registrars\n")
            for registrar, count in list(
                reg_analysis.get("top_registrars", {}).items()
            )[:5]:
                f.write(f"- {registrar}: {count}\n")
            f.write("\n")

            # Security risk analysis
            f.write("## Security Risk Analysis\n\n")
            risk_analysis = analysis_results.get("risk_analysis", {})
            risk_dist = risk_analysis.get("risk_distribution", {})
            f.write(f"- **High Risk:** {risk_dist.get('HIGH', 0)}\n")
            f.write(f"- **Medium Risk:** {risk_dist.get('MEDIUM', 0)}\n")
            f.write(f"- **Low Risk:** {risk_dist.get('LOW', 0)}\n")
            f.write(f"- **No Risk:** {risk_dist.get('NONE', 0)}\n\n")

            # Expiration analysis
            f.write("## Expiration Analysis\n\n")
            exp_analysis = analysis_results.get("expiration_analysis", {})
            f.write(f"- **Expiring Soon:** {exp_analysis.get('total_expiring', 0)}\n")
            f.write(
                f"- **Already Expired:** {exp_analysis.get('total_expired', 0)}\n\n"
            )

            # Privacy analysis
            f.write("## Privacy Service Analysis\n\n")
            priv_analysis = analysis_results.get("privacy_analysis", {})
            f.write(
                f"- **Using Privacy Services:** {priv_analysis.get('total_with_privacy', 0)}\n"
            )
            f.write(
                f"- **Privacy Percentage:** {priv_analysis.get('privacy_percentage', 0):.1f}%\n\n"
            )

        if verbose:
            click.echo(f"[+] 📝 Saved analysis report to {md_path}")


def generate_analysis_statistics(results: List[Dict], verbose: bool) -> Dict[str, Any]:
    """Generate comprehensive analysis statistics"""
    stats: Dict[str, Any] = {
        "total_domains": len(results),
        "successful_lookups": len([r for r in results if r.get("status") == "success"]),
        "failed_lookups": len([r for r in results if r.get("status") != "success"]),
    }

    # Risk statistics
    if any("risk_analysis" in r for r in results):
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for result in results:
            risk_level = result.get("risk_analysis", {}).get("risk_level", "NONE")
            risk_counts[risk_level] += 1
        stats["risk_distribution"] = risk_counts

    # Expiry statistics
    expiring_count = len([r for r in results if "expiring_soon" in r])
    if expiring_count > 0:
        stats["expiring_domains"] = expiring_count

    return stats


def send_whoisfreaks_notifications(
    results: List[Dict],
    stats: Dict,
    total: int,
    success: int,
    failed: int,
    elapsed: float,
    slack_webhook: str,
    discord_webhook: str,
    verbose: bool,
):
    """Send WhoisFreaks scan notifications"""
    if not (send_notification and (slack_webhook or discord_webhook)):
        return

    try:
        scan_metadata = {
            "total_domains": total,
            "success_count": success,
            "failed_count": failed,
            "success_rate": round(success / total * 100, 1) if total > 0 else 0,
            "scan_duration": f"{elapsed}s",
            "risk_distribution": stats.get("risk_distribution", {}),
            "expiring_domains": stats.get("expiring_domains", 0),
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "tool": "whoisfreakscli",
        }

        # Prepare sample results for notification
        sample_results = [r for r in results if r.get("status") == "success"][:10]

        if verbose:
            click.echo("[+] 📱 Sending WhoisFreaks scan notifications...")

        success = send_notification(
            notification_type="whoisfreaks",
            results=sample_results,
            scan_metadata=scan_metadata,
            slack_webhook=slack_webhook,
            discord_webhook=discord_webhook,
            verbose=verbose,
        )

        if success and verbose:
            click.echo("[+] ✅ Notifications sent successfully")

    except Exception as e:
        if verbose:
            click.echo(f"[!] ❌ Notification failed: {e}")


def show_resume_status(output_dir: str, tool_prefix: str):
    """Show status of previous scans from resume file"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    matching_scans = [k for k in resume_state.keys() if k.startswith(tool_prefix)]

    if not matching_scans:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    click.echo(f"[+] Found {len(matching_scans)} previous scan(s):")
    click.echo()

    for scan_key in matching_scans:
        scan_data = resume_state[scan_key]
        click.echo(f"🔍 Scan: {scan_key}")

        # Display input source
        if scan_data.get("single_domain"):
            click.echo(f"   Input: Single domain - {scan_data.get('single_domain')}")
        else:
            click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")

        click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

        if scan_data.get("completed"):
            click.echo("   Status: ✅ Completed")
            click.echo(f"   Completed: {scan_data.get('completion_time', 'unknown')}")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
            click.echo(f"   Success: {scan_data.get('success_count', 0)}")
            click.echo(f"   Failed: {scan_data.get('failed_count', 0)}")
        else:
            click.echo("   Status: ⏳ Incomplete")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

        click.echo()


if __name__ == "__main__":
    cli()
