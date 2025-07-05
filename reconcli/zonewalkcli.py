import os
import click
import dns.query
import dns.zone
import dns.resolver
import dns.name
import dns.message
from tqdm import tqdm
from reconcli.utils.loaders import load_lines
from reconcli.utils.mdexport import export_zonewalk_report


@click.command(
    "zonewalkcli",
    help="Zonewalk scanner – checks for DNS zone transfers, NSEC/NSEC3, delegated subdomains",
)
@click.option("-d", "--domain", help="Single domain to scan", required=False)
@click.option("-i", "--input", help="File with domains to scan", required=False)
@click.option(
    "-o", "--output-dir", help="Directory to save Markdown reports", required=True
)
@click.option(
    "--shodan-api-key", help="Shodan API key for additional information", required=False
)
@click.option("--verbose", is_flag=True, help="Show detailed errors and debug info")
def cli(domain, input, output_dir, shodan_api_key, verbose):
    os.makedirs(output_dir, exist_ok=True)

    summary = {
        "total": 0,
        "axfr": 0,
        "nsec": 0,
        "nsec3": 0,
        "delegated": 0,
    }

    domains = []
    if domain:
        domains.append(domain)
    if input:
        domains.extend(load_lines(input))

    for target_domain in tqdm(domains, desc="[ZoneWalk]"):
        result = {
            "domain": target_domain,
            "nsec_supported": False,
            "nsec3_supported": False,
            "delegated_subs": [],
            "zone_transfer_success": False,
            "zone_entries": [],
        }

        try:
            ns_records = dns.resolver.resolve(target_domain, "NS")
            name_servers = [str(r.target).rstrip(".") for r in ns_records]
        except Exception as e:
            result["error"] = f"Failed to get NS records: {str(e)}"
            if verbose:
                click.echo(f"[VERBOSE] NS error for {target_domain}: {e}")
            export_zonewalk_report(target_domain, result, output_dir)
            continue

        for ns in name_servers:
            try:
                answer = dns.resolver.resolve(ns, "A")
                ns_ip = answer[0].address
            except Exception as e:
                if verbose:
                    click.echo(f"[VERBOSE] Failed to resolve A for NS {ns}: {e}")
                continue

            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, target_domain, timeout=5))
                result["zone_transfer_success"] = True
                result["zone_entries"] = [
                    str(n) + "." + target_domain for n in z.nodes.keys()
                ]
                if verbose:
                    click.echo(
                        f"[VERBOSE] AXFR success for {target_domain} on {ns} ({ns_ip})"
                    )
            except Exception as e:
                if verbose:
                    click.echo(
                        f"[VERBOSE] AXFR failed for {target_domain} on {ns} ({ns_ip}): {e}"
                    )

            try:
                fake_name = "doesnotexist-zonewalk." + target_domain
                qname = dns.name.from_text(fake_name)
                request = dns.message.make_query(
                    qname, dns.rdatatype.A, want_dnssec=True
                )
                response = dns.query.udp(request, ns_ip, timeout=5)

                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        result["nsec_supported"] = True
                    elif rrset.rdtype == dns.rdatatype.NSEC3:
                        result["nsec3_supported"] = True
                if verbose:
                    click.echo(
                        f"[VERBOSE] DNSSEC checked for {target_domain} on {ns} ({ns_ip})"
                    )
            except Exception as e:
                if verbose:
                    click.echo(
                        f"[VERBOSE] DNSSEC check failed for {target_domain} on {ns} ({ns_ip}): {e}"
                    )

            try:
                delegated = []
                for sub in ["dev", "test", "staging", "mail", "docs"]:
                    try:
                        sub_ns = dns.resolver.resolve(f"{sub}.{target_domain}", "NS")
                        if sub_ns:
                            delegated.append(f"{sub}.{target_domain}")
                    except Exception as e:
                        if verbose:
                            click.echo(
                                f"[VERBOSE] Delegation check failed for {sub}.{target_domain}: {e}"
                            )
                        continue
                result["delegated_subs"] = delegated
            except Exception as e:
                if verbose:
                    click.echo(
                        f"[VERBOSE] Delegation block failed for {target_domain}: {e}"
                    )

        if shodan_api_key:
            try:
                from reconcli.modules.shodan import Shodan

                shodan = Shodan(shodan_api_key)
                ns_info = []
                for ns in name_servers:
                    try:
                        ip_address = dns.resolver.resolve(ns, "A")[0].address
                        info = shodan.host(ip_address)
                        ns_info.append(
                            {
                                "ns": ns,
                                "ip": ip_address,
                                "org": info.get("org"),
                                "os": info.get("os"),
                                "ports": info.get("ports"),
                                "hostnames": info.get("hostnames"),
                                "country": info.get("country"),
                            }
                        )
                        if verbose:
                            click.echo(
                                f"[VERBOSE] Shodan info for {ns} ({ip_address}): {info}"
                            )
                    except Exception as e:
                        ns_info.append({"ns": ns, "error": str(e)})
                        if verbose:
                            click.echo(f"[VERBOSE] Shodan lookup failed for {ns}: {e}")

                result["shodan_ns_info"] = ns_info
            except Exception as e:
                result["shodan_error"] = f"Shodan lookup failed: {str(e)}"
                if verbose:
                    click.echo(f"[VERBOSE] Shodan block failed: {e}")

        export_zonewalk_report(target_domain, result, output_dir)

        summary["total"] += 1
        if result["zone_transfer_success"]:
            summary["axfr"] += 1
        if result["nsec_supported"]:
            summary["nsec"] += 1
        if result["nsec3_supported"]:
            summary["nsec3"] += 1
        if result["delegated_subs"]:
            summary["delegated"] += 1

    click.echo("\n[ZoneWalk] SUMMARY")
    click.echo(f"Domains checked: {summary['total']}")
    click.echo(f"AXFR vulnerable: {summary['axfr']}")
    click.echo(f"NSEC vulnerable: {summary['nsec']}")
    click.echo(f"NSEC3 vulnerable: {summary['nsec3']}")
    click.echo(f"Delegated subdomains found: {summary['delegated']}")
