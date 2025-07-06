#!/usr/bin/env python3
"""
ReconCLI Virtual Host Check Module

Advanced virtual host discovery and enumeration tool for identifying valid VHOSTs
on target IP addresses. Features comprehensive error handling, technology detection,
and detailed response analysis.
"""

import click
import httpx
import time
import os
from pathlib import Path
from datetime import datetime


@click.command()
@click.option("--ip", help="Target IP (e.g. 1.2.3.4 or 1.2.3.4:8080)")
@click.option("--input", "input_file", help="File with list of IPs (one per line)")
@click.option("--domain", required=True, help="Main domain (e.g. example.com)")
@click.option(
    "--vhost", required=True, help="Subdomain/VHOST to test (e.g. admin, store)"
)
@click.option("--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
@click.option("--https", is_flag=True, help="Use HTTPS instead of HTTP")
@click.option("--insecure", is_flag=True, help="Ignore SSL cert warnings")
@click.option(
    "--verbose", "-v", is_flag=True, help="Show detailed response information"
)
@click.option("--timeout", default=10, help="Request timeout in seconds (default: 10)")
@click.option(
    "--output-dir", default="output/vhostcheck", help="Directory to save results"
)
@click.option(
    "--output-format",
    default="txt",
    type=click.Choice(["txt", "json", "csv"]),
    help="Output format for results",
)
@click.option("--save-output", is_flag=True, help="Save results to file")
def vhostcheckcli(
    ip,
    input_file,
    domain,
    vhost,
    proxy,
    https,
    insecure,
    verbose,
    timeout,
    output_dir,
    output_format,
    save_output,
):
    """
    Virtual Host Discovery and Enumeration

    Test for valid virtual hosts on target IP addresses with comprehensive
    response analysis and technology detection.

    Examples:
        # Basic VHOST check
        reconcli vhostcheck --ip 192.168.1.100 --domain example.com --vhost admin

        # Multiple IPs from file
        reconcli vhostcheck --input ips.txt --domain example.com --vhost admin

        # HTTPS with proxy
        reconcli vhostcheck --ip 192.168.1.100:8443 --domain example.com --vhost api --https --proxy http://127.0.0.1:8080

        # Verbose output with file saving
        reconcli vhostcheck --input ips.txt --domain example.com --vhost store --verbose --save-output
    """

    # Validate input - either --ip or --input must be provided
    if not ip and not input_file:
        click.echo("❌ Error: Either --ip or --input must be provided", err=True)
        return

    if ip and input_file:
        click.echo(
            "❌ Error: Cannot use both --ip and --input at the same time", err=True
        )
        return

    # Get list of IPs to process
    if input_file:
        if not os.path.exists(input_file):
            click.echo(f"❌ Error: Input file '{input_file}' not found", err=True)
            return

        try:
            with open(input_file, "r") as f:
                ip_list = [line.strip() for line in f.readlines() if line.strip()]

            if not ip_list:
                click.echo(f"❌ Error: No valid IPs found in '{input_file}'", err=True)
                return

            click.echo(
                f"🔍 ReconCLI Virtual Host Check - Testing {vhost}.{domain} on {len(ip_list)} IPs from {input_file}"
            )
        except Exception as e:
            click.echo(f"❌ Error reading file '{input_file}': {e}", err=True)
            return
    else:
        ip_list = [ip]
        click.echo(f"🔍 ReconCLI Virtual Host Check - Testing {vhost}.{domain} on {ip}")

    # Create output directory if saving results
    if save_output:
        os.makedirs(output_dir, exist_ok=True)

    # Process all IPs
    all_results = []
    valid_vhosts_found = 0

    for i, current_ip in enumerate(ip_list, 1):
        if len(ip_list) > 1:
            click.echo(f"\n[{i}/{len(ip_list)}] Processing IP: {current_ip}")

        result = check_vhost(
            current_ip, domain, vhost, proxy, https, insecure, verbose, timeout
        )
        all_results.append(result)

        if result["is_valid"]:
            valid_vhosts_found += 1

    # Summary for multiple IPs
    if len(ip_list) > 1:
        click.echo(f"\n📊 Summary:")
        click.echo(f"   Total IPs processed: {len(ip_list)}")
        click.echo(f"   Valid VHOSTs found: {valid_vhosts_found}")
        click.echo(f"   Success rate: {(valid_vhosts_found/len(ip_list)*100):.1f}%")

    # Save results if requested
    if save_output:
        if len(ip_list) > 1:
            save_batch_results(all_results, output_dir, output_format, domain, vhost)
        else:
            save_results(
                all_results[0], output_dir, output_format, ip_list[0], domain, vhost
            )

    return all_results


def check_vhost(
    ip,
    domain,
    vhost,
    proxy=None,
    https=False,
    insecure=False,
    verbose=False,
    timeout=10,
):
    """Perform virtual host check and return results"""
    scheme = "https" if https else "http"

    # Handle IP with port
    if ":" in ip and not ip.startswith("["):  # IPv4 with port
        target_url = f"{scheme}://{ip}/"
    elif ip.startswith("[") and "]:" in ip:  # IPv6 with port
        target_url = f"{scheme}://{ip}/"
    else:  # IP without port
        target_url = f"{scheme}://{ip}/"

    vhost_header = f"{vhost}.{domain}"

    headers = {
        "Host": vhost_header,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Create client with proper configuration
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": not insecure,
    }

    if proxy:
        client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

    result = {
        "vhost": vhost_header,
        "target_url": target_url,
        "status": "error",
        "status_code": None,
        "response_size": 0,
        "response_time": 0,
        "is_valid": False,
        "technologies": [],
        "server": None,
        "title": None,
        "error": None,
        "headers": {},
        "final_url": None,
    }

    try:
        start_time = time.time()
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(target_url, headers=headers)

        response_time = round((time.time() - start_time) * 1000, 2)

        result.update(
            {
                "status": "success",
                "status_code": resp.status_code,
                "response_size": len(resp.text),
                "response_time": response_time,
                "headers": dict(resp.headers),
                "final_url": str(resp.url),
            }
        )

        click.echo(
            f"[+] {vhost_header} → {resp.status_code} ({len(resp.text)} bytes) [{response_time}ms]"
        )

        # Check if VHOST is potentially valid
        if resp.status_code in [200, 403, 401]:
            result["is_valid"] = True
            click.echo("    ⚠️  Possible valid VHOST!")

        # Technology detection
        response_lower = resp.text.lower()
        technologies = []

        if "shopify" in response_lower:
            technologies.append("Shopify")
            click.echo("    🛍️  Shopify detected in response body.")
        if "cloudflare" in response_lower:
            technologies.append("Cloudflare")
            click.echo("    ☁️  Cloudflare detected in response body.")
        if "nginx" in response_lower or "nginx" in str(resp.headers).lower():
            technologies.append("Nginx")
            click.echo("    🔧  Nginx detected.")
        if "apache" in response_lower or "apache" in str(resp.headers).lower():
            technologies.append("Apache")
            click.echo("    🔧  Apache detected.")
        if "iis" in response_lower or "iis" in str(resp.headers).lower():
            technologies.append("IIS")
            click.echo("    🔧  IIS detected.")
        if "wordpress" in response_lower:
            technologies.append("WordPress")
            click.echo("    📰  WordPress detected.")
        if "drupal" in response_lower:
            technologies.append("Drupal")
            click.echo("    📰  Drupal detected.")

        result["technologies"] = technologies

        # Show server header if present
        if "server" in resp.headers:
            server = resp.headers["server"]
            result["server"] = server
            click.echo(f"    🖥️  Server: {server}")

        # Extract and show title if present
        if "<title>" in response_lower:
            title_start = response_lower.find("<title>") + 7
            title_end = response_lower.find("</title>", title_start)
            if title_end > title_start:
                title = resp.text[title_start:title_end].strip()
                if title:
                    result["title"] = title
                    click.echo(f"    📄  Title: {title}")

        # Verbose output
        if verbose:
            click.echo(f"    📊  Response headers:")
            for key, value in resp.headers.items():
                click.echo(f"        {key}: {value}")
            click.echo(f"    🔗  Final URL: {resp.url}")

    except httpx.ConnectError as e:
        error_msg = f"CONNECTION ERROR: {e}"
        result["error"] = error_msg
        click.echo(f"[-] {vhost_header} → {error_msg}")
    except httpx.TimeoutException as e:
        error_msg = f"TIMEOUT: {e}"
        result["error"] = error_msg
        click.echo(f"[-] {vhost_header} → {error_msg}")
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP ERROR: {e}"
        result["error"] = error_msg
        click.echo(f"[-] {vhost_header} → {error_msg}")
    except httpx.RequestError as e:
        error_msg = f"REQUEST ERROR: {e}"
        result["error"] = error_msg
        click.echo(f"[-] {vhost_header} → {error_msg}")
    except Exception as e:
        error_msg = f"UNEXPECTED ERROR: {e}"
        result["error"] = error_msg
        click.echo(f"[-] {vhost_header} → {error_msg}")

    return result


def save_results(result, output_dir, output_format, ip, domain, vhost):
    """Save scan results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vhostcheck_{ip}_{vhost}.{domain}_{timestamp}"

    if output_format == "json":
        import json

        filepath = Path(output_dir) / f"{filename}.json"
        with open(filepath, "w") as f:
            json.dump(result, f, indent=2)
    elif output_format == "csv":
        import csv

        filepath = Path(output_dir) / f"{filename}.csv"
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "VHOST",
                    "Status Code",
                    "Response Size",
                    "Response Time",
                    "Is Valid",
                    "Technologies",
                    "Server",
                    "Title",
                    "Error",
                ]
            )
            writer.writerow(
                [
                    result["vhost"],
                    result["status_code"],
                    result["response_size"],
                    result["response_time"],
                    result["is_valid"],
                    "; ".join(result["technologies"]),
                    result["server"],
                    result["title"],
                    result["error"],
                ]
            )
    else:  # txt format
        filepath = Path(output_dir) / f"{filename}.txt"
        with open(filepath, "w") as f:
            f.write(f"VHOST Check Results\n")
            f.write(f"==================\n\n")
            f.write(f"Target: {result['vhost']} on {result['target_url']}\n")
            f.write(f"Status: {result['status']}\n")
            f.write(f"Status Code: {result['status_code']}\n")
            f.write(f"Response Size: {result['response_size']} bytes\n")
            f.write(f"Response Time: {result['response_time']}ms\n")
            f.write(f"Is Valid VHOST: {result['is_valid']}\n")
            f.write(f"Technologies: {', '.join(result['technologies'])}\n")
            f.write(f"Server: {result['server']}\n")
            f.write(f"Title: {result['title']}\n")
            if result["error"]:
                f.write(f"Error: {result['error']}\n")

    click.echo(f"💾 Results saved to: {filepath}")


def save_batch_results(all_results, output_dir, output_format, domain, vhost):
    """Save batch scan results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vhostcheck_batch_{vhost}.{domain}_{timestamp}"

    if output_format == "json":
        import json

        filepath = Path(output_dir) / f"{filename}.json"
        with open(filepath, "w") as f:
            json.dump(
                {
                    "scan_info": {
                        "vhost": f"{vhost}.{domain}",
                        "timestamp": timestamp,
                        "total_ips": len(all_results),
                        "valid_vhosts": sum(1 for r in all_results if r["is_valid"]),
                    },
                    "results": all_results,
                },
                f,
                indent=2,
            )
    elif output_format == "csv":
        import csv

        filepath = Path(output_dir) / f"{filename}.csv"
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "VHOST",
                    "Target IP",
                    "Status Code",
                    "Response Size",
                    "Response Time",
                    "Is Valid",
                    "Technologies",
                    "Server",
                    "Title",
                    "Error",
                ]
            )
            for result in all_results:
                writer.writerow(
                    [
                        result["vhost"],
                        result["target_url"].split("://")[1].rstrip("/"),
                        result["status_code"],
                        result["response_size"],
                        result["response_time"],
                        result["is_valid"],
                        "; ".join(result["technologies"]),
                        result["server"],
                        result["title"],
                        result["error"],
                    ]
                )
    else:  # txt format
        filepath = Path(output_dir) / f"{filename}.txt"
        with open(filepath, "w") as f:
            f.write(f"VHOST Batch Check Results\n")
            f.write(f"========================\n\n")
            f.write(f"VHOST: {vhost}.{domain}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Total IPs: {len(all_results)}\n")
            f.write(f"Valid VHOSTs: {sum(1 for r in all_results if r['is_valid'])}\n")
            f.write(
                f"Success Rate: {(sum(1 for r in all_results if r['is_valid'])/len(all_results)*100):.1f}%\n\n"
            )

            for i, result in enumerate(all_results, 1):
                f.write(f"[{i}] {result['target_url']}\n")
                f.write(f"    Status: {result['status']}\n")
                f.write(f"    Status Code: {result['status_code']}\n")
                f.write(f"    Response Size: {result['response_size']} bytes\n")
                f.write(f"    Response Time: {result['response_time']}ms\n")
                f.write(f"    Is Valid VHOST: {result['is_valid']}\n")
                if result["technologies"]:
                    f.write(f"    Technologies: {', '.join(result['technologies'])}\n")
                if result["server"]:
                    f.write(f"    Server: {result['server']}\n")
                if result["title"]:
                    f.write(f"    Title: {result['title']}\n")
                if result["error"]:
                    f.write(f"    Error: {result['error']}\n")
                f.write(f"\n")

    click.echo(f"💾 Batch results saved to: {filepath}")


if __name__ == "__main__":
    vhostcheckcli()
