import click
import os
import requests
import json
import socket
from reconcli.utils.cloud_detect import (
    detect_cloud_provider,
    print_cloud_detection_results,
    batch_detect_cloud_providers,
)
from reconcli.utils.s3_enum import (
    enumerate_s3_buckets,
    print_s3_results,
    save_s3_results,
)


@click.command()
@click.option("--domain", help="Target domain (e.g. example.com)")
@click.option("--domains-file", help="File with list of domains (one per line)")
@click.option("--ip", help="Optional IP address (used for ASN/cloud detection)")
@click.option("--s3-enum", is_flag=True, help="Enable S3 bucket enumeration for domain")
@click.option(
    "--s3-regions",
    is_flag=True,
    help="Check S3 buckets in multiple AWS regions (slower)",
)
@click.option(
    "--s3-threads",
    default=10,
    help="Number of threads for S3 enumeration (default: 10)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--output-dir", default="output/cloudcli", help="Directory to save results"
)
@click.option(
    "--output-format",
    default="json",
    type=click.Choice(["json", "txt", "csv"]),
    help="Output format for results",
)
def cloudcli(
    domain,
    domains_file,
    ip,
    s3_enum,
    s3_regions,
    s3_threads,
    verbose,
    output_dir,
    output_format,
):
    """Detect cloud providers and enumerate public cloud assets (S3, etc)."""

    if not domain and not domains_file:
        click.echo("❌ Error: Must specify either --domain or --domains-file")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Handle single domain or batch processing
    if domains_file:
        if not os.path.exists(domains_file):
            click.echo(f"❌ Error: Domains file not found: {domains_file}")
            return

        with open(domains_file, "r") as f:
            domains = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]

        if not domains:
            click.echo("❌ Error: No valid domains found in file")
            return

        print(f"[+] Processing {len(domains)} domains from {domains_file}")

        # Batch cloud detection
        all_results = batch_detect_cloud_providers(domains, verbose=verbose)

        # Save batch results
        batch_output = os.path.join(
            output_dir, f"batch_cloud_detection.{output_format}"
        )
        if output_format == "json":
            with open(batch_output, "w") as f:
                json.dump(all_results, f, indent=2)
        else:
            with open(batch_output, "w") as f:
                for result in all_results:
                    domain_name = result.get("domain", "unknown")
                    cloud_providers = ", ".join(result.get("cloud_guess", ["None"]))
                    f.write(f"{domain_name}: {cloud_providers}\n")

        print(f"[✓] Batch results saved: {batch_output}")

        # S3 enumeration for batch processing (if requested)
        if s3_enum:
            print(f"\n[+] Starting S3 enumeration for {len(domains)} domains...")
            for i, target_domain in enumerate(domains, 1):
                print(f"\n[{i}/{len(domains)}] S3 enumeration for: {target_domain}")
                s3_results = enumerate_s3_buckets(
                    target_domain,
                    check_regional=s3_regions,
                    max_workers=s3_threads,
                    verbose=verbose,
                )

                # Save individual S3 results
                s3_output = os.path.join(
                    output_dir, f"{target_domain}_s3_buckets.{output_format}"
                )
                save_s3_results(s3_results, s3_output, output_format)

                # Show summary
                if not verbose:
                    interesting = [
                        r for r in s3_results if r["status"] in ["200", "403", "302"]
                    ]
                    if interesting:
                        print(
                            f"[✓] Found {len(interesting)} interesting S3 buckets for {target_domain}"
                        )
                        public = [r for r in interesting if r["status"] == "200"]
                        if public:
                            print(f"    🚨 {len(public)} PUBLIC buckets found!")

    else:
        # Single domain processing
        print(f"[+] Detecting cloud provider for: {domain}")
        cloud_info = detect_cloud_provider(domain, ip, verbose=verbose)

        # Pretty print results
        print_cloud_detection_results(cloud_info, verbose=verbose)

        # Save cloud detection results
        cloud_output = os.path.join(output_dir, f"{domain}_cloud.{output_format}")
        if output_format == "json":
            with open(cloud_output, "w") as f:
                json.dump(cloud_info, f, indent=2)
        else:
            with open(cloud_output, "w") as f:
                domain_name = cloud_info.get("domain", "unknown")
                cloud_providers = ", ".join(cloud_info.get("cloud_guess", ["None"]))
                if output_format == "csv":
                    f.write("domain,cloud_providers,ip,ptr\n")
                    f.write(
                        f"{domain_name},{cloud_providers},{cloud_info.get('ip', '')},{cloud_info.get('ptr', '')}\n"
                    )
                else:
                    f.write(f"Domain: {domain_name}\n")
                    f.write(f"Cloud Providers: {cloud_providers}\n")
                    f.write(f"IP: {cloud_info.get('ip', '')}\n")
                    f.write(f"PTR: {cloud_info.get('ptr', '')}\n")

        print(f"[✓] Cloud detection saved: {cloud_output}")

        # S3 enumeration for single domain
        if s3_enum:
            print(f"\n[+] Enumerating S3 buckets for: {domain}")
            s3_results = enumerate_s3_buckets(
                domain,
                check_regional=s3_regions,
                max_workers=s3_threads,
                verbose=verbose,
            )

            # Pretty print S3 results
            print_s3_results(s3_results, show_all=verbose)

            # Save S3 results
            s3_output = os.path.join(output_dir, f"{domain}_s3_buckets.{output_format}")
            save_s3_results(s3_results, s3_output, output_format)

            print(f"[✓] S3 results saved: {s3_output}")


if __name__ == "__main__":
    cloudcli()
