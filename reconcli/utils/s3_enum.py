import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

# Extended S3 bucket naming patterns
COMMON_BUCKET_PATTERNS = [
    # Basic patterns
    "{domain}",
    "{domain_nodot}",
    "{subdomain}",
    # Asset patterns
    "{domain}-assets",
    "{domain_nodot}-assets",
    "assets-{domain}",
    "assets-{domain_nodot}",
    "cdn.{domain}",
    "{domain}-cdn",
    "{domain_nodot}-cdn",
    "cdn-{domain_nodot}",
    # Media patterns
    "media.{domain}",
    "{domain}-media",
    "{domain_nodot}-media",
    "media-{domain_nodot}",
    "images.{domain}",
    "{domain}-images",
    "{domain_nodot}-images",
    "img-{domain_nodot}",
    "photos-{domain_nodot}",
    # Static content
    "static.{domain}",
    "{domain}-static",
    "{domain_nodot}-static",
    "static-{domain_nodot}",
    "www.{domain}",
    "www-{domain_nodot}",
    # Application patterns
    "{domain}-files",
    "{domain_nodot}-files",
    "files-{domain_nodot}",
    "{domain}-uploads",
    "{domain_nodot}-uploads",
    "uploads-{domain_nodot}",
    "{domain}-documents",
    "{domain_nodot}-docs",
    "docs-{domain_nodot}",
    # Backup patterns
    "{domain}-backup",
    "{domain_nodot}-backup",
    "backup-{domain_nodot}",
    "{domain}-backups",
    "{domain_nodot}-backups",
    "backups-{domain_nodot}",
    # Environment patterns
    "{domain}-prod",
    "{domain_nodot}-prod",
    "{domain}-production",
    "{domain_nodot}-production",
    "{domain}-dev",
    "{domain_nodot}-dev",
    "{domain}-development",
    "{domain_nodot}-development",
    "{domain}-staging",
    "{domain_nodot}-staging",
    "{domain}-test",
    "{domain_nodot}-test",
    # Versioned patterns
    "{domain}123",
    "{domain_nodot}123",
    "{domain}2023",
    "{domain_nodot}2023",
    "{domain}2024",
    "{domain_nodot}2024",
    "{domain}-v1",
    "{domain_nodot}-v1",
    "{domain}-v2",
    "{domain_nodot}-v2",
    # Common short forms
    "{domain_nodot}cdn",
    "{domain_nodot}api",
    "{domain_nodot}app",
    "{domain_nodot}web",
    "{domain_nodot}www",
    # With common prefixes
    "my-{domain_nodot}",
    "the-{domain_nodot}",
    "app-{domain_nodot}",
    "api-{domain_nodot}",
    "web-{domain_nodot}",
]

# AWS regions to check
AWS_REGIONS = [
    "us-east-1",  # Virginia (default)
    "us-west-1",  # N. California
    "us-west-2",  # Oregon
    "eu-west-1",  # Ireland
    "eu-central-1",  # Frankfurt
    "ap-southeast-1",  # Singapore
    "ap-northeast-1",  # Tokyo
    "us-east-2",  # Ohio
    "eu-west-2",  # London
    "eu-west-3",  # Paris
    "ap-south-1",  # Mumbai
    "ap-southeast-2",  # Sydney
]

# Rate limiting
rate_limiter = threading.Semaphore(10)  # Max 10 concurrent requests


def check_s3_bucket(
    bucket_name: str, region: str = "us-east-1", timeout: int = 4
) -> Dict:
    """Check a single S3 bucket for existence and accessibility."""

    with rate_limiter:  # Rate limiting
        # Build URL based on region
        if region == "us-east-1":
            url = f"http://{bucket_name}.s3.amazonaws.com"
        else:
            url = f"http://{bucket_name}.s3-{region}.amazonaws.com"

        result = {
            "bucket": bucket_name,
            "region": region,
            "url": url,
            "status": "ERR",
            "notes": "Unknown error",
            "public_read": False,
            "listable": False,
            "file_count": 0,
        }

        try:
            resp = requests.get(url, timeout=timeout)
            result["status"] = str(resp.status_code)

            if "NoSuchBucket" in resp.text:
                result["notes"] = "Bucket does not exist"
            elif "PermanentRedirect" in resp.text and region == "us-east-1":
                # Bucket exists but in different region
                result["notes"] = "Bucket exists in different region"
                result["status"] = "302"
            elif "AccessDenied" in resp.text:
                result["notes"] = "Bucket exists but access denied"
                result["public_read"] = False
            elif resp.status_code == 200:
                result["public_read"] = True
                result["listable"] = True
                result["notes"] = "Public bucket - listable!"

                # Try to count files if bucket is listable
                try:
                    # Simple count of <Key> elements in XML response
                    file_count = resp.text.count("<Key>")
                    result["file_count"] = file_count
                    if file_count > 0:
                        result["notes"] = f"Public bucket with {file_count} files!"
                    else:
                        result["notes"] = "Public bucket but empty"
                except:
                    pass

            elif resp.status_code == 403:
                # Bucket exists but not public
                result["notes"] = "Bucket exists but not public"
                result["public_read"] = False
            else:
                result["notes"] = f"Unexpected response: {resp.status_code}"

        except requests.exceptions.Timeout:
            result["notes"] = "Request timeout"
        except requests.exceptions.ConnectionError:
            result["notes"] = "Connection error"
        except requests.RequestException as e:
            result["notes"] = f"Request error: {str(e)[:50]}"

        # Small delay to be nice to AWS
        time.sleep(0.1)

        return result


def enumerate_s3_buckets(
    domain: str,
    regions: Optional[List[str]] = None,
    max_workers: int = 10,
    verbose: bool = False,
    check_regional: bool = False,
) -> List[Dict]:
    """
    Enumerate S3 buckets for a domain using common naming patterns.

    Args:
        domain: Target domain (e.g., example.com)
        regions: List of AWS regions to check (defaults to just us-east-1)
        max_workers: Number of concurrent threads
        verbose: Enable verbose output
        check_regional: Whether to check buckets in multiple regions
    """

    if regions is None:
        regions = (
            ["us-east-1"] if not check_regional else AWS_REGIONS[:6]
        )  # Limit to first 6 regions

    # Prepare domain variations
    domain_nodot = domain.replace(".", "")
    subdomain = domain.split(".")[0] if "." in domain else domain

    # Generate bucket names from patterns
    bucket_names = set()

    for pattern in COMMON_BUCKET_PATTERNS:
        try:
            bucket_name = pattern.format(
                domain=domain, domain_nodot=domain_nodot, subdomain=subdomain
            )
            # S3 bucket names must be lowercase and follow DNS naming
            bucket_name = bucket_name.lower()
            if 3 <= len(bucket_name) <= 63:  # S3 bucket name length limits
                bucket_names.add(bucket_name)
        except:
            continue

    if verbose:
        print(
            f"[+] Checking {len(bucket_names)} potential bucket names across {len(regions)} regions"
        )
        print(f"[+] Total requests: {len(bucket_names) * len(regions)}")

    results = []

    # Use ThreadPoolExecutor for concurrent requests
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all bucket/region combinations
        future_to_bucket = {}

        for bucket_name in bucket_names:
            for region in regions:
                future = executor.submit(check_s3_bucket, bucket_name, region)
                future_to_bucket[future] = (bucket_name, region)

        # Collect results
        completed = 0
        total_tasks = len(future_to_bucket)

        for future in as_completed(future_to_bucket):
            bucket_name, region = future_to_bucket[future]
            completed += 1

            try:
                result = future.result()
                results.append(result)

                # Show interesting results immediately
                if verbose or result["status"] in ["200", "403", "302"]:
                    status_emoji = (
                        "🟢"
                        if result["status"] == "200"
                        else "🟡"
                        if result["status"] in ["403", "302"]
                        else "🔴"
                    )
                    print(
                        f"{status_emoji} {result['bucket']} ({result['region']}) - {result['status']} - {result['notes']}"
                    )

            except Exception as e:
                if verbose:
                    print(f"❌ {bucket_name} ({region}) - Error: {e}")
                results.append(
                    {
                        "bucket": bucket_name,
                        "region": region,
                        "status": "ERR",
                        "notes": f"Exception: {str(e)}",
                    }
                )

            if verbose and completed % 50 == 0:
                print(f"[+] Progress: {completed}/{total_tasks} completed")

    # Filter and sort results
    interesting_results = [r for r in results if r["status"] in ["200", "403", "302"]]

    if verbose:
        print(
            f"\n[+] Found {len(interesting_results)} interesting buckets out of {len(results)} checked"
        )

    return sorted(
        results, key=lambda x: (x["status"] != "200", x["status"] != "403", x["bucket"])
    )


def print_s3_results(results: List[Dict], show_all: bool = False) -> None:
    """Pretty print S3 enumeration results."""

    if not results:
        print("❌ No S3 buckets found")
        return

    # Categorize results
    public_buckets = [r for r in results if r["status"] == "200"]
    private_buckets = [r for r in results if r["status"] == "403"]
    redirected_buckets = [r for r in results if r["status"] == "302"]
    error_buckets = [
        r for r in results if r["status"] not in ["200", "403", "302", "404"]
    ]

    print("\n📊 S3 Bucket Enumeration Results")
    print(f"Total buckets checked: {len(results)}")

    if public_buckets:
        print(f"\n🟢 Public/Listable Buckets ({len(public_buckets)}):")
        for bucket in public_buckets:
            file_info = (
                f" ({bucket['file_count']} files)"
                if bucket.get("file_count", 0) > 0
                else ""
            )
            print(f"  ✅ {bucket['bucket']} ({bucket['region']}){file_info}")
            print(f"     🔗 {bucket['url']}")

    if private_buckets:
        print(f"\n🟡 Private/Existing Buckets ({len(private_buckets)}):")
        for bucket in private_buckets[:10]:  # Limit output
            print(f"  🔒 {bucket['bucket']} ({bucket['region']}) - {bucket['notes']}")
        if len(private_buckets) > 10:
            print(f"  ... and {len(private_buckets) - 10} more")

    if redirected_buckets:
        print(f"\n🔄 Redirected Buckets ({len(redirected_buckets)}):")
        for bucket in redirected_buckets[:5]:
            print(f"  ↗️  {bucket['bucket']} - {bucket['notes']}")

    if error_buckets and show_all:
        print(f"\n❌ Error Buckets ({len(error_buckets)}):")
        for bucket in error_buckets[:5]:
            print(f"  ⚠️  {bucket['bucket']} - {bucket['notes']}")


def save_s3_results(
    results: List[Dict], output_file: str, format: str = "json"
) -> None:
    """Save S3 enumeration results to file."""

    if format.lower() == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
    elif format.lower() == "txt":
        with open(output_file, "w") as f:
            for result in results:
                f.write(
                    f"{result['bucket']} - {result['status']} - {result['notes']}\n"
                )
    elif format.lower() == "csv":
        import csv

        with open(output_file, "w", newline="") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
