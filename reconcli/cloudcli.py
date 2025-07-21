import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import click

from reconcli.utils.cloud_detect import (
    detect_cloud_provider,
    print_cloud_detection_results,
)
from reconcli.utils.resume import clear_resume as clear_resume_func
from reconcli.utils.resume import load_resume, save_resume_state
from reconcli.utils.s3_enum import (
    enumerate_s3_buckets,
    print_s3_results,
    save_s3_results,
)


class CloudCacheManager:
    """Intelligent caching system for cloud detection and S3 enumeration operations."""

    def __init__(
        self,
        cache_dir: str = "cloud_cache",
        ttl_hours: int = 24,
        max_cache_size: int = 500,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.max_cache_size = max_cache_size
        self.cache_index_file = self.cache_dir / "cloud_cache_index.json"
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_files": 0,
            "total_size_mb": 0.0,
        }
        self._load_cache_index()

    def _load_cache_index(self):
        """Load cache index from disk."""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    self.cache_index = json.load(f)
            except:
                self.cache_index = {}
        else:
            self.cache_index = {}

    def _save_cache_index(self):
        """Save cache index to disk."""
        with open(self.cache_index_file, "w") as f:
            json.dump(self.cache_index, f, indent=2)

    def _generate_cache_key(self, domain: str, analysis_type: str, **kwargs) -> str:
        """Generate SHA256 cache key based on domain and analysis parameters."""
        cache_data = {
            "domain": domain,
            "analysis_type": analysis_type,
            "ip": kwargs.get("ip", ""),
            "s3_enum": kwargs.get("s3_enum", False),
            "s3_regions": kwargs.get("s3_regions", False),
            "s3_threads": kwargs.get("s3_threads", 10),
        }

        # Sort for consistent ordering
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def get_cached_result(
        self, domain: str, analysis_type: str, **kwargs
    ) -> Optional[Dict]:
        """Retrieve cached result if valid and not expired."""
        self.cache_stats["total_requests"] += 1

        cache_key = self._generate_cache_key(domain, analysis_type, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            self.cache_stats["misses"] += 1
            return None

        try:
            with open(cache_file, "r") as f:
                cached_data = json.load(f)

            # Check if cache is still valid
            cache_time = cached_data.get("cache_metadata", {}).get("timestamp", 0)
            if time.time() - cache_time > self.ttl_seconds:
                cache_file.unlink()  # Remove expired cache
                self.cache_stats["misses"] += 1
                return None

            self.cache_stats["hits"] += 1
            cached_data["cache_metadata"]["cache_hit"] = True
            return cached_data

        except Exception:
            # If cache file is corrupted, remove it
            if cache_file.exists():
                cache_file.unlink()
            self.cache_stats["misses"] += 1
            return None

    def save_result_to_cache(
        self, domain: str, analysis_type: str, result: Dict, **kwargs
    ):
        """Save analysis result to cache with metadata."""
        cache_key = self._generate_cache_key(domain, analysis_type, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add cache metadata
        cached_result = {
            **result,
            "cache_metadata": {
                "timestamp": time.time(),
                "cache_key": cache_key,
                "domain": domain,
                "analysis_type": analysis_type,
                "ttl_seconds": self.ttl_seconds,
                "cache_hit": False,
            },
        }

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(cached_result, f, indent=2)

        # Update cache index
        self.cache_index[cache_key] = {
            "domain": domain,
            "analysis_type": analysis_type,
            "timestamp": time.time(),
            "file": str(cache_file.name),
        }
        self._save_cache_index()

        # Cleanup old cache if needed
        self._cleanup_old_cache()

    def _cleanup_old_cache(self):
        """Remove oldest cache files if cache size exceeds limit."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "cloud_cache_index.json"]

        if len(cache_files) > self.max_cache_size:
            # Sort by modification time and remove oldest
            cache_files.sort(key=lambda x: x.stat().st_mtime)
            files_to_remove = cache_files[: -self.max_cache_size]

            for cache_file in files_to_remove:
                cache_file.unlink()
                # Remove from index
                cache_key = cache_file.stem
                self.cache_index.pop(cache_key, None)

            self._save_cache_index()

    def get_cache_stats(self) -> Dict:
        """Get comprehensive cache statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "cloud_cache_index.json"]

        total_size = sum(f.stat().st_size for f in cache_files)

        hit_rate = (
            (self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100)
            if self.cache_stats["total_requests"] > 0
            else 0
        )

        return {
            **self.cache_stats,
            "hit_rate_percent": round(hit_rate, 1),
            "cache_files": len(cache_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
            "ttl_hours": self.ttl_seconds / 3600,
        }

    def clear_cache(self):
        """Clear all cached results."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

        self.cache_index = {}
        self._save_cache_index()

        # Reset stats
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_files": 0,
            "total_size_mb": 0.0,
        }


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
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option("--cache-dir", default="cloud_cache", help="Directory for cache storage")
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
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
    resume,
    clear_resume,
    show_resume,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """Detect cloud providers and enumerate public cloud assets (S3, etc)."""

    # Initialize cache manager if caching is enabled
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = CloudCacheManager(cache_dir=cache_dir, ttl_hours=cache_max_age)

    # Handle cache operations
    if cache_stats:
        if cache_manager:
            stats = cache_manager.get_cache_stats()
            click.echo("🚀 Cloud Cache Performance Statistics")
            click.echo("═" * 45)
            click.echo(
                f"Hit Rate: {stats['hit_rate_percent']}% ({stats['hits']}/{stats['total_requests']} requests)"
            )
            click.echo(f"Cache Files: {stats['cache_files']}")
            click.echo(f"Total Size: {stats['total_size_mb']} MB")
            click.echo(f"Cache Directory: {stats['cache_dir']}")
            click.echo(f"TTL: {stats['ttl_hours']} hours")
        else:
            click.echo("⚠️  Cache not enabled. Use --cache to enable caching.")
        return

    if clear_cache:
        if cache_manager:
            cache_manager.clear_cache()
            click.echo("✅ Cloud cache cleared successfully")
        return

    # Handle resume options first
    os.makedirs(output_dir, exist_ok=True)

    if clear_resume:
        clear_resume_func(output_dir)
        click.echo("✅ Resume state cleared")
        return

    if show_resume:
        resume_state = load_resume(output_dir)
        if not resume_state:
            click.echo("❌ No previous scans found")
            return

        click.echo("📋 Previous scan status:")
        for scan_key, data in sorted(
            resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True
        ):
            start_time = data.get("start_time", "Unknown")
            completed = (
                "✅ Completed" if data.get("completed", False) else "⏸️  Incomplete"
            )
            target = data.get("target", "Unknown")
            domains_count = data.get("domains_processed", 0)
            total_domains = data.get("total_domains", 0)

            click.echo(f"  {scan_key}: {target} - {completed}")
            click.echo(f"    Started: {start_time}")
            if total_domains > 0:
                click.echo(f"    Progress: {domains_count}/{total_domains} domains")
        return

    if not domain and not domains_file:
        click.echo("❌ Error: Must specify either --domain or --domains-file")
        return

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

        # Enhanced resume system for batch processing
        scan_key = f"cloud_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        resume_state = load_resume(output_dir)

        processed_domains = set()
        start_from_index = 0

        if resume and resume_state:
            if verbose:
                click.echo("[+] 📁 Checking for previous batch scans...")

            # Find the most recent incomplete scan
            for key, data in sorted(
                resume_state.items(),
                key=lambda x: x[1].get("start_time", ""),
                reverse=True,
            ):
                if key.startswith("cloud_batch_") and not data.get("completed", False):
                    scan_key = key
                    processed_domains = set(data.get("processed_domains", []))
                    start_from_index = len(processed_domains)

                    if verbose:
                        click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                        click.echo(
                            f"[+] 📊 Already processed: {len(processed_domains)}/{len(domains)} domains"
                        )
                    break

        if scan_key not in resume_state:
            # Initialize new scan
            resume_state[scan_key] = {
                "target": f"batch_from_{os.path.basename(domains_file)}",
                "start_time": datetime.now().isoformat(),
                "completed": False,
                "total_domains": len(domains),
                "domains_processed": 0,
                "processed_domains": [],
                "domains_file": domains_file,
            }

        print(
            f"[+] Processing {len(domains) - start_from_index} domains from {domains_file}"
        )
        if start_from_index > 0:
            print(f"[+] 🔄 Resuming from domain #{start_from_index + 1}")

        # Process domains with resume capability
        all_results = []

        # Load existing results if resuming
        batch_output = os.path.join(
            output_dir, f"batch_cloud_detection.{output_format}"
        )
        if resume and os.path.exists(batch_output) and output_format == "json":
            try:
                with open(batch_output, "r") as f:
                    all_results = json.load(f)
                if verbose:
                    print(f"[+] 📂 Loaded {len(all_results)} existing results")
            except:
                all_results = []

        # Process domains one by one for resume capability
        for i, target_domain in enumerate(domains):
            if target_domain in processed_domains:
                continue  # Skip already processed domains

            try:
                if verbose:
                    print(f"\n[{i + 1}/{len(domains)}] Processing: {target_domain}")

                result = detect_cloud_provider(target_domain, verbose=verbose)
                all_results.append(result)
                processed_domains.add(target_domain)

                # Update resume state
                resume_state[scan_key]["domains_processed"] = len(processed_domains)
                resume_state[scan_key]["processed_domains"] = list(processed_domains)
                save_resume_state(output_dir, resume_state)

                # Show progress
                if not verbose:
                    cloud_providers = result.get("cloud_guess", [])
                    if cloud_providers:
                        print(f"✅ {target_domain}: {', '.join(cloud_providers)}")
                    else:
                        print(f"❌ {target_domain}: No cloud providers detected")

                # Save intermediate results every 10 domains
                if len(processed_domains) % 10 == 0:
                    if output_format == "json":
                        with open(batch_output, "w") as f:
                            json.dump(all_results, f, indent=2)
                    if verbose:
                        print(
                            f"[+] 💾 Intermediate save: {len(processed_domains)}/{len(domains)} completed"
                        )

            except KeyboardInterrupt:
                print("\n[!] ⏸️  Scan interrupted. Resume with --resume flag")
                print(
                    f"[+] 📊 Progress saved: {len(processed_domains)}/{len(domains)} domains processed"
                )
                return
            except Exception as e:
                print(f"❌ Error processing {target_domain}: {e}")
                continue

        # Mark scan as completed
        resume_state[scan_key]["completed"] = True
        resume_state[scan_key]["end_time"] = datetime.now().isoformat()
        save_resume_state(output_dir, resume_state)

        # Save final batch results
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
        print(
            f"[✅] Scan completed: {len(processed_domains)}/{len(domains)} domains processed"
        )

        # S3 enumeration for batch processing (if requested)
        if s3_enum:
            print("\n[+] Starting S3 enumeration for processed domains...")

            # S3 enumeration with resume capability
            s3_scan_key = f"s3_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            s3_processed_domains = set()

            if resume and resume_state:
                # Look for existing S3 scan
                for key, data in sorted(
                    resume_state.items(),
                    key=lambda x: x[1].get("start_time", ""),
                    reverse=True,
                ):
                    if key.startswith("s3_batch_") and not data.get("completed", False):
                        s3_scan_key = key
                        s3_processed_domains = set(data.get("processed_domains", []))
                        if verbose:
                            print(f"[+] 🔄 Resuming S3 scan: {s3_scan_key}")
                            print(
                                f"[+] 📊 S3 already processed: {len(s3_processed_domains)}/{len(domains)} domains"
                            )
                        break

            if s3_scan_key not in resume_state:
                resume_state[s3_scan_key] = {
                    "target": f"s3_batch_from_{os.path.basename(domains_file)}",
                    "start_time": datetime.now().isoformat(),
                    "completed": False,
                    "total_domains": len(domains),
                    "domains_processed": 0,
                    "processed_domains": [],
                    "scan_type": "s3_enumeration",
                }

            try:
                for i, target_domain in enumerate(domains, 1):
                    if target_domain in s3_processed_domains:
                        continue  # Skip already processed domains

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

                    # Update S3 resume state
                    s3_processed_domains.add(target_domain)
                    resume_state[s3_scan_key]["domains_processed"] = len(
                        s3_processed_domains
                    )
                    resume_state[s3_scan_key]["processed_domains"] = list(
                        s3_processed_domains
                    )
                    save_resume_state(output_dir, resume_state)

                    # Show summary
                    if not verbose:
                        interesting = [
                            r
                            for r in s3_results
                            if r["status"] in ["200", "403", "302"]
                        ]
                        if interesting:
                            print(
                                f"[✓] Found {len(interesting)} interesting S3 buckets for {target_domain}"
                            )
                            public = [r for r in interesting if r["status"] == "200"]
                            if public:
                                print(f"    🚨 {len(public)} PUBLIC buckets found!")

                # Mark S3 scan as completed
                resume_state[s3_scan_key]["completed"] = True
                resume_state[s3_scan_key]["end_time"] = datetime.now().isoformat()
                save_resume_state(output_dir, resume_state)
                print(
                    f"[✅] S3 enumeration completed: {len(s3_processed_domains)}/{len(domains)} domains"
                )

            except KeyboardInterrupt:
                print("\n[!] ⏸️  S3 scan interrupted. Resume with --resume flag")
                print(
                    f"[+] 📊 S3 progress saved: {len(s3_processed_domains)}/{len(domains)} domains processed"
                )
                return

    else:
        # Single domain processing with cache support
        print(f"[+] Detecting cloud provider for: {domain}")

        # Check cache first if enabled
        cloud_info = None
        s3_results = None

        if cache_manager:
            cache_params = {
                "ip": ip,
                "s3_enum": s3_enum,
                "s3_regions": s3_regions,
                "s3_threads": s3_threads,
            }

            cached_result = cache_manager.get_cached_result(
                domain, "cloud_analysis", **cache_params
            )

            if cached_result:
                cloud_info = cached_result.get("cloud_info")
                s3_results = cached_result.get("s3_results")
                print(f"🚀 Cache hit! Using cached results for {domain}")
                print(
                    f"   Cache key: {cached_result['cache_metadata']['cache_key'][:16]}..."
                )
                print(
                    f"   Cached at: {datetime.fromtimestamp(cached_result['cache_metadata']['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"
                )

        # Perform analysis if not cached
        if not cloud_info:
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
        if s3_enum and not s3_results:  # Only run if not cached
            print(f"\n[+] Enumerating S3 buckets for: {domain}")
            s3_results = enumerate_s3_buckets(
                domain,
                check_regional=s3_regions,
                max_workers=s3_threads,
                verbose=verbose,
            )

        if s3_enum and s3_results:
            # Pretty print S3 results
            print_s3_results(s3_results, show_all=verbose)

            # Save S3 results
            s3_output = os.path.join(output_dir, f"{domain}_s3_buckets.{output_format}")
            save_s3_results(s3_results, s3_output, output_format)

            print(f"[✓] S3 results saved: {s3_output}")

        # Save to cache if enabled and not from cache
        if cache_manager and not (
            cloud_info and cloud_info.get("cache_metadata", {}).get("cache_hit", False)
        ):
            cache_params = {
                "ip": ip,
                "s3_enum": s3_enum,
                "s3_regions": s3_regions,
                "s3_threads": s3_threads,
            }

            cache_result = {
                "cloud_info": cloud_info,
                "s3_results": s3_results if s3_enum else None,
            }

            cache_manager.save_result_to_cache(
                domain, "cloud_analysis", cache_result, **cache_params
            )


if __name__ == "__main__":
    cloudcli()
