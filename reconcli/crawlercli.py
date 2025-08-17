import concurrent.futures
import json
import re
import subprocess
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import click
import requests


class CrawlerCacheManager:
    """Intelligent caching system for web crawler results."""

    def __init__(
        self,
        cache_dir: str = "crawler_cache",
        ttl_hours: int = 24,
        max_cache_size: int = 200,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.max_cache_size = max_cache_size
        self.cache_index_file = self.cache_dir / "crawler_cache_index.json"
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

    def _generate_cache_key(self, target: str, **kwargs) -> str:
        """Generate SHA256 cache key based on target and crawl parameters."""
        cache_data = {
            "target": target,
            "tools": sorted(kwargs.get("tools", [])),
            "profile": kwargs.get("profile", "comprehensive"),
            "max_depth": kwargs.get("max_depth", 3),
            "max_pages": kwargs.get("max_pages", 500),
            "include_subdomains": kwargs.get("include_subdomains", False),
            "javascript": kwargs.get("javascript", True),
            "forms": kwargs.get("forms", False),
            "api_endpoints": kwargs.get("api_endpoints", False),
            "wayback": kwargs.get("wayback", False),
            "social_media": kwargs.get("social_media", False),
            "emails": kwargs.get("emails", False),
            "phone_numbers": kwargs.get("phone_numbers", False),
            "sensitive_files": kwargs.get("sensitive_files", False),
            "filter_ext": sorted(kwargs.get("filter_ext", [])),
            "include_ext": sorted(kwargs.get("include_ext", [])),
            "exclude_domains": sorted(kwargs.get("exclude_domains", [])),
        }

        # Sort for consistent ordering
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def get_cached_result(self, target: str, **kwargs) -> Optional[Dict]:
        """Retrieve cached result if valid and not expired."""
        self.cache_stats["total_requests"] += 1

        cache_key = self._generate_cache_key(target, **kwargs)
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

    def save_result_to_cache(self, target: str, result: Dict, **kwargs):
        """Save crawl result to cache with metadata."""
        cache_key = self._generate_cache_key(target, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add cache metadata
        cached_result = {
            **result,
            "cache_metadata": {
                "timestamp": time.time(),
                "cache_key": cache_key,
                "target": target,
                "ttl_seconds": self.ttl_seconds,
                "cache_hit": False,
            },
        }

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(cached_result, f, indent=2)

        # Update cache index
        self.cache_index[cache_key] = {
            "target": target,
            "timestamp": time.time(),
            "file": str(cache_file.name),
        }
        self._save_cache_index()

        # Cleanup old cache if needed
        self._cleanup_old_cache()

    def _cleanup_old_cache(self):
        """Remove oldest cache files if cache size exceeds limit."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "crawler_cache_index.json"]

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
        cache_files = [f for f in cache_files if f.name != "crawler_cache_index.json"]

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
@click.option("--domain", help="Target domain to crawl")
@click.option(
    "--input",
    "input_file",
    type=click.Path(exists=True),
    help="Input file with URLs/domains to crawl",
)
@click.option(
    "--tools",
    default="waymore,gospider,xnLinkFinder,crawley,crawlergo",
    help="Comma-separated tools to use",
)
@click.option(
    "--output-dir", default="crawler_output", help="Output directory for crawl data"
)
@click.option(
    "--profile",
    type=click.Choice(["quick", "comprehensive", "stealth", "aggressive", "custom"]),
    default="comprehensive",
    help="Crawling profile with predefined settings",
)
@click.option(
    "--filter-ext",
    default="jpg,jpeg,png,gif,bmp,svg,ico,woff,woff2,ttf,eot,css,js,pdf,zip,rar,tar,gz,mp4,mp3,avi,mov,wmv,flv",
    help="Comma-separated list of extensions to filter out",
)
@click.option(
    "--include-ext", help="Only include URLs with these extensions (comma-separated)"
)
@click.option("--max-depth", type=int, default=3, help="Maximum crawling depth")
@click.option(
    "--max-pages", type=int, default=500, help="Maximum pages to crawl per tool"
)
@click.option(
    "--threads", type=int, default=10, help="Number of threads for concurrent crawling"
)
@click.option(
    "--delay", type=float, default=0.1, help="Delay between requests (seconds)"
)
@click.option("--timeout", type=int, default=30, help="Request timeout (seconds)")
@click.option("--resume", is_flag=True, help="Resume from previous crawling session")
@click.option("--proxy", help="Proxy for HTTP requests (e.g., http://127.0.0.1:8080)")
@click.option(
    "--user-agent",
    default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    help="Custom User-Agent",
)
@click.option(
    "--cookies",
    help="Cookies for authenticated crawling (format: key1=value1;key2=value2)",
)
@click.option(
    "--headers", help="Custom headers (format: Header1:Value1,Header2:Value2)"
)
@click.option(
    "--crawlergo-chrome",
    default="/usr/bin/chromium",
    help="Path to Chromium binary for Crawlergo",
)
@click.option(
    "--exclude-domains", help="Domains to exclude from crawling (comma-separated)"
)
@click.option(
    "--include-subdomains", is_flag=True, help="Include subdomains in crawling"
)
@click.option(
    "--javascript", is_flag=True, default=True, help="Enable JavaScript execution"
)
@click.option("--forms", is_flag=True, help="Extract and analyze web forms")
@click.option("--api-endpoints", is_flag=True, help="Focus on API endpoint discovery")
@click.option("--wayback", is_flag=True, help="Include Wayback Machine historical URLs")
@click.option(
    "--social-media", is_flag=True, help="Extract social media links and profiles"
)
@click.option("--emails", is_flag=True, help="Extract email addresses")
@click.option("--phone-numbers", is_flag=True, help="Extract phone numbers")
@click.option(
    "--sensitive-files",
    is_flag=True,
    help="Look for sensitive files (configs, backups, etc.)",
)
@click.option("--parallel", is_flag=True, help="Run crawling tools in parallel")
@click.option("--notifications", help="Webhook URL for completion notifications")
@click.option(
    "--output-format",
    type=click.Choice(["txt", "json", "csv", "xml"]),
    default="txt",
    help="Output format",
)
@click.option("--deduplicate", is_flag=True, default=True, help="Remove duplicate URLs")
@click.option(
    "--validate-urls", is_flag=True, help="Validate URLs by making HEAD requests"
)
@click.option("--screenshot", is_flag=True, help="Take screenshots of discovered pages")
@click.option(
    "--verbose", "-v", is_flag=True, help="Verbose output with detailed progress"
)
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode - minimal output")
@click.option(
    "--dry-run", is_flag=True, help="Show what would be executed without running"
)
@click.option(
    "--cache",
    is_flag=True,
    help="Enable intelligent caching for faster repeated crawls",
)
@click.option(
    "--cache-dir", default="crawler_cache", help="Directory for cache storage"
)
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
def crawlercli(
    domain,
    input_file,
    tools,
    output_dir,
    profile,
    filter_ext,
    include_ext,
    max_depth,
    max_pages,
    threads,
    delay,
    timeout,
    resume,
    proxy,
    user_agent,
    cookies,
    headers,
    crawlergo_chrome,
    exclude_domains,
    include_subdomains,
    javascript,
    forms,
    api_endpoints,
    wayback,
    social_media,
    emails,
    phone_numbers,
    sensitive_files,
    parallel,
    notifications,
    output_format,
    deduplicate,
    validate_urls,
    screenshot,
    verbose,
    quiet,
    dry_run,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """🕷️ Advanced Web Crawler Suite

    Professional web crawling toolkit with multiple engines, intelligent filtering,
    and comprehensive data extraction capabilities.

    Features:
    - Multiple crawling engines (Waymore, GoSpider, XnLinkFinder, Crawley, Crawlergo)
    - Parallel execution and resume support
    - Smart filtering and deduplication
    - API endpoint discovery and form extraction
    - Historical data from Wayback Machine
    - Screenshot capture and validation
    - Professional reporting and notifications

    Examples:
        # Quick domain crawl
        reconcli crawlercli --domain example.com --profile quick

        # Comprehensive crawl with API focus
        reconcli crawlercli --domain target.com --profile comprehensive \\
          --api-endpoints --forms --parallel --max-pages 1000

        # Stealth crawl with proxy
        reconcli crawlercli --domain target.com --profile stealth \\
          --proxy http://127.0.0.1:8080 --delay 2.0

        # Multi-domain crawl from file
        reconcli crawlercli --input domains.txt --profile aggressive \\
          --parallel --threads 20 --screenshot
    """

    # Initialize cache manager if caching is enabled
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = CrawlerCacheManager(
            cache_dir=cache_dir, ttl_hours=cache_max_age
        )

    # Handle cache operations
    if cache_stats:
        if cache_manager:
            stats = cache_manager.get_cache_stats()
            click.echo("🚀 Crawler Cache Performance Statistics")
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
            click.echo("✅ Crawler cache cleared successfully")
        return

    # Validate required parameters
    if not domain and not input_file:
        click.echo("❌ Error: Either --domain or --input must be provided", err=True)
        return

    # Initialize crawler session
    crawler_session = CrawlerSession(
        domain=domain,
        input_file=input_file,
        output_dir=output_dir,
        profile=profile,
        verbose=verbose,
        quiet=quiet,
        notifications=notifications,
        parallel=parallel,
        threads=threads,
    )

    if dry_run:
        crawler_session.show_execution_plan(
            tools,
            filter_ext,
            include_ext,
            max_depth,
            max_pages,
            delay,
            timeout,
            proxy,
            user_agent,
            cookies,
            headers,
            exclude_domains,
            include_subdomains,
            javascript,
            forms,
            api_endpoints,
            wayback,
            social_media,
            emails,
            phone_numbers,
            sensitive_files,
            output_format,
            deduplicate,
            validate_urls,
            screenshot,
        )
        return

    try:
        # Check cache first if enabled
        target = domain if domain else str(input_file)

        if cache_manager:
            cache_params = {
                "tools": tools.split(",") if tools else [],
                "profile": profile,
                "max_depth": max_depth,
                "max_pages": max_pages,
                "include_subdomains": include_subdomains,
                "javascript": javascript,
                "forms": forms,
                "api_endpoints": api_endpoints,
                "wayback": wayback,
                "social_media": social_media,
                "emails": emails,
                "phone_numbers": phone_numbers,
                "sensitive_files": sensitive_files,
                "filter_ext": filter_ext.split(",") if filter_ext else [],
                "include_ext": include_ext.split(",") if include_ext else [],
                "exclude_domains": (
                    exclude_domains.split(",") if exclude_domains else []
                ),
            }

            cached_result = cache_manager.get_cached_result(target, **cache_params)

            if cached_result:
                if not quiet:
                    click.echo(f"🚀 Cache hit! Using cached crawl results for {target}")
                    click.echo(
                        f"   Cache key: {cached_result['cache_metadata']['cache_key'][:16]}..."
                    )
                    click.echo(
                        f"   Cached at: {datetime.fromtimestamp(cached_result['cache_metadata']['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                # Display cached results
                urls_found = cached_result.get("urls_found", [])
                if urls_found:
                    click.echo(f"📊 Found {len(urls_found)} URLs from cache")
                    if verbose:
                        for url in urls_found[:10]:  # Show first 10 URLs
                            click.echo(f"  - {url}")
                        if len(urls_found) > 10:
                            click.echo(f"  ... and {len(urls_found) - 10} more")

                return

        crawler_session.start()

        # Execute crawling pipeline
        success = crawler_session.execute_crawling(
            tools=tools,
            filter_ext=filter_ext,
            include_ext=include_ext,
            max_depth=max_depth,
            max_pages=max_pages,
            delay=delay,
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            cookies=cookies,
            headers=headers,
            crawlergo_chrome=crawlergo_chrome,
            exclude_domains=exclude_domains,
            include_subdomains=include_subdomains,
            javascript=javascript,
            forms=forms,
            api_endpoints=api_endpoints,
            wayback=wayback,
            social_media=social_media,
            emails=emails,
            phone_numbers=phone_numbers,
            sensitive_files=sensitive_files,
            output_format=output_format,
            deduplicate=deduplicate,
            validate_urls=validate_urls,
            screenshot=screenshot,
            resume=resume,
        )

        if success:
            crawler_session.complete()

            # Save to cache if enabled
            if cache_manager:
                # Get crawl results for caching
                crawl_results = {
                    "urls_found": getattr(crawler_session, "all_urls", []),
                    "tools_used": tools.split(",") if tools else [],
                    "success": True,
                    "timestamp": datetime.now().isoformat(),
                    "total_urls": len(getattr(crawler_session, "all_urls", [])),
                    "profile": profile,
                }

                cache_params = {
                    "tools": tools.split(",") if tools else [],
                    "profile": profile,
                    "max_depth": max_depth,
                    "max_pages": max_pages,
                    "include_subdomains": include_subdomains,
                    "javascript": javascript,
                    "forms": forms,
                    "api_endpoints": api_endpoints,
                    "wayback": wayback,
                    "social_media": social_media,
                    "emails": emails,
                    "phone_numbers": phone_numbers,
                    "sensitive_files": sensitive_files,
                    "filter_ext": filter_ext.split(",") if filter_ext else [],
                    "include_ext": include_ext.split(",") if include_ext else [],
                    "exclude_domains": (
                        exclude_domains.split(",") if exclude_domains else []
                    ),
                }

                cache_manager.save_result_to_cache(
                    target, crawl_results, **cache_params
                )

                if not quiet:
                    click.echo("💾 Crawl results cached for future use")
        else:
            crawler_session.failed()

    except KeyboardInterrupt:
        crawler_session.interrupted()
    except Exception as e:
        crawler_session.error(str(e))


class CrawlerSession:
    """Advanced crawler session manager with progress tracking and professional reporting."""

    def __init__(
        self,
        domain: Optional[str] = None,
        input_file: Optional[str] = None,
        output_dir: str = "crawler_output",
        profile: str = "comprehensive",
        verbose: bool = False,
        quiet: bool = False,
        notifications: Optional[str] = None,
        parallel: bool = False,
        threads: int = 10,
    ):
        self.domain = domain
        self.input_file = input_file
        self.output_dir = Path(output_dir)
        self.profile = profile
        self.verbose = verbose
        self.quiet = quiet
        self.notifications = notifications
        self.parallel = parallel
        self.threads = threads
        self.start_time = None

        # Initialize target list
        self.targets = []
        if domain:
            self.targets.append(domain)
        if input_file:
            with open(input_file) as f:
                self.targets.extend([line.strip() for line in f if line.strip()])

        # Statistics tracking
        self.stats = {
            "targets_processed": 0,
            "total_urls_found": 0,
            "unique_urls": 0,
            "api_endpoints": 0,
            "forms_found": 0,
            "emails_found": 0,
            "phone_numbers_found": 0,
            "sensitive_files": 0,
            "tools_executed": [],
            "tools_failed": [],
            "execution_time": 0,
            "peak_memory_usage": 0,
        }

        # Crawler profiles
        self.profiles = {
            "quick": {
                "tools": ["waymore", "gospider"],
                "max_depth": 2,
                "max_pages": 100,
                "delay": 0.1,
                "threads": 5,
                "timeout": 15,
            },
            "comprehensive": {
                "tools": [
                    "waymore",
                    "gospider",
                    "xnLinkFinder",
                    "crawley",
                    "crawlergo",
                ],
                "max_depth": 4,
                "max_pages": 1000,
                "delay": 0.2,
                "threads": 10,
                "timeout": 30,
            },
            "stealth": {
                "tools": ["waymore", "gospider"],
                "max_depth": 2,
                "max_pages": 200,
                "delay": 2.0,
                "threads": 3,
                "timeout": 45,
            },
            "aggressive": {
                "tools": [
                    "waymore",
                    "gospider",
                    "xnLinkFinder",
                    "crawley",
                    "crawlergo",
                ],
                "max_depth": 6,
                "max_pages": 5000,
                "delay": 0.05,
                "threads": 20,
                "timeout": 60,
            },
        }

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Session management
        self.session_file = self.output_dir / "crawler_session.json"
        self.resume_file = self.output_dir / ".crawler_resume.cfg"
        self.init_session()

    def init_session(self):
        """Initialize crawler session metadata."""
        session_data = {
            "targets": self.targets,
            "profile": self.profile,
            "start_time": datetime.now().isoformat(),
            "status": "initialized",
            "stats": self.stats.copy(),
        }

        with open(self.session_file, "w") as f:
            json.dump(session_data, f, indent=2)

    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with colors and timestamps."""
        if self.quiet and level not in ["ERROR", "SUCCESS"]:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[36m",  # Cyan
            "SUCCESS": "\033[32m",  # Green
            "WARNING": "\033[33m",  # Yellow
            "ERROR": "\033[31m",  # Red
            "PROGRESS": "\033[35m",  # Magenta
            "CRAWLER": "\033[94m",  # Blue
        }
        reset = "\033[0m"

        color = colors.get(level, "")
        prefix = f"{color}[CRAWLER-{level}]{reset}"
        print(f"{prefix} [{timestamp}] {message}")

        # Send notification if configured
        if self.notifications and level in ["SUCCESS", "ERROR"]:
            self.send_notification(f"🕷️ Crawler: {message}")

    def send_notification(self, message: str):
        """Send notification to configured webhook."""
        if not self.notifications:
            return

        try:
            data = (
                {"text": message}
                if "slack" in self.notifications
                else {"content": message}
            )
            requests.post(self.notifications, json=data, timeout=10)
        except Exception:
            pass  # Fail silently for notifications

    def show_execution_plan(
        self,
        tools,
        filter_ext,
        include_ext,
        max_depth,
        max_pages,
        delay,
        timeout,
        proxy,
        user_agent,
        cookies,
        headers,
        exclude_domains,
        include_subdomains,
        javascript,
        forms,
        api_endpoints,
        wayback,
        social_media,
        emails,
        phone_numbers,
        sensitive_files,
        output_format,
        deduplicate,
        validate_urls,
        screenshot,
    ):
        """Show what would be executed in dry-run mode."""
        self.log("🔍 DRY RUN - Crawler Execution Plan", "INFO")
        print(f"  Targets: {len(self.targets)} domains")
        if self.targets:
            print(f"  Primary: {self.targets[0]}")
        print(f"  Profile: {self.profile}")
        print(f"  Output: {self.output_dir}")
        print(f"  Parallel: {self.parallel}")
        print(f"  Threads: {self.threads}")

        profile_config = self.profiles.get(self.profile, {})
        tools_list = tools.split(",") if tools else profile_config.get("tools", [])
        print(f"  Tools: {', '.join(tools_list)}")
        print(f"  Max Depth: {max_depth}")
        print(f"  Max Pages: {max_pages}")
        print(f"  Output Format: {output_format}")

        if self.verbose:
            print("\n📋 Advanced Features:")
            print(f"  JavaScript: {javascript}")
            print(f"  Forms: {forms}")
            print(f"  API Endpoints: {api_endpoints}")
            print(f"  Wayback: {wayback}")
            print(f"  Screenshots: {screenshot}")
            print(f"  Validation: {validate_urls}")

    def start(self):
        """Start crawler session."""
        self.start_time = time.time()
        self.log(f"🕷️ Starting crawler for {len(self.targets)} target(s)", "INFO")
        self.log(f"📁 Output directory: {self.output_dir}", "INFO")
        self.log(f"🎯 Profile: {self.profile}", "INFO")

        # Update session status
        self.update_session_status("running")

    def execute_crawling(self, **kwargs) -> bool:
        """Execute the complete crawling pipeline."""
        try:
            tools = kwargs.get("tools", "")
            profile_config = self.profiles.get(self.profile, {})

            # Use profile settings as defaults
            tools_list = tools.split(",") if tools else profile_config.get("tools", [])

            if self.parallel and len(tools_list) > 1:
                return self.execute_parallel_crawling(tools_list, **kwargs)
            else:
                return self.execute_sequential_crawling(tools_list, **kwargs)

        except Exception as e:
            self.log(f"❌ Crawling execution failed: {e}", "ERROR")
            return False

    def execute_sequential_crawling(self, tools_list: List[str], **kwargs) -> bool:
        """Execute crawling tools sequentially."""
        self.log(f"⚡ Executing {len(tools_list)} tools sequentially", "INFO")

        all_urls = set()

        for i, tool in enumerate(tools_list, 1):
            tool = tool.strip().lower()
            self.log(f"📋 [{i}/{len(tools_list)}] Executing {tool.upper()}", "PROGRESS")

            try:
                urls = self.execute_crawler_tool(tool, **kwargs)
                if urls:
                    all_urls.update(urls)
                    self.stats["tools_executed"].append(tool)
                    self.log(f"✅ {tool.upper()} found {len(urls)} URLs", "SUCCESS")
                else:
                    self.log(f"⚠️ {tool.upper()} found no URLs", "WARNING")
            except Exception as e:
                self.log(f"❌ {tool.upper()} failed: {e}", "ERROR")
                self.stats["tools_failed"].append(tool)

        # Process and save results
        return self.process_crawl_results(all_urls, **kwargs)

    def execute_parallel_crawling(self, tools_list: List[str], **kwargs) -> bool:
        """Execute crawling tools in parallel."""
        self.log(f"⚡ Executing {len(tools_list)} tools in parallel", "INFO")

        all_urls = set()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(tools_list), self.threads)
        ) as executor:
            future_to_tool = {
                executor.submit(
                    self.execute_crawler_tool, tool.strip().lower(), **kwargs
                ): tool.strip().lower()
                for tool in tools_list
            }

            for future in concurrent.futures.as_completed(future_to_tool):
                tool = future_to_tool[future]
                try:
                    urls = future.result()
                    if urls:
                        all_urls.update(urls)
                        self.stats["tools_executed"].append(tool)
                        self.log(f"✅ {tool.upper()} found {len(urls)} URLs", "SUCCESS")
                    else:
                        self.log(f"⚠️ {tool.upper()} found no URLs", "WARNING")
                except Exception as e:
                    self.log(f"❌ {tool.upper()} failed: {e}", "ERROR")
                    self.stats["tools_failed"].append(tool)

        # Process and save results
        return self.process_crawl_results(all_urls, **kwargs)

    def execute_crawler_tool(self, tool: str, **kwargs) -> Set[str]:
        """Execute a specific crawler tool and return found URLs."""
        urls = set()

        try:

            for target in self.targets:
                if tool == "waymore":
                    tool_urls = self.run_waymore(target, **kwargs)
                elif tool == "gospider":
                    tool_urls = self.run_gospider(target, **kwargs)
                elif tool == "xnlinkfinder":
                    tool_urls = self.run_xnLinkFinder(target, **kwargs)
                elif tool == "crawley":
                    tool_urls = self.run_crawley(target, **kwargs)
                elif tool == "crawlergo":
                    tool_urls = self.run_crawlergo(target, **kwargs)
                else:
                    self.log(f"⚠️ Unknown tool: {tool}", "WARNING")
                    continue

                if tool_urls:
                    urls.update(tool_urls)

        except Exception as e:
            self.log(f"❌ Tool {tool} execution failed: {e}", "ERROR")
            raise

        return urls

    def run_waymore(self, target: str, **kwargs) -> Set[str]:
        """Run Waymore crawler."""
        urls = set()
        proxy = kwargs.get("proxy")

        try:
            cmd = ["waymore", "-i", target, "-mode", "U", "-r", "3"]
            if proxy:
                cmd += ["-p", proxy]

            output_file = self.output_dir / f"{target}_waymore.txt"

            with open(output_file, "w") as f:
                result = subprocess.run(
                    cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=1200
                )

            if result.returncode == 0 and output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith(("http://", "https://")):
                            urls.add(url)

        except Exception as e:
            self.log(f"Waymore error: {e}", "ERROR")

        return urls

    def run_gospider(self, target: str, **kwargs) -> Set[str]:
        """Run GoSpider crawler."""
        urls = set()
        proxy = kwargs.get("proxy")
        max_depth = kwargs.get("max_depth", 3)

        try:
            output_dir = self.output_dir / f"{target}_gospider"
            output_dir.mkdir(exist_ok=True)

            # Try both HTTP and HTTPS
            target_urls = [f"https://{target}", f"http://{target}"]

            for target_url in target_urls:
                cmd = [
                    "gospider",
                    "-s",
                    target_url,
                    "-o",
                    str(output_dir),
                    "-c",
                    str(self.threads),
                    "-d",
                    str(max_depth),
                    "--include-subs",
                    "--other-source",
                    "--include-other",
                ]
                if proxy:
                    cmd += ["--proxy", proxy]

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=1200
                    )
                    if self.verbose:
                        self.log(f"GoSpider command: {' '.join(cmd)}", "INFO")
                        self.log(f"GoSpider return code: {result.returncode}", "INFO")
                        if result.stderr:
                            self.log(
                                f"GoSpider stderr: {result.stderr[:200]}", "WARNING"
                            )

                    if result.returncode == 0:
                        break  # Success, don't try the other protocol
                except subprocess.TimeoutExpired:
                    continue  # Try next URL if timeout

            # Parse GoSpider output - check both JSON and TXT files
            if output_dir.exists():
                # First try JSON files
                for file_path in output_dir.rglob("*.json"):
                    with open(file_path) as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                if "output" in data:
                                    urls.add(data["output"])
                            except:
                                continue

                # Also try TXT files and other formats
                for file_path in output_dir.rglob("*"):
                    if file_path.is_file() and file_path.suffix in [".txt", ".out", ""]:
                        try:
                            with open(
                                file_path, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                for line in f:
                                    line = line.strip()
                                    if line and (
                                        line.startswith("http://")
                                        or line.startswith("https://")
                                    ):
                                        urls.add(line)
                        except:
                            continue

        except Exception as e:
            self.log(f"GoSpider error: {e}", "ERROR")

        return urls

    def run_xnLinkFinder(self, target: str, **kwargs) -> Set[str]:
        """Run XnLinkFinder crawler."""
        urls = set()

        try:
            output_json = self.output_dir / f"{target}_xnLinkFinder.json"

            # Try HTTPS first, then HTTP
            target_urls = [f"https://{target}", f"http://{target}"]

            for target_url in target_urls:
                cmd = [
                    "xnLinkFinder",
                    "-i",
                    target_url,
                    "-o",
                    str(output_json),
                ]

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=1200
                    )
                    if result.returncode == 0 and output_json.exists():
                        break  # Success, don't try the other protocol
                except subprocess.TimeoutExpired:
                    continue  # Try next URL if timeout

            if output_json.exists():
                with open(output_json) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "url" in item:
                                urls.add(item["url"])
                            elif isinstance(item, str):
                                urls.add(item)

        except Exception as e:
            self.log(f"XnLinkFinder error: {e}", "ERROR")

        return urls

    def run_crawley(self, target: str, **kwargs) -> Set[str]:
        """Run Crawley crawler."""
        urls = set()
        proxy = kwargs.get("proxy")
        max_depth = kwargs.get("max_depth", 3)
        delay = kwargs.get("delay", 0.2)

        try:
            output_file = self.output_dir / f"{target}_crawley.txt"

            cmd = [
                "crawley",
                "-all",
                "-subdomains",
                "-depth",
                str(max_depth),
                "-delay",
                f"{int(delay * 1000)}ms",
                "-js",
                "-css",
                "-brute",
                "-silent",
                target,
            ]
            if proxy:
                cmd += ["-proxy-auth", proxy]

            with open(output_file, "w") as f:
                result = subprocess.run(
                    cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=1200
                )

            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith(("http://", "https://")):
                            urls.add(url)

        except Exception as e:
            self.log(f"Crawley error: {e}", "ERROR")

        return urls

    def run_crawlergo(self, target: str, **kwargs) -> Set[str]:
        """Run Crawlergo crawler."""
        urls = set()
        proxy = kwargs.get("proxy")
        crawlergo_chrome = kwargs.get("crawlergo_chrome", "/usr/bin/chromium")
        max_pages = kwargs.get("max_pages", 200)

        try:
            output_json = self.output_dir / f"{target}_crawlergo.json"

            # Try HTTPS first, then HTTP
            target_urls = [f"https://{target}", f"http://{target}"]

            for target_url in target_urls:
                cmd = [
                    "crawlergo",
                    "-c",
                    crawlergo_chrome,
                    "--output-mode",
                    "json",
                    "--output-json",
                    str(output_json),
                    "--filter-mode",
                    "smart",
                    "--fuzz-path",
                    "--robots-path",
                    "--max-crawled-count",
                    str(max_pages),
                    "--max-tab-count",
                    "6",
                    target_url,
                ]
                if proxy:
                    cmd += ["--request-proxy", proxy]

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=1800
                    )
                    if result.returncode == 0 and output_json.exists():
                        break  # Success, don't try the other protocol
                except subprocess.TimeoutExpired:
                    continue  # Try next URL if timeout

            if output_json.exists():
                with open(output_json) as f:
                    data = json.load(f)
                    if "req_list" in data:
                        for req in data["req_list"]:
                            if "url" in req:
                                urls.add(req["url"])

        except Exception as e:
            self.log(f"Crawlergo error: {e}", "ERROR")

        return urls

    def process_crawl_results(self, all_urls: Set[str], **kwargs) -> bool:
        """Process and filter crawl results."""
        try:
            self.log(f"📊 Processing {len(all_urls)} discovered URLs", "INFO")

            # Apply filters
            filtered_urls = self.apply_filters(all_urls, **kwargs)

            # Extract additional data
            extracted_data = self.extract_additional_data(filtered_urls, **kwargs)

            # Generate outputs
            self.generate_outputs(filtered_urls, extracted_data, **kwargs)

            # Update statistics
            self.stats["total_urls_found"] = len(all_urls)
            self.stats["unique_urls"] = len(filtered_urls)

            return True

        except Exception as e:
            self.log(f"❌ Results processing failed: {e}", "ERROR")
            return False

    def apply_filters(self, urls: Set[str], **kwargs) -> Set[str]:
        """Apply filtering to discovered URLs."""
        filter_ext = kwargs.get("filter_ext", "")
        include_ext = kwargs.get("include_ext")
        exclude_domains = kwargs.get("exclude_domains", "")
        include_subdomains = kwargs.get("include_subdomains", True)
        deduplicate = kwargs.get("deduplicate", True)

        filtered_urls = set()

        # Parse filter extensions
        filter_extensions = tuple(
            ext.strip() for ext in filter_ext.split(",") if ext.strip()
        )
        include_extensions = (
            tuple(ext.strip() for ext in include_ext.split(","))
            if include_ext
            else None
        )
        exclude_domain_list = (
            [d.strip() for d in exclude_domains.split(",")] if exclude_domains else []
        )

        for url in urls:
            try:
                parsed = urlparse(url)

                # Skip invalid URLs
                if not parsed.scheme or not parsed.netloc:
                    continue

                # Check excluded domains
                if any(
                    exc_domain in parsed.netloc for exc_domain in exclude_domain_list
                ):
                    continue

                # Check subdomain inclusion
                if not include_subdomains:
                    if any(target in parsed.netloc for target in self.targets):
                        pass
                    else:
                        continue

                # Check extension filters
                if filter_extensions and url.lower().endswith(filter_extensions):
                    continue

                if include_extensions and not url.lower().endswith(include_extensions):
                    continue

                filtered_urls.add(url)

            except Exception:
                continue

        self.log(
            f"📋 Filtered to {len(filtered_urls)} URLs after applying filters", "INFO"
        )
        return filtered_urls

    def extract_additional_data(self, urls: Set[str], **kwargs) -> Dict:
        """Extract additional data like emails, phone numbers, API endpoints."""
        extracted = {
            "emails": set(),
            "phone_numbers": set(),
            "api_endpoints": set(),
            "forms": [],
            "sensitive_files": set(),
            "social_media": set(),
        }

        # Extract based on enabled features
        if kwargs.get("emails"):
            extracted["emails"] = self.extract_emails(urls)

        if kwargs.get("phone_numbers"):
            extracted["phone_numbers"] = self.extract_phone_numbers(urls)

        if kwargs.get("api_endpoints"):
            extracted["api_endpoints"] = self.extract_api_endpoints(urls)

        if kwargs.get("sensitive_files"):
            extracted["sensitive_files"] = self.extract_sensitive_files(urls)

        if kwargs.get("social_media"):
            extracted["social_media"] = self.extract_social_media(urls)

        # Update statistics
        self.stats["api_endpoints"] = len(extracted["api_endpoints"])
        self.stats["emails_found"] = len(extracted["emails"])
        self.stats["phone_numbers_found"] = len(extracted["phone_numbers"])
        self.stats["sensitive_files"] = len(extracted["sensitive_files"])

        return extracted

    def extract_emails(self, urls: Set[str]) -> Set[str]:
        """Extract email addresses from URLs and page content."""
        emails = set()
        email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        )

        for url in list(urls)[:50]:  # Limit to avoid too many requests
            try:
                if "mailto:" in url:
                    email_match = email_pattern.search(url)
                    if email_match:
                        emails.add(email_match.group())
            except:
                continue

        return emails

    def extract_phone_numbers(self, urls: Set[str]) -> Set[str]:
        """Extract phone numbers from URLs."""
        phones = set()
        phone_pattern = re.compile(
            r"(\+?1?[- .]?\(?[0-9]{3}\)?[- .]?[0-9]{3}[- .]?[0-9]{4})"
        )

        for url in urls:
            matches = phone_pattern.findall(url)
            phones.update(matches)

        return phones

    def extract_api_endpoints(self, urls: Set[str]) -> Set[str]:
        """Identify potential API endpoints."""
        api_endpoints = set()
        api_patterns = [
            r"/api/",
            r"/v\d+/",
            r"\.json",
            r"\.xml",
            r"/rest/",
            r"/graphql",
            r"/webhook",
        ]

        for url in urls:
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in api_patterns):
                api_endpoints.add(url)

        return api_endpoints

    def extract_sensitive_files(self, urls: Set[str]) -> Set[str]:
        """Identify potentially sensitive files."""
        sensitive = set()
        sensitive_patterns = [
            r"\.env",
            r"\.config",
            r"\.bak",
            r"\.backup",
            r"\.sql",
            r"\.log",
            r"/admin",
            r"/config",
            r"/backup",
            r"\.git/",
        ]

        for url in urls:
            if any(
                re.search(pattern, url, re.IGNORECASE) for pattern in sensitive_patterns
            ):
                sensitive.add(url)

        return sensitive

    def extract_social_media(self, urls: Set[str]) -> Set[str]:
        """Extract social media links."""
        social = set()
        social_domains = [
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "instagram.com",
            "youtube.com",
            "github.com",
            "telegram.org",
            "discord.gg",
        ]

        for url in urls:
            parsed = urlparse(url)
            if any(domain in parsed.netloc for domain in social_domains):
                social.add(url)

        return social

    def generate_outputs(self, urls: Set[str], extracted_data: Dict, **kwargs):
        """Generate output files in various formats."""
        output_format = kwargs.get("output_format", "txt")

        # Main URLs output
        if output_format == "txt":
            self.save_txt_output(urls, extracted_data)
        elif output_format == "json":
            self.save_json_output(urls, extracted_data)
        elif output_format == "csv":
            self.save_csv_output(urls, extracted_data)
        elif output_format == "xml":
            self.save_xml_output(urls, extracted_data)

        # Always generate summary report
        self.generate_summary_report(urls, extracted_data)

    def save_txt_output(self, urls: Set[str], extracted_data: Dict):
        """Save results in TXT format."""
        output_file = self.output_dir / "crawler_results.txt"

        with open(output_file, "w") as f:
            f.write("# Crawler Results\n\n")
            f.write("## URLs\n")
            for url in sorted(urls):
                f.write(f"{url}\n")

            if extracted_data["api_endpoints"]:
                f.write("\n## API Endpoints\n")
                for endpoint in sorted(extracted_data["api_endpoints"]):
                    f.write(f"{endpoint}\n")

            if extracted_data["emails"]:
                f.write("\n## Email Addresses\n")
                for email in sorted(extracted_data["emails"]):
                    f.write(f"{email}\n")

    def save_json_output(self, urls: Set[str], extracted_data: Dict):
        """Save results in JSON format."""
        output_file = self.output_dir / "crawler_results.json"

        data = {
            "urls": sorted(list(urls)),
            "extracted_data": {
                "api_endpoints": sorted(list(extracted_data["api_endpoints"])),
                "emails": sorted(list(extracted_data["emails"])),
                "phone_numbers": sorted(list(extracted_data["phone_numbers"])),
                "sensitive_files": sorted(list(extracted_data["sensitive_files"])),
                "social_media": sorted(list(extracted_data["social_media"])),
            },
            "stats": self.stats,
            "timestamp": datetime.now().isoformat(),
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

    def save_csv_output(self, urls: Set[str], extracted_data: Dict):
        """Save results in CSV format."""
        output_file = self.output_dir / "crawler_results.csv"

        with open(output_file, "w") as f:
            f.write("URL,Type,Category\n")
            for url in sorted(urls):
                url_type = "Standard"
                if url in extracted_data["api_endpoints"]:
                    url_type = "API Endpoint"
                elif url in extracted_data["sensitive_files"]:
                    url_type = "Sensitive File"
                f.write(f'"{url}","{url_type}","Web"\n')

    def save_xml_output(self, urls: Set[str], extracted_data: Dict):
        """Save results in XML format."""
        output_file = self.output_dir / "crawler_results.xml"

        with open(output_file, "w") as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write("<crawler_results>\n")
            f.write("  <urls>\n")
            for url in sorted(urls):
                f.write(f"    <url>{url}</url>\n")
            f.write("  </urls>\n")
            f.write("</crawler_results>\n")

    def update_session_status(self, status: str):
        """Update session status in metadata file."""
        try:
            if self.session_file.exists():
                with open(self.session_file) as f:
                    data = json.load(f)
                data["status"] = status
                data["stats"] = self.stats.copy()
                with open(self.session_file, "w") as f:
                    json.dump(data, f, indent=2)
        except Exception:
            pass

    def complete(self):
        """Mark session as completed and generate final report."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time

        self.update_session_status("completed")

        self.log("🎉 Crawling completed successfully!", "SUCCESS")
        self.log(
            f"⏱️ Total execution time: {self.stats['execution_time']:.2f} seconds",
            "INFO",
        )
        self.log(f"🔗 Total URLs found: {self.stats['total_urls_found']:,}", "INFO")
        self.log(f"✨ Unique URLs: {self.stats['unique_urls']:,}", "INFO")
        self.log(f"🔌 API endpoints: {self.stats['api_endpoints']:,}", "INFO")
        self.log(f"📧 Emails found: {self.stats['emails_found']:,}", "INFO")
        self.log(f"📁 Results saved to: {self.output_dir}", "SUCCESS")

        if self.notifications:
            self.send_notification(
                f"🕷️ Crawling completed! Found {self.stats['unique_urls']} URLs, "
                f"{self.stats['api_endpoints']} API endpoints"
            )

    def failed(self):
        """Mark session as failed."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("failed")
        self.log("❌ Crawling failed", "ERROR")

        if self.notifications:
            self.send_notification("❌ Crawling failed")

    def interrupted(self):
        """Mark session as interrupted."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("interrupted")
        self.log("⏹️ Crawling interrupted by user", "WARNING")

        if self.notifications:
            self.send_notification("⏹️ Crawling interrupted")

    def error(self, error_msg: str):
        """Mark session as error."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("error")
        self.log(f"💥 Crawling error: {error_msg}", "ERROR")

        if self.notifications:
            self.send_notification(f"💥 Crawling error: {error_msg}")

    def generate_summary_report(self, urls: Set[str], extracted_data: Dict):
        """Generate a comprehensive summary report."""
        report_file = self.output_dir / "crawler_summary.md"

        start_time_str = (
            datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S")
            if self.start_time
            else "Unknown"
        )

        report_content = f"""# 🕷️ Web Crawler Summary Report

## 🎯 Target Information
- **Targets**: {len(self.targets)} domain(s)
- **Primary Domain**: {self.targets[0] if self.targets else "N/A"}
- **Profile**: {self.profile}
- **Start Time**: {start_time_str}
- **Execution Time**: {self.stats["execution_time"]:.2f} seconds

## 📊 Crawling Results
- **Total URLs Found**: {self.stats["total_urls_found"]:,}
- **Unique URLs**: {self.stats["unique_urls"]:,}
- **API Endpoints**: {self.stats["api_endpoints"]:,}
- **Email Addresses**: {self.stats["emails_found"]:,}
- **Phone Numbers**: {self.stats["phone_numbers_found"]:,}
- **Sensitive Files**: {self.stats["sensitive_files"]:,}

## 🛠️ Tools Execution
- **Successful**: {", ".join(self.stats["tools_executed"]) if self.stats["tools_executed"] else "None"}
- **Failed**: {", ".join(self.stats["tools_failed"]) if self.stats["tools_failed"] else "None"}

## 📁 Output Files
- **Main Results**: `crawler_results.txt`
- **Session Data**: `crawler_session.json`
- **Summary Report**: `crawler_summary.md`

## 🔗 Top Discovered URLs
{chr(10).join(f"- {url}" for url in sorted(list(urls))[:20])}

## 🚀 Next Steps
1. **Review API endpoints** for potential security testing
2. **Analyze sensitive files** for misconfigurations
3. **Test discovered forms** for vulnerabilities
4. **Validate email addresses** for OSINT purposes
5. **Check social media profiles** for additional information

---
*🕷️ Generated by ReconCLI CrawlerCLI v2.0*
*Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}*
"""

        with open(report_file, "w") as f:
            f.write(report_content)

        self.log(f"📋 Summary report generated: {report_file}", "SUCCESS")


if __name__ == "__main__":
    crawlercli()
