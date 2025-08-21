#!/usr/bin/env python3

import hashlib
import json
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import click

try:
    import requests
    from gql import Client, gql
    from gql.transport.requests import RequestsHTTPTransport

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False


class GraphQLCacheManager:
    """Intelligent cache manager for GraphQL security operations."""

    def __init__(self, cache_dir: str = "graphql_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_seconds = max_age_hours * 3600
        self.cache_index_file = self.cache_dir / "graphql_cache_index.json"
        self.cache_stats = {"hits": 0, "misses": 0, "total_requests": 0}

    def _generate_cache_key(self, target: str, engine: str, options: dict) -> str:
        """Generate unique cache key based on target and scan parameters."""
        # Create a deterministic key from target, engine, and options
        key_data = {
            "target": target,
            "engine": engine,
            "options": {k: v for k, v in sorted(options.items()) if v is not None},
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid based on age."""
        if not cache_file.exists():
            return False

        file_age = time.time() - cache_file.stat().st_mtime
        return file_age < self.max_age_seconds

    def get_cached_result(self, target: str, engine: str, options: dict):
        """Retrieve cached result if available and valid."""
        cache_key = self._generate_cache_key(target, engine, options)
        cache_file = self.cache_dir / f"{cache_key}.json"

        self.cache_stats["total_requests"] += 1

        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                    self.cache_stats["hits"] += 1
                    return cached_data
            except (json.JSONDecodeError, IOError):
                # If cache file is corrupted, treat as cache miss
                pass

        self.cache_stats["misses"] += 1
        return None

    def store_result(self, target: str, engine: str, options: dict, result_data: dict):
        """Store scan result in cache."""
        cache_key = self._generate_cache_key(target, engine, options)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add metadata to cached result
        cache_data = {
            "metadata": {
                "target": target,
                "engine": engine,
                "options": options,
                "cached_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cache_key": cache_key,
            },
            "result": result_data,
        }

        try:
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            # Update cache index
            self._update_cache_index(cache_key, target, engine)

        except IOError as e:
            print(f"⚠️  [CACHE] Failed to store cache: {e}")

    def _update_cache_index(self, cache_key: str, target: str, engine: str):
        """Update cache index with new entry."""
        index_data = {}

        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    index_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                index_data = {}

        index_data[cache_key] = {
            "target": target,
            "engine": engine,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": (self.cache_dir / f"{cache_key}.json").stat().st_size,
        }

        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(index_data, f, indent=2)
        except IOError as e:
            print(f"⚠️  [CACHE] Failed to update cache index: {e}")

    def clear_cache(self) -> bool:
        """Clear all cached results."""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                print("✅ [CACHE] All cached results cleared successfully")
                return True
            return True
        except Exception as e:
            print(f"❌ [CACHE] Failed to clear cache: {e}")
            return False

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_size = sum(
            f.stat().st_size
            for f in cache_files
            if f.name != "graphql_cache_index.json"
        )

        hit_rate = (
            (self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100)
            if self.cache_stats["total_requests"] > 0
            else 0
        )

        return {
            "cache_hits": self.cache_stats["hits"],
            "cache_misses": self.cache_stats["misses"],
            "hit_rate": f"{hit_rate:.1f}%",
            "total_requests": self.cache_stats["total_requests"],
            "cache_files": len(
                [f for f in cache_files if f.name != "graphql_cache_index.json"]
            ),
            "cache_size": cache_size,
            "cache_dir": str(self.cache_dir),
        }


@click.command()
@click.option("--domain", required=False, help="Target domain (e.g. target.com)")
@click.option(
    "--url",
    required=False,
    help="Full GraphQL URL (e.g. https://api.target.com/graphql)",
)
@click.option(
    "--input", "-i", "input_file", help="File with URLs or domains (one per line)"
)
@click.option(
    "--engine",
    default="graphw00f",
    type=click.Choice(
        ["graphw00f", "graphql-cop", "graphqlmap", "gql", "gql-cli", "all"]
    ),
    help="Engine to use: graphw00f (default), graphql-cop, graphqlmap, gql, gql-cli, or all",
)
@click.option("--endpoint", help="Custom GraphQL endpoint (e.g. /api/graphql)")
@click.option("--proxy", help="Proxy (http://127.0.0.1:8080)")
@click.option("--tor", is_flag=True, help="Use Tor (graphql-cop only)")
@click.option(
    "--header",
    multiple=True,
    help='Custom headers: --header "Authorization: Bearer xyz" (use multiple times)',
)
@click.option("--wordlist", help="Path to custom endpoint wordlist")
@click.option(
    "--common-endpoints",
    is_flag=True,
    help="Test common GraphQL endpoints (/graphql, /api/graphql, /v1/graphql, etc.)",
)
@click.option("--schema-dump", is_flag=True, help="Dump GraphQL schema to file")
@click.option("--schema-json", is_flag=True, help="Dump GraphQL schema to JSON format")
@click.option(
    "--schema-introspect", is_flag=True, help="Full introspection schema dump"
)
@click.option("--introspection-query", help="Custom introspection query file")
@click.option("--mutations-only", is_flag=True, help="Focus only on mutation testing")
@click.option("--queries-only", is_flag=True, help="Focus only on query testing")
@click.option("--threads", default=10, help="Number of threads for scanning")
@click.option("--timeout", default=30, help="Request timeout in seconds")
@click.option("--output-dir", default="output", help="Output directory")
@click.option("--csv-output", is_flag=True, help="Save results in CSV format")
@click.option("--json-output", is_flag=True, help="Save results in JSON format")
@click.option("--store-db", is_flag=True, help="Store session state")
@click.option("--resume", is_flag=True, help="Resume previous session")
@click.option("--resume-stat", is_flag=True, help="Show previous session state")
@click.option("--resume-reset", is_flag=True, help="Delete previous session state")
@click.option("--report", is_flag=True, help="Generate Markdown report")
@click.option("--fingerprint", is_flag=True, help="Enable GraphQL fingerprinting")
@click.option(
    "--threat-matrix", is_flag=True, help="Run GraphQL Threat Matrix assessment"
)
@click.option(
    "--detect-engines", is_flag=True, help="Detect GraphQL engine/implementation"
)
@click.option("--batch-queries", is_flag=True, help="Test GraphQL batching support")
@click.option(
    "--field-suggestions", is_flag=True, help="Test field suggestion vulnerabilities"
)
@click.option("--depth-limit", is_flag=True, help="Test query depth limit")
@click.option("--rate-limit", is_flag=True, help="Test rate limiting")
@click.option(
    "--sqli-test", is_flag=True, help="Test for SQL injection vulnerabilities"
)
@click.option(
    "--nosqli-test", is_flag=True, help="Test for NoSQL injection vulnerabilities"
)
@click.option(
    "--gql-cli", is_flag=True, help="Use gql-cli for enhanced GraphQL operations"
)
@click.option(
    "--print-schema",
    is_flag=True,
    help="Download and save GraphQL schema using gql-cli",
)
@click.option(
    "--schema-file", help="Custom schema output filename (default: schema.graphql)"
)
@click.option("--gql-variables", help="Variables for gql-cli in key:value format")
@click.option("--gql-operation", help="Specific GraphQL operation name to execute")
@click.option("--interactive-gql", is_flag=True, help="Run gql-cli in interactive mode")
@click.option(
    "--gql-transport",
    type=click.Choice(["auto", "aiohttp", "httpx", "websockets"]),
    default="auto",
    help="Transport type for gql-cli (default: auto)",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--insecure",
    is_flag=True,
    help="Disable SSL certificate verification (security risk)",
)
# ========== Cache Options ==========
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option(
    "--cache-dir", default="graphql_cache", help="Directory for cache storage"
)
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
@click.option("--ai", is_flag=True, help="Enable AI-powered GraphQL security analysis")
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    default="openai",
    help="AI provider for analysis",
)
@click.option(
    "--ai-context",
    help="Additional context for AI analysis (e.g., 'financial API', 'social media')",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "table", "rich"]),
    default="table",
    help="Output format",
)
@click.option(
    "--concurrency", type=int, default=10, help="Number of concurrent requests"
)
@click.option("--user-agent", help="Custom User-Agent header")
@click.option(
    "--cookies", help="Cookies to include (format: 'name1=value1; name2=value2')"
)
@click.option(
    "--extract-urls", is_flag=True, help="Extract URLs from input file/text using regex"
)
@click.option(
    "--url-pattern",
    default=r"https?://[a-zA-Z0-9\.\-_:/]+",
    help="Custom regex pattern for URL extraction",
)
@click.option("--bulk-test", is_flag=True, help="Bulk test all extracted/provided URLs")
@click.option(
    "--max-urls",
    type=int,
    default=100,
    help="Maximum number of URLs to test in bulk mode",
)
@click.option(
    "--filter-graphql",
    is_flag=True,
    help="Only test URLs that look like GraphQL endpoints",
)
def graphqlcli(
    domain,
    url,
    input_file,
    engine,
    endpoint,
    proxy,
    tor,
    header,
    wordlist,
    common_endpoints,
    schema_dump,
    schema_json,
    schema_introspect,
    introspection_query,
    mutations_only,
    queries_only,
    threads,
    timeout,
    output_dir,
    csv_output,
    json_output,
    store_db,
    resume,
    resume_stat,
    resume_reset,
    report,
    fingerprint,
    threat_matrix,
    detect_engines,
    batch_queries,
    field_suggestions,
    depth_limit,
    rate_limit,
    sqli_test,
    nosqli_test,
    gql_cli,
    print_schema,
    schema_file,
    gql_variables,
    gql_operation,
    interactive_gql,
    gql_transport,
    verbose,
    insecure,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
    ai,
    ai_provider,
    ai_context,
    output_format,
    concurrency,
    user_agent,
    cookies,
    extract_urls,
    url_pattern,
    bulk_test,
    max_urls,
    filter_graphql,
):
    """GraphQL recon & audit module using multiple engines and advanced techniques"""

    # ========== Cache System ==========
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = GraphQLCacheManager(
            cache_dir=cache_dir, max_age_hours=cache_max_age
        )

        if clear_cache:
            if cache_manager.clear_cache():
                print(f"✅ [CACHE] Cache cleared successfully: {cache_dir}")
            else:
                print(f"❌ [CACHE] Failed to clear cache: {cache_dir}")
            return

        if cache_stats:
            stats = cache_manager.get_cache_stats()
            print("📊 [CACHE] GraphQL Cache Statistics:")
            print(f"    Cache hits: {stats['cache_hits']}")
            print(f"    Cache misses: {stats['cache_misses']}")
            print(f"    Hit rate: {stats['hit_rate']}")
            print(f"    Total requests: {stats['total_requests']}")
            print(f"    Cache files: {stats['cache_files']}")
            print(f"    Cache size: {stats['cache_size']} bytes")
            print(f"    Cache directory: {stats['cache_dir']}")
            return

    if not DEPENDENCIES_AVAILABLE:
        click.echo("[!] Required dependencies not found. Install with:")
        click.echo("    pip install requests gql[all] click")
        return

    # Validate required parameters
    targets = []

    if url:
        targets.append(url)
    elif domain:
        targets.append(f"https://{domain}/graphql")
    elif input_file:
        if not Path(input_file).exists():
            print(f"❌ Error: Input file '{input_file}' not found")
            return

        with open(input_file, "r") as f:
            if extract_urls:
                # If extracting URLs, read entire file as text for regex processing
                file_content = f.read()
                targets = [file_content]  # Will be processed later in URL extraction
            else:
                # Normal line-by-line processing
                lines = f.read().strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line.startswith("http"):
                            targets.append(line)
                        else:
                            targets.append(f"https://{line}/graphql")

    if not targets:
        print("❌ Error: Target is required. Use --url, --domain, or --input")
        print("💡 Available cache-only commands: --cache-stats, --clear-cache")
        return

    # ========== URL Extraction & Bulk Processing ==========
    if extract_urls or bulk_test:
        import re

        all_extracted_urls = []

        # Extract URLs from targets (treating them as text sources)
        for target in targets:
            if extract_urls:
                if verbose:
                    print(f"🔍 [URL-EXTRACT] Extracting URLs from: {target}")

                # Try to read as file first, then as text
                try:
                    if Path(target).exists():
                        with open(target, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    else:
                        content = target
                except:
                    content = target

                # Extract URLs using regex
                extracted_urls = re.findall(url_pattern, content)

                # Also extract IP addresses from GraphQL context and convert to URLs
                lines = content.split("\n")
                for line in lines:
                    line_lower = line.lower()
                    # Check if line mentions GraphQL
                    if any(
                        keyword in line_lower
                        for keyword in ["graphql", "playground", "gql"]
                    ):
                        # Extract IP addresses from this line
                        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?\b"
                        ips = re.findall(ip_pattern, line)
                        for ip in ips:
                            # Add both HTTP and HTTPS versions
                            if ":" in ip:  # Has port
                                extracted_urls.append(f"http://{ip}")
                                extracted_urls.append(f"https://{ip}")
                            else:  # No port, try common GraphQL ports
                                extracted_urls.append(f"http://{ip}")
                                extracted_urls.append(f"https://{ip}")
                                extracted_urls.append(f"http://{ip}:4000")
                                extracted_urls.append(f"https://{ip}:4000")

                # Filter GraphQL-like URLs if requested
                if filter_graphql:
                    # For GraphQL filtering, check both URL patterns and content context
                    graphql_patterns = [
                        r"/graphql",
                        r"/api/graphql",
                        r"/v1/graphql",
                        r"/v2/graphql",
                        r"/query",
                        r"/api/query",
                        r"/gql",
                        r"/api/gql",
                        r"/graphql-api",
                        r"/graphql-dev",
                        r"/graphql-playground",
                        r"/graphiql",
                        r"/altair",
                        r"/voyager",
                        r"/__graphql",
                        r"/q/graphql",
                        r"/graphql/api",
                        r"/apollo",
                        r"/graphql/query",
                        r"/graphql/mutation",
                    ]

                    filtered_urls = []
                    for url in extracted_urls:
                        # Check if URL has GraphQL path
                        if any(pattern in url.lower() for pattern in graphql_patterns):
                            filtered_urls.append(url)
                            continue

                        # For URLs without GraphQL paths, check if they came from GraphQL context
                        # Find the URL in content and check surrounding context
                        url_index = content.lower().find(url.lower())
                        if url_index != -1:
                            # Get context around the URL
                            context_start = max(0, url_index - 200)
                            context_end = min(len(content), url_index + len(url) + 200)
                            context = content[context_start:context_end].lower()

                            # Check if context mentions GraphQL
                            if any(
                                keyword in context
                                for keyword in ["graphql", "playground", "gql"]
                            ):
                                filtered_urls.append(url)

                    extracted_urls = filtered_urls

                all_extracted_urls.extend(extracted_urls)

                if verbose:
                    print(f"🎯 [URL-EXTRACT] Found {len(extracted_urls)} URLs")
            else:
                all_extracted_urls.append(target)

        # Remove duplicates and limit
        unique_urls = list(set(all_extracted_urls))
        if max_urls and len(unique_urls) > max_urls:
            unique_urls = unique_urls[:max_urls]
            if verbose:
                print(
                    f"⚠️  [BULK] Limited to {max_urls} URLs (use --max-urls to change)"
                )

        targets = unique_urls

        if verbose:
            print(f"🎯 [BULK] Final target count: {len(targets)} URLs")
            if len(targets) <= 10:
                for i, target in enumerate(targets, 1):
                    print(f"    [{i}] {target}")
            else:
                print(f"    [Sample] {targets[0]}")
                print(f"    [Sample] {targets[1]}")
                print(f"    [...] {len(targets)-4} more")
                print(f"    [Sample] {targets[-2]}")
                print(f"    [Sample] {targets[-1]}")

    if verbose:
        print(f"🎯 [TARGETS] Found {len(targets)} target(s) to scan")

    # Security warning for insecure mode
    if insecure:
        click.echo(
            "⚠️  WARNING: SSL certificate verification is disabled. This is a security risk!"
        )
        click.echo("    Use --insecure only for testing against trusted endpoints.")

    # Set SSL verification behavior
    ssl_verify = not insecure

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Expand targets with common endpoints if requested
    if common_endpoints:
        expanded_targets = []
        common_paths = [
            "/graphql",
            "/graphql/",
            "/api/graphql",
            "/api/graphql/",
            "/gql",
            "/gql/",
            "/v1/graphql",
            "/v1/graphql/",
            "/v2/graphql",
            "/v2/graphql/",
            "/graphql-dev",
            "/graphql-dev/",
            "/graphql-playground",
            "/graphql-playground/",
            "/graphiql",
            "/graphiql/",
            "/altair",
            "/altair/",
            "/voyager",
            "/voyager/",
            "/__graphql",
            "/__graphql/",
            "/q/graphql",
            "/q/graphql/",
            "/api",
            "/api/",
            "/graphql/api",
            "/graphql/api/",
            "/apollo",
            "/apollo/",
            "/graphql/query",
            "/graphql/query/",
            "/graphql/mutation",
            "/graphql/mutation/",
            "/query",
            "/api/query",
            "/graphql/v1",
            "/api/v1/graphql",
            "/graphql-api",
            "/api/gql",
        ]

        for target in targets:
            # Extract base URL - handle different URL formats
            if target.endswith("/graphql"):
                base_url = target.replace("/graphql", "")
            elif target.endswith("/"):
                base_url = target.rstrip("/")
            else:
                base_url = target

            # Add all common paths to the base URL
            for path in common_paths:
                expanded_targets.append(f"{base_url}{path}")

        targets = expanded_targets
        if verbose:
            print(
                f"🔍 [ENDPOINTS] Expanded to {len(targets)} endpoints with common paths"
            )

    # Set up User-Agent
    headers_dict = {}
    if user_agent:
        headers_dict["User-Agent"] = user_agent
    else:
        headers_dict["User-Agent"] = "ReconCLI-GraphQLCLI/1.0"

    # Set up cookies
    if cookies:
        headers_dict["Cookie"] = cookies

    # Merge with existing headers
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers_dict[k.strip()] = v.strip()

    # Convert back to header list format for compatibility
    header = [f"{k}: {v}" for k, v in headers_dict.items()]

    state_file = output_path / f"graphqlcli_state_{domain}.json"
    json_output_file = output_path / f"graphql_audit_{domain}.json"
    csv_output_file = output_path / f"graphql_audit_{domain}.csv"
    md_output = output_path / f"graphql_report_{domain}.md"

    if verbose:
        click.echo(f"[+] Starting GraphQL security assessment for {domain}")
        click.echo(f"[+] Engine: {engine}")
        click.echo(f"[+] Output directory: {output_path}")
        if cache_manager:
            click.echo(
                f"💾 [CACHE] Cache: ENABLED (dir: {cache_dir}, TTL: {cache_max_age}h)"
            )
        else:
            click.echo("💾 [CACHE] Cache: DISABLED")

    # Resume logic
    if resume_reset:
        if state_file.exists():
            state_file.unlink()
            click.echo(f"[+] Reset state file for {domain}")
        return
    if resume_stat:
        if state_file.exists():
            click.echo(state_file.read_text())
        else:
            click.echo("[!] No session found.")
        return
    if resume and state_file.exists():
        with state_file.open() as f:
            session_data = json.load(f)
            click.echo(f"[+] Resuming previous session for {domain}")
            engine = session_data.get("engine", engine)
    elif resume:
        click.echo("[!] No previous session found.")
        return

    # Build target URL
    if endpoint:
        target_url = f"https://{domain}{endpoint}"
    else:
        target_url = f"https://{domain}/graphql"

    if verbose:
        click.echo(f"[+] Target URL: {target_url}")

    # Run selected engine(s) on all targets
    all_results = {}

    for target_idx, target_url in enumerate(targets, 1):
        if verbose and len(targets) > 1:
            print(f"\n[{target_idx}/{len(targets)}] 🔍 Processing: {target_url}")

        # Extract domain from URL for file naming
        from urllib.parse import urlparse

        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc or domain or "unknown"

        if verbose:
            print(f"[+] Target URL: {target_url}")
            print(f"[+] Target domain: {target_domain}")

        state_file = output_path / f"graphqlcli_state_{target_domain}.json"
        json_output_file = output_path / f"graphql_audit_{target_domain}.json"
        csv_output_file = output_path / f"graphql_audit_{target_domain}.csv"
        md_output = output_path / f"graphql_report_{target_domain}.md"

        # Resume logic for each target
        if resume_reset:
            if state_file.exists():
                state_file.unlink()
                click.echo(f"[+] Reset state file for {target_domain}")
            continue
        if resume_stat:
            if state_file.exists():
                click.echo(state_file.read_text())
            else:
                click.echo(f"[!] No session found for {target_domain}")
            continue
        if resume and state_file.exists():
            with state_file.open() as f:
                session_data = json.load(f)
                click.echo(f"[+] Resuming previous session for {target_domain}")
                engine = session_data.get("engine", engine)
        elif resume:
            click.echo(f"[!] No previous session found for {target_domain}")
            continue

        results = {}

        if engine == "all":
            engines = ["graphw00f", "graphql-cop", "graphqlmap", "gql", "gql-cli"]
        else:
            engines = [engine]

        for eng in engines:
            if verbose:
                click.echo(f"[+] Running {eng} engine...")

            # ========== Cache Check ==========
            cache_options = {
                "endpoint": endpoint,
                "proxy": proxy,
                "tor": tor,
                "headers": header,
                "wordlist": wordlist,
                "threads": threads,
                "timeout": timeout,
                "fingerprint": fingerprint,
                "threat_matrix": threat_matrix,
                "detect_engines": detect_engines,
                "batch_queries": batch_queries,
                "field_suggestions": field_suggestions,
                "depth_limit": depth_limit,
                "rate_limit": rate_limit,
                "sqli_test": sqli_test,
                "nosqli_test": nosqli_test,
            }

            if cache_manager:
                cached_result = cache_manager.get_cached_result(
                    target_url, eng, cache_options
                )
                if cached_result:
                    if verbose:
                        click.echo(f"💾 [CACHE] Using cached result for {eng} engine")
                    results[eng] = cached_result["result"]
                    continue
                elif verbose:
                    click.echo(
                        f"💾 [CACHE] No cache found for {eng} engine, scanning..."
                    )

            if eng == "graphw00f":
                result = run_graphw00f(
                    target_domain,
                    header,
                    proxy,
                    fingerprint,
                    detect_engines,
                    verbose,
                    ssl_verify,
                )
                result["url"] = target_url  # Add the URL to results
            elif eng == "gql":
                result = run_gql_engine_enhanced(
                    target_url, header, proxy, endpoint, timeout, verbose
                )
            elif eng == "gql-cli":
                # Run gql-cli as engine
                schema_output_file = schema_file or f"{target_domain}_schema.graphql"
                schema_path = output_path / schema_output_file
                result = run_gql_cli_operations(
                    target_url,
                    header,
                    proxy,
                    True,
                    schema_path,
                    gql_variables,
                    gql_operation,
                    False,
                    gql_transport,
                    verbose,
                )
            elif eng == "graphqlmap":
                result = run_graphqlmap_enhanced(
                    target_url, header, proxy, endpoint, timeout, verbose, ssl_verify
                )
            elif eng == "graphql-cop":
                result = run_graphqlcop_enhanced(
                    target_url, header, proxy, tor, endpoint, timeout, verbose
                )
            else:
                click.echo(f"[!] Unknown engine: {eng}")
                continue

            results[eng] = result

            # ========== Cache Storage ==========
            if cache_manager and result:
                cache_manager.store_result(target_url, eng, cache_options, result)
                if verbose:
                    click.echo(f"💾 [CACHE] Stored {eng} result in cache")

        # Run advanced tests if requested
        if threat_matrix:
            results[f"{eng}_threat_matrix"] = run_threat_matrix_assessment(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

        if batch_queries:
            results[f"{eng}_batch_test"] = test_batch_queries(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

        if sqli_test:
            results[f"{eng}_sqli"] = test_sql_injection(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

            if nosqli_test:
                results[f"{eng}_nosqli"] = test_nosql_injection(
                    target_url, header, proxy, timeout, verbose, ssl_verify
                )

        # AI Analysis if requested
        if ai and results:
            if verbose:
                print(f"🧠 [AI] Running AI analysis with {ai_provider}...")

            ai_analysis = run_ai_analysis(
                target_url, results, ai_provider, ai_context, verbose
            )
            results["ai_analysis"] = ai_analysis

        # Handle schema dumping requests
        if schema_dump or schema_json or schema_introspect or print_schema:
            schema_results = {}

            if schema_json or schema_introspect:
                # JSON schema dump using introspection
                schema_results.update(
                    dump_schema_json(target_url, header, proxy, verbose, ssl_verify)
                )

            if schema_dump or print_schema:
                # GraphQL schema dump
                schema_output_file = schema_file or f"{target_domain}_schema.graphql"
                schema_path = output_path / schema_output_file

                gql_result = run_gql_cli_operations(
                    target_url,
                    header,
                    proxy,
                    True,  # print_schema
                    schema_path,
                    gql_variables,
                    gql_operation,
                    False,  # interactive_gql
                    gql_transport,
                    verbose,
                )
                schema_results.update(gql_result)

            # Save schema results
            if schema_json:
                json_schema_file = output_path / f"{target_domain}_schema.json"
                if schema_results.get("introspection_result"):
                    json_schema_file.write_text(
                        json.dumps(schema_results["introspection_result"], indent=2)
                    )
                    if verbose:
                        print(f"📄 [SCHEMA] JSON schema saved to: {json_schema_file}")

            results["schema_dump"] = schema_results
            schema_output_file = schema_file or f"{target_domain}_schema.graphql"
            schema_path = output_path / schema_output_file

            gql_result = run_gql_cli_operations(
                target_url,
                header,
                proxy,
                print_schema,
                schema_path,
                gql_variables,
                gql_operation,
                interactive_gql,
                gql_transport,
                verbose,
            )

            if print_schema and not interactive_gql:
                # If only schema download was requested, save and exit
                if gql_result.get("schema_downloaded"):
                    click.echo(f"[+] Schema saved to: {schema_path}")
                    all_results[target_url] = gql_result
                    continue
                else:
                    click.echo(
                        f"[!] Failed to download schema: {gql_result.get('error', 'Unknown error')}"
                    )
                    continue

        # Save results in different formats
        if json_output or not csv_output:
            json_output_file.write_text(json.dumps(results, indent=2))
            if verbose:
                click.echo(f"[+] Saved JSON: {json_output_file}")

        if csv_output:
            save_csv_results(results, csv_output_file)
            if verbose:
                click.echo(f"[+] Saved CSV: {csv_output_file}")

        # Save session
        if store_db:
            state = {
                "domain": target_domain,
                "url": target_url,
                "engine": engine,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
            }
            state_file.write_text(json.dumps(state, indent=2))
            if verbose:
                click.echo(f"[+] Session saved: {state_file}")

        # Generate report
        if report:
            md_content = generate_markdown_report(
                target_domain, engines, results, verbose
            )
            md_output.write_text(md_content)
            if verbose:
                click.echo(f"[+] Markdown report saved: {md_output}")

        # Store results for this target
        all_results[target_url] = results

    # Handle special commands that should exit early
    if resume_reset or resume_stat:
        return all_results

    # Handle multi-target output
    if len(targets) > 1:
        # Save combined results
        combined_json = output_path / "graphql_audit_combined.json"
        combined_json.write_text(json.dumps(all_results, indent=2))

        if verbose:
            print(f"\n📊 [SUMMARY] Processed {len(targets)} targets")
            print(f"📁 [COMBINED] Results saved to: {combined_json}")

    # Display formatted output
    if len(targets) == 1:
        final_results = list(all_results.values())[0] if all_results else {}
    else:
        final_results = all_results

    # Format and display results
    if final_results:
        formatted_output = format_output(final_results, output_format, verbose)
        if output_format not in ["rich"]:  # Rich already prints directly
            print(formatted_output)

    # ========== Cache Statistics ==========
    if cache_manager and verbose:
        stats = cache_manager.get_cache_stats()
        click.echo("\n📊 [CACHE] GraphQL Cache Performance:")
        click.echo(f"    Cache hits: {stats['cache_hits']}")
        click.echo(f"    Cache misses: {stats['cache_misses']}")
        click.echo(f"    Hit rate: {stats['hit_rate']}")
        click.echo(f"    Cache files: {stats['cache_files']}")
        click.echo(f"    Cache size: {stats['cache_size']} bytes")

    return all_results


def run_ai_analysis(target_url, results, ai_provider, ai_context, verbose):
    """Run AI-powered analysis of GraphQL security results"""
    try:
        # Import AI libraries based on provider
        if ai_provider == "openai":
            import openai

            client = openai.OpenAI()
        elif ai_provider == "anthropic":
            import anthropic

            client = anthropic.Anthropic()
        elif ai_provider == "gemini":
            import google.generativeai as genai

            client = genai
        else:
            return {"error": f"Unsupported AI provider: {ai_provider}"}

        # Prepare analysis prompt
        context = ai_context or "general GraphQL API security assessment"

        prompt = f"""
You are a GraphQL security expert analyzing scan results for: {target_url}

Context: {context}

Scan Results:
{json.dumps(results, indent=2)}

Please provide a comprehensive security analysis including:
1. Risk Assessment (CRITICAL/HIGH/MEDIUM/LOW)
2. Identified Vulnerabilities
3. Attack Vectors
4. Specific Recommendations
5. Business Impact
6. Remediation Priority

Format as JSON with these keys: risk_level, vulnerabilities, attack_vectors, recommendations, business_impact, priority_actions
"""

        if verbose:
            print(f"🧠 [AI] Sending {len(prompt)} characters to {ai_provider}")

        # Make AI request based on provider
        if ai_provider == "openai":
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.3,
            )
            ai_response = response.choices[0].message.content

        elif ai_provider == "anthropic":
            response = client.messages.create(
                model="claude-3-sonnet-20240229",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.3,
            )
            ai_response = response.content[0].text

        elif ai_provider == "gemini":
            model = genai.GenerativeModel("gemini-pro")
            response = model.generate_content(prompt)
            ai_response = response.text

        # Try to parse JSON response
        try:
            analysis = json.loads(ai_response)
        except json.JSONDecodeError:
            # If not JSON, wrap as text response
            analysis = {
                "raw_response": ai_response,
                "provider": ai_provider,
                "context": context,
            }

        analysis.update(
            {
                "provider": ai_provider,
                "context": context,
                "timestamp": datetime.utcnow().isoformat(),
                "target_url": target_url,
            }
        )

        return analysis

    except ImportError:
        return {
            "error": f"AI provider '{ai_provider}' library not installed",
            "install_hint": f"pip install {ai_provider}",
        }
    except Exception as e:
        return {"error": f"AI analysis failed: {str(e)}", "provider": ai_provider}


def format_output(results, output_format, verbose):
    """Format results according to specified output format"""
    if output_format == "json":
        return json.dumps(results, indent=2)
    elif output_format == "csv":
        # Convert to CSV-friendly format
        csv_data = []
        for engine, data in results.items():
            if isinstance(data, dict):
                csv_data.append(
                    {
                        "engine": engine,
                        "url": data.get("url", "N/A"),
                        "status": "success" if not data.get("error") else "error",
                        "details": str(data)[:100],
                    }
                )
        return csv_data
    elif output_format == "rich":
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.json import JSON

            console = Console()
            table = Table(title="GraphQL Security Analysis")
            table.add_column("Engine", style="cyan")
            table.add_column("URL", style="magenta")
            table.add_column("Status", style="green")
            table.add_column("Key Findings", style="white")

            for engine, data in results.items():
                if isinstance(data, dict):
                    url = data.get("url", "N/A")
                    status = "✅ Success" if not data.get("error") else "❌ Error"
                    findings = str(
                        data.get("introspection", data.get("vulnerable", "Unknown"))
                    )
                    table.add_row(engine, url, status, findings)

            console.print(table)
            return "Rich output displayed above"
        except ImportError:
            return format_output(results, "table", verbose)
    else:  # table format
        output = []
        output.append("=" * 80)
        output.append("GraphQL Security Analysis Results")
        output.append("=" * 80)

        for engine, data in results.items():
            output.append(f"\n🔍 Engine: {engine.upper()}")
            output.append("-" * 40)

            if isinstance(data, dict):
                if data.get("error"):
                    output.append(f"❌ Error: {data['error']}")
                elif data.get("introspection"):
                    output.append("✅ Introspection: Enabled")
                    if data.get("types_count"):
                        output.append(f"   Types: {data['types_count']}")
                elif "threats" in data:
                    for threat, result in data["threats"].items():
                        status = (
                            "⚠️  VULNERABLE" if result.get("vulnerable") else "✅ Safe"
                        )
                        output.append(f"   {threat}: {status}")
                else:
                    output.append(f"   Status: Completed")

        return "\n".join(output)


def dump_schema_json(target_url, headers, proxy, verbose, ssl_verify=True):
    """Dump GraphQL schema to JSON using introspection query"""

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Full introspection query
    full_introspection_query = {
        "query": """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }

        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }

        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
    }

    try:
        if verbose:
            print(f"📄 [SCHEMA] Executing full introspection query on {target_url}")

        response = requests.post(
            target_url,
            json=full_introspection_query,
            headers=header_dict,
            proxies=proxies,
            timeout=60,
            verify=ssl_verify,
        )

        if response.status_code == 200:
            introspection_data = response.json()

            # Parse schema statistics
            schema_stats = parse_schema_statistics(introspection_data)

            return {
                "introspection_result": introspection_data,
                "schema_statistics": schema_stats,
                "status": "success",
                "url": target_url,
            }
        else:
            return {
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "status": "failed",
                "url": target_url,
            }

    except Exception as e:
        return {"error": str(e), "status": "failed", "url": target_url}


def parse_schema_statistics(introspection_data):
    """Parse statistics from introspection result"""
    stats = {}  # Use regular dict for flexibility

    try:
        schema = introspection_data.get("data", {}).get("__schema", {})
        types = schema.get("types", [])

        built_in_types = {
            "__Schema",
            "__Type",
            "__TypeKind",
            "__Field",
            "__InputValue",
            "__EnumValue",
            "__Directive",
            "__DirectiveLocation",
            "String",
            "Int",
            "Float",
            "Boolean",
            "ID",
        }

        stats["total_types"] = len(types)
        stats["directives"] = len(schema.get("directives", []))
        stats["query_fields"] = 0
        stats["mutation_fields"] = 0
        stats["subscription_fields"] = 0
        stats["custom_types"] = 0
        stats["built_in_types"] = 0
        stats["enum_types"] = 0
        stats["interface_types"] = 0
        stats["union_types"] = 0
        stats["input_types"] = 0

        for type_def in types:
            type_name = type_def.get("name", "")
            type_kind = type_def.get("kind", "")

            if type_name in built_in_types or type_name.startswith("__"):
                stats["built_in_types"] += 1
            else:
                stats["custom_types"] += 1

            if type_kind == "ENUM":
                stats["enum_types"] += 1
            elif type_kind == "INTERFACE":
                stats["interface_types"] += 1
            elif type_kind == "UNION":
                stats["union_types"] += 1
            elif type_kind == "INPUT_OBJECT":
                stats["input_types"] += 1

        # Count fields in root types
        query_type = schema.get("queryType", {}).get("name")
        mutation_type = (
            schema.get("mutationType", {}).get("name")
            if schema.get("mutationType")
            else None
        )
        subscription_type = (
            schema.get("subscriptionType", {}).get("name")
            if schema.get("subscriptionType")
            else None
        )

        for type_def in types:
            type_name = type_def.get("name")
            fields = type_def.get("fields", [])

            if type_name == query_type:
                stats["query_fields"] = len(fields)
            elif type_name == mutation_type:
                stats["mutation_fields"] = len(fields)
            elif type_name == subscription_type:
                stats["subscription_fields"] = len(fields)

    except Exception as e:
        stats["parsing_error"] = str(e)

    return stats


def run_gql_engine_enhanced(
    target_url, headers, proxy, endpoint=None, timeout=30, verbose=False
):
    """Enhanced wrapper for run_gql_engine with URL support"""
    from urllib.parse import urlparse

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    # Override endpoint if URL has a specific path
    if parsed_url.path and parsed_url.path != "/":
        endpoint = parsed_url.path

    result = run_gql_engine(domain, headers, proxy, endpoint, timeout, verbose)
    result["url"] = target_url
    return result


def run_graphqlmap_enhanced(
    target_url,
    headers,
    proxy,
    endpoint=None,
    timeout=30,
    verbose=False,
    ssl_verify=True,
):
    """Enhanced wrapper for run_graphqlmap with URL support"""
    from urllib.parse import urlparse

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    if parsed_url.path and parsed_url.path != "/":
        endpoint = parsed_url.path

    result = run_graphqlmap(
        domain, headers, proxy, endpoint, timeout, verbose, ssl_verify
    )
    result["url"] = target_url
    return result


def run_graphqlcop_enhanced(
    target_url, headers, proxy, tor, endpoint=None, timeout=30, verbose=False
):
    """Enhanced wrapper for run_graphqlcop with URL support"""
    from urllib.parse import urlparse

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    if parsed_url.path and parsed_url.path != "/":
        endpoint = parsed_url.path

    result = run_graphqlcop(domain, headers, proxy, tor, endpoint, timeout, verbose)
    result["url"] = target_url
    return result


def run_graphw00f(
    domain, headers, proxy, fingerprint, detect_engines, verbose, ssl_verify=True
):
    """Run GraphW00F fingerprinting tool"""
    url = f"https://{domain}/graphql"
    cmd = ["graphw00f", "-t", url]

    for h in headers:
        cmd += ["-H", h]
    if proxy:
        cmd += ["-p", proxy]
    if fingerprint:
        cmd += ["-f"]
    if detect_engines:
        cmd += ["-d"]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Parse GraphW00F output
        output_data = {
            "engine": "graphw00f",
            "url": url,
            "fingerprint_enabled": fingerprint,
            "detect_engines": detect_engines,
            "raw_output": result.stdout,
            "errors": result.stderr if result.stderr else None,
        }

        # Try to extract structured data from output
        if "GraphQL Engine" in result.stdout:
            lines = result.stdout.split("\n")
            for line in lines:
                if "GraphQL Engine:" in line:
                    output_data["detected_engine"] = line.split(":", 1)[1].strip()
                elif "Version:" in line:
                    output_data["detected_version"] = line.split(":", 1)[1].strip()

        return output_data

    except subprocess.TimeoutExpired:
        return {
            "engine": "graphw00f",
            "url": url,
            "error": "Timeout expired",
            "timeout": 120,
        }
    except FileNotFoundError:
        # Fallback to manual fingerprinting if GraphW00F not installed
        if verbose:
            click.echo("[!] GraphW00F not found, using manual fingerprinting")
        return manual_graphql_fingerprinting(
            domain, headers, proxy, verbose, ssl_verify
        )
    except Exception as e:
        return {"engine": "graphw00f", "url": url, "error": str(e)}


def manual_graphql_fingerprinting(domain, headers, proxy, verbose, ssl_verify=True):
    """Manual GraphQL fingerprinting implementation"""
    url = f"https://{domain}/graphql"

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    fingerprint_data = {"engine": "manual_fingerprint", "url": url, "tests": {}}

    # Test 1: Introspection query
    introspection_query = {"query": "{ __schema { queryType { name } } }"}

    try:
        if verbose:
            click.echo("[+] Testing introspection...")
        response = requests.post(
            url,
            json=introspection_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        fingerprint_data["tests"]["introspection"] = {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "enabled": "queryType" in response.text,
        }
    except Exception as e:
        fingerprint_data["tests"]["introspection"] = {"error": str(e)}

    # Test 2: Error message fingerprinting
    invalid_query = {"query": "{ invalid_field }"}

    try:
        if verbose:
            click.echo("[+] Testing error messages...")
        response = requests.post(
            url,
            json=invalid_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        error_text = response.text.lower()

        # Engine detection based on error patterns
        detected_engine = "unknown"
        if "apollo" in error_text:
            detected_engine = "Apollo Server"
        elif "graphene" in error_text:
            detected_engine = "Graphene"
        elif "hasura" in error_text:
            detected_engine = "Hasura"
        elif "lighthouse" in error_text:
            detected_engine = "Lighthouse"
        elif "sangria" in error_text:
            detected_engine = "Sangria"
        elif "juniper" in error_text:
            detected_engine = "Juniper"

        fingerprint_data["tests"]["error_fingerprint"] = {
            "detected_engine": detected_engine,
            "response_text": response.text[:500],  # First 500 chars
        }
    except Exception as e:
        fingerprint_data["tests"]["error_fingerprint"] = {"error": str(e)}

    # Test 3: Batching support
    batch_query = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]

    try:
        if verbose:
            click.echo("[+] Testing batch queries...")
        response = requests.post(
            url,
            json=batch_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        fingerprint_data["tests"]["batching"] = {
            "status_code": response.status_code,
            "supported": response.status_code == 200 and "[" in response.text,
        }
    except Exception as e:
        fingerprint_data["tests"]["batching"] = {"error": str(e)}

    return fingerprint_data


def run_gql_engine(domain, headers, proxy, endpoint=None, timeout=30, verbose=False):
    """Enhanced GQL engine with better error handling and features"""
    if endpoint:
        url = f"https://{domain}{endpoint}"
    else:
        url = f"https://{domain}/graphql"

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    transport_opts = {
        "url": url,
        "headers": header_dict,
        "use_json": True,
        "verify": False,
        "timeout": timeout,
    }

    if proxy:
        transport_opts["proxies"] = {"http": proxy, "https": proxy}

    try:
        transport = RequestsHTTPTransport(**transport_opts)
        client = Client(transport=transport, fetch_schema_from_transport=False)

        # Enhanced introspection query
        introspection_query = gql(
            """
        {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              description
              fields {
                name
                description
                type {
                  name
                  kind
                }
              }
            }
            directives {
              name
              description
              locations
            }
          }
        }
        """
        )

        if verbose:
            click.echo(f"[+] Executing introspection query on {url}")

        result = client.execute(introspection_query)

        # Extract additional information
        schema_data = result.get("__schema", {})
        types_count = len(schema_data.get("types", []))
        directives_count = len(schema_data.get("directives", []))

        return {
            "engine": "gql",
            "url": url,
            "introspection": True,
            "types_count": types_count,
            "directives_count": directives_count,
            "has_mutations": schema_data.get("mutationType") is not None,
            "has_subscriptions": schema_data.get("subscriptionType") is not None,
            "result": result,
        }
    except Exception as e:
        if verbose:
            click.echo(f"[!] GQL engine error: {str(e)}")
        return {"engine": "gql", "url": url, "introspection": False, "error": str(e)}


def run_graphqlcop(
    domain, headers, proxy, tor, endpoint=None, timeout=30, verbose=False
):
    """Enhanced GraphQL-Cop with additional options"""
    if endpoint:
        url = f"https://{domain}{endpoint}"
    else:
        url = f"https://{domain}"

    cmd = ["graphql-cop", "-t", url, "-o", "json"]

    for h in headers:
        cmd += ["-H", h]
    if proxy:
        cmd += ["-x", proxy]
    if tor:
        cmd += ["-T"]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.stdout.strip():
            return json.loads(result.stdout)
        else:
            return {
                "engine": "graphql-cop",
                "url": url,
                "error": "No output received",
                "stderr": result.stderr,
            }
    except json.JSONDecodeError:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": "Invalid JSON output",
            "raw_output": result.stdout,
        }
    except subprocess.TimeoutExpired:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": f"Timeout after {timeout} seconds",
        }
    except FileNotFoundError:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": "graphql-cop not found in PATH",
        }
    except Exception as e:
        return {"engine": "graphql-cop", "url": url, "error": str(e)}


def run_graphqlmap(
    domain, headers, proxy, endpoint=None, timeout=30, verbose=False, ssl_verify=True
):
    """Enhanced GraphQLMap with interactive mode simulation"""
    if endpoint:
        url = f"https://{domain}{endpoint}?query={{}}"
    else:
        url = f"https://{domain}/graphql?query={{}}"

    cmd = ["graphqlmap", "-u", url, "--json"]

    if proxy:
        cmd += ["--proxy", proxy]
    if headers:
        header_string = (
            "{"
            + ", ".join(
                f'"{h.split(":")[0].strip()}": "{h.split(":")[1].strip()}"'
                for h in headers
                if ":" in h
            )
            + "}"
        )
        cmd += ["--headers", header_string]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")

        # Since GraphQLMap is interactive, we'll simulate some common commands
        test_commands = ["dump_via_introspection", "dump_via_fragment", "debug"]

        results = {"engine": "graphqlmap", "url": url, "tests": {}}

        for command in test_commands:
            try:
                # Simulate GraphQLMap commands by sending requests manually
                if command == "dump_via_introspection":
                    result = test_graphqlmap_introspection(
                        url, headers, proxy, timeout, verbose, ssl_verify
                    )
                    results["tests"][command] = result
                elif command == "debug":
                    result = test_graphqlmap_debug(
                        url, headers, proxy, timeout, verbose, ssl_verify
                    )
                    results["tests"][command] = result
            except Exception as e:
                results["tests"][command] = {"error": str(e)}

        return results

    except Exception as e:
        return {"engine": "graphqlmap", "url": url, "error": str(e)}


def test_graphqlmap_introspection(
    url, headers, proxy, timeout, verbose, ssl_verify=True
):
    """Test GraphQL introspection manually"""
    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    introspection_query = "{__schema{types{name}}}"
    test_url = url.replace("{}", introspection_query)

    try:
        response = requests.get(
            test_url,
            headers=header_dict,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "introspection_works": "__schema" in response.text
            and "types" in response.text,
        }
    except Exception as e:
        return {"error": str(e)}


def test_graphqlmap_debug(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test GraphQL debug information"""
    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    debug_query = '{__type(name:"Query"){name}}'
    test_url = url.replace("{}", debug_query)

    try:
        response = requests.get(
            test_url,
            headers=header_dict,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "debug_info_available": "__type" in response.text,
        }
    except Exception as e:
        return {"error": str(e)}


def run_threat_matrix_assessment(
    url, headers, proxy, timeout, verbose, ssl_verify=True
):
    """Run GraphQL Threat Matrix assessment"""
    if verbose:
        click.echo("[+] Running GraphQL Threat Matrix assessment...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    threats = {
        "introspection_enabled": test_introspection_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "deep_recursion": test_deep_recursion_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "field_duplication": test_field_duplication_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "alias_overload": test_alias_overload_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "directive_overload": test_directive_overload_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
    }

    return {
        "assessment_type": "threat_matrix",
        "url": url,
        "threats": threats,
        "timestamp": datetime.utcnow().isoformat(),
    }


def test_introspection_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for introspection vulnerability"""
    query = {"query": "{ __schema { queryType { name } } }"}
    try:
        response = requests.post(
            url,
            json=query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "vulnerable": "queryType" in response.text and response.status_code == 200,
            "status_code": response.status_code,
            "response_size": len(response.text),
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_deep_recursion_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for deep recursion DoS"""
    deep_query = {"query": "{ " + "user { user { " * 50 + "id" + " } }" * 50 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=deep_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 5 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_field_duplication_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for field duplication DoS"""
    duplicate_query = {"query": "{ " + "__typename " * 1000 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=duplicate_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_alias_overload_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for alias overload DoS"""
    alias_query = {
        "query": "{ " + " ".join([f"alias{i}: __typename" for i in range(1000)]) + " }"
    }
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=alias_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_directive_overload_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for directive overload DoS"""
    directive_query = {"query": "{ __typename " + "@include(if: true) " * 1000 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=directive_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_batch_queries(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test GraphQL batching capabilities"""
    if verbose:
        click.echo("[+] Testing GraphQL batching...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Test various batch sizes
    batch_tests = {}

    for batch_size in [2, 5, 10, 50, 100]:
        batch_query = [{"query": "{ __typename }"} for _ in range(batch_size)]

        try:
            start_time = time.time()
            response = requests.post(
                url,
                json=batch_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )
            response_time = time.time() - start_time

            batch_tests[f"batch_{batch_size}"] = {
                "status_code": response.status_code,
                "response_time": response_time,
                "supported": response.status_code == 200 and "[" in response.text,
                "response_size": len(response.text),
            }
        except Exception as e:
            batch_tests[f"batch_{batch_size}"] = {"error": str(e)}

    return {"test_type": "batch_queries", "url": url, "results": batch_tests}


def test_sql_injection(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test for SQL injection vulnerabilities"""
    if verbose:
        click.echo("[+] Testing SQL injection...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT version() --",
        "' AND 1=1 --",
        "' AND 1=2 --",
    ]

    injection_tests = {}

    for i, payload in enumerate(sql_payloads):
        test_query = {"query": f'{{ user(id: "{payload}") {{ id name }} }}'}

        try:
            response = requests.post(
                url,
                json=test_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )

            # Look for SQL error indicators
            error_indicators = [
                "sql",
                "mysql",
                "postgresql",
                "sqlite",
                "syntax error",
                "database",
            ]
            sql_error_detected = any(
                indicator in response.text.lower() for indicator in error_indicators
            )

            injection_tests[f"payload_{i + 1}"] = {
                "payload": payload,
                "status_code": response.status_code,
                "sql_error_detected": sql_error_detected,
                "response_snippet": response.text[:200],
            }
        except Exception as e:
            injection_tests[f"payload_{i + 1}"] = {"payload": payload, "error": str(e)}

    return {"test_type": "sql_injection", "url": url, "results": injection_tests}


def test_nosql_injection(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test for NoSQL injection vulnerabilities"""
    if verbose:
        click.echo("[+] Testing NoSQL injection...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # NoSQL injection payloads
    nosql_payloads = [
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$where": "function() { return true; }"}',
        '{"$gt": ""}',
        '{"$exists": true}',
    ]

    injection_tests = {}

    for i, payload in enumerate(nosql_payloads):
        test_query = {"query": f'{{ user(filter: "{payload}") {{ id name }} }}'}

        try:
            response = requests.post(
                url,
                json=test_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )

            # Look for NoSQL error indicators
            error_indicators = [
                "mongodb",
                "nosql",
                "bson",
                "mongo",
                "regex",
                "$ne",
                "$gt",
            ]
            nosql_error_detected = any(
                indicator in response.text.lower() for indicator in error_indicators
            )

            injection_tests[f"payload_{i + 1}"] = {
                "payload": payload,
                "status_code": response.status_code,
                "nosql_error_detected": nosql_error_detected,
                "response_snippet": response.text[:200],
            }
        except Exception as e:
            injection_tests[f"payload_{i + 1}"] = {"payload": payload, "error": str(e)}

    return {"test_type": "nosql_injection", "url": url, "results": injection_tests}


def save_csv_results(results, csv_file):
    """Save results in CSV format"""
    import csv

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Engine", "Test Type", "URL", "Status", "Details"])

        for engine, data in results.items():
            if isinstance(data, dict):
                url = data.get("url", "N/A")
                if "error" in data:
                    writer.writerow([engine, "error", url, "failed", data["error"]])
                elif "tests" in data:
                    for test_name, test_result in data["tests"].items():
                        status = "passed" if not test_result.get("error") else "failed"
                        details = str(test_result)[:100]  # Truncate for CSV
                        writer.writerow([engine, test_name, url, status, details])
                else:
                    status = "passed" if data.get("introspection", False) else "failed"
                    writer.writerow([engine, "main", url, status, str(data)[:100]])


def generate_markdown_report(domain, engines, results, verbose):
    """Generate enhanced Markdown report"""
    lines = [
        f"# GraphQL Security Assessment Report for `{domain}`",
        f"- **Engines Used**: {', '.join(engines)}",
        f"- **Timestamp**: {datetime.utcnow().isoformat()}",
        f"- **Total Tests**: {len(results)}",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Count vulnerabilities
    vuln_count = 0
    total_tests = 0

    for engine, data in results.items():
        if isinstance(data, dict):
            if "threats" in data:
                for threat, result in data["threats"].items():
                    total_tests += 1
                    if result.get("vulnerable", False):
                        vuln_count += 1
            elif "tests" in data:
                total_tests += len(data["tests"])
            else:
                total_tests += 1
                if data.get("introspection", False):
                    vuln_count += 1

    lines.extend(
        [
            f"- **Total Vulnerabilities Found**: {vuln_count}",
            f"- **Total Tests Performed**: {total_tests}",
            f"- **Security Score**: {max(0, 100 - (vuln_count * 10))}%",
            "",
            "## Detailed Results",
            "",
        ]
    )

    for engine, data in results.items():
        if isinstance(data, dict):
            lines.append(f"### {engine.upper()}")
            if "introspection" in data:
                if data.get("introspection"):
                    lines.append("✅ **Introspection**: Enabled")
                    lines.append(f"- Types found: {data.get('types_count', 'N/A')}")
                    lines.append(
                        f"- Mutations: {'Yes' if data.get('has_mutations') else 'No'}"
                    )
                    lines.append(
                        f"- Subscriptions: {'Yes' if data.get('has_subscriptions') else 'No'}"
                    )
                else:
                    lines.append("❌ **Introspection**: Disabled or Failed")
            elif "threats" in data:
                lines.append("**Threat Matrix Results:**")
                for threat, result in data["threats"].items():
                    if result.get("vulnerable", False):
                        lines.append(f"- ⚠️  **{threat}**: Vulnerable")
                    else:
                        lines.append(f"- ✅ **{threat}**: Safe")
            elif "tests" in data:
                lines.append("**Test Results:**")
                for test_name, test_result in data["tests"].items():
                    if "error" in test_result:
                        lines.append(
                            f"- ❌ **{test_name}**: Error - {test_result['error']}"
                        )
                    else:
                        lines.append(f"- ✅ **{test_name}**: Completed")

        lines.append("")

    lines.extend(
        [
            "## Recommendations",
            "",
            "1. **Disable Introspection** in production environments",
            "2. **Implement Query Depth Limiting** to prevent DoS attacks",
            "3. **Use Query Complexity Analysis** to limit resource consumption",
            "4. **Implement Rate Limiting** on GraphQL endpoints",
            "5. **Validate and Sanitize** all input parameters",
            "6. **Use Query Whitelisting** for critical applications",
            "7. **Enable Query Logging** for security monitoring",
            "",
            "## Security Tools Used",
            "",
        ]
    )

    for engine in engines:
        if engine == "graphw00f":
            lines.append("- **GraphW00F**: GraphQL fingerprinting and engine detection")
        elif engine == "graphql-cop":
            lines.append(
                "- **GraphQL-Cop**: Security analysis and vulnerability detection"
            )
        elif engine == "graphqlmap":
            lines.append(
                "- **GraphQLMap**: Interactive GraphQL testing and exploitation"
            )
        elif engine == "gql":
            lines.append(
                "- **GQL**: Python GraphQL client for introspection and testing"
            )
        elif engine == "gql-cli":
            lines.append(
                "- **GQL-CLI**: Command-line GraphQL client with schema downloading"
            )

    lines.extend(
        [
            "",
            "---",
            f"*Report generated by GraphQLCLI on {datetime.utcnow().isoformat()}*",
        ]
    )

    return "\n".join(lines)


def run_gql_cli_operations(
    url,
    headers,
    proxy,
    print_schema,
    schema_path,
    gql_variables,
    gql_operation,
    interactive_gql,
    gql_transport,
    verbose,
):
    """Run gql-cli operations for schema download and interactive mode"""

    # Prepare gql-cli command
    cmd = ["gql-cli", url]

    # Add headers
    for h in headers:
        cmd += ["-H", h]

    # Add transport type
    if gql_transport != "auto":
        cmd += ["--transport", gql_transport]

    # Add proxy if specified
    if proxy:
        # gql-cli doesn't have direct proxy support, but we can use env vars
        import os

        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy

    # Add variables if specified
    if gql_variables:
        var_parts = gql_variables.split(",")
        for var_part in var_parts:
            if ":" in var_part:
                cmd += ["-V", var_part.strip()]

    # Add operation name if specified
    if gql_operation:
        cmd += ["-o", gql_operation]

    result = {"engine": "gql-cli", "url": url, "command": " ".join(cmd)}

    try:
        if print_schema:
            # Download schema
            schema_cmd = cmd + ["--print-schema"]
            if verbose:
                click.echo(
                    f"[+] Running gql-cli schema download: {' '.join(schema_cmd)}"
                )

            schema_result = subprocess.run(
                schema_cmd, capture_output=True, text=True, timeout=60
            )

            if schema_result.returncode == 0 and schema_result.stdout.strip():
                # Save schema to file
                schema_path.write_text(schema_result.stdout)
                result.update(
                    {
                        "schema_downloaded": True,
                        "schema_file": str(schema_path),
                        "schema_size": len(schema_result.stdout),
                    }
                )

                # Parse basic schema info
                schema_info = parse_graphql_schema_info(schema_result.stdout)
                result.update(schema_info)

            else:
                result.update(
                    {
                        "schema_downloaded": False,
                        "error": schema_result.stderr or "No schema output received",
                    }
                )

        if interactive_gql:
            # Run interactive mode
            if verbose:
                click.echo(f"[+] Starting gql-cli interactive mode: {' '.join(cmd)}")
            click.echo("[+] Starting gql-cli interactive mode...")
            click.echo("[+] Use Ctrl-D to send queries, 'exit' to quit")

            # Run in interactive mode (non-capturing)
            interactive_result = subprocess.run(cmd, timeout=300)  # 5 minute timeout
            result.update(
                {"interactive_mode": True, "exit_code": interactive_result.returncode}
            )

        return result

    except subprocess.TimeoutExpired:
        return {
            "engine": "gql-cli",
            "url": url,
            "error": "Command timeout expired",
            "timeout": True,
        }
    except FileNotFoundError:
        return {
            "engine": "gql-cli",
            "url": url,
            "error": "gql-cli not found in PATH. Install with: pip install gql[all]",
            "missing_tool": True,
        }
    except Exception as e:
        return {"engine": "gql-cli", "url": url, "error": str(e)}


def parse_graphql_schema_info(schema_text):
    """Parse basic information from GraphQL schema"""
    info = {
        "types_found": [],
        "queries_found": [],
        "mutations_found": [],
        "subscriptions_found": [],
        "total_types": 0,
        "total_queries": 0,
        "total_mutations": 0,
        "total_subscriptions": 0,
    }

    lines = schema_text.split("\n")
    current_type = None

    for line in lines:
        line = line.strip()

        # Find type definitions
        if (
            line.startswith("type ")
            and not line.startswith("type Query")
            and not line.startswith("type Mutation")
        ):
            type_name = line.split()[1].split("(")[0].split("{")[0]
            info["types_found"].append(type_name)

        # Find Query type
        elif line.startswith("type Query"):
            current_type = "query"
        elif line.startswith("type Mutation"):
            current_type = "mutation"
        elif line.startswith("type Subscription"):
            current_type = "subscription"
        elif line.startswith("}"):
            current_type = None
        elif current_type and ":" in line and not line.startswith("#"):
            # Extract field name
            field_name = line.split(":")[0].strip()
            if "(" in field_name:
                field_name = field_name.split("(")[0]

            if current_type == "query":
                info["queries_found"].append(field_name)
            elif current_type == "mutation":
                info["mutations_found"].append(field_name)
            elif current_type == "subscription":
                info["subscriptions_found"].append(field_name)

    # Add counts
    info["total_types"] = len(info["types_found"])
    info["total_queries"] = len(info["queries_found"])
    info["total_mutations"] = len(info["mutations_found"])
    info["total_subscriptions"] = len(info["subscriptions_found"])

    return info


if __name__ == "__main__":
    graphqlcli.main()
