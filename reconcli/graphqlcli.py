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
        [
            "graphw00f",
            "graphql-cop",
            "graphqlmap",
            "gql",
            "gql-cli",
            "param-fuzz",
            "all",
        ]
    ),
    help="Engine to use: graphw00f (default), graphql-cop, graphqlmap, gql, gql-cli, param-fuzz, or all",
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
@click.option("--param-fuzz", is_flag=True, help="Enable GraphQL parameter fuzzing")
@click.option(
    "--fuzzer",
    type=click.Choice(["native", "ffuf", "wfuzz", "auto"]),
    default="native",
    help="Fuzzing engine to use for parameter testing",
)
@click.option(
    "--fuzz-params",
    default="gql-params.txt",
    help="Parameter wordlist file for fuzzing",
)
@click.option(
    "--fuzz-payloads",
    default=None,
    help="Custom GraphQL payloads file (default: built-in payloads)",
)
@click.option(
    "--fuzz-methods",
    default="GET,POST",
    help="HTTP methods to test during fuzzing (comma-separated)",
)
@click.option(
    "--fuzz-threads",
    type=int,
    default=10,
    help="Number of threads for parameter fuzzing",
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
# ========== NEW: Advanced Security Testing Options ==========
@click.option(
    "--jwt-testing", is_flag=True, help="Enable JWT/API Key authentication testing"
)
@click.option(
    "--dos-testing", is_flag=True, help="Enable DoS/Performance testing suite"
)
@click.option(
    "--payload-library", is_flag=True, help="Use advanced payload library system"
)
@click.option(
    "--custom-payloads", help="Path to custom payload library file (JSON or text)"
)
@click.option(
    "--html-report",
    is_flag=True,
    help="Generate enhanced HTML report with risk scoring",
)
@click.option(
    "--risk-assessment", is_flag=True, help="Perform comprehensive risk assessment"
)
@click.option(
    "--compliance-check", is_flag=True, help="Check compliance with security standards"
)
@click.option(
    "--auth-bypass-test",
    is_flag=True,
    help="Test for authentication bypass vulnerabilities",
)
@click.option(
    "--role-bypass-test", is_flag=True, help="Test for role-based access control bypass"
)
@click.option(
    "--context-aware",
    is_flag=True,
    help="Generate context-aware payloads based on target",
)
@click.option("--save-payloads", help="Save payload library to specified file path")
@click.option("--load-payloads", help="Load payload library from specified file path")
@click.option(
    "--security-suite",
    is_flag=True,
    help="Enable complete GraphQL security testing suite (all features)",
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
    param_fuzz,
    fuzzer,
    fuzz_params,
    fuzz_payloads,
    fuzz_methods,
    fuzz_threads,
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
    # NEW: Advanced Security Testing Parameters
    jwt_testing,
    dos_testing,
    payload_library,
    custom_payloads,
    html_report,
    risk_assessment,
    compliance_check,
    auth_bypass_test,
    role_bypass_test,
    context_aware,
    save_payloads,
    load_payloads,
    security_suite,
):
    """GraphQL recon & audit module using multiple engines and advanced techniques"""

    # ========== Security Suite Mode ==========
    if security_suite:
        # Enable all advanced security features
        jwt_testing = True
        dos_testing = True
        payload_library = True
        html_report = True
        risk_assessment = True
        compliance_check = True
        auth_bypass_test = True
        role_bypass_test = True
        context_aware = True

        if verbose:
            print(
                "🔒 [SECURITY-SUITE] Complete GraphQL Security Testing Suite activated!"
            )
            print("    🔐 JWT/API Key Testing: ENABLED")
            print("    💥 DoS/Performance Testing: ENABLED")
            print("    📚 Advanced Payload Library: ENABLED")
            print("    📊 Enhanced HTML Reporting: ENABLED")
            print("    🛡️ Risk Assessment: ENABLED")
            print("    📋 Compliance Checking: ENABLED")

    # ========== Advanced Payload Library System ==========
    global_payload_library = None
    if payload_library or load_payloads or security_suite:
        if verbose:
            print("📚 [PAYLOAD-LIB] Initializing advanced payload library...")

        if load_payloads and Path(load_payloads).exists():
            try:
                with open(load_payloads, "r") as f:
                    if load_payloads.endswith(".json"):
                        global_payload_library = json.load(f)
                    else:
                        # Text file format
                        lines = [
                            line.strip()
                            for line in f
                            if line.strip() and not line.startswith("#")
                        ]
                        global_payload_library = {"custom_payloads": lines}

                if verbose:
                    print(
                        f"📚 [PAYLOAD-LIB] Loaded custom payload library from: {load_payloads}"
                    )
            except Exception as e:
                print(f"⚠️  [PAYLOAD-LIB] Could not load {load_payloads}: {e}")
                global_payload_library = initialize_payload_library()
        else:
            global_payload_library = initialize_payload_library()

        if verbose:
            if isinstance(global_payload_library, dict):
                total_payloads = global_payload_library.get("metadata", {}).get(
                    "total_payloads", 0
                )
                print(
                    f"📚 [PAYLOAD-LIB] Library initialized with {total_payloads} payloads"
                )
            else:
                print(f"📚 [PAYLOAD-LIB] Library initialized with custom payloads")

        # Save payload library if requested
        if save_payloads:
            if save_payload_library(global_payload_library, save_payloads):
                if verbose:
                    print(f"📚 [PAYLOAD-LIB] Library saved to: {save_payloads}")

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
            if param_fuzz:
                engines.append("param-fuzz")
        else:
            engines = [engine]
            if param_fuzz and engine != "param-fuzz":
                engines.append("param-fuzz")

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
            elif eng == "param-fuzz":
                result = run_param_fuzz_engine(
                    target_url,
                    fuzzer,
                    fuzz_params,
                    fuzz_payloads,
                    fuzz_methods,
                    header,
                    proxy,
                    fuzz_threads,
                    timeout,
                    verbose,
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

        # ========== NEW: Advanced Security Tests ==========

        # JWT/API Key Testing
        if jwt_testing or auth_bypass_test or role_bypass_test or security_suite:
            if verbose:
                print("🔐 [SECURITY] Running JWT/API Key authentication tests...")
            results["jwt_auth_testing"] = run_jwt_testing_engine(
                target_url, header, proxy, timeout, verbose
            )

        # DoS/Performance Testing
        if dos_testing or security_suite:
            if verbose:
                print("💥 [SECURITY] Running DoS/Performance testing suite...")
            results["dos_performance_testing"] = run_dos_performance_suite(
                target_url, header, proxy, timeout, verbose
            )

        # Context-Aware Payload Generation
        if context_aware or security_suite:
            if verbose:
                print("🎯 [SECURITY] Generating context-aware payloads...")

            # Generate context payloads based on target URL
            context_payloads = generate_context_payloads(target_url, verbose)
            if context_payloads:
                results["context_payloads"] = {
                    "engine": "context-aware-payloads",
                    "target": target_url,
                    "payloads_generated": len(context_payloads),
                    "payloads": context_payloads[:10],  # Store first 10 for reporting
                }

        # AI Analysis if requested (enhanced for new features)
        if ai and results:
            if verbose:
                print(f"🧠 [AI] Running enhanced AI analysis with {ai_provider}...")

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

        # ========== NEW: Enhanced HTML Report Generation ==========
        if html_report or risk_assessment or compliance_check or security_suite:
            html_output = output_path / f"graphql_security_report_{target_domain}.html"

            if verbose:
                print("📊 [HTML-REPORT] Generating enhanced HTML security report...")

            if generate_enhanced_html_report(target_url, results, html_output, verbose):
                if verbose:
                    print(f"📊 [HTML-REPORT] Enhanced HTML report saved: {html_output}")

            # Generate risk assessment summary
            if risk_assessment or security_suite:
                risk_data = calculate_risk_score(results)
                if verbose:
                    print(
                        f"🎯 [RISK] Security Score: {risk_data['score']}/100 ({risk_data['level']})"
                    )
                    print(
                        f"🎯 [RISK] Vulnerabilities: {risk_data['vulnerabilities_found']}"
                    )
                    print(f"🎯 [RISK] Critical Issues: {risk_data['critical_issues']}")

                # Save risk assessment data
                risk_file = output_path / f"risk_assessment_{target_domain}.json"
                risk_file.write_text(json.dumps(risk_data, indent=2))

            # Generate compliance report
            if compliance_check or security_suite:
                compliance_data = generate_compliance_mapping(results)
                if verbose:
                    print(
                        f"📋 [COMPLIANCE] Overall Compliance: {compliance_data['overall_compliance']}%"
                    )
                    print(
                        f"📋 [COMPLIANCE] Checks Passed: {compliance_data['passed_checks']}/{compliance_data['total_checks']}"
                    )

                # Save compliance data
                compliance_file = (
                    output_path / f"compliance_report_{target_domain}.json"
                )
                compliance_file.write_text(json.dumps(compliance_data, indent=2))

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
            try:
                import openai

                client = openai.OpenAI()
            except ImportError:
                return {
                    "error": "OpenAI library not installed. Install with: pip install openai"
                }
        elif ai_provider == "anthropic":
            try:
                import anthropic

                client = anthropic.Anthropic()
            except ImportError:
                return {
                    "error": "Anthropic library not installed. Install with: pip install anthropic"
                }
        elif ai_provider == "gemini":
            try:
                import google.generativeai as genai

                client = genai
            except ImportError:
                return {
                    "error": "Google Generative AI library not installed. Install with: pip install google-generativeai"
                }
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


def dump_schema_json(target_url, headers, proxy, verbose, ssl_verify=ssl_verify):
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
    ssl_verify=ssl_verify,
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
    domain, headers, proxy, fingerprint, detect_engines, verbose, ssl_verify=ssl_verify
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


def manual_graphql_fingerprinting(domain, headers, proxy, verbose, ssl_verify=ssl_verify):
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
    domain, headers, proxy, endpoint=None, timeout=30, verbose=False, ssl_verify=ssl_verify
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
    url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify
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


def test_graphqlmap_debug(url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify):
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
    url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify
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


def test_introspection_threat(url, headers, proxies, timeout, ssl_verify=ssl_verify):
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


def test_deep_recursion_threat(url, headers, proxies, timeout, ssl_verify=ssl_verify):
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


def test_field_duplication_threat(url, headers, proxies, timeout, ssl_verify=ssl_verify):
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


def test_alias_overload_threat(url, headers, proxies, timeout, ssl_verify=ssl_verify):
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


def test_directive_overload_threat(url, headers, proxies, timeout, ssl_verify=ssl_verify):
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


def test_batch_queries(url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify):
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


def test_sql_injection(url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify):
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


def test_nosql_injection(url, headers, proxy, timeout, verbose, ssl_verify=ssl_verify):
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


# ========== JWT/API Key Testing Engine ==========


def run_jwt_testing_engine(target_url, headers, proxy, timeout, verbose):
    """Advanced JWT/API Key Testing Engine"""
    if verbose:
        print("🔐 [JWT-AUTH] Starting JWT/API Key Testing Engine...")

    results = {
        "engine": "jwt-auth-testing",
        "target": target_url,
        "timestamp": datetime.utcnow().isoformat(),
        "jwt_tests": {},
        "api_key_tests": {},
        "auth_bypass_tests": {},
        "role_tests": {},
    }

    # JWT Token Tests
    jwt_payloads = [
        {"alg": "none"},  # None algorithm attack
        {"alg": "HS256", "typ": "JWT"},  # Standard JWT
        {"alg": "RS256", "typ": "JWT"},  # RSA signature
        {"alg": "HS256", "typ": "JWT", "kid": "../../../etc/passwd"},  # Path traversal
    ]

    # Test JWT manipulation
    for i, payload in enumerate(jwt_payloads):
        test_name = f"jwt_test_{i+1}"
        try:
            # Create test JWT
            import base64
            import json

            # Create header and payload
            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            test_payload = {"sub": "test", "iat": 1234567890, "exp": 9999999999}
            payload_b64 = (
                base64.urlsafe_b64encode(json.dumps(test_payload).encode())
                .decode()
                .rstrip("=")
            )

            # Test without signature (none alg)
            if payload.get("alg") == "none":
                test_jwt = f"{header_b64}.{payload_b64}."
            else:
                test_jwt = f"{header_b64}.{payload_b64}.fake_signature"

            # Test with GraphQL
            graphql_query = {
                "query": "{ __schema { queryType { name } } }",
                "variables": {},
            }

            test_headers = dict(headers) if isinstance(headers, dict) else {}
            test_headers["Authorization"] = f"Bearer {test_jwt}"

            response = requests.post(
                target_url,
                json=graphql_query,
                headers=test_headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            results["jwt_tests"][test_name] = {
                "jwt_type": payload.get("alg", "unknown"),
                "status_code": response.status_code,
                "response_size": len(response.text),
                "auth_bypassed": response.status_code == 200
                and "__schema" in response.text,
                "test_jwt": test_jwt[:50] + "...",
            }

            if verbose and results["jwt_tests"][test_name]["auth_bypassed"]:
                print(
                    f"⚠️  [JWT-AUTH] Potential bypass with {payload.get('alg')} algorithm"
                )

        except Exception as e:
            results["jwt_tests"][test_name] = {"error": str(e)}

    # API Key Testing
    api_key_locations = [
        {"location": "header", "name": "X-API-Key"},
        {"location": "header", "name": "API-Key"},
        {"location": "header", "name": "Authorization"},
        {"location": "query", "name": "api_key"},
        {"location": "query", "name": "key"},
        {"location": "query", "name": "token"},
    ]

    test_api_keys = [
        "test_key_123",
        "admin",
        "guest",
        "development",
        "null",
        "",
        "12345",
        "test",
    ]

    for location_info in api_key_locations:
        for api_key in test_api_keys:
            test_name = f"api_{location_info['location']}_{location_info['name']}_{api_key[:10]}"

            try:
                graphql_query = {"query": "{ __schema { queryType { name } } }"}

                if location_info["location"] == "header":
                    test_headers = dict(headers) if isinstance(headers, dict) else {}
                    test_headers[location_info["name"]] = api_key
                    test_url = target_url
                else:  # query parameter
                    test_headers = dict(headers) if isinstance(headers, dict) else {}
                    test_url = f"{target_url}?{location_info['name']}={api_key}"

                response = requests.post(
                    test_url,
                    json=graphql_query,
                    headers=test_headers,
                    proxies={"http": proxy, "https": proxy} if proxy else None,
                    timeout=timeout,
                    verify=ssl_verify,
                )

                results["api_key_tests"][test_name] = {
                    "location": location_info["location"],
                    "header_name": location_info["name"],
                    "api_key": api_key,
                    "status_code": response.status_code,
                    "response_size": len(response.text),
                    "auth_bypassed": response.status_code == 200
                    and "__schema" in response.text,
                }

                if verbose and results["api_key_tests"][test_name]["auth_bypassed"]:
                    print(
                        f"⚠️  [API-KEY] Potential bypass with {location_info['name']}={api_key}"
                    )

            except Exception as e:
                results["api_key_tests"][test_name] = {"error": str(e)}

    # Role-Based Access Control Tests
    role_tests = [
        {"role": "admin", "user": "admin"},
        {"role": "guest", "user": "guest"},
        {"role": "user", "user": "test"},
        {"role": "dev", "user": "developer"},
        {"role": "null", "user": "null"},
    ]

    for role_test in role_tests:
        test_name = f"role_{role_test['role']}"

        try:
            # Create role-based payload
            role_payload = {
                "sub": role_test["user"],
                "role": role_test["role"],
                "permissions": (
                    ["read", "write"] if role_test["role"] == "admin" else ["read"]
                ),
                "iat": 1234567890,
                "exp": 9999999999,
            }

            # Simple base64 encoding (for testing purposes)
            import base64
            import json

            header_b64 = (
                base64.urlsafe_b64encode(
                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                )
                .decode()
                .rstrip("=")
            )
            payload_b64 = (
                base64.urlsafe_b64encode(json.dumps(role_payload).encode())
                .decode()
                .rstrip("=")
            )
            test_jwt = f"{header_b64}.{payload_b64}.fake_signature"

            graphql_query = {"query": "{ __schema { queryType { name } } }"}

            test_headers = dict(headers) if isinstance(headers, dict) else {}
            test_headers["Authorization"] = f"Bearer {test_jwt}"

            response = requests.post(
                target_url,
                json=graphql_query,
                headers=test_headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            results["role_tests"][test_name] = {
                "role": role_test["role"],
                "user": role_test["user"],
                "status_code": response.status_code,
                "response_size": len(response.text),
                "auth_bypassed": response.status_code == 200
                and "__schema" in response.text,
                "test_jwt": test_jwt[:50] + "...",
            }

            if verbose and results["role_tests"][test_name]["auth_bypassed"]:
                print(f"⚠️  [ROLE] Potential role bypass with {role_test['role']} role")

        except Exception as e:
            results["role_tests"][test_name] = {"error": str(e)}

    if verbose:
        total_jwt_tests = len(results["jwt_tests"])
        total_api_tests = len(results["api_key_tests"])
        total_role_tests = len(results["role_tests"])
        print(
            f"🔐 [JWT-AUTH] Completed: {total_jwt_tests} JWT + {total_api_tests} API key + {total_role_tests} role tests"
        )

    return results


# ========== DoS/Performance Testing Suite ==========


def run_dos_performance_suite(target_url, headers, proxy, timeout, verbose):
    """Advanced DoS/Performance Testing Suite"""
    if verbose:
        print("💥 [DOS-PERF] Starting DoS/Performance Testing Suite...")

    results = {
        "engine": "dos-performance-testing",
        "target": target_url,
        "timestamp": datetime.utcnow().isoformat(),
        "query_depth_tests": {},
        "alias_bomb_tests": {},
        "fragment_abuse_tests": {},
        "complexity_tests": {},
        "recursive_tests": {},
    }

    # Query Depth Bomb Tests
    depth_levels = [5, 10, 20, 50, 100]

    for depth in depth_levels:
        test_name = f"depth_bomb_{depth}"

        try:
            # Create deep recursive query
            deep_query = "{ " + "user { " * depth + "id" + " }" * depth + " }"

            import time

            start_time = time.time()

            response = requests.post(
                target_url,
                json={"query": deep_query},
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            response_time = time.time() - start_time

            results["query_depth_tests"][test_name] = {
                "depth_level": depth,
                "query_size": len(deep_query),
                "response_time": round(response_time, 3),
                "status_code": response.status_code,
                "response_size": len(response.text),
                "potential_dos": response_time > 5.0 or response.status_code >= 500,
                "error_indicators": (
                    ["timeout", "error", "limit"]
                    if any(
                        word in response.text.lower()
                        for word in ["timeout", "error", "limit"]
                    )
                    else []
                ),
            }

            if verbose:
                status = (
                    "⚠️  VULNERABLE"
                    if results["query_depth_tests"][test_name]["potential_dos"]
                    else "✅ Safe"
                )
                print(f"💥 [DOS-PERF] Depth {depth}: {status} ({response_time:.2f}s)")

        except requests.exceptions.Timeout:
            results["query_depth_tests"][test_name] = {
                "depth_level": depth,
                "response_time": timeout,
                "status_code": "TIMEOUT",
                "potential_dos": True,
                "timeout": True,
            }
            if verbose:
                print(f"💥 [DOS-PERF] Depth {depth}: ⚠️  TIMEOUT (potential DoS)")
        except Exception as e:
            results["query_depth_tests"][test_name] = {
                "depth_level": depth,
                "error": str(e),
            }

    # Alias Bomb Tests
    alias_counts = [10, 50, 100, 500, 1000]

    for count in alias_counts:
        test_name = f"alias_bomb_{count}"

        try:
            # Create alias bomb query
            aliases = [f"alias{i}: __typename" for i in range(count)]
            alias_query = "{ " + " ".join(aliases) + " }"

            start_time = time.time()

            response = requests.post(
                target_url,
                json={"query": alias_query},
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            response_time = time.time() - start_time

            results["alias_bomb_tests"][test_name] = {
                "alias_count": count,
                "query_size": len(alias_query),
                "response_time": round(response_time, 3),
                "status_code": response.status_code,
                "response_size": len(response.text),
                "potential_dos": response_time > 3.0 or response.status_code >= 500,
            }

            if verbose:
                status = (
                    "⚠️  VULNERABLE"
                    if results["alias_bomb_tests"][test_name]["potential_dos"]
                    else "✅ Safe"
                )
                print(f"💥 [DOS-PERF] Alias {count}: {status} ({response_time:.2f}s)")

        except requests.exceptions.Timeout:
            results["alias_bomb_tests"][test_name] = {
                "alias_count": count,
                "response_time": timeout,
                "status_code": "TIMEOUT",
                "potential_dos": True,
                "timeout": True,
            }
        except Exception as e:
            results["alias_bomb_tests"][test_name] = {
                "alias_count": count,
                "error": str(e),
            }

    # Fragment Abuse Tests
    fragment_counts = [5, 10, 20, 50]

    for count in fragment_counts:
        test_name = f"fragment_abuse_{count}"

        try:
            # Create fragment abuse query
            fragments = []
            for i in range(count):
                fragments.append(f"fragment frag{i} on Query {{ __typename }}")

            fragment_query = (
                " ".join(fragments)
                + " query { "
                + " ".join([f"...frag{i}" for i in range(count)])
                + " }"
            )

            start_time = time.time()

            response = requests.post(
                target_url,
                json={"query": fragment_query},
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            response_time = time.time() - start_time

            results["fragment_abuse_tests"][test_name] = {
                "fragment_count": count,
                "query_size": len(fragment_query),
                "response_time": round(response_time, 3),
                "status_code": response.status_code,
                "response_size": len(response.text),
                "potential_dos": response_time > 4.0 or response.status_code >= 500,
            }

            if verbose:
                status = (
                    "⚠️  VULNERABLE"
                    if results["fragment_abuse_tests"][test_name]["potential_dos"]
                    else "✅ Safe"
                )
                print(
                    f"💥 [DOS-PERF] Fragment {count}: {status} ({response_time:.2f}s)"
                )

        except requests.exceptions.Timeout:
            results["fragment_abuse_tests"][test_name] = {
                "fragment_count": count,
                "response_time": timeout,
                "status_code": "TIMEOUT",
                "potential_dos": True,
                "timeout": True,
            }
        except Exception as e:
            results["fragment_abuse_tests"][test_name] = {
                "fragment_count": count,
                "error": str(e),
            }

    # Complexity Analysis Tests
    complexity_queries = [
        {"name": "simple", "query": "{ __typename }", "expected_complexity": 1},
        {
            "name": "moderate",
            "query": "{ __schema { types { name fields { name } } } }",
            "expected_complexity": 10,
        },
        {
            "name": "complex",
            "query": "{ __schema { types { name fields { name type { name ofType { name } } } } } }",
            "expected_complexity": 50,
        },
        {
            "name": "very_complex",
            "query": "{ __schema { types { name fields { name type { name ofType { name ofType { name } } } args { name type { name } } } } } }",
            "expected_complexity": 100,
        },
    ]

    for query_info in complexity_queries:
        test_name = f"complexity_{query_info['name']}"

        try:
            start_time = time.time()

            response = requests.post(
                target_url,
                json={"query": query_info["query"]},
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=timeout,
                verify=ssl_verify,
            )

            response_time = time.time() - start_time

            # Calculate complexity score based on query structure
            complexity_score = (
                query_info["query"].count("{") * 2
                + query_info["query"].count("type") * 3
                + query_info["query"].count("ofType") * 5
                + len(query_info["query"].split()) * 0.1
            )

            results["complexity_tests"][test_name] = {
                "complexity_name": query_info["name"],
                "calculated_complexity": round(complexity_score, 2),
                "expected_complexity": query_info["expected_complexity"],
                "query_size": len(query_info["query"]),
                "response_time": round(response_time, 3),
                "status_code": response.status_code,
                "response_size": len(response.text),
                "performance_ratio": (
                    round(response_time / (complexity_score / 10), 3)
                    if complexity_score > 0
                    else 0
                ),
            }

            if verbose:
                print(
                    f"💥 [DOS-PERF] Complexity {query_info['name']}: {complexity_score:.1f} score, {response_time:.2f}s"
                )

        except Exception as e:
            results["complexity_tests"][test_name] = {
                "complexity_name": query_info["name"],
                "error": str(e),
            }

    if verbose:
        total_depth_tests = len(results["query_depth_tests"])
        total_alias_tests = len(results["alias_bomb_tests"])
        total_fragment_tests = len(results["fragment_abuse_tests"])
        total_complexity_tests = len(results["complexity_tests"])
        print(
            f"💥 [DOS-PERF] Completed: {total_depth_tests} depth + {total_alias_tests} alias + {total_fragment_tests} fragment + {total_complexity_tests} complexity tests"
        )

    return results


# ========== Advanced Payload Library System ==========


def initialize_payload_library():
    """Initialize comprehensive GraphQL payload library"""
    payload_library = {
        "metadata": {
            "version": "1.0.0",
            "created": datetime.utcnow().isoformat(),
            "total_payloads": 0,
            "categories": [],
        },
        "introspection": {
            "basic": [
                "{ __schema { queryType { name } } }",
                "{ __schema { mutationType { name } } }",
                "{ __schema { subscriptionType { name } } }",
                "{ __typename }",
            ],
            "detailed": [
                "{ __schema { types { name kind description } } }",
                "{ __schema { types { name fields { name type { name } } } } }",
                "{ __schema { queryType { fields { name description args { name type { name } } } } } }",
                "{ __schema { mutationType { fields { name description args { name type { name } } } } } }",
            ],
            "full": [
                """query IntrospectionQuery {
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
                    args { ...InputValue }
                    type { ...TypeRef }
                    isDeprecated
                    deprecationReason
                  }
                  inputFields { ...InputValue }
                  interfaces { ...TypeRef }
                  enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                  }
                  possibleTypes { ...TypeRef }
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
                      }
                    }
                  }
                }"""
            ],
        },
        "injection": {
            "sql": [
                "{ user(id: \"1' OR '1'='1\") { id name } }",
                '{ user(id: "\'; DROP TABLE users; --") { id name } }',
                '{ user(id: "\' UNION SELECT version() --") { id name } }',
                '{ user(id: "1\' AND 1=1 --") { id name } }',
                '{ user(id: "1\' AND 1=2 --") { id name } }',
            ],
            "nosql": [
                '{ user(filter: "{\\"$ne\\": \\"\\"}") { id name } }',
                '{ user(filter: "{\\"$regex\\": \\".*\\"}") { id name } }',
                '{ user(filter: "{\\"$where\\": \\"function() { return true; }\\"}") { id name } }',
                '{ user(filter: "{\\"$gt\\": \\"\\"}") { id name } }',
            ],
            "ldap": [
                '{ user(id: "admin)(&") { id name } }',
                '{ user(id: "admin)(|(objectClass=*))") { id name } }',
                '{ user(id: "*)(uid=*))(|(uid=*") { id name } }',
            ],
        },
        "dos_attacks": {
            "depth_bombs": [
                "{ " + "user { " * 10 + "id" + " }" * 10 + " }",
                "{ " + "user { " * 20 + "id" + " }" * 20 + " }",
                "{ " + "user { " * 50 + "id" + " }" * 50 + " }",
            ],
            "alias_bombs": [
                "{ " + " ".join([f"alias{i}: __typename" for i in range(100)]) + " }",
                "{ " + " ".join([f"alias{i}: __typename" for i in range(500)]) + " }",
                "{ " + " ".join([f"alias{i}: __typename" for i in range(1000)]) + " }",
            ],
            "directive_abuse": [
                "{ __typename " + "@include(if: true) " * 100 + " }",
                "{ __typename " + "@skip(if: false) " * 100 + " }",
                "{ __typename " + '@deprecated(reason: "test") ' * 100 + " }",
            ],
        },
        "bypass_techniques": {
            "field_suggestions": [
                "{ __schema { types { name fieldsssss } } }",  # Typo to trigger suggestions
                "{ __schema { types { name field } } }",
                "{ user { ide } }",  # Typo for 'id'
                "{ user { namee } }",  # Typo for 'name'
            ],
            "unicode": [
                "{ \\u005f\\u005fschema { types { name } } }",  # Unicode __schema
                "{ \\u005f\\u005ftypename }",  # Unicode __typename
                "{ user\\u0028id: \\u00221\\u0022\\u0029 { id } }",  # Unicode function call
            ],
            "encoding": [
                "{ __\\u0073chema { types { name } } }",  # Partial unicode
                "{ _\\u005fschema { types { name } } }",  # Mixed encoding
                '{ user(id: "\\x31") { id } }',  # Hex encoding
            ],
        },
        "mutation_attacks": [
            'mutation { createUser(input: {name: "test", email: "test@test.com"}) { id } }',
            'mutation { updateUser(id: "1", input: {name: "admin"}) { id name } }',
            'mutation { deleteUser(id: "1") { success } }',
            'mutation { bulkUpdate(filter: {}, input: {role: "admin"}) { count } }',
        ],
        "subscription_attacks": [
            "subscription { userUpdated { id name } }",
            'subscription { messageAdded(channel: "*") { content } }',
            "subscription { allChanges { __typename } }",
        ],
        "error_disclosure": [
            "{ nonExistentField }",
            "{ user(id: 999999) { id } }",
            '{ user(invalidParam: "test") { id } }',
            "query InvalidQuery { user { nonExistentField } }",
        ],
    }

    # Calculate total payloads
    total_payloads = 0
    categories = []

    for category, subcategories in payload_library.items():
        if category != "metadata":
            categories.append(category)
            if isinstance(subcategories, dict):
                for subcat, payloads in subcategories.items():
                    if isinstance(payloads, list):
                        total_payloads += len(payloads)
            elif isinstance(subcategories, list):
                total_payloads += len(subcategories)

    payload_library["metadata"]["total_payloads"] = total_payloads
    payload_library["metadata"]["categories"] = categories

    return payload_library


def save_payload_library(library, output_path):
    """Save payload library to JSON file"""
    try:
        with open(output_path, "w") as f:
            json.dump(library, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ [PAYLOAD-LIB] Failed to save library: {e}")
        return False


def load_custom_payloads(custom_file):
    """Load custom payloads from external file"""
    try:
        if Path(custom_file).exists():
            with open(custom_file, "r") as f:
                if custom_file.endswith(".json"):
                    return json.load(f)
                else:
                    # Treat as text file with one payload per line
                    return [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
        return []
    except Exception as e:
        print(f"⚠️  [PAYLOAD-LIB] Could not load custom payloads: {e}")
        return []


def generate_context_payloads(target_info, verbose=False):
    """Generate context-aware payloads based on target analysis"""
    context_payloads = []

    # Analyze target for context clues
    if "user" in target_info.lower():
        context_payloads.extend(
            [
                "{ users { id name email role } }",
                '{ user(id: "1") { id name email password } }',
                "{ me { id name email permissions } }",
            ]
        )

    if "admin" in target_info.lower():
        context_payloads.extend(
            [
                "{ admin { id permissions } }",
                "{ adminUsers { id name role } }",
                "{ systemInfo { version database } }",
            ]
        )

    if "product" in target_info.lower() or "shop" in target_info.lower():
        context_payloads.extend(
            [
                "{ products { id name price } }",
                "{ orders { id total items { name price } } }",
                "{ cart { items { product { name price } } } }",
            ]
        )

    if "message" in target_info.lower() or "chat" in target_info.lower():
        context_payloads.extend(
            [
                "{ messages { id content author { name } } }",
                "{ conversations { id participants { name } } }",
                "{ channels { id name members { name role } } }",
            ]
        )

    if verbose and context_payloads:
        print(
            f"📚 [PAYLOAD-LIB] Generated {len(context_payloads)} context-aware payloads"
        )

    return context_payloads


# ========== Enhanced HTML Reporting ==========


def generate_enhanced_html_report(target_url, all_results, output_path, verbose=False):
    """Generate comprehensive HTML report with risk scoring and compliance mapping"""
    if verbose:
        print("📊 [HTML-REPORT] Generating enhanced HTML report...")

    # Calculate overall risk score
    risk_assessment = calculate_risk_score(all_results)

    # Generate compliance mapping
    compliance_data = generate_compliance_mapping(all_results)

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL Security Assessment Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }}
        .risk-score {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .risk-critical {{ color: #dc3545; }}
        .risk-high {{ color: #fd7e14; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #667eea; }}
        .card h3 {{ margin-top: 0; color: #333; }}
        .metric {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .vulnerability {{ background: #fff5f5; border: 1px solid #fed7d7; border-radius: 6px; padding: 15px; margin: 10px 0; }}
        .vuln-critical {{ border-left: 4px solid #dc3545; }}
        .vuln-high {{ border-left: 4px solid #fd7e14; }}
        .vuln-medium {{ border-left: 4px solid #ffc107; }}
        .vuln-low {{ border-left: 4px solid #28a745; }}
        .compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }}
        .compliance-item {{ padding: 15px; border-radius: 6px; text-align: center; }}
        .compliance-pass {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
        .compliance-fail {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
        .compliance-partial {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
        .section {{ margin: 30px 0; }}
        .table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .table th {{ background-color: #f8f9fa; font-weight: 600; }}
        .recommendation {{ background: #e7f3ff; border: 1px solid #b3d9ff; border-radius: 6px; padding: 15px; margin: 10px 0; }}
        .recommendation h4 {{ margin-top: 0; color: #0056b3; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 6px; color: #666; }}
        .progress-bar {{ width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #28a745 0%, #ffc107 50%, #dc3545 100%); transition: width 0.3s ease; }}
        .nav {{ background: #343a40; padding: 15px 0; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        .nav ul {{ list-style: none; margin: 0; padding: 0; display: flex; justify-content: center; }}
        .nav li {{ margin: 0 15px; }}
        .nav a {{ color: white; text-decoration: none; padding: 8px 16px; border-radius: 4px; transition: background 0.3s; }}
        .nav a:hover {{ background: #495057; }}
        .chart {{ margin: 20px 0; text-align: center; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 GraphQL Security Assessment</h1>
            <h2>{target_url}</h2>
            <div class="risk-score risk-{risk_assessment['level'].lower()}">{risk_assessment['score']}/100</div>
            <p>Risk Level: {risk_assessment['level']} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </div>
        
        <nav class="nav">
            <ul>
                <li><a href="#dashboard">Dashboard</a></li>
                <li><a href="#vulnerabilities">Vulnerabilities</a></li>
                <li><a href="#compliance">Compliance</a></li>
                <li><a href="#recommendations">Recommendations</a></li>
                <li><a href="#technical-details">Technical Details</a></li>
            </ul>
        </nav>
        
        <section id="dashboard" class="section">
            <h2>📊 Executive Dashboard</h2>
            <div class="dashboard">
                <div class="card">
                    <h3>🎯 Security Score</h3>
                    <div class="metric">{risk_assessment['score']}/100</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {risk_assessment['score']}%;"></div>
                    </div>
                </div>
                <div class="card">
                    <h3>🔍 Tests Performed</h3>
                    <div class="metric">{risk_assessment['total_tests']}</div>
                    <p>Comprehensive security analysis</p>
                </div>
                <div class="card">
                    <h3>⚠️ Vulnerabilities</h3>
                    <div class="metric risk-{risk_assessment['level'].lower()}">{risk_assessment['vulnerabilities_found']}</div>
                    <p>Critical issues identified</p>
                </div>
                <div class="card">
                    <h3>📋 Compliance</h3>
                    <div class="metric">{compliance_data['overall_compliance']}%</div>
                    <p>Security standards alignment</p>
                </div>
            </div>
        </section>
        
        <section id="vulnerabilities" class="section">
            <h2>🚨 Vulnerability Assessment</h2>
            {generate_vulnerability_section(all_results)}
        </section>
        
        <section id="compliance" class="section">
            <h2>📋 Compliance Mapping</h2>
            <div class="compliance-grid">
                {generate_compliance_cards(compliance_data)}
            </div>
        </section>
        
        <section id="recommendations" class="section">
            <h2>💡 Security Recommendations</h2>
            {generate_recommendations_section(risk_assessment, all_results)}
        </section>
        
        <section id="technical-details" class="section">
            <h2>🔧 Technical Analysis Details</h2>
            {generate_technical_details(all_results)}
        </section>
        
        <div class="footer">
            <p>Generated by GraphQLCLI Security Testing Suite | <strong>ReconCLI Framework</strong></p>
            <p>Report generated on {datetime.utcnow().strftime('%Y-%m-%d at %H:%M:%S')} UTC</p>
        </div>
    </div>
    
    <script>
        // Add interactive charts and visualizations
        // Risk distribution chart, vulnerability timeline, etc.
        console.log('GraphQL Security Report loaded');
        
        // Smooth scrolling for navigation
        document.querySelectorAll('nav a').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({{
                    behavior: 'smooth'
                }});
            }});
        }});
    </script>
</body>
</html>
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        if verbose:
            print(f"📊 [HTML-REPORT] Enhanced report saved to: {output_path}")

        return True
    except Exception as e:
        print(f"❌ [HTML-REPORT] Failed to generate report: {e}")
        return False


def calculate_risk_score(results):
    """Calculate comprehensive risk score with CVSS-like methodology"""
    risk_data = {
        "score": 100,  # Start with perfect score, deduct for issues
        "level": "LOW",
        "total_tests": 0,
        "vulnerabilities_found": 0,
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "low_issues": 0,
    }

    vulnerability_weights = {
        "introspection_enabled": -15,  # High risk
        "dos_vulnerable": -20,  # Critical risk
        "injection_vulnerable": -25,  # Critical risk
        "auth_bypass": -30,  # Critical risk
        "role_bypass": -20,  # High risk
        "error_disclosure": -10,  # Medium risk
    }

    for engine, data in results.items():
        if isinstance(data, dict):
            risk_data["total_tests"] += 1

            # Check for introspection
            if data.get("introspection", False):
                risk_data["score"] += vulnerability_weights["introspection_enabled"]
                risk_data["vulnerabilities_found"] += 1
                risk_data["high_issues"] += 1

            # Check DoS vulnerabilities
            if "dos-performance-testing" in engine:
                for test_category, tests in data.items():
                    if isinstance(tests, dict):
                        for test_name, test_result in tests.items():
                            if isinstance(test_result, dict) and test_result.get(
                                "potential_dos", False
                            ):
                                risk_data["score"] += vulnerability_weights[
                                    "dos_vulnerable"
                                ]
                                risk_data["vulnerabilities_found"] += 1
                                risk_data["critical_issues"] += 1

            # Check auth bypasses
            if "jwt-auth-testing" in engine:
                for test_category, tests in data.items():
                    if isinstance(tests, dict):
                        for test_name, test_result in tests.items():
                            if isinstance(test_result, dict) and test_result.get(
                                "auth_bypassed", False
                            ):
                                risk_data["score"] += vulnerability_weights[
                                    "auth_bypass"
                                ]
                                risk_data["vulnerabilities_found"] += 1
                                risk_data["critical_issues"] += 1

            # Check for errors
            if data.get("error"):
                risk_data["score"] += vulnerability_weights["error_disclosure"]
                risk_data["vulnerabilities_found"] += 1
                risk_data["medium_issues"] += 1

    # Ensure score doesn't go below 0
    risk_data["score"] = max(0, risk_data["score"])

    # Determine risk level
    if risk_data["score"] >= 80:
        risk_data["level"] = "LOW"
    elif risk_data["score"] >= 60:
        risk_data["level"] = "MEDIUM"
    elif risk_data["score"] >= 40:
        risk_data["level"] = "HIGH"
    else:
        risk_data["level"] = "CRITICAL"

    return risk_data


def generate_compliance_mapping(results):
    """Generate compliance mapping for security standards"""
    compliance_standards = {
        "OWASP_Top_10": {
            "A01_Broken_Access_Control": False,
            "A03_Injection": False,
            "A04_Insecure_Design": False,
            "A05_Security_Misconfiguration": False,
            "A06_Vulnerable_Components": False,
        },
        "NIST_CSF": {
            "Identify": True,
            "Protect": False,
            "Detect": True,
            "Respond": False,
            "Recover": False,
        },
        "ISO_27001": {
            "Access_Control": False,
            "Cryptography": False,
            "Security_Architecture": False,
            "Vulnerability_Management": True,
        },
    }

    # Analyze results for compliance
    for engine, data in results.items():
        if isinstance(data, dict):
            # Check for injection vulnerabilities
            if any(
                keyword in str(data).lower()
                for keyword in ["injection", "sql", "nosql"]
            ):
                compliance_standards["OWASP_Top_10"]["A03_Injection"] = True

            # Check for access control issues
            if any(
                keyword in str(data).lower() for keyword in ["auth", "bypass", "role"]
            ):
                compliance_standards["OWASP_Top_10"]["A01_Broken_Access_Control"] = True

            # Check for misconfigurations
            if data.get("introspection", False):
                compliance_standards["OWASP_Top_10"][
                    "A05_Security_Misconfiguration"
                ] = True

    # Calculate overall compliance percentage
    total_checks = sum(
        len(standard.values()) for standard in compliance_standards.values()
    )
    passed_checks = sum(
        sum(standard.values()) for standard in compliance_standards.values()
    )
    overall_compliance = (
        round((passed_checks / total_checks) * 100) if total_checks > 0 else 0
    )

    return {
        "standards": compliance_standards,
        "overall_compliance": overall_compliance,
        "total_checks": total_checks,
        "passed_checks": passed_checks,
    }


def generate_vulnerability_section(results):
    """Generate HTML for vulnerability section"""
    vulnerabilities_html = ""

    for engine, data in results.items():
        if isinstance(data, dict) and any(
            key in engine for key in ["jwt-auth", "dos-performance", "param-fuzz"]
        ):
            vulnerabilities_html += f"""
            <div class="vulnerability vuln-high">
                <h4>🔍 {engine.replace('-', ' ').title()}</h4>
                <p><strong>Engine:</strong> {engine}</p>
                <p><strong>Status:</strong> Analysis Complete</p>
                <p><strong>Findings:</strong> {len(data)} test categories executed</p>
            </div>
            """

    if not vulnerabilities_html:
        vulnerabilities_html = (
            "<p>✅ No critical vulnerabilities detected in this assessment.</p>"
        )

    return vulnerabilities_html


def generate_compliance_cards(compliance_data):
    """Generate HTML for compliance cards"""
    cards_html = ""

    for standard_name, checks in compliance_data["standards"].items():
        passed = sum(checks.values())
        total = len(checks)
        percentage = round((passed / total) * 100) if total > 0 else 0

        status_class = (
            "compliance-pass"
            if percentage >= 80
            else "compliance-fail" if percentage < 50 else "compliance-partial"
        )

        cards_html += f"""
        <div class="compliance-item {status_class}">
            <h4>{standard_name.replace('_', ' ')}</h4>
            <div class="metric">{percentage}%</div>
            <p>{passed}/{total} checks passed</p>
        </div>
        """

    return cards_html


def generate_recommendations_section(risk_assessment, results):
    """Generate security recommendations based on findings"""
    recommendations = []

    if risk_assessment["score"] < 60:
        recommendations.append(
            {
                "priority": "CRITICAL",
                "title": "Immediate Security Hardening Required",
                "description": "Multiple critical vulnerabilities detected. Implement comprehensive security controls immediately.",
                "actions": [
                    "Disable GraphQL introspection in production",
                    "Implement query depth limiting",
                    "Add authentication and authorization checks",
                    "Enable comprehensive logging and monitoring",
                ],
            }
        )

    recommendations.append(
        {
            "priority": "HIGH",
            "title": "Implement GraphQL Security Best Practices",
            "description": "Follow industry standard security practices for GraphQL endpoints.",
            "actions": [
                "Use query whitelisting for critical applications",
                "Implement rate limiting and complexity analysis",
                "Add input validation and sanitization",
                "Regular security assessments and penetration testing",
            ],
        }
    )

    recommendations_html = ""
    for rec in recommendations:
        actions_html = "".join([f"<li>{action}</li>" for action in rec["actions"]])

        recommendations_html += f"""
        <div class="recommendation">
            <h4>🚨 {rec['priority']} - {rec['title']}</h4>
            <p>{rec['description']}</p>
            <ul>{actions_html}</ul>
        </div>
        """

    return recommendations_html


def generate_technical_details(results):
    """Generate technical details section"""
    details_html = "<table class='table'><thead><tr><th>Engine</th><th>Tests</th><th>Status</th><th>Key Findings</th></tr></thead><tbody>"

    for engine, data in results.items():
        if isinstance(data, dict):
            status = "✅ Complete" if not data.get("error") else "❌ Error"
            test_count = len(data) if isinstance(data, dict) else 1
            findings = data.get("error", "Analysis completed successfully")[:100]

            details_html += f"""
            <tr>
                <td>{engine}</td>
                <td>{test_count}</td>
                <td>{status}</td>
                <td>{findings}</td>
            </tr>
            """

    details_html += "</tbody></table>"
    return details_html


# ========== GraphQL Parameter Fuzzing ==========


def detect_fuzzer():
    """Auto-detect best available fuzzer"""
    import shutil

    if shutil.which("ffuf"):
        return "ffuf"
    elif shutil.which("wfuzz"):
        return "wfuzz"
    else:
        return "native"


def load_fuzz_params(params_file):
    """Load parameter wordlist from file"""
    try:
        if Path(params_file).exists():
            with open(params_file, "r") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        else:
            # Default GraphQL parameters if file not found
            return [
                "query",
                "mutation",
                "graphql",
                "gql",
                "operation",
                "operationName",
                "variables",
                "extensions",
                "batch",
                "request",
                "doc",
                "document",
                "source",
                "schema",
                "introspection",
                "data",
            ]
    except Exception as e:
        if params_file != "gql-params.txt":  # Only warn if custom file specified
            print(f"⚠️  [FUZZ] Could not load params file {params_file}: {e}")
        # Return default params
        return [
            "query",
            "mutation",
            "graphql",
            "gql",
            "operation",
            "operationName",
            "variables",
            "extensions",
            "batch",
            "request",
            "doc",
            "document",
            "source",
            "schema",
            "introspection",
            "data",
        ]


def load_fuzz_payloads(payloads_file=None):
    """Load GraphQL payloads for fuzzing"""
    default_payloads = [
        "{__typename}",
        "{__schema{types{name}}}",
        "{__schema{queryType{name}}}",
        "{__schema{mutationType{name}}}",
        "{__schema{subscriptionType{name}}}",
        "query{__typename}",
        "mutation{__typename}",
        "query{__schema{types{name}}}",
        "query{__schema{queryType{fields{name}}}}",
        "query{__schema{mutationType{fields{name}}}}",
        "{__schema{types{name,fields{name,type{name}}}}}",
        "query IntrospectionQuery{__schema{types{name}}}",
        '{"query":"{__typename}"}',
        '{"query":"query{__typename}"}',
        '{"query":"{__schema{types{name}}}"}',
    ]

    if payloads_file and Path(payloads_file).exists():
        try:
            with open(payloads_file, "r") as f:
                custom_payloads = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                return custom_payloads if custom_payloads else default_payloads
        except Exception as e:
            print(f"⚠️  [FUZZ] Could not load payloads file {payloads_file}: {e}")

    return default_payloads


def run_native_param_fuzz(
    target_url, params, payloads, methods, headers, proxy, threads, timeout, verbose
):
    """Native Python GraphQL parameter fuzzer"""
    import requests
    import threading
    import queue
    from urllib.parse import urljoin, urlparse

    results = {
        "engine": "param-fuzz-native",
        "target": target_url,
        "total_tests": 0,
        "successful_tests": 0,
        "graphql_responses": [],
        "interesting_responses": [],
        "errors": [],
    }

    def worker(q, results_list):
        """Worker thread for fuzzing"""
        session = requests.Session()
        if headers:
            session.headers.update(headers)
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}

        while True:
            try:
                item = q.get(timeout=1)
                if item is None:
                    break

                method, param, payload, test_url = item

                try:
                    if method.upper() == "GET":
                        # GET parameter fuzzing
                        test_url_with_param = f"{test_url}?{param}={payload}"
                        response = session.get(
                            test_url_with_param, timeout=timeout, verify=ssl_verify
                        )
                    elif method.upper() == "POST":
                        # POST form fuzzing
                        data = {param: payload}
                        response = session.post(
                            test_url, data=data, timeout=timeout, verify=ssl_verify
                        )
                    else:
                        continue

                    results["total_tests"] += 1

                    # Analyze response for GraphQL indicators
                    response_text = response.text.lower()
                    graphql_indicators = [
                        "__typename",
                        "__schema",
                        "graphql",
                        "query",
                        "mutation",
                        "subscription",
                        "introspection",
                        "extensions",
                        "errors",
                    ]

                    if any(
                        indicator in response_text for indicator in graphql_indicators
                    ):
                        results["successful_tests"] += 1
                        graphql_resp = {
                            "method": method,
                            "param": param,
                            "payload": payload,
                            "url": (
                                test_url_with_param
                                if method.upper() == "GET"
                                else test_url
                            ),
                            "status_code": response.status_code,
                            "content_length": len(response.text),
                            "headers": dict(response.headers),
                            "graphql_indicators": [
                                ind
                                for ind in graphql_indicators
                                if ind in response_text
                            ],
                        }
                        results["graphql_responses"].append(graphql_resp)

                        if verbose:
                            print(
                                f"✅ [FUZZ] GraphQL response: {method} {param}={payload[:50]}... -> {response.status_code}"
                            )

                    # Check for interesting response codes/sizes
                    if (
                        response.status_code in [200, 400, 500]
                        and len(response.text) > 100
                    ):
                        interesting_resp = {
                            "method": method,
                            "param": param,
                            "payload": payload,
                            "url": (
                                test_url_with_param
                                if method.upper() == "GET"
                                else test_url
                            ),
                            "status_code": response.status_code,
                            "content_length": len(response.text),
                        }
                        results["interesting_responses"].append(interesting_resp)

                except Exception as e:
                    results["errors"].append(f"{method} {param}={payload}: {str(e)}")
                    if verbose:
                        print(
                            f"❌ [FUZZ] Error: {method} {param}={payload[:30]}... -> {str(e)[:100]}"
                        )

            except queue.Empty:
                continue
            except Exception as e:
                results["errors"].append(f"Worker error: {str(e)}")
                break
            finally:
                q.task_done()

    # Prepare work queue
    work_queue = queue.Queue()
    methods_list = [m.strip().upper() for m in methods.split(",")]

    for method in methods_list:
        for param in params:
            for payload in payloads:
                work_queue.put((method, param, payload, target_url))

    total_tests = work_queue.qsize()
    if verbose:
        print(
            f"🔍 [FUZZ] Starting native fuzzer: {total_tests} tests ({len(methods_list)} methods × {len(params)} params × {len(payloads)} payloads)"
        )

    # Start worker threads
    workers = []
    for i in range(min(threads, total_tests)):
        t = threading.Thread(target=worker, args=(work_queue, results))
        t.daemon = True
        t.start()
        workers.append(t)

    # Wait for completion
    work_queue.join()

    # Stop workers
    for i in range(len(workers)):
        work_queue.put(None)
    for t in workers:
        t.join()

    if verbose:
        print(
            f"🎯 [FUZZ] Native fuzzing completed: {results['successful_tests']}/{results['total_tests']} GraphQL responses found"
        )

    return results


def run_ffuf_param_fuzz(
    target_url, params_file, payloads, methods, headers, proxy, timeout, verbose
):
    """FFUF-based GraphQL parameter fuzzer"""
    import subprocess
    import tempfile
    import json

    results = {
        "engine": "param-fuzz-ffuf",
        "target": target_url,
        "ffuf_results": [],
        "graphql_responses": [],
        "errors": [],
    }

    try:
        # Create temporary payload file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for payload in payloads:
                f.write(f"{payload}\n")
            payloads_file = f.name

        methods_list = [m.strip().upper() for m in methods.split(",")]

        for method in methods_list:
            if verbose:
                print(f"🔍 [FUZZ] Running ffuf with method {method}...")

            # Create output file
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".json"
            ) as f:
                output_file = f.name

            if method == "GET":
                # GET parameter fuzzing
                cmd = [
                    "ffuf",
                    "-u",
                    f"{target_url}?FUZZ=PAYLOAD",
                    "-w",
                    f"{params_file}:FUZZ",
                    "-w",
                    f"{payloads_file}:PAYLOAD",
                    "-mc",
                    "200,400,403,500",
                    "-o",
                    output_file,
                    "-of",
                    "json",
                    "-t",
                    "10",
                    "-timeout",
                    str(timeout),
                ]
            elif method == "POST":
                # POST data fuzzing
                cmd = [
                    "ffuf",
                    "-u",
                    target_url,
                    "-w",
                    f"{params_file}:FUZZ",
                    "-w",
                    f"{payloads_file}:PAYLOAD",
                    "-X",
                    "POST",
                    "-d",
                    "FUZZ=PAYLOAD",
                    "-H",
                    "Content-Type: application/x-www-form-urlencoded",
                    "-mc",
                    "200,400,403,500",
                    "-o",
                    output_file,
                    "-of",
                    "json",
                    "-t",
                    "10",
                    "-timeout",
                    str(timeout),
                ]
            else:
                continue

            if headers:
                for header_name, header_value in headers.items():
                    cmd.extend(["-H", f"{header_name}: {header_value}"])

            if proxy:
                cmd.extend(["-x", proxy])

            # Run ffuf
            try:
                if verbose:
                    print(f"🔧 [FUZZ] Running: {' '.join(cmd[:8])}...")

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )

                if result.returncode == 0:
                    # Parse ffuf JSON output
                    try:
                        with open(output_file, "r") as f:
                            ffuf_data = json.load(f)

                        if "results" in ffuf_data:
                            results["ffuf_results"].extend(ffuf_data["results"])

                            # Analyze results for GraphQL indicators
                            for item in ffuf_data["results"]:
                                if (
                                    item.get("length", 0) > 100
                                ):  # Filter out empty responses
                                    graphql_resp = {
                                        "method": method,
                                        "url": item.get("url", ""),
                                        "status_code": item.get("status", 0),
                                        "content_length": item.get("length", 0),
                                        "words": item.get("words", 0),
                                        "lines": item.get("lines", 0),
                                    }
                                    results["graphql_responses"].append(graphql_resp)

                    except Exception as e:
                        results["errors"].append(
                            f"Failed to parse ffuf output: {str(e)}"
                        )

                else:
                    results["errors"].append(
                        f"ffuf failed for method {method}: {result.stderr}"
                    )

            except subprocess.TimeoutExpired:
                results["errors"].append(f"ffuf timeout for method {method}")
            except Exception as e:
                results["errors"].append(
                    f"ffuf execution error for method {method}: {str(e)}"
                )
            finally:
                # Cleanup temp files
                try:
                    Path(output_file).unlink(missing_ok=True)
                except OSError as e:
                    click.echo(f"[!] Warning: Could not delete temp file {output_file}: {e}")

        # Cleanup payload file
        try:
            Path(payloads_file).unlink(missing_ok=True)
        except OSError as e:
            click.echo(f"[!] Warning: Could not delete payload file {payloads_file}: {e}")

    except Exception as e:
        results["errors"].append(f"FFUF fuzzer setup error: {str(e)}")

    if verbose:
        print(
            f"🎯 [FUZZ] FFUF fuzzing completed: {len(results['graphql_responses'])} responses found"
        )

    return results


def run_param_fuzz_engine(
    target_url,
    fuzzer,
    params_file,
    payloads_file,
    methods,
    headers,
    proxy,
    threads,
    timeout,
    verbose,
):
    """Main parameter fuzzing engine dispatcher"""

    # Auto-detect fuzzer if requested
    if fuzzer == "auto":
        fuzzer = detect_fuzzer()
        if verbose:
            print(f"🔧 [FUZZ] Auto-detected fuzzer: {fuzzer}")

    # Load parameters and payloads
    params = load_fuzz_params(params_file)
    payloads = load_fuzz_payloads(payloads_file)

    if verbose:
        print(f"🔍 [FUZZ] Loaded {len(params)} parameters and {len(payloads)} payloads")

    # Convert headers to dict if needed
    headers_dict = {}
    if headers:
        if isinstance(headers, list):
            for h in headers:
                if ":" in h:
                    key, value = h.split(":", 1)
                    headers_dict[key.strip()] = value.strip()
        elif isinstance(headers, dict):
            headers_dict = headers

    # Run appropriate fuzzer
    if fuzzer == "ffuf":
        return run_ffuf_param_fuzz(
            target_url,
            params_file,
            payloads,
            methods,
            headers_dict,
            proxy,
            timeout,
            verbose,
        )
    elif fuzzer == "wfuzz":
        # TODO: Implement wfuzz integration
        if verbose:
            print(
                "⚠️  [FUZZ] WFUZZ integration not yet implemented, falling back to native"
            )
        return run_native_param_fuzz(
            target_url,
            params,
            payloads,
            methods,
            headers_dict,
            proxy,
            threads,
            timeout,
            verbose,
        )
    else:  # native
        return run_native_param_fuzz(
            target_url,
            params,
            payloads,
            methods,
            headers_dict,
            proxy,
            threads,
            timeout,
            verbose,
        )


if __name__ == "__main__":
    graphqlcli.main()
