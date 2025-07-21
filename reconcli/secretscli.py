#!/usr/bin/env python3

import csv
import glob
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 - subprocess is required for tool execution
import time
from pathlib import Path

import click


# Simple utility functions
def print_info(msg):
    """Print info message with blue color."""
    print(f"\033[94m{msg}\033[0m")


def print_good(msg):
    """Print success message with green color."""
    print(f"\033[92m{msg}\033[0m")


def print_warn(msg):
    """Print warning m                           if verbose:
        print_info(f"[CMD] {' '.join(cmd)}")

    result = safe_subprocess_run(
        cmd, "gitleaks", timeout=timeout, capture_output=True, text=True
    )
    if result.returncode != 0 and verbose:
        print_warn(f"[WARN] {t} returned code {result.returncode}")     if verbose:
        print_info(f"[CMD] {' '.join(cmd)}")

    result = safe_subprocess_run(
        cmd, "jsubfinder", timeout=timeout, capture_output=True, text=True
    )
    if result.returncode != 0 and verbose:
        print_warn(f"[WARN] {t} returned code {result.returncode}")ith yellow color."""
    print(f"\033[93m{msg}\033[0m")


def print_bad(msg):
    """Print error message with red color."""
    print(f"\033[91m{msg}\033[0m")


def check_tool(tool_name):
    """Check if tool is available in PATH."""
    return shutil.which(tool_name) is not None


def resume_handler(tool_name, resume, resume_clear, resume_stat):
    """Simple resume handler."""
    resume_dir = Path("output") / f".resume_{tool_name}"
    resume_file = resume_dir / "state.json"

    if resume_clear:
        if resume_dir.exists():
            shutil.rmtree(resume_dir)
            print_good(f"[RESUME] Cleared resume data for {tool_name}")
        else:
            print_warn(f"[RESUME] No resume data found for {tool_name}")
        return "exit"

    if resume_stat:
        if resume_file.exists():
            try:
                with open(resume_file, "r") as f:
                    state = json.load(f)
                print_info(f"[RESUME] Resume state for {tool_name}:")
                print_info(f"  Started: {state.get('start_time', 'Unknown')}")
                print_info(f"  Last update: {state.get('last_update', 'Unknown')}")
                print_info(f"  Progress: {state.get('progress', 'Unknown')}")
            except Exception as e:
                print_warn(f"[RESUME] Error reading resume state: {e}")
        else:
            print_warn(f"[RESUME] No resume data found for {tool_name}")
        return "exit"

    if resume:
        if resume_file.exists():
            print_info(f"[RESUME] Resume mode enabled for {tool_name}")
            return "resume"
        else:
            print_info("[RESUME] No previous state found, starting fresh")

    # Create resume directory and state file
    resume_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S"),
        "progress": "started",
    }
    with open(resume_file, "w") as f:
        json.dump(state, f, indent=2)

    return None


class SecretsCacheManager:
    """Intelligent cache manager for secret discovery operations."""

    def __init__(self, cache_dir: str = "secrets_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_seconds = max_age_hours * 3600
        self.cache_index_file = self.cache_dir / "secrets_cache_index.json"
        self.cache_stats = {"hits": 0, "misses": 0, "total_requests": 0}

    def _generate_cache_key(self, target: str, tools: list, options: dict) -> str:
        """Generate unique cache key based on target and scan parameters."""
        # Create a deterministic key from target, tools, and options
        key_data = {
            "target": target,
            "tools": sorted(tools),
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

    def get_cached_result(self, target: str, tools: list, options: dict):
        """Retrieve cached result if available and valid."""
        cache_key = self._generate_cache_key(target, tools, options)
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

    def store_result(self, target: str, tools: list, options: dict, result_data: dict):
        """Store scan result in cache."""
        cache_key = self._generate_cache_key(target, tools, options)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add metadata to cached result
        cache_data = {
            "metadata": {
                "target": target,
                "tools": tools,
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
            self._update_cache_index(cache_key, target, tools)

        except IOError as e:
            print_warn(f"[CACHE] Failed to store cache: {e}")

    def _update_cache_index(self, cache_key: str, target: str, tools: list):
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
            "tools": tools,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": (self.cache_dir / f"{cache_key}.json").stat().st_size,
        }

        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(index_data, f, indent=2)
        except IOError as e:
            print_warn(f"[CACHE] Failed to update cache index: {e}")

    def clear_cache(self) -> bool:
        """Clear all cached results."""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                print_good("[CACHE] All cached results cleared successfully")
                return True
            return True
        except Exception as e:
            print_bad(f"[CACHE] Failed to clear cache: {e}")
            return False

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_size = sum(
            f.stat().st_size
            for f in cache_files
            if f.name != "secrets_cache_index.json"
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
                [f for f in cache_files if f.name != "secrets_cache_index.json"]
            ),
            "cache_size": cache_size,
            "cache_dir": str(self.cache_dir),
        }


@click.command()
@click.option("--input", help="Input file (e.g. domains.txt) or single domain/URL")
@click.option(
    "--tool",
    multiple=True,
    help="Tool to use: jsubfinder, gitleaks, shhgit, mantra, cariddi, trufflehog, semgrep",
)
@click.option("--output", default="output/secrets", help="Directory to store results")
@click.option(
    "--rl", default=50, type=int, help="Rate limit (requests per minute/tool)"
)
@click.option("--concurrency", default=5, type=int, help="Number of concurrent scans")
@click.option("--timeout", default=30, type=int, help="Timeout per scan (seconds)")
@click.option("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
@click.option(
    "--tool-flags", default="", help="Extra flags to pass to selected tool(s)"
)
@click.option("--json", is_flag=True, help="Export results to JSON")
@click.option("--markdown", is_flag=True, help="Export results to Markdown")
@click.option("--report", is_flag=True, help="Generate summary report")
@click.option("--retry", is_flag=True, help="Retry failed scans")
@click.option("--resume", is_flag=True, help="Resume previous scan if possible")
@click.option("--resume-clear", is_flag=True, help="Clear previous scan state")
@click.option("--resume-stat", is_flag=True, help="Show resume status and stats")
@click.option("--store-db", is_flag=True, help="Store results to database via dbcli")
@click.option(
    "--export",
    multiple=True,
    type=click.Choice(["json", "markdown", "csv", "txt"]),
    help="Export results to selected formats",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Minimize output to essential only")
@click.option("--filter-keywords", help="Filter results by keywords (comma-separated)")
@click.option(
    "--exclude-keywords", help="Exclude results containing keywords (comma-separated)"
)
@click.option(
    "--min-confidence",
    default=0.5,
    type=float,
    help="Minimum confidence threshold for results (0.0-1.0)",
)
@click.option(
    "--max-filesize", default="10MB", help="Maximum file size to scan (e.g. 10MB, 1GB)"
)
@click.option(
    "--extensions", help="File extensions to scan (comma-separated, e.g. js,php,py)"
)
@click.option(
    "--exclude-paths", help="Paths to exclude from scanning (comma-separated)"
)
@click.option(
    "--depth",
    default=5,
    type=int,
    help="Maximum directory depth for recursive scanning",
)
@click.option(
    "--follow-redirects", is_flag=True, help="Follow HTTP redirects during scanning"
)
@click.option(
    "--user-agent", default="secretscli/1.0", help="Custom User-Agent for HTTP requests"
)
@click.option(
    "--headers", help="Custom HTTP headers (format: 'Header1:Value1,Header2:Value2')"
)
@click.option(
    "--config-file", type=click.Path(exists=True), help="Custom configuration file"
)
@click.option(
    "--wordlist",
    type=click.Path(exists=True),
    help="Custom wordlist for secret patterns",
)
@click.option(
    "--entropy-threshold",
    default=4.5,
    type=float,
    help="Entropy threshold for detecting secrets",
)
# ========== Cache Options ==========
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option(
    "--cache-dir", default="secrets_cache", help="Directory for cache storage"
)
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
def secretscli(
    input,
    tool,
    output,
    rl,
    concurrency,
    timeout,
    proxy,
    tool_flags,
    json,
    markdown,
    report,
    retry,
    resume,
    resume_clear,
    resume_stat,
    store_db,
    export,
    verbose,
    quiet,
    filter_keywords,
    exclude_keywords,
    min_confidence,
    max_filesize,
    extensions,
    exclude_paths,
    depth,
    follow_redirects,
    user_agent,
    headers,
    config_file,
    wordlist,
    entropy_threshold,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """
    🔐 secretscli – Secret discovery using tools like jsubfinder, gitleaks, trufflehog, etc.
    """

    # ========== Cache System ==========
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = SecretsCacheManager(
            cache_dir=cache_dir, max_age_hours=cache_max_age
        )

        if clear_cache:
            if cache_manager.clear_cache():
                print_good(f"✅ [CACHE] Cache cleared successfully: {cache_dir}")
            else:
                print_bad(f"❌ [CACHE] Failed to clear cache: {cache_dir}")
            return

        if cache_stats:
            stats = cache_manager.get_cache_stats()
            print_info("📊 [CACHE] Secrets Cache Statistics:")
            print_info(f"    Cache hits: {stats['cache_hits']}")
            print_info(f"    Cache misses: {stats['cache_misses']}")
            print_info(f"    Hit rate: {stats['hit_rate']}")
            print_info(f"    Total requests: {stats['total_requests']}")
            print_info(f"    Cache files: {stats['cache_files']}")
            print_info(f"    Cache size: {stats['cache_size']} bytes")
            print_info(f"    Cache directory: {stats['cache_dir']}")
            return

    # Validate required input for scanning operations
    if not input:
        print_bad("❌ Error: --input is required for scanning operations")
        print_info(
            "💡 Use --cache-stats to view cache statistics or --clear-cache to clear cache"
        )
        return

    # Handle verbose/quiet modes
    if verbose:
        print_info("[secretscli] Verbose mode enabled")
        print_info(f"[secretscli] Input: {input}")
        print_info(f"[secretscli] Output: {output}")
        print_info(f"[secretscli] Tools: {', '.join(tool) if tool else 'auto-detect'}")
        print_info(f"[secretscli] Rate limit: {rl}/min")
        print_info(f"[secretscli] Concurrency: {concurrency}")
        print_info(f"[secretscli] Timeout: {timeout}s")
        print_info(f"[secretscli] Min confidence: {min_confidence}")
        print_info(f"[secretscli] Max depth: {depth}")
        print_info(f"[secretscli] Entropy threshold: {entropy_threshold}")
        if cache_manager:
            print_info(
                f"[secretscli] Cache: ENABLED (dir: {cache_dir}, TTL: {cache_max_age}h)"
            )
        else:
            print_info("[secretscli] Cache: DISABLED")
    elif not quiet:
        print_info(f"[secretscli] Input: {input}")
        print_info(f"[secretscli] Output: {output}")
        if cache_manager:
            print_info(f"[secretscli] Cache: ENABLED")

    os.makedirs(output, exist_ok=True)

    # Load configuration file if provided
    config = {}
    if config_file:
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            if verbose:
                print_info(f"[secretscli] Loaded config from: {config_file}")
        except Exception as e:
            print_warn(f"[secretscli] Failed to load config file: {e}")

    # Parse custom headers
    custom_headers = {}
    if headers:
        try:
            for header_pair in headers.split(","):
                if ":" in header_pair:
                    key, value = header_pair.split(":", 1)
                    custom_headers[key.strip()] = value.strip()
            if verbose:
                print_info(
                    f"[secretscli] Custom headers: {len(custom_headers)} header(s)"
                )
        except Exception as e:
            print_warn(f"[secretscli] Failed to parse headers: {e}")

    # Parse filter and exclude keywords
    filter_list = filter_keywords.split(",") if filter_keywords else []
    exclude_list = exclude_keywords.split(",") if exclude_keywords else []

    if verbose and filter_list:
        print_info(f"[secretscli] Filter keywords: {', '.join(filter_list)}")
    if verbose and exclude_list:
        print_info(f"[secretscli] Exclude keywords: {', '.join(exclude_list)}")

    # Parse extensions and exclude paths
    allowed_extensions = extensions.split(",") if extensions else []
    excluded_paths = exclude_paths.split(",") if exclude_paths else []

    if verbose and allowed_extensions:
        print_info(f"[secretscli] File extensions: {', '.join(allowed_extensions)}")
    if verbose and excluded_paths:
        print_info(f"[secretscli] Excluded paths: {', '.join(excluded_paths)}")

    # Load custom wordlist if provided
    custom_patterns = []
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                custom_patterns = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            if verbose:
                print_info(
                    f"[secretscli] Loaded {len(custom_patterns)} custom patterns"
                )
        except Exception as e:
            print_warn(f"[secretscli] Failed to load wordlist: {e}")

    # Support both file-based and single target input
    inputs = []
    if os.path.isfile(input) and input.endswith(".txt"):
        with open(input, "r") as f:
            inputs = [line.strip() for line in f if line.strip()]
    else:
        inputs = [input.strip()]

    resume_state = resume_handler("secretscli", resume, resume_clear, resume_stat)
    if resume_state == "exit":
        return

    tools_available = {
        "jsubfinder": check_tool("JSubFinder"),
        "gitleaks": check_tool("gitleaks"),
        "shhgit": check_tool("shhgit"),
        "mantra": check_tool("mantra"),
        "cariddi": check_tool("cariddi"),
        "trufflehog": check_tool("trufflehog"),
        "semgrep": check_tool("semgrep"),
    }

    if not tool:
        print_warn("No tool selected with --tool, auto-selecting available defaults...")
        tool = tuple(t for t in ["gitleaks", "jsubfinder"] if tools_available[t])

    for t in tool:
        if not tools_available.get(t):
            print_bad(f"[!] Tool '{t}' not found in PATH – skipping.")
            continue

        for target in inputs:
            if not quiet:
                print_info(f"[+] Running tool: {t} on target: {target}")

            # ========== Cache Check ==========
            cache_options = {
                "tool": t,
                "min_confidence": min_confidence,
                "entropy_threshold": entropy_threshold,
                "extensions": extensions,
                "exclude_paths": exclude_paths,
                "depth": depth,
                "timeout": timeout,
                "filter_keywords": filter_keywords,
                "exclude_keywords": exclude_keywords,
            }

            if cache_manager:
                cached_result = cache_manager.get_cached_result(
                    target, [t], cache_options
                )
                if cached_result:
                    if verbose:
                        print_good(f"[CACHE] ✓ Using cached result for {t} on {target}")
                    # Use cached result instead of running tool
                    continue
                elif verbose:
                    print_info(f"[CACHE] ✗ Cache miss for {t} on {target}")

            # Apply filtering logic based on target type and exclusions
            if should_skip_target(target, excluded_paths, verbose):
                if verbose:
                    print_warn(f"[SKIP] Target excluded: {target}")
                continue

            try:
                if t == "jsubfinder":
                    cmd = [
                        "JSubFinder",
                        "search",
                        "--silent",
                        "-o",
                        os.path.join(
                            output, f"jsubfinder_{sanitize_filename(target)}.txt"
                        ),
                        "-s",
                        os.path.join(
                            output,
                            f"jsubfinder_secrets_{sanitize_filename(target)}.txt",
                        ),
                        "-K",
                    ]

                    # Add rate limiting if supported
                    if rl and rl > 0:
                        cmd.extend(["--rate-limit", str(rl)])

                    # Add depth control
                    if depth and depth > 0:
                        cmd.extend(["--depth", str(depth)])

                    # Add user agent
                    if user_agent:
                        cmd.extend(["--user-agent", user_agent])

                    # Add proxy support
                    if proxy:
                        cmd.extend(["--proxy", proxy])

                    if tool_flags:
                        cmd += tool_flags.split()

                    if verbose:
                        print_info(f"[CMD] {' '.join(cmd)}")

                    result = safe_subprocess_run(
                        cmd,
                        "jsubfinder",
                        timeout=timeout,
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0 and verbose:
                        print_warn(f"[WARN] {t} returned code {result.returncode}")

                elif t == "gitleaks":
                    cmd = [
                        "gitleaks",
                        "detect",
                        "--source",
                        target,
                        "--report",
                        os.path.join(
                            output, f"gitleaks_{sanitize_filename(target)}.json"
                        ),
                        "--no-banner",
                    ]

                    # Add entropy threshold
                    if entropy_threshold > 0:
                        cmd.extend(["--log-level", "info"])

                    # Add file extensions filter
                    if allowed_extensions:
                        for ext in allowed_extensions:
                            cmd.extend(["--include-patterns", f"*.{ext}"])

                    # Add exclude paths
                    if excluded_paths:
                        for path in excluded_paths:
                            cmd.extend(["--exclude-patterns", path])

                    if tool_flags:
                        cmd += tool_flags.split()

                    if verbose:
                        print_info(f"[CMD] {' '.join(cmd)}")

                    result = safe_subprocess_run(
                        cmd, "gitleaks", timeout=timeout, capture_output=True, text=True
                    )
                    if result.returncode != 0 and verbose:
                        print_warn(f"[WARN] {t} returned code {result.returncode}")

                elif t == "trufflehog":
                    # Detect if target is a Git repository URL or local path
                    if target.startswith(("http://", "https://")) and "git" in target:
                        cmd = ["trufflehog", "git", target, "--json", "--no-update"]
                    else:
                        cmd = [
                            "trufflehog",
                            "filesystem",
                            target,
                            "--json",
                            "--no-update",
                        ]

                    # Add concurrency
                    if concurrency > 1:
                        cmd.extend(["--concurrency", str(concurrency)])

                    # Add depth control (only for filesystem mode)
                    if depth > 0 and not target.startswith(("http://", "https://")):
                        cmd.extend(["--max-depth", str(depth)])

                    # Add include patterns for extensions (only for filesystem mode)
                    if allowed_extensions and not target.startswith(
                        ("http://", "https://")
                    ):
                        patterns = [f"*.{ext}" for ext in allowed_extensions]
                        cmd.extend(["--include-patterns", ",".join(patterns)])

                    # Add exclude patterns (only for filesystem mode)
                    if excluded_paths and not target.startswith(
                        ("http://", "https://")
                    ):
                        cmd.extend(["--exclude-patterns", ",".join(excluded_paths)])

                    if tool_flags:
                        cmd += tool_flags.split()

                    if verbose:
                        print_info(f"[CMD] {' '.join(cmd)}")

                    output_file = os.path.join(
                        output, f"trufflehog_{sanitize_filename(target)}.json"
                    )
                    with open(output_file, "w") as f:
                        result = safe_subprocess_run(
                            cmd,
                            "trufflehog",
                            stdout=f,
                            timeout=timeout,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        if result.returncode != 0 and verbose:
                            print_warn(f"[WARN] {t} returned code {result.returncode}")
                            if result.stderr:
                                print_warn(f"[STDERR] {result.stderr}")

                elif t == "cariddi":
                    cmd = ["cariddi", "-t", str(timeout), "-c", str(concurrency)]

                    if proxy:
                        cmd.extend(["-proxy", proxy])

                    if user_agent:
                        cmd.extend(["-ua", user_agent])

                    if follow_redirects:
                        cmd.append("-fr")

                    # Add output file
                    output_file = os.path.join(
                        output, f"cariddi_{sanitize_filename(target)}.txt"
                    )
                    cmd.extend(["-o", output_file])

                    # Add target
                    cmd.append(target)

                    if tool_flags:
                        cmd += tool_flags.split()

                    if verbose:
                        print_info(f"[CMD] {' '.join(cmd)}")

                    result = safe_subprocess_run(
                        cmd, "cariddi", timeout=timeout, capture_output=True, text=True
                    )
                    if result.returncode != 0 and verbose:
                        print_warn(f"[WARN] {t} returned code {result.returncode}")

                elif t == "semgrep":
                    # Semgrep static analysis for secrets and security issues
                    cmd = ["semgrep"]

                    # Use security-focused rulesets - only use valid configs
                    cmd.extend(["--config", "p/secrets"])

                    # Output format
                    output_file = os.path.join(
                        output, f"semgrep_{sanitize_filename(target)}.json"
                    )
                    cmd.extend(["--json", "--output", output_file])

                    # Use appropriate severity level
                    cmd.extend(["--severity", "ERROR"])

                    # Don't respect gitignore for comprehensive scanning
                    cmd.append("--no-git-ignore")

                    # Exclude common non-important paths (but not test files when explicitly targeting them)
                    if not (
                        os.path.isfile(target) and "test" in os.path.basename(target)
                    ):
                        cmd.extend(["--exclude", "test*"])
                    cmd.extend(
                        [
                            "--exclude",
                            "node_modules*",
                            "--exclude",
                            ".git*",
                            "--exclude",
                            "vendor*",
                        ]
                    )

                    # Add target (directory or file)
                    if os.path.isfile(target):
                        cmd.append(target)
                    elif os.path.isdir(target):
                        cmd.append(target)
                    else:
                        # For URL targets, skip semgrep as it needs local files
                        if verbose:
                            print_warn(
                                f"[SKIP] Semgrep requires local files/directories, skipping URL: {target}"
                            )
                        continue

                    # Add custom flags
                    if tool_flags:
                        cmd += tool_flags.split()

                    if verbose:
                        print_info(f"[CMD] {' '.join(cmd)}")

                    result = safe_subprocess_run(
                        cmd, "semgrep", timeout=timeout, capture_output=True, text=True
                    )
                    if result.returncode != 0 and verbose:
                        print_warn(f"[WARN] {t} returned code {result.returncode}")
                        if result.stderr:
                            print_warn(f"[STDERR] {result.stderr}")

                # Post-process results with filtering
                filter_results(
                    output,
                    target,
                    t,
                    filter_list,
                    exclude_list,
                    min_confidence,
                    verbose,
                )

                # ========== Cache Storage ==========
                if cache_manager:
                    # Store successful scan result in cache
                    scan_result = {
                        "tool": t,
                        "target": target,
                        "output_dir": output,
                        "scan_completed": True,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    cache_manager.store_result(target, [t], cache_options, scan_result)
                    if verbose:
                        print_good(f"[CACHE] ✓ Stored result for {t} on {target}")

            except subprocess.TimeoutExpired:
                print_warn(f"[TIMEOUT] Tool {t} timed out on {target}")
            except Exception as e:
                print_bad(f"[ERROR] Tool {t} failed on {target}: {str(e)}")
                if verbose:
                    import traceback

                    traceback.print_exc()

    if export:
        export_results(output, export, verbose)

    if store_db:
        print_info("[DB] Storing results to database via dbcli...")
        # TODO: Implement dbcli integration

    if report:
        print_good("[+] Generating summary report...")
        # TODO: Implement summary report generation

    print_good("[✔] secretscli finished.")


def sanitize_filename(name):
    return name.replace("/", "_").replace(":", "_").replace(".", "_")


def export_results(output_dir, formats, verbose=False):
    data = []
    result_files = glob.glob(os.path.join(output_dir, "*"))
    for fpath in result_files:
        if fpath.endswith(".json"):
            try:
                with open(fpath, "r") as f:
                    parsed = json.load(f)
                    data.append({"source": os.path.basename(fpath), "data": parsed})
            except (json.JSONDecodeError, IOError, OSError) as e:
                if verbose:
                    print_warn(f"[EXPORT] Failed to process JSON file {fpath}: {e}")
                continue
        elif (
            fpath.endswith(".txt")
            or fpath.endswith(".log")
            or fpath.endswith(".output")
        ):
            try:
                with open(fpath, "r") as f:
                    lines = [l.strip() for l in f if l.strip()]
                    data.append({"source": os.path.basename(fpath), "data": lines})
            except (IOError, OSError) as e:
                if verbose:
                    print_warn(f"[EXPORT] Failed to process text file {fpath}: {e}")
                continue

    if "json" in formats:
        with open(os.path.join(output_dir, "export_combined.json"), "w") as outjson:
            json.dump(data, outjson, indent=2)
        print_good("[✓] Exported to JSON")

    if "txt" in formats:
        with open(os.path.join(output_dir, "export_combined.txt"), "w") as outtxt:
            for entry in data:
                outtxt.write(f"# Source: {entry['source']}\n")
                for line in entry["data"]:
                    outtxt.write(str(line) + "\n")
                outtxt.write("\n")
        print_good("[✓] Exported to TXT")

    if "markdown" in formats:
        with open(os.path.join(output_dir, "export_combined.md"), "w") as outmd:
            outmd.write("# Secret Discovery Report\n\n")
            for entry in data:
                outmd.write(f"## {entry['source']}\n")
                for line in entry["data"]:
                    outmd.write(f"- `{str(line)}`\n")
                outmd.write("\n")
        print_good("[✓] Exported to Markdown")

    if "csv" in formats:
        with open(
            os.path.join(output_dir, "export_combined.csv"), "w", newline=""
        ) as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["source", "value"])
            for entry in data:
                for line in entry["data"]:
                    writer.writerow([entry["source"], str(line)])
        print_good("[✓] Exported to CSV")


def should_skip_target(target, excluded_paths, verbose=False):
    """Check if target should be skipped based on exclusion rules."""
    if not excluded_paths:
        return False

    for exclude_pattern in excluded_paths:
        exclude_pattern = exclude_pattern.strip()
        if exclude_pattern in target:
            if verbose:
                print_warn(
                    f"[SKIP] Target matches exclude pattern '{exclude_pattern}': {target}"
                )
            return True
    return False


def filter_results(
    output_dir, target, tool, filter_list, exclude_list, min_confidence, verbose=False
):
    """Filter and post-process results based on criteria."""
    if not filter_list and not exclude_list and min_confidence <= 0:
        return

    # Find result files for this target and tool
    pattern = f"{tool}_{sanitize_filename(target)}.*"
    result_files = glob.glob(os.path.join(output_dir, pattern))

    for result_file in result_files:
        if verbose:
            print_info(f"[FILTER] Processing {result_file}")

        try:
            # Handle JSON files
            if result_file.endswith(".json"):
                with open(result_file, "r") as f:
                    content = f.read().strip()

                # Skip empty files
                if not content:
                    if verbose:
                        print_info(f"[FILTER] Skipping empty file: {result_file}")
                    continue

                data = json.loads(content)
                filtered_data = filter_json_results(
                    data, filter_list, exclude_list, min_confidence, verbose
                )

                if filtered_data != data:
                    with open(result_file, "w") as f:
                        json.dump(filtered_data, f, indent=2)
                    if verbose:
                        print_info(f"[FILTER] Updated {result_file}")

            # Handle text files
            elif result_file.endswith(".txt"):
                with open(result_file, "r") as f:
                    lines = f.readlines()

                filtered_lines = filter_text_results(
                    lines, filter_list, exclude_list, verbose
                )

                if len(filtered_lines) != len(lines):
                    with open(result_file, "w") as f:
                        f.writelines(filtered_lines)
                    if verbose:
                        print_info(
                            f"[FILTER] Updated {result_file} ({len(lines)} -> {len(filtered_lines)} lines)"
                        )

        except Exception as e:
            if verbose:
                print_warn(f"[FILTER] Error processing {result_file}: {e}")


def filter_json_results(data, filter_list, exclude_list, min_confidence, verbose=False):
    """Filter JSON results based on criteria."""
    if isinstance(data, list):
        filtered = []
        for item in data:
            if should_include_item(
                item, filter_list, exclude_list, min_confidence, verbose
            ):
                filtered.append(item)
        return filtered
    elif isinstance(data, dict):
        if should_include_item(
            data, filter_list, exclude_list, min_confidence, verbose
        ):
            return data
        else:
            return {}
    return data


def filter_text_results(lines, filter_list, exclude_list, verbose=False):
    """Filter text lines based on criteria."""
    filtered = []
    for line in lines:
        line_text = line.strip().lower()

        # Apply include filters
        if filter_list:
            include = any(keyword.lower() in line_text for keyword in filter_list)
            if not include:
                continue

        # Apply exclude filters
        if exclude_list:
            exclude = any(keyword.lower() in line_text for keyword in exclude_list)
            if exclude:
                continue

        filtered.append(line)

    return filtered


def should_include_item(item, filter_list, exclude_list, min_confidence, verbose=False):
    """Check if an item should be included based on filtering criteria."""
    # Convert item to searchable text
    if isinstance(item, dict):
        searchable_text = json.dumps(item).lower()

        # Check confidence if available
        confidence = item.get("confidence", item.get("score", 1.0))
        if isinstance(confidence, (int, float)) and confidence < min_confidence:
            if verbose:
                print_warn(f"[FILTER] Low confidence ({confidence} < {min_confidence})")
            return False
    else:
        searchable_text = str(item).lower()

    # Apply include filters
    if filter_list:
        include = any(keyword.lower() in searchable_text for keyword in filter_list)
        if not include:
            return False

    # Apply exclude filters
    if exclude_list:
        exclude = any(keyword.lower() in searchable_text for keyword in exclude_list)
        if exclude:
            return False

    return True


def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    import math

    if not text:
        return 0

    # Count frequency of each character
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    # Calculate entropy
    entropy = 0
    text_length = len(text)
    for count in frequency.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def validate_command_args(cmd, tool_name):
    """Validate command arguments for security."""
    if not cmd or not isinstance(cmd, list):
        raise ValueError(f"Invalid command for {tool_name}")

    # Check for dangerous characters in command arguments
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">"]
    for arg in cmd:
        if not isinstance(arg, str):
            continue
        for char in dangerous_chars:
            if char in arg and not arg.startswith(("http://", "https://", "/")):
                # Allow URLs and file paths to contain some special characters
                if char in [";", "&", "|", "`", "$", "(", ")", "{", "}"]:
                    raise ValueError(
                        f"Potentially dangerous character '{char}' in command argument: {arg}"
                    )

    return True


def safe_subprocess_run(cmd, tool_name, **kwargs):
    """Safely execute subprocess with validation."""
    try:
        validate_command_args(cmd, tool_name)
        # nosec B603 - command arguments are validated above
        return subprocess.run(cmd, **kwargs)  # nosec B603
    except (ValueError, TypeError) as e:
        raise ValueError(f"Command validation failed for {tool_name}: {e}")


if __name__ == "__main__":
    secretscli()
