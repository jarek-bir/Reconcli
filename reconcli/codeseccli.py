import json
import os
import shutil
import subprocess
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import click


class CodeSecCacheManager:
    """Intelligent caching system for code security analysis results."""

    def __init__(
        self,
        cache_dir: str = "codesec_cache",
        ttl_hours: int = 24,
        max_cache_size: int = 100,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.max_cache_size = max_cache_size
        self.cache_index_file = self.cache_dir / "codesec_cache_index.json"
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

    def _generate_cache_key(self, input_path: str, **kwargs) -> str:
        """Generate SHA256 cache key based on input path and analysis parameters."""
        # Get file modification times for cache invalidation
        if os.path.isfile(input_path):
            file_mtime = os.path.getmtime(input_path)
            file_size = os.path.getsize(input_path)
        else:
            # For directories, use a simple hash of file list and modification times
            file_mtime = 0
            file_size = 0
            if os.path.isdir(input_path):
                for root, dirs, files in os.walk(input_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            file_mtime += os.path.getmtime(full_path)
                            file_size += os.path.getsize(full_path)
                        except OSError:
                            continue

        cache_data = {
            "input_path": input_path,
            "file_mtime": file_mtime,
            "file_size": file_size,
            "tools": sorted(kwargs.get("tools", [])),
            "config": kwargs.get("config", ""),
            "severity": kwargs.get("severity", "ERROR"),
            "exclude": sorted(kwargs.get("exclude", [])),
            "include": sorted(kwargs.get("include", [])),
            "timeout": kwargs.get("timeout", 300),
        }

        # Sort for consistent ordering
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def get_cached_result(self, input_path: str, **kwargs) -> Optional[Dict]:
        """Retrieve cached result if valid and not expired."""
        self.cache_stats["total_requests"] += 1

        cache_key = self._generate_cache_key(input_path, **kwargs)
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

    def save_result_to_cache(self, input_path: str, result: Dict, **kwargs):
        """Save analysis result to cache with metadata."""
        cache_key = self._generate_cache_key(input_path, **kwargs)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add cache metadata
        cached_result = {
            **result,
            "cache_metadata": {
                "timestamp": time.time(),
                "cache_key": cache_key,
                "input_path": input_path,
                "ttl_seconds": self.ttl_seconds,
                "cache_hit": False,
            },
        }

        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(cached_result, f, indent=2)

        # Update cache index
        self.cache_index[cache_key] = {
            "input_path": input_path,
            "timestamp": time.time(),
            "file": str(cache_file.name),
        }
        self._save_cache_index()

        # Cleanup old cache if needed
        self._cleanup_old_cache()

    def _cleanup_old_cache(self):
        """Remove oldest cache files if cache size exceeds limit."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_files = [f for f in cache_files if f.name != "codesec_cache_index.json"]

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
        cache_files = [f for f in cache_files if f.name != "codesec_cache_index.json"]

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
@click.option("--input", help="Input directory or file for code analysis")
@click.option("--output", default="output/codesec", help="Output directory for results")
@click.option(
    "--tool",
    multiple=True,
    type=click.Choice(["semgrep", "bandit", "safety", "all"]),
    default=["semgrep"],
    help="Security analysis tools to use",
)
@click.option("--config", help="Custom Semgrep config file or rulesets")
@click.option(
    "--severity",
    type=click.Choice(["INFO", "WARNING", "ERROR"]),
    default="ERROR",
    help="Minimum severity level",
)
@click.option(
    "--exclude", multiple=True, help="Exclude patterns (e.g., test/, node_modules/)"
)
@click.option("--include", multiple=True, help="Include only specific file patterns")
@click.option(
    "--export",
    type=click.Choice(["json", "sarif", "text", "markdown"]),
    multiple=True,
    default=["json"],
    help="Export formats",
)
@click.option("--store-db", is_flag=True, help="Store results in ReconCLI database")
@click.option("--target-domain", help="Associate findings with target domain")
@click.option("--program", help="Bug bounty program name")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--timeout", default=300, type=int, help="Timeout per analysis (seconds)")
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option(
    "--cache-dir", default="codesec_cache", help="Directory for cache storage"
)
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
def codeseccli(
    input,
    output,
    tool,
    config,
    severity,
    exclude,
    include,
    export,
    store_db,
    target_domain,
    program,
    verbose,
    quiet,
    timeout,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """🔍 Code Security Analysis with Semgrep, Bandit, and other SAST tools."""

    # Initialize cache manager if caching is enabled
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = CodeSecCacheManager(
            cache_dir=cache_dir, ttl_hours=cache_max_age
        )

    # Handle cache operations
    if cache_stats:
        if cache_manager:
            stats = cache_manager.get_cache_stats()
            click.echo("🚀 Code Security Cache Performance Statistics")
            click.echo("═" * 50)
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
            click.echo("✅ Code security cache cleared successfully")
        return

    # Input is required for analysis operations
    if not input:
        click.echo("❌ Error: --input is required for analysis operations")
        return

    if not quiet:
        click.secho("🔍 ReconCLI Code Security Analysis", fg="bright_blue", bold=True)
        click.secho("=" * 50, fg="blue")

        # Create output directory
    Path(output).mkdir(parents=True, exist_ok=True)

    # Check cache first if enabled
    if cache_manager:
        cache_params = {
            "tools": list(tool),
            "config": config,
            "severity": severity,
            "exclude": list(exclude),
            "include": list(include),
            "timeout": timeout,
        }

        cached_result = cache_manager.get_cached_result(input, **cache_params)

        if cached_result:
            if not quiet:
                click.secho(
                    f"🚀 Cache hit! Using cached results for {input}", fg="green"
                )
                click.secho(
                    f"   Cache key: {cached_result['cache_metadata']['cache_key'][:16]}...",
                    fg="yellow",
                )
                click.secho(
                    f"   Cached at: {datetime.fromtimestamp(cached_result['cache_metadata']['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}",
                    fg="yellow",
                )

            # Copy cached results to output directory if they exist
            cache_output_dir = cached_result.get("output_directory")
            if (
                cache_output_dir
                and Path(cache_output_dir).exists()
                and cache_output_dir != output
            ):
                import shutil

                try:
                    if Path(output).exists():
                        shutil.rmtree(output)
                    shutil.copytree(cache_output_dir, output)
                    if not quiet:
                        click.secho(f"📁 Cached results copied to {output}", fg="green")
                except Exception as e:
                    if verbose:
                        click.secho(
                            f"⚠️  Could not copy cached results: {e}", fg="yellow"
                        )

            return

    # Create output directory
    Path(output).mkdir(parents=True, exist_ok=True)

    # Semgrep Analysis
    if "semgrep" in tool or "all" in tool:
        run_semgrep_analysis(
            input,
            output,
            config,
            severity,
            exclude,
            include,
            export,
            verbose,
            quiet,
            timeout,
        )

    # Bandit Analysis (Python)
    if "bandit" in tool or "all" in tool:
        run_bandit_analysis(input, output, export, verbose, quiet, timeout)

    # Safety Analysis (Python dependencies)
    if "safety" in tool or "all" in tool:
        run_safety_analysis(input, output, export, verbose, quiet, timeout)

    # Store in database if requested
    if store_db:
        store_codesec_findings(output, target_domain, program, verbose)

    # Save to cache if enabled
    if cache_manager:
        cache_params = {
            "tools": list(tool),
            "config": config,
            "severity": severity,
            "exclude": list(exclude),
            "include": list(include),
            "timeout": timeout,
        }

        cache_result = {
            "analysis_completed": True,
            "output_directory": output,
            "tools_used": list(tool),
            "timestamp": datetime.now().isoformat(),
        }

        cache_manager.save_result_to_cache(input, cache_result, **cache_params)

        if not quiet:
            click.secho(f"💾 Results cached for future use", fg="green")


def run_semgrep_analysis(
    input_path,
    output,
    config,
    severity,
    exclude,
    include,
    export_formats,
    verbose,
    quiet,
    timeout,
):
    """Run Semgrep static analysis."""

    if not shutil.which("semgrep"):
        if not quiet:
            click.secho(
                "❌ Semgrep not found. Install with: pip install semgrep", fg="red"
            )
        return False

    if not quiet:
        click.secho("🔍 Running Semgrep analysis...", fg="cyan")

    # Build Semgrep command
    cmd = ["semgrep"]

    # Add config/rulesets
    if config:
        cmd.extend(["--config", config])
    else:
        # Default security rulesets - only use valid configs
        cmd.extend(["--config", "p/secrets"])

    # Add severity filter
    cmd.extend(["--severity", severity])

    # Don't respect gitignore for comprehensive scanning
    cmd.append("--no-git-ignore")

    # Add excludes
    for exc in exclude:
        cmd.extend(["--exclude", exc])

    # Add includes
    for inc in include:
        cmd.extend(["--include", inc])

    # Add output formats
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in export_formats:
        if fmt == "json":
            cmd.extend(
                ["--json", "--output", f"{output}/semgrep_results_{timestamp}.json"]
            )
        elif fmt == "sarif":
            cmd.extend(
                ["--sarif", "--output", f"{output}/semgrep_results_{timestamp}.sarif"]
            )
        elif fmt == "text":
            cmd.extend(
                ["--text", "--output", f"{output}/semgrep_results_{timestamp}.txt"]
            )

    # Add target path
    cmd.append(input_path)

    if verbose:
        click.secho(f"    Command: {' '.join(cmd)}", fg="blue")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode == 0:
            if not quiet:
                click.secho("✅ Semgrep analysis completed successfully", fg="green")
            return True
        else:
            if not quiet:
                click.secho(
                    f"⚠️ Semgrep completed with warnings: {result.stderr}", fg="yellow"
                )
            return True

    except subprocess.TimeoutExpired:
        if not quiet:
            click.secho("❌ Semgrep analysis timed out", fg="red")
        return False
    except Exception as e:
        if not quiet:
            click.secho(f"❌ Semgrep error: {str(e)}", fg="red")
        return False


def run_bandit_analysis(input_path, output, export_formats, verbose, quiet, timeout):
    """Run Bandit Python security analysis."""

    if not shutil.which("bandit"):
        if not quiet:
            click.secho(
                "⚠️ Bandit not found. Install with: pip install bandit", fg="yellow"
            )
        return False

    if not quiet:
        click.secho("🐍 Running Bandit Python analysis...", fg="cyan")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        # JSON output (always generate)
        cmd = [
            "bandit",
            "-r",
            input_path,
            "-f",
            "json",
            "-o",
            f"{output}/bandit_results_{timestamp}.json",
        ]

        if verbose:
            click.secho(f"    Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # Text output if requested
        if "text" in export_formats:
            cmd_txt = [
                "bandit",
                "-r",
                input_path,
                "-f",
                "txt",
                "-o",
                f"{output}/bandit_results_{timestamp}.txt",
            ]
            subprocess.run(cmd_txt, capture_output=True, timeout=timeout)

        if not quiet:
            click.secho("✅ Bandit analysis completed", fg="green")
        return True

    except subprocess.TimeoutExpired:
        if not quiet:
            click.secho("❌ Bandit analysis timed out", fg="red")
        return False
    except Exception as e:
        if not quiet:
            click.secho(f"❌ Bandit error: {str(e)}", fg="red")
        return False


def run_safety_analysis(input_path, output, export_formats, verbose, quiet, timeout):
    """Run Safety dependency vulnerability analysis."""

    if not shutil.which("safety"):
        if not quiet:
            click.secho(
                "⚠️ Safety not found. Install with: pip install safety", fg="yellow"
            )
        return False

    # Look for requirements files
    requirements_files = []
    if os.path.isdir(input_path):
        for req_file in [
            "requirements.txt",
            "requirements-dev.txt",
            "Pipfile",
            "pyproject.toml",
        ]:
            req_path = os.path.join(input_path, req_file)
            if os.path.exists(req_path):
                requirements_files.append(req_path)

    if not requirements_files:
        if verbose:
            click.secho(
                "⚠️ No requirements files found for Safety analysis", fg="yellow"
            )
        return False

    if not quiet:
        click.secho("🛡️ Running Safety dependency analysis...", fg="cyan")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        for req_file in requirements_files:
            cmd = ["safety", "check", "-r", req_file, "--json"]

            if verbose:
                click.secho(f"    Checking: {req_file}", fg="blue")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )

            # Save results
            filename = f"safety_results_{os.path.basename(req_file)}_{timestamp}.json"
            with open(os.path.join(output, filename), "w") as f:
                f.write(result.stdout)

        if not quiet:
            click.secho("✅ Safety analysis completed", fg="green")
        return True

    except subprocess.TimeoutExpired:
        if not quiet:
            click.secho("❌ Safety analysis timed out", fg="red")
        return False
    except Exception as e:
        if not quiet:
            click.secho(f"❌ Safety error: {str(e)}", fg="red")
        return False


def store_codesec_findings(output_dir, target_domain, program, verbose):
    """Store code security findings in ReconCLI database."""
    try:
        # Import database functions
        from reconcli.db.operations import store_target

        if target_domain:
            store_target(target_domain, program or "unknown")

        # Process JSON results
        for json_file in Path(output_dir).glob("*_results_*.json"):
            with open(json_file) as f:
                findings = json.load(f)

            tool_name = json_file.name.split("_")[0]
            store_codesec_findings(findings, target_domain, tool_name, str(json_file))

        if verbose:
            click.secho("✅ Results stored in database", fg="green")

    except ImportError:
        if verbose:
            click.secho("⚠️ Database module not available", fg="yellow")
    except Exception as e:
        if verbose:
            click.secho(f"❌ Database storage error: {str(e)}", fg="red")


if __name__ == "__main__":
    codeseccli()
