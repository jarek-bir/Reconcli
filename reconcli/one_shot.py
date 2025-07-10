import os
import sys
import subprocess
import shlex
import click
import time
import json
import datetime
import psutil
import platform
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import yaml


@click.command(name="one-shot")
@click.option("--domain", required=True, help="Target domain")
@click.option("--output-dir", required=True, help="Directory to save results")
@click.option("--resolvers", type=click.Path(), help="Resolvers file for DNS")
@click.option("--wordlist", type=click.Path(), help="Wordlist for permutations")
@click.option("--proxy", help="Proxy URL for tools like httpcli or urlcli")
@click.option("--flow", type=click.Path(), help="Path to recon flow YAML for dnscli")
@click.option("--resume", is_flag=True, help="Resume previous oneshot session")
@click.option("--only-dns", is_flag=True, help="Only run DNS module")
@click.option(
    "--profile",
    type=click.Choice(
        ["quick", "comprehensive", "stealth", "aggressive", "bug-bounty", "custom"]
    ),
    default="comprehensive",
    help="Reconnaissance profile",
)
@click.option("--config", type=click.Path(), help="Path to custom configuration file")
@click.option("--parallel", is_flag=True, help="Run compatible modules in parallel")
@click.option(
    "--max-workers",
    type=int,
    default=4,
    help="Maximum worker threads for parallel execution",
)
@click.option(
    "--ai-analysis", is_flag=True, help="Include AI-powered analysis and reporting"
)
@click.option(
    "--notifications", help="Slack/Discord webhook for progress notifications"
)
@click.option(
    "--exclude", multiple=True, help="Exclude specific modules (dns,ips,url,vuln,ai)"
)
@click.option("--include-cloud", is_flag=True, help="Include cloud provider detection")
@click.option(
    "--include-permut", is_flag=True, help="Include advanced permutation generation"
)
@click.option(
    "--verbose", "-v", is_flag=True, help="Verbose output with detailed progress"
)
@click.option(
    "--dry-run", is_flag=True, help="Show what would be executed without running"
)
@click.option(
    "--no-cleanup", is_flag=True, help="Keep intermediate files (don't clean up)"
)
@click.option(
    "--timeout",
    type=int,
    default=3600,
    help="Global timeout in seconds (default: 1 hour)",
)
@click.option("--retry-failed", is_flag=True, help="Retry failed modules once")
def cli(
    domain,
    output_dir,
    resolvers,
    wordlist,
    proxy,
    flow,
    resume,
    only_dns,
    profile,
    config,
    parallel,
    max_workers,
    ai_analysis,
    notifications,
    exclude,
    include_cloud,
    include_permut,
    verbose,
    dry_run,
    no_cleanup,
    timeout,
    retry_failed,
):
    """🚀 OneShot Automated Reconnaissance Pipeline
    
    Advanced automated reconnaissance with AI analysis, parallel execution,
    comprehensive reporting, and enterprise-grade features.
    
    Examples:
        # Quick reconnaissance
        reconcli oneshot --domain example.com --output-dir results --profile quick
        
        # Comprehensive bug bounty reconnaissance
        reconcli oneshot --domain target.com --output-dir results --profile bug-bounty \
          --parallel --ai-analysis --include-cloud --include-permut --max-workers 6
        
        # Stealth reconnaissance with notifications
        reconcli oneshot --domain target.com --output-dir results --profile stealth \
          --notifications "https://hooks.slack.com/..." --proxy http://127.0.0.1:8080
        
        # Custom reconnaissance with timeout and retry
        reconcli oneshot --domain target.com --output-dir results \
          --exclude vuln --timeout 7200 --retry-failed --verbose
          
        # Resume previous session
        reconcli oneshot --domain target.com --output-dir results --resume
        
        # Custom configuration
        reconcli oneshot --domain target.com --output-dir results \
          --profile custom --config custom_recon.yaml
    """

    # Initialize reconnaissance session
    recon_session = ReconSession(
        domain=domain,
        output_dir=output_dir,
        profile=profile,
        verbose=verbose,
        notifications=notifications,
        config_file=config,
        max_workers=max_workers,
        timeout=timeout,
        no_cleanup=no_cleanup,
        retry_failed=retry_failed,
    )

    if dry_run:
        recon_session.show_execution_plan(
            resolvers,
            wordlist,
            proxy,
            flow,
            resume,
            only_dns,
            parallel,
            ai_analysis,
            exclude,
            include_cloud,
            include_permut,
        )
        return

    # Check system resources before starting
    if not recon_session.check_system_resources():
        return

    try:
        recon_session.start()

        # Execute reconnaissance pipeline
        success = recon_session.execute_pipeline(
            resolvers=resolvers,
            wordlist=wordlist,
            proxy=proxy,
            flow=flow,
            resume=resume,
            only_dns=only_dns,
            parallel=parallel,
            ai_analysis=ai_analysis,
            exclude=exclude,
            include_cloud=include_cloud,
            include_permut=include_permut,
        )

        if success:
            recon_session.complete()
        else:
            recon_session.failed()

    except KeyboardInterrupt:
        recon_session.interrupted()
    except TimeoutError:
        recon_session.timeout_exceeded()
    except Exception as e:
        recon_session.error(str(e))


class ReconSession:
    """Advanced reconnaissance session manager with progress tracking and reporting."""

    def __init__(
        self,
        domain: str,
        output_dir: str,
        profile: str,
        verbose: bool = False,
        notifications: Optional[str] = None,
        config_file: Optional[str] = None,
        max_workers: int = 4,
        timeout: int = 3600,
        no_cleanup: bool = False,
        retry_failed: bool = False,
    ):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.profile = profile
        self.verbose = verbose
        self.notifications = notifications
        self.config_file = config_file
        self.max_workers = max_workers
        self.global_timeout = timeout
        self.no_cleanup = no_cleanup
        self.retry_failed = retry_failed
        self.start_time = None
        self.stats = {
            "modules_executed": [],
            "modules_failed": [],
            "modules_retried": [],
            "total_subdomains": 0,
            "total_ips": 0,
            "total_urls": 0,
            "total_vulnerabilities": 0,
            "total_open_ports": 0,
            "execution_time": 0,
            "peak_memory_usage": 0,
            "system_info": {
                "platform": platform.system(),
                "cpu_count": psutil.cpu_count(),
                "memory_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            },
        }

        # Load custom configuration if provided
        self.custom_config = {}
        if config_file and Path(config_file).exists():
            try:
                with open(config_file) as f:
                    self.custom_config = yaml.safe_load(f)
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")

        # Profile configurations
        self.profiles = {
            "quick": {
                "dns_args": "--wordlist-size medium --timeout 30",
                "ip_args": "--scan simple --timeout 15",
                "url_args": "--timeout 60",
                "vuln_args": "--quick-scan",
                "modules": ["dns", "ips", "url"],
            },
            "comprehensive": {
                "dns_args": "--wordlist-size large --all-tools --timeout 120",
                "ip_args": "--scan rustscan --enrich --timeout 60",
                "url_args": "--comprehensive --katana --timeout 300",
                "vuln_args": "--comprehensive",
                "modules": ["dns", "ips", "url", "vuln"],
            },
            "stealth": {
                "dns_args": "--passive-only --timeout 60",
                "ip_args": "--scan simple --stealth --timeout 30",
                "url_args": "--passive-only --timeout 120",
                "vuln_args": "--stealth",
                "modules": ["dns", "ips", "url"],
            },
            "aggressive": {
                "dns_args": "--wordlist-size xlarge --all-tools --brute --timeout 300",
                "ip_args": "--scan nmap --enrich --aggressive --timeout 120",
                "url_args": "--aggressive --katana --depth 5 --timeout 600",
                "vuln_args": "--aggressive --all-templates",
                "modules": ["dns", "ips", "url", "vuln"],
            },
            "bug-bounty": {
                "dns_args": "--wordlist-size large --all-tools --timeout 180",
                "ip_args": "--scan rustscan --enrich --filter-cdn --timeout 90",
                "url_args": "--comprehensive --katana --js-crawl --timeout 400",
                "vuln_args": "--bug-bounty --high-severity",
                "modules": ["dns", "ips", "url", "vuln"],
            },
        }

        # Apply custom configuration if provided
        if self.custom_config:
            if "profiles" in self.custom_config:
                self.profiles.update(self.custom_config["profiles"])
            if "max_workers" in self.custom_config:
                self.max_workers = self.custom_config["max_workers"]

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize session metadata
        self.session_file = self.output_dir / "recon_session.json"
        self.init_session()

    def check_system_resources(self) -> bool:
        """Check if system has sufficient resources for reconnaissance."""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(self.output_dir.parent))

            # Check available memory (require at least 2GB)
            if memory.available < 2 * 1024**3:
                self.log(
                    f"⚠️  Low memory warning: {memory.available / 1024**3:.1f}GB available",
                    "WARNING",
                )

            # Check available disk space (require at least 10GB)
            if disk.free < 10 * 1024**3:
                self.log(
                    f"⚠️  Low disk space warning: {disk.free / 1024**3:.1f}GB available",
                    "WARNING",
                )

            # Check CPU load
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self.log(f"⚠️  High CPU usage warning: {cpu_percent}%", "WARNING")

            self.log(
                f"💻 System resources: {memory.available / 1024**3:.1f}GB RAM, {disk.free / 1024**3:.1f}GB disk",
                "INFO",
            )
            return True

        except Exception as e:
            self.log(f"⚠️  Could not check system resources: {e}", "WARNING")
            return True

    def init_session(self):
        """Initialize reconnaissance session metadata."""
        session_data = {
            "domain": self.domain,
            "profile": self.profile,
            "start_time": datetime.datetime.now().isoformat(),
            "status": "initialized",
            "modules": {},
            "stats": self.stats.copy(),
        }

        with open(self.session_file, "w") as f:
            json.dump(session_data, f, indent=2)

    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with colors and timestamps."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[36m",  # Cyan
            "SUCCESS": "\033[32m",  # Green
            "WARNING": "\033[33m",  # Yellow
            "ERROR": "\033[31m",  # Red
            "PROGRESS": "\033[35m",  # Magenta
        }
        reset = "\033[0m"

        color = colors.get(level, "")
        prefix = f"{color}[ONESHOT-{level}]{reset}"
        print(f"{prefix} [{timestamp}] {message}")

        # Send notification if configured
        if self.notifications and level in ["SUCCESS", "ERROR"]:
            self.send_notification(f"🎯 {self.domain}: {message}")

    def send_notification(self, message: str):
        """Send notification to configured webhook."""
        if not self.notifications:
            return

        try:
            import requests

            data = (
                {"text": message}
                if "slack" in self.notifications
                else {"content": message}
            )
            requests.post(self.notifications, json=data, timeout=10)
        except Exception:
            pass  # Fail silently for notifications

    def show_progress_bar(self, current: int, total: int, module: str, width: int = 50):
        """Display a progress bar for module execution."""
        if not self.verbose:
            return

        percent = (current / total) * 100
        filled = int(width * current // total)
        bar = "█" * filled + "░" * (width - filled)

        print(
            f"\r🔄 {module.upper()}: |{bar}| {percent:.1f}% ({current}/{total})",
            end="",
            flush=True,
        )

        if current == total:
            print()  # New line when complete

    def show_execution_plan(
        self,
        resolvers,
        wordlist,
        proxy,
        flow,
        resume,
        only_dns,
        parallel,
        ai_analysis,
        exclude,
        include_cloud,
        include_permut,
    ):
        """Show what would be executed in dry-run mode."""
        self.log("🔍 DRY RUN - Execution Plan", "INFO")
        print(f"  Domain: {self.domain}")
        print(f"  Profile: {self.profile}")
        print(f"  Output: {self.output_dir}")
        print(f"  Parallel: {parallel}")
        print(f"  AI Analysis: {ai_analysis}")

        modules = self.get_modules_to_execute(
            exclude, only_dns, include_cloud, include_permut, ai_analysis
        )
        print(f"  Modules: {', '.join(modules)}")

        if self.verbose:
            profile_config = self.profiles[self.profile]
            print("\n📋 Detailed Commands:")
            for module in modules:
                cmd = self.build_command(
                    module, profile_config, resolvers, wordlist, proxy, flow, resume
                )
                print(f"  {module.upper()}: {cmd}")

    def start(self):
        """Start reconnaissance session."""
        self.start_time = time.time()
        self.log(f"🚀 Starting reconnaissance for {self.domain}", "INFO")
        self.log(f"📁 Output directory: {self.output_dir}", "INFO")
        self.log(f"🎯 Profile: {self.profile}", "INFO")

        # Update session status
        self.update_session_status("running")

    def execute_pipeline(self, **kwargs) -> bool:
        """Execute the complete reconnaissance pipeline."""
        try:
            exclude = kwargs.get("exclude", [])
            only_dns = kwargs.get("only_dns", False)
            parallel = kwargs.get("parallel", False)
            ai_analysis = kwargs.get("ai_analysis", False)
            include_cloud = kwargs.get("include_cloud", False)
            include_permut = kwargs.get("include_permut", False)

            # Determine modules to execute
            modules = self.get_modules_to_execute(
                exclude, only_dns, include_cloud, include_permut, ai_analysis
            )

            if parallel and len(modules) > 1:
                return self.execute_parallel(modules, **kwargs)
            else:
                return self.execute_sequential(modules, **kwargs)

        except Exception as e:
            self.log(f"❌ Pipeline execution failed: {e}", "ERROR")
            return False

    def get_modules_to_execute(
        self, exclude, only_dns, include_cloud, include_permut, ai_analysis
    ) -> List[str]:
        """Determine which modules to execute based on parameters."""
        base_modules = self.profiles[self.profile]["modules"].copy()

        if only_dns:
            base_modules = ["dns"]

        # Add optional modules
        if include_cloud and "cloud" not in base_modules:
            base_modules.append("cloud")
        if include_permut and "permut" not in base_modules:
            base_modules.append("permut")
        if ai_analysis and "ai" not in base_modules:
            base_modules.append("ai")

        # Remove excluded modules
        return [mod for mod in base_modules if mod not in exclude]

    def execute_sequential(self, modules: List[str], **kwargs) -> bool:
        """Execute modules sequentially with retry support."""
        self.log(f"⚡ Executing {len(modules)} modules sequentially", "INFO")

        for i, module in enumerate(modules, 1):
            self.log(
                f"📋 [{i}/{len(modules)}] Executing {module.upper()} module", "PROGRESS"
            )

            # Monitor memory usage
            memory_usage = psutil.virtual_memory().percent
            if memory_usage > 85:
                self.log(f"⚠️  Memory usage: {memory_usage}%", "WARNING")

            if not self.execute_module_with_retry(module, **kwargs):
                self.log(f"❌ Module {module} failed after retries", "ERROR")
                self.stats["modules_failed"].append(module)
                return False
            else:
                self.log(f"✅ Module {module} completed successfully", "SUCCESS")
                self.stats["modules_executed"].append(module)

                # Update peak memory usage
                current_memory = psutil.virtual_memory().percent
                self.stats["peak_memory_usage"] = max(
                    self.stats["peak_memory_usage"], current_memory
                )

        return True

    def execute_parallel(self, modules: List[str], **kwargs) -> bool:
        """Execute compatible modules in parallel with retry support."""
        # DNS must run first, then we can parallelize others
        if "dns" in modules:
            self.log("📋 [1/2] Executing DNS module (prerequisite)", "PROGRESS")
            if not self.execute_module_with_retry("dns", **kwargs):
                self.log("❌ DNS module failed", "ERROR")
                return False
            modules.remove("dns")
            self.stats["modules_executed"].append("dns")

        if not modules:
            return True

        self.log(
            f"⚡ [2/2] Executing {len(modules)} modules in parallel (max workers: {self.max_workers})",
            "PROGRESS",
        )

        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(modules))
        ) as executor:
            future_to_module = {
                executor.submit(
                    self.execute_module_with_retry, module, **kwargs
                ): module
                for module in modules
            }

            success = True
            completed = 0
            total = len(modules)

            for future in as_completed(future_to_module, timeout=self.global_timeout):
                module = future_to_module[future]
                completed += 1

                # Monitor memory usage
                memory_usage = psutil.virtual_memory().percent
                if memory_usage > 90:
                    self.log(f"⚠️  High memory usage: {memory_usage}%", "WARNING")

                try:
                    if future.result():
                        self.log(
                            f"✅ [{completed}/{total}] Module {module} completed successfully",
                            "SUCCESS",
                        )
                        self.stats["modules_executed"].append(module)
                    else:
                        self.log(
                            f"❌ [{completed}/{total}] Module {module} failed", "ERROR"
                        )
                        self.stats["modules_failed"].append(module)
                        success = False
                except Exception as e:
                    self.log(
                        f"❌ [{completed}/{total}] Module {module} crashed: {e}",
                        "ERROR",
                    )
                    self.stats["modules_failed"].append(module)
                    success = False

        return success

    def execute_module_with_retry(self, module: str, **kwargs) -> bool:
        """Execute a module with retry support."""
        max_retries = 1 if self.retry_failed else 0

        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    self.log(
                        f"🔄 Retrying {module} module (attempt {attempt + 1})", "INFO"
                    )
                    self.stats["modules_retried"].append(
                        f"{module}_attempt_{attempt + 1}"
                    )

                success = self.execute_module(module, **kwargs)
                if success:
                    return True

            except Exception as e:
                self.log(
                    f"❌ Module {module} attempt {attempt + 1} failed: {e}", "ERROR"
                )

            if attempt < max_retries:
                # Wait before retry
                time.sleep(min(5, 2**attempt))

        return False

    def execute_module(self, module: str, **kwargs) -> bool:
        """Execute a specific reconnaissance module."""
        try:
            profile_config = self.profiles[self.profile]

            if module == "dns":
                return self.execute_dns_module(profile_config, **kwargs)
            elif module == "ips":
                return self.execute_ips_module(profile_config, **kwargs)
            elif module == "url":
                return self.execute_url_module(profile_config, **kwargs)
            elif module == "vuln":
                return self.execute_vuln_module(profile_config, **kwargs)
            elif module == "cloud":
                return self.execute_cloud_module(profile_config, **kwargs)
            elif module == "permut":
                return self.execute_permut_module(profile_config, **kwargs)
            elif module == "ai":
                return self.execute_ai_module(profile_config, **kwargs)
            else:
                self.log(f"⚠️  Unknown module: {module}", "WARNING")
                return False

        except Exception as e:
            self.log(f"❌ Module {module} execution failed: {e}", "ERROR")
            return False

    def build_command(
        self,
        module: str,
        profile_config: dict,
        resolvers=None,
        wordlist=None,
        proxy=None,
        flow=None,
        resume=False,
    ) -> str:
        """Build command for specific module."""
        base_cmds = {
            "dns": f"reconcli dns --domain {self.domain} --output-dir {self.output_dir}",
            "ips": f"reconcli ipscli --input {self.output_dir}/ips.txt --output-dir {self.output_dir}/ipscan",
            "url": f"reconcli urlcli --input {self.output_dir}/subs_resolved.txt --output-dir {self.output_dir}/urlscan",
            "vuln": f"reconcli vulncli --input {self.output_dir}/urlscan/urls.json --output-dir {self.output_dir}/vulnscan",
            "cloud": f"reconcli cloudcli --domain {self.domain} --output-dir {self.output_dir}/cloudscan",
            "permut": f"reconcli permutcli --input {self.domain} --output {self.output_dir}/permutations.txt",
            "ai": f"reconcli aicli --vuln-scan {self.output_dir}/urlscan/urls.json --output-dir {self.output_dir}/aiscan",
        }

        cmd = base_cmds.get(module, "")

        # Add profile-specific arguments
        if module in profile_config and "args" in profile_config:
            cmd += f" {profile_config[f'{module}_args']}"

        # Add common arguments
        if resolvers and module in ["dns"]:
            cmd += f" --resolvers {resolvers}"
        if wordlist and module in ["dns", "permut"]:
            cmd += f" --wordlist {wordlist}"
        if proxy and module in ["url", "vuln"]:
            cmd += f" --proxy {proxy}"
        if flow and module == "dns":
            cmd += f" --flow {flow}"
        if resume:
            cmd += " --resume"
        if self.verbose:
            cmd += " --verbose"

        return cmd

    def execute_dns_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute DNS reconnaissance module."""
        cmd = self.build_command("dns", profile_config, **kwargs)

        if self.verbose:
            self.log(f"🔍 DNS Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)

        if result.returncode == 0:
            self.extract_ips_from_dns_results()
            self.update_stats_from_dns()
            return True
        else:
            self.log(f"DNS module error: {result.stderr}", "ERROR")
            return False

    def execute_ips_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute IP scanning module."""
        ips_file = self.output_dir / "ips.txt"
        if not ips_file.exists():
            self.log("❌ No IPs file found for scanning", "ERROR")
            return False

        cmd = self.build_command("ips", profile_config, **kwargs)

        if self.verbose:
            self.log(f"🖥️  IPS Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)

        if result.returncode == 0:
            self.update_stats_from_ips()
            return True
        else:
            self.log(f"IPS module error: {result.stderr}", "ERROR")
            return False

    def execute_url_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute URL discovery module."""
        subs_file = self.output_dir / "subs_resolved.txt"
        if not subs_file.exists():
            self.log("❌ No resolved subdomains file found", "ERROR")
            return False

        cmd = self.build_command("url", profile_config, **kwargs)

        if self.verbose:
            self.log(f"🔗 URL Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)

        if result.returncode == 0:
            self.update_stats_from_url()
            return True
        else:
            self.log(f"URL module error: {result.stderr}", "ERROR")
            return False

    def execute_vuln_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute vulnerability scanning module."""
        urls_file = self.output_dir / "urlscan" / "urls.json"
        if not urls_file.exists():
            self.log("❌ No URLs file found for vulnerability scanning", "ERROR")
            return False

        cmd = self.build_command("vuln", profile_config, **kwargs)

        if self.verbose:
            self.log(f"🛡️  VULN Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)

        if result.returncode == 0:
            self.update_stats_from_vuln()
            return True
        else:
            self.log(f"VULN module error: {result.stderr}", "ERROR")
            return False

    def execute_cloud_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute cloud provider detection module."""
        cmd = self.build_command("cloud", profile_config, **kwargs)

        if self.verbose:
            self.log(f"☁️  CLOUD Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
        return result.returncode == 0

    def execute_permut_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute permutation generation module."""
        cmd = self.build_command("permut", profile_config, **kwargs)

        if self.verbose:
            self.log(f"🔄 PERMUT Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
        return result.returncode == 0

    def execute_ai_module(self, profile_config: dict, **kwargs) -> bool:
        """Execute AI-powered analysis module."""
        cmd = self.build_command("ai", profile_config, **kwargs)
        cmd += " --scan-type comprehensive --persona pentester --integration"

        if self.verbose:
            self.log(f"🧠 AI Command: {cmd}", "INFO")

        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
        return result.returncode == 0

    def extract_ips_from_dns_results(self):
        """Extract IP addresses from DNS results."""
        resolved_file = self.output_dir / "subs_resolved_tagged.txt"
        ips_file = self.output_dir / "ips.txt"

        if resolved_file.exists():
            self.log("📊 Extracting IPs from DNS results...", "INFO")
            with open(resolved_file) as rf, open(ips_file, "w") as wf:
                unique_ips = set()
                for line in rf:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1].count(".") == 3:
                        unique_ips.add(parts[1])

                for ip in sorted(unique_ips):
                    wf.write(ip + "\n")

            self.log(
                f"✅ Exported {len(unique_ips)} unique IPs to {ips_file}", "SUCCESS"
            )
        else:
            self.log(f"⚠️  Could not find {resolved_file}", "WARNING")

    def update_stats_from_dns(self):
        """Update statistics from DNS results."""
        try:
            subs_file = self.output_dir / "subs_resolved.txt"
            if subs_file.exists():
                with open(subs_file) as f:
                    self.stats["total_subdomains"] = len(f.readlines())

            ips_file = self.output_dir / "ips.txt"
            if ips_file.exists():
                with open(ips_file) as f:
                    self.stats["total_ips"] = len(f.readlines())
        except Exception:
            pass

    def update_stats_from_ips(self):
        """Update statistics from IP scanning results."""
        # Could parse scan results for open ports count
        pass

    def update_stats_from_url(self):
        """Update statistics from URL discovery results."""
        try:
            urls_file = self.output_dir / "urlscan" / "urls.json"
            if urls_file.exists():
                with open(urls_file) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.stats["total_urls"] = len(data)
                    elif isinstance(data, dict) and "urls" in data:
                        self.stats["total_urls"] = len(data["urls"])
        except Exception:
            pass

    def update_stats_from_vuln(self):
        """Update statistics from vulnerability scanning results."""
        # Could parse vulnerability results for count
        pass

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

        # Final memory usage update
        self.stats["peak_memory_usage"] = max(
            self.stats.get("peak_memory_usage", 0), psutil.virtual_memory().percent
        )

        self.log("🎉 Reconnaissance completed successfully!", "SUCCESS")
        self.log(
            f"⏱️  Total execution time: {self.stats['execution_time']:.2f} seconds ({self.stats['execution_time']//60:.0f}m {self.stats['execution_time']%60:.0f}s)",
            "INFO",
        )
        self.log(f"📊 Subdomains: {self.stats['total_subdomains']:,}", "INFO")
        self.log(f"🖥️  IPs: {self.stats['total_ips']:,}", "INFO")
        self.log(f"🔗 URLs: {self.stats['total_urls']:,}", "INFO")
        self.log(
            f"� Peak memory usage: {self.stats.get('peak_memory_usage', 0):.1f}%",
            "INFO",
        )

        # Generate summary report
        self.generate_summary_report()

        # Cleanup intermediate files
        self.cleanup_intermediate_files()

        # Create archive if results are significant
        total_findings = (
            self.stats["total_subdomains"]
            + self.stats["total_ips"]
            + self.stats["total_urls"]
        )
        if total_findings > 100:
            archive_path = self.create_archive()
            if archive_path:
                self.log(f"📦 Large result set archived for easy sharing", "INFO")

        self.log(f"📁 Results saved to: {self.output_dir}", "SUCCESS")

        if self.notifications:
            retries_msg = (
                f" ({len(self.stats.get('modules_retried', []))} retries)"
                if self.stats.get("modules_retried")
                else ""
            )
            self.send_notification(
                f"🎯 Reconnaissance completed for {self.domain}! "
                f"Found {self.stats['total_subdomains']:,} subdomains, "
                f"{self.stats['total_ips']:,} IPs, {self.stats['total_urls']:,} URLs"
                f"{retries_msg}"
            )

        # Cleanup intermediate files
        self.cleanup_intermediate_files()

        # Create archive of results
        self.create_archive()

    def failed(self):
        """Mark session as failed."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("failed")
        self.log("❌ Reconnaissance failed", "ERROR")

        if self.notifications:
            self.send_notification(f"❌ Reconnaissance failed for {self.domain}")

    def interrupted(self):
        """Mark session as interrupted."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("interrupted")
        self.log("⏹️  Reconnaissance interrupted by user", "WARNING")

        if self.notifications:
            self.send_notification(f"⏹️ Reconnaissance interrupted for {self.domain}")

    def timeout_exceeded(self):
        """Mark session as timed out."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("timeout")
        self.log(
            f"⏰ Reconnaissance timed out after {self.global_timeout} seconds",
            "WARNING",
        )

        if self.notifications:
            self.send_notification(f"⏰ Reconnaissance timed out for {self.domain}")

    def error(self, error_msg: str):
        """Mark session as error."""
        if self.start_time:
            self.stats["execution_time"] = time.time() - self.start_time
        self.update_session_status("error")
        self.log(f"💥 Reconnaissance error: {error_msg}", "ERROR")

        if self.notifications:
            self.send_notification(
                f"💥 Reconnaissance error for {self.domain}: {error_msg}"
            )

    def generate_summary_report(self):
        """Generate a comprehensive summary report."""
        report_file = self.output_dir / "reconnaissance_summary.md"

        start_time_str = "Unknown"
        if self.start_time:
            start_time_str = datetime.datetime.fromtimestamp(self.start_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        # Calculate efficiency metrics
        total_modules = len(self.stats["modules_executed"]) + len(
            self.stats["modules_failed"]
        )
        success_rate = (
            (len(self.stats["modules_executed"]) / total_modules * 100)
            if total_modules > 0
            else 0
        )
        retries_count = len(self.stats.get("modules_retried", []))

        report_content = f"""# 🎯 Reconnaissance Summary Report

## Target Information
- **🌐 Domain:** `{self.domain}`
- **📝 Profile:** `{self.profile}`
- **⏰ Start Time:** {start_time_str}
- **⌛ Execution Time:** {self.stats['execution_time']:.2f} seconds ({self.stats['execution_time']//60:.0f}m {self.stats['execution_time']%60:.0f}s)
- **💾 Peak Memory Usage:** {self.stats.get('peak_memory_usage', 0):.1f}%

## 📊 Results Summary
- **🔍 Subdomains Discovered:** {self.stats['total_subdomains']:,}
- **🖥️  Unique IPs Found:** {self.stats['total_ips']:,}
- **🔗 URLs Discovered:** {self.stats['total_urls']:,}
- **🛡️  Vulnerabilities Found:** {self.stats['total_vulnerabilities']:,}
- **🚪 Open Ports:** {self.stats.get('total_open_ports', 0):,}

## ⚙️ Execution Statistics
- **✅ Modules Successful:** {len(self.stats['modules_executed'])} ({success_rate:.1f}% success rate)
- **❌ Modules Failed:** {len(self.stats['modules_failed'])}
- **🔄 Module Retries:** {retries_count}
- **🧠 Max Workers Used:** {self.max_workers}

## 📋 Module Results
### ✅ Successful Modules
{chr(10).join(f'- **{mod.upper()}**: Completed successfully' for mod in self.stats['modules_executed']) if self.stats['modules_executed'] else '- None'}

### ❌ Failed Modules  
{chr(10).join(f'- **{mod.upper()}**: Failed to complete' for mod in self.stats['modules_failed']) if self.stats['modules_failed'] else '- None'}

## 🖥️  System Information
- **Platform:** {self.stats.get('system_info', {}).get('platform', 'Unknown')}
- **CPU Cores:** {self.stats.get('system_info', {}).get('cpu_count', 'Unknown')}
- **Total Memory:** {self.stats.get('system_info', {}).get('memory_gb', 'Unknown')} GB

## 📁 File Locations
- **🔍 DNS Results:** `subs_resolved.txt`, `subs_resolved_tagged.txt`
- **🖥️  IP Addresses:** `ips.txt`
- **🔍 IP Scan Results:** `ipscan/`
- **🔗 URL Discovery:** `urlscan/`
- **🛡️  Vulnerability Scan:** `vulnscan/`
- **☁️  Cloud Results:** `cloudscan/` (if enabled)
- **🧠 AI Analysis:** `aiscan/` (if enabled)
- **📊 Session Metadata:** `recon_session.json`

## 🚀 Next Steps
1. **🔍 Review discovered subdomains** for interesting targets and potential attack vectors
2. **🖥️  Analyze IP scan results** for exposed services and unusual ports
3. **🔗 Investigate URLs** for potential entry points and hidden endpoints
4. **🛡️  Review vulnerability scan results** for security issues and misconfigurations
5. **🧠 Examine AI analysis** (if available) for insights and recommendations
6. **🎯 Consider manual testing** of high-value targets identified
7. **📋 Cross-reference findings** with threat intelligence and CVE databases

## 🔧 Performance Notes
- Execution completed in {self.stats['execution_time']:.1f} seconds
- Peak memory usage: {self.stats.get('peak_memory_usage', 0):.1f}%
- {retries_count} module retries performed
- {len(self.stats['modules_executed'])} out of {total_modules} modules successful

---
*🚀 Generated by ReconCLI OneShot Pipeline v2.0*  
*Report generated on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}*
"""

        with open(report_file, "w") as f:
            f.write(report_content)

        self.log(f"📋 Enhanced summary report generated: {report_file}", "SUCCESS")

    def cleanup_intermediate_files(self):
        """Clean up intermediate files if cleanup is enabled."""
        if self.no_cleanup:
            return

        cleanup_files = [
            "*.tmp",
            "*.temp",
            "*.log",
            "*_temp.txt",
            "*.bak",
        ]

        cleaned_count = 0
        for pattern in cleanup_files:
            for file_path in self.output_dir.glob(pattern):
                try:
                    file_path.unlink()
                    cleaned_count += 1
                except Exception:
                    pass

        if cleaned_count > 0:
            self.log(f"🧹 Cleaned up {cleaned_count} intermediate files", "INFO")

    def create_archive(self):
        """Create a compressed archive of results."""
        try:
            import tarfile

            archive_path = (
                self.output_dir.parent
                / f"{self.domain}_recon_{int(time.time())}.tar.gz"
            )

            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(self.output_dir, arcname=self.domain)

            self.log(f"📦 Results archived to: {archive_path}", "SUCCESS")
            return archive_path
        except Exception as e:
            self.log(f"⚠️  Could not create archive: {e}", "WARNING")
            return None


if __name__ == "__main__":
    cli()
