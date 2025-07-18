import hashlib
import json
import os
import platform
import shutil
import subprocess  # nosec B404 - subprocess required for tool verification
import sys
from datetime import datetime
from pathlib import Path

import click

REQUIRED_TOOLS = [
    # Subdomain Enumeration
    "amass",
    "sublist3r",
    "subfinder",
    "assetfinder",
    "findomain",
    # Web Technologies
    "httpx",
    "nuclei",
    "dalfox",
    "ffuf",
    "gobuster",
    # Secret Discovery
    "gitleaks",
    "trufflehog",
    "jsubfinder",
    "shhgit",
    "semgrep",
    # API & GraphQL
    "uncover",
    "graphw00f",
    # Web Crawling & URL Discovery
    "hakrawler",
    "gau",
    "waybackurls",
    "katana",
    "gospider",
    "cariddi",
    # Vulnerability Assessment
    "jaeles",
    "gowitness",
    "aquatone",
    # Network & Port Scanning
    "nmap",
    "masscan",
    "naabu",
    # Additional Tools
    "waybackurls",
    "unfurl",
    "anew",
    "qsreplace",
]

OPTIONAL_TOOLS = [
    "wafw00f",
    "whatwaf",
    "gotestwaf",
    "subzy",
    "tko-subs",
    "openredirex",
    "kxss",
    "mantra",
]

PYTHON_PACKAGES = [
    "click",
    "requests",
    "beautifulsoup4",
    "lxml",
    "colorama",
    "tqdm",
    "pyyaml",
    "python-dotenv",
]

REQUIRED_DIRS = [
    "output",
    "output/secrets",
    "output/vulns",
    "output/reports",
    "workflows",
    "wordlists",
    "wordlists/subdomains",
    "wordlists/directories",
    "wordlists/parameters",
    "configs",
    "templates",
]

CONFIG_FILES = [
    "configs/nuclei-config.yaml",
    "configs/httpx-config.yaml",
    "configs/amass-config.ini",
    "wordlists/subdomains/common.txt",
    "wordlists/directories/common.txt",
]
ENV_FILE = ".env_secrets"
REQUIRED_KEYS = ["SHODAN_API_KEY", "WHOISFREAKS_API_KEY", "FOFA_EMAIL", "FOFA_KEY"]

# Programming languages and environments to check
PROGRAMMING_ENVIRONMENTS = [
    {"name": "Go", "command": "go", "version_flag": "version"},
    {"name": "Python", "command": "python3", "version_flag": "--version"},
    {"name": "Python", "command": "python", "version_flag": "--version"},
    {"name": "Ruby", "command": "ruby", "version_flag": "--version"},
    {"name": "Perl", "command": "perl", "version_flag": "--version"},
    {"name": "Node.js", "command": "node", "version_flag": "--version"},
    {"name": "NPM", "command": "npm", "version_flag": "--version"},
    {"name": "Pip", "command": "pip3", "version_flag": "--version"},
    {"name": "Pip", "command": "pip", "version_flag": "--version"},
    {"name": "Git", "command": "git", "version_flag": "--version"},
    {"name": "Curl", "command": "curl", "version_flag": "--version"},
    {"name": "Wget", "command": "wget", "version_flag": "--version"},
]

# Optional tool hash whitelist (disabled for amass 3.2 - user preference)
TOOL_HASHES = {
    # "amass": "disabled",  # User prefers amass 3.2 for better output format
    # "dalfox": "abc123deadbeef...",
}

# Tools with user-preferred versions
PREFERRED_VERSIONS = {
    "amass": "3.2",  # User prefers v3.2 for cleaner output format
}


@click.command()
@click.option("--all", is_flag=True, help="Run all checks.")
@click.option("--tools", is_flag=True, help="Check required tools.")
@click.option("--optional", is_flag=True, help="Check optional tools.")
@click.option("--python", is_flag=True, help="Check Python packages.")
@click.option("--env", is_flag=True, help="Check .env_secrets file.")
@click.option("--structure", is_flag=True, help="Check reconcli folder structure.")
@click.option("--configs", is_flag=True, help="Check configuration files.")
@click.option("--permissions", is_flag=True, help="Check file permissions.")
@click.option("--system", is_flag=True, help="Check system requirements.")
@click.option("--network", is_flag=True, help="Test network connectivity.")
@click.option(
    "--paths", is_flag=True, help="Check environment paths for programming languages."
)
@click.option("--fix", is_flag=True, help="Fix issues if possible.")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Check everything but don't fix anything. Report only.",
)
@click.option("--strict", is_flag=True, help="Enable strict hash and alias checking.")
@click.option(
    "--export",
    type=click.Choice(["json", "markdown", "html"]),
    help="Export format for report.",
)
@click.option("--output-dir", default="output", help="Output directory for reports.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--quiet", "-q", is_flag=True, help="Minimize output.")
def doctorcli(
    all,
    tools,
    optional,
    python,
    env,
    structure,
    configs,
    permissions,
    system,
    network,
    paths,
    fix,
    dry_run,
    strict,
    export,
    output_dir,
    verbose,
    quiet,
):
    """🩺 ReconCLI Doctor - Diagnose and fix your reconnaissance environment."""

    # If no specific checks are requested, run all checks
    if not any(
        [
            all,
            tools,
            optional,
            python,
            env,
            structure,
            configs,
            permissions,
            system,
            network,
            paths,
        ]
    ):
        all = True

    # Dry-run mode overrides fix flag
    if dry_run:
        fix = False
        if verbose and not quiet:
            click.secho(
                "🔍 Running in dry-run mode - no fixes will be applied",
                fg="yellow",
                bold=True,
            )

    if not quiet:
        click.secho(
            "🩺 ReconCLI Doctor - Environment Diagnostic Tool",
            fg="bright_blue",
            bold=True,
        )
        click.secho("=" * 50, fg="blue")

    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "system_info": get_system_info() if (all or system) else {},
        "tools": [],
        "optional_tools": [],
        "python_packages": [],
        "env": {},
        "structure": {},
        "configs": {},
        "permissions": {},
        "network": {},
        "paths": {},
        "strict": strict,
        "dry_run": dry_run,
        "summary": {"total_issues": 0, "fixed_issues": 0},
    }

    # System Information Check
    if all or system:
        if not quiet:
            click.secho("\n🖥️  System Information...", fg="cyan")
        system_info = get_system_info()
        report["system_info"] = system_info

        if verbose:
            click.secho(
                f"    OS: {system_info['os']} {system_info['version']}", fg="white"
            )
            click.secho(f"    Python: {system_info['python_version']}", fg="white")
            click.secho(f"    Architecture: {system_info['architecture']}", fg="white")

    # Required Tools Check
    if all or tools:
        if not quiet:
            click.secho("\n🔧 Checking required tools...", fg="cyan")
        check_tools(REQUIRED_TOOLS, report, "tools", verbose, quiet, fix, dry_run)

    # Optional Tools Check
    if all or optional:
        if not quiet:
            click.secho("\n🔧 Checking optional tools...", fg="cyan")
        check_tools(
            OPTIONAL_TOOLS, report, "optional_tools", verbose, quiet, fix, dry_run
        )

    # Python Packages Check
    if all or python:
        if not quiet:
            click.secho("\n🐍 Checking Python packages...", fg="cyan")
        check_python_packages(PYTHON_PACKAGES, report, verbose, quiet, fix, dry_run)

    # Environment File Check
    if all or env:
        if not quiet:
            click.secho("\n🔐 Checking .env_secrets...", fg="cyan")
        check_env_file(report, verbose, quiet, fix, dry_run)

    # Directory Structure Check
    if all or structure:
        if not quiet:
            click.secho("\n📁 Checking folder structure...", fg="cyan")
        check_directory_structure(report, verbose, quiet, fix, dry_run)

    # Configuration Files Check
    if all or configs:
        if not quiet:
            click.secho("\n⚙️  Checking configuration files...", fg="cyan")
        check_config_files(report, verbose, quiet, fix, dry_run)

    # Permissions Check
    if all or permissions:
        if not quiet:
            click.secho("\n🔒 Checking file permissions...", fg="cyan")
        check_permissions(report, verbose, quiet, fix, dry_run)

    # Network Connectivity Check
    if all or network:
        if not quiet:
            click.secho("\n🌐 Testing network connectivity...", fg="cyan")
        check_network_connectivity(report, verbose, quiet)

    # Programming Environments Path Check
    if all or paths:
        if not quiet:
            click.secho("\n🛤️  Checking programming environment paths...", fg="cyan")
        check_programming_paths(report, verbose, quiet)

    # Generate and save report
    if not quiet:
        click.secho("\n📊 Generating report...", fg="cyan")

    save_report(report, export, output_dir, verbose)
    print_summary(report, quiet)

    if not quiet:
        click.secho(
            f"\n✅ Doctor scan complete. Report saved to {output_dir}/",
            fg="bright_green",
            bold=True,
        )

        if dry_run:
            click.secho(
                "🔍 Dry-run mode: No changes were made to the system.",
                fg="yellow",
                bold=True,
            )


def get_system_info():
    """Get system information."""
    return {
        "os": platform.system(),
        "version": platform.release(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "Unknown",
        "hostname": platform.node(),
    }


def check_tools(tools_list, report, key, verbose, quiet, fix, dry_run):
    """Check if tools are installed."""
    for tool in tools_list:
        path = shutil.which(tool)
        result = {
            "tool": tool,
            "found": False,
            "version": None,
            "path": None,
            "hash": None,
            "executable": False,
        }

        if path:
            result["found"] = True
            result["path"] = path
            result["version"] = get_version(tool)
            result["executable"] = os.access(path, os.X_OK)

            if verbose:
                result["hash"] = sha256sum(path)
                expected = TOOL_HASHES.get(tool)

                # Special handling for user's preferred amass 3.2
                if tool == "amass" and "3.2" in result["version"]:
                    if not quiet:
                        click.secho(
                            f"    ✅ {tool} OK ({result['version']} - preferred version)",
                            fg="green",
                        )
                elif expected and result["hash"] != expected:
                    if not quiet:
                        click.secho(f"    ⚠️  {tool} hash mismatch!", fg="yellow")
                else:
                    if not quiet:
                        click.secho(
                            f"    ✅ {tool} OK ({result['version']})", fg="green"
                        )
            else:
                if not quiet:
                    click.secho(f"    ✅ {tool} found: {result['version']}", fg="green")
        else:
            if not quiet:
                click.secho(f"    ❌ {tool} not found!", fg="red")
            report["summary"]["total_issues"] += 1

            if fix and not dry_run and tool in ["ffuf", "gobuster", "httpx"]:
                install_suggestion = get_install_suggestion(tool)
                if install_suggestion and not quiet:
                    click.secho(
                        f"       💡 Install with: {install_suggestion}", fg="blue"
                    )
            elif dry_run and tool in ["ffuf", "gobuster", "httpx"]:
                install_suggestion = get_install_suggestion(tool)
                if install_suggestion and not quiet:
                    click.secho(
                        f"       💡 Would install with: {install_suggestion}", fg="cyan"
                    )

        report[key].append(result)


def check_python_packages(packages, report, verbose, quiet, fix, dry_run):
    """Check Python packages."""
    for package in packages:
        result = {"package": package, "installed": False, "version": None}

        try:
            import importlib

            module = importlib.import_module(package.replace("-", "_"))
            result["installed"] = True
            result["version"] = getattr(module, "__version__", "Unknown")

            if not quiet:
                click.secho(f"    ✅ {package} ({result['version']})", fg="green")
        except ImportError:
            if not quiet:
                click.secho(f"    ❌ {package} not installed", fg="red")
            report["summary"]["total_issues"] += 1

            if fix and not dry_run and not quiet:
                click.secho(f"       💡 Install with: pip install {package}", fg="blue")
            elif dry_run and not quiet:
                click.secho(
                    f"       💡 Would install with: pip install {package}", fg="cyan"
                )

        report["python_packages"].append(result)


def check_env_file(report, verbose, quiet, fix, dry_run):
    """Check environment file."""
    env_status = {"exists": False, "keys": {}, "created": False}

    if os.path.isfile(ENV_FILE):
        env_status["exists"] = True
        with open(ENV_FILE) as f:
            content = f.read()
            for key in REQUIRED_KEYS:
                found = key in content and f"{key}=" in content
                has_value = found and content.split(f"{key}=")[1].split("\n")[0].strip()

                env_status["keys"][key] = {
                    "present": found,
                    "has_value": bool(has_value) if found else False,
                }

                if found:
                    if has_value:
                        if not quiet:
                            click.secho(f"    ✅ {key} configured", fg="green")
                    else:
                        if not quiet:
                            click.secho(f"    ⚠️  {key} present but empty", fg="yellow")
                else:
                    if not quiet:
                        click.secho(f"    ❌ {key} missing", fg="red")
                    report["summary"]["total_issues"] += 1
    else:
        if not quiet:
            click.secho(f"    ❌ {ENV_FILE} not found!", fg="red")
        report["summary"]["total_issues"] += 1

        if fix and not dry_run:
            with open(ENV_FILE, "w") as f:
                f.write("# ReconCLI Environment Variables\n")
                f.write("# Add your API keys below\n\n")
                for key in REQUIRED_KEYS:
                    f.write(f"{key}=\n")
            if not quiet:
                click.secho(f"    ✅ Created sample {ENV_FILE}", fg="green")
            env_status["created"] = True
            report["summary"]["fixed_issues"] += 1
        elif dry_run and not quiet:
            click.secho(f"    💡 Would create sample {ENV_FILE}", fg="cyan")

    report["env"] = env_status


def check_directory_structure(report, verbose, quiet, fix, dry_run):
    """Check directory structure."""
    structure_status = {}

    for d in REQUIRED_DIRS:
        path = Path(d)
        exists = path.exists() and path.is_dir()
        structure_status[d] = {
            "exists": exists,
            "writable": exists and os.access(path, os.W_OK),
            "created": False,
        }

        if exists:
            if not quiet:
                click.secho(f"    ✅ {d}/ exists", fg="green")
        else:
            if not quiet:
                click.secho(f"    ❌ {d}/ missing", fg="red")
            report["summary"]["total_issues"] += 1

            if fix and not dry_run:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    if not quiet:
                        click.secho(f"    ✅ Created {d}/", fg="green")
                    structure_status[d]["created"] = True
                    structure_status[d]["exists"] = True
                    report["summary"]["fixed_issues"] += 1
                except Exception as e:
                    if not quiet:
                        click.secho(f"    ❌ Failed to create {d}/: {e}", fg="red")
            elif dry_run and not quiet:
                click.secho(f"    💡 Would create {d}/", fg="cyan")

    report["structure"] = structure_status


def check_config_files(report, verbose, quiet, fix, dry_run):
    """Check configuration files."""
    config_status = {}

    for config_file in CONFIG_FILES:
        path = Path(config_file)
        exists = path.exists() and path.is_file()

        config_status[config_file] = {
            "exists": exists,
            "readable": exists and os.access(path, os.R_OK),
            "created": False,
        }

        if exists:
            if not quiet:
                click.secho(f"    ✅ {config_file} exists", fg="green")
        else:
            if not quiet:
                click.secho(f"    ⚠️  {config_file} missing", fg="yellow")

            if fix and not dry_run:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    create_default_config(config_file, path)
                    if not quiet:
                        click.secho(f"    ✅ Created default {config_file}", fg="green")
                    config_status[config_file]["created"] = True
                    config_status[config_file]["exists"] = True
                    report["summary"]["fixed_issues"] += 1
                except Exception as e:
                    if not quiet:
                        click.secho(
                            f"    ❌ Failed to create {config_file}: {e}", fg="red"
                        )
            elif dry_run and not quiet:
                click.secho(f"    💡 Would create default {config_file}", fg="cyan")

    report["configs"] = config_status


def check_permissions(report, verbose, quiet, fix, dry_run):
    """Check file permissions."""
    permissions_status = {}

    critical_paths = ["output", "wordlists", "configs", ENV_FILE]

    for path_str in critical_paths:
        path = Path(path_str)
        if path.exists():
            readable = os.access(path, os.R_OK)
            writable = os.access(path, os.W_OK)
            executable = os.access(path, os.X_OK) if path.is_dir() else True

            permissions_status[path_str] = {
                "readable": readable,
                "writable": writable,
                "executable": executable,
                "fixed": False,
            }

            if readable and writable and executable:
                if not quiet:
                    click.secho(f"    ✅ {path_str} permissions OK", fg="green")
            else:
                if not quiet:
                    click.secho(f"    ⚠️  {path_str} permission issues", fg="yellow")

                if fix and not dry_run:
                    try:
                        if path.is_dir():
                            os.chmod(
                                path, 0o755
                            )  # nosec B103 - Standard directory permissions for config dirs
                        else:
                            os.chmod(
                                path, 0o644
                            )  # nosec B103 - Standard file permissions for config files
                        permissions_status[path_str]["fixed"] = True
                        if not quiet:
                            click.secho(
                                f"    ✅ Fixed permissions for {path_str}", fg="green"
                            )
                        report["summary"]["fixed_issues"] += 1
                    except Exception as e:
                        if not quiet:
                            click.secho(
                                f"    ❌ Failed to fix permissions for {path_str}: {e}",
                                fg="red",
                            )
                elif dry_run and not quiet:
                    perm_mode = "755" if path.is_dir() else "644"
                    click.secho(
                        f"    💡 Would fix permissions to {perm_mode} for {path_str}",
                        fg="cyan",
                    )

    report["permissions"] = permissions_status


def check_network_connectivity(report, verbose, quiet):
    """Check network connectivity to common reconnaissance targets."""
    test_urls = [
        "github.com",
        "api.shodan.io",
        "crt.sh",
        "web.archive.org",
        "api.whoisfreaks.com",
    ]

    network_status = {}

    for url in test_urls:
        try:
            # Use full path to ping for security
            ping_path = shutil.which("ping")
            if not ping_path:
                if not quiet:
                    click.secho(
                        f"    ❌ {url} test failed: ping command not found", fg="red"
                    )
                network_status[url] = {"reachable": False, "error": "ping not found"}
                continue

            # nosec B603 - using full path to ping with validated input
            result = subprocess.run(
                [ping_path, "-c", "1", "-W", "3", url],
                capture_output=True,
                text=True,
                timeout=5,
            )  # nosec B603

            success = result.returncode == 0
            network_status[url] = {
                "reachable": success,
                "response_time": "OK" if success else "Failed",
            }

            if success:
                if not quiet:
                    click.secho(f"    ✅ {url} reachable", fg="green")
            else:
                if not quiet:
                    click.secho(f"    ❌ {url} unreachable", fg="red")

        except Exception as e:
            network_status[url] = {"reachable": False, "error": str(e)}
            if not quiet:
                click.secho(f"    ❌ {url} test failed: {e}", fg="red")

    report["network"] = network_status


def check_programming_paths(report, verbose, quiet):
    """Check programming language environments and their paths."""
    paths_status = {}

    # Check PATH environment variable
    path_env = os.environ.get("PATH", "")
    if not quiet:
        click.secho(
            f"    📍 Current PATH has {len(path_env.split(':'))} directories", fg="blue"
        )

    paths_status["path_info"] = {
        "total_dirs": len(path_env.split(":")),
        "path_variable": path_env[:100] + "..." if len(path_env) > 100 else path_env,
    }

    # Check each programming environment
    environments_found = {}

    for env in PROGRAMMING_ENVIRONMENTS:
        name = env["name"]
        command = env["command"]
        version_flag = env["version_flag"]

        path = shutil.which(command)
        if path:
            version = get_environment_version(command, version_flag)

            if name not in environments_found:
                environments_found[name] = []

            environments_found[name].append(
                {
                    "command": command,
                    "path": path,
                    "version": version,
                    "executable": os.access(path, os.X_OK),
                }
            )

            if not quiet:
                click.secho(
                    f"    ✅ {name} ({command}): {version} at {path}", fg="green"
                )
        else:
            if not quiet:
                click.secho(f"    ❌ {name} ({command}): not found in PATH", fg="red")

    paths_status["environments"] = environments_found

    # Check important directories in PATH
    important_dirs = [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/local/go/bin",
        "~/.local/bin",
        "~/go/bin",
    ]
    paths_status["important_dirs"] = {}

    for dir_path in important_dirs:
        expanded_path = os.path.expanduser(dir_path)
        exists = os.path.exists(expanded_path)
        in_path = dir_path in path_env or expanded_path in path_env

        paths_status["important_dirs"][dir_path] = {
            "exists": exists,
            "in_path": in_path,
            "expanded": expanded_path,
        }

        if verbose:
            status = "✅" if exists and in_path else ("⚠️" if exists else "❌")
            state = (
                "exists & in PATH"
                if exists and in_path
                else ("exists but not in PATH" if exists else "doesn't exist")
            )
            if not quiet:
                click.secho(f"    {status} {dir_path}: {state}", fg="white")

    # Summary
    total_envs = len(set(env["name"] for env in PROGRAMMING_ENVIRONMENTS))
    found_envs = len(environments_found)

    if not quiet:
        click.secho(
            f"    📊 Found {found_envs}/{total_envs} programming environments",
            fg="blue",
        )

    paths_status["summary"] = {
        "total_environments": total_envs,
        "found_environments": found_envs,
    }

    report["paths"] = paths_status


def get_environment_version(command, version_flag):
    """Get version of a programming environment."""
    try:
        # nosec B603 - command and flag are from predefined list
        result = subprocess.run(
            [command, version_flag], capture_output=True, text=True, timeout=3
        )  # nosec B603

        if result.returncode == 0:
            output = result.stdout.strip() or result.stderr.strip()
            # Extract first line and truncate if too long
            first_line = output.split("\n")[0]
            return first_line[:80] if len(first_line) > 80 else first_line
        else:
            return "version check failed"

    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        FileNotFoundError,
    ):
        return "unknown"


def create_default_config(config_file, path):
    """Create default configuration files."""
    if "nuclei" in config_file:
        content = """# Nuclei Configuration
update-templates: true
silent: false
no-color: false
"""
    elif "httpx" in config_file:
        content = """# HTTPx Configuration
threads: 50
timeout: 10
retries: 2
"""
    elif "amass" in config_file:
        content = """# Amass Configuration
[scope]
port = 80,443,8080,8443

[datasources]
minimum_ttl = 1440
"""
    elif "common.txt" in config_file:
        if "subdomains" in config_file:
            content = """admin
api
app
blog
cdn
dev
ftp
mail
shop
test
www
"""
        else:
            content = """admin
api
backup
config
test
uploads
"""
    else:
        content = f"# Default configuration for {config_file}\n"

    with open(path, "w") as f:
        f.write(content)


def get_install_suggestion(tool):
    """Get installation suggestion for tools."""
    suggestions = {
        "ffuf": "go install github.com/ffuf/ffuf@latest",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "# For v3.2 (preferred): download from GitHub releases or build from v3.2 tag",
        "gitleaks": "go install github.com/gitleaks/gitleaks/v8@latest",
        "trufflehog": "go install github.com/trufflesecurity/trufflehog/v3@latest",
        "semgrep": "pip install semgrep",
    }
    return suggestions.get(tool)


def print_summary(report, quiet):
    """Print summary of the diagnostic."""
    if quiet:
        return

    summary = report["summary"]
    total_tools = len(report["tools"]) + len(report["optional_tools"])
    found_tools = sum(
        1 for t in report["tools"] + report["optional_tools"] if t["found"]
    )

    click.secho("\n📋 SUMMARY", fg="bright_blue", bold=True)
    click.secho("=" * 30, fg="blue")

    click.secho(
        f"🔧 Tools: {found_tools}/{total_tools} found",
        fg="green" if found_tools == total_tools else "yellow",
    )

    if report["python_packages"]:
        found_packages = sum(1 for p in report["python_packages"] if p["installed"])
        total_packages = len(report["python_packages"])
        click.secho(
            f"🐍 Python packages: {found_packages}/{total_packages} installed",
            fg="green" if found_packages == total_packages else "yellow",
        )

    if summary["total_issues"] > 0:
        click.secho(f"⚠️  Issues found: {summary['total_issues']}", fg="yellow")
        if summary["fixed_issues"] > 0:
            click.secho(f"✅ Issues fixed: {summary['fixed_issues']}", fg="green")
    else:
        click.secho("✅ No issues found!", fg="green")


def get_version(tool):
    """Get version of a tool."""
    version_flags = ["--version", "-v", "-V", "version", "--help"]

    for flag in version_flags:
        try:
            # nosec B603 - tool name is validated, flag is from predefined list
            result = subprocess.run(
                [tool, flag], capture_output=True, text=True, timeout=5
            )  # nosec B603

            if result.returncode == 0 and result.stdout:
                # Extract version from output (first line, first word with numbers)
                output = result.stdout.strip().split("\n")[0]
                # Look for version patterns like "v1.2.3", "1.2.3", "version 1.2.3"
                import re

                version_match = re.search(r"v?(\d+\.[\d\.]+)", output)
                if version_match:
                    return version_match.group(1)
                return output[:50]  # Return first 50 chars if no version pattern found

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ):
            continue

    return "unknown"


def sha256sum(filename):
    """Calculate SHA256 hash of a file."""
    try:
        with open(filename, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError):
        return None


def save_report(report, export_format, output_dir, verbose):
    """Save diagnostic report in various formats."""
    os.makedirs(output_dir, exist_ok=True)

    # Always save JSON
    json_file = Path(output_dir) / "doctor_report.json"
    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)

    # Save Markdown
    markdown_file = Path(output_dir) / "doctor_report.md"
    save_markdown_report(report, markdown_file)

    # Save HTML if requested
    if export_format == "html":
        html_file = Path(output_dir) / "doctor_report.html"
        save_html_report(report, html_file)

    if verbose:
        click.secho("    📄 Reports saved:", fg="blue")
        click.secho(f"    - JSON: {json_file}", fg="white")
        click.secho(f"    - Markdown: {markdown_file}", fg="white")
        if export_format == "html":
            click.secho(f"    - HTML: {html_file}", fg="white")


def save_markdown_report(report, file_path):
    """Save markdown report."""
    with open(file_path, "w") as f:
        f.write("# 🩺 ReconCLI Doctor Report\n\n")
        f.write(f"**Generated:** {report['timestamp']}\n\n")

        # System Information
        if report.get("system_info"):
            f.write("## 🖥️ System Information\n\n")
            sys_info = report["system_info"]
            f.write(f"- **OS:** {sys_info.get('os')} {sys_info.get('version')}\n")
            f.write(f"- **Python:** {sys_info.get('python_version')}\n")
            f.write(f"- **Architecture:** {sys_info.get('architecture')}\n")
            f.write(f"- **Hostname:** {sys_info.get('hostname')}\n\n")

        # Tools Section
        if report.get("tools"):
            f.write("## 🔧 Required Tools\n\n")
            for tool in report["tools"]:
                status = "✅" if tool["found"] else "❌"
                version = f" – {tool.get('version', 'N/A')}" if tool["found"] else ""
                f.write(f"- {status} `{tool['tool']}`{version}\n")
            f.write("\n")

        # Optional Tools
        if report.get("optional_tools"):
            f.write("## 🔧 Optional Tools\n\n")
            for tool in report["optional_tools"]:
                status = "✅" if tool["found"] else "⚠️"
                version = f" – {tool.get('version', 'N/A')}" if tool["found"] else ""
                f.write(f"- {status} `{tool['tool']}`{version}\n")
            f.write("\n")

        # Python Packages
        if report.get("python_packages"):
            f.write("## 🐍 Python Packages\n\n")
            for pkg in report["python_packages"]:
                status = "✅" if pkg["installed"] else "❌"
                version = f" – {pkg.get('version', 'N/A')}" if pkg["installed"] else ""
                f.write(f"- {status} `{pkg['package']}`{version}\n")
            f.write("\n")

        # Environment
        if report.get("env", {}).get("keys"):
            f.write("## 🔐 Environment Variables\n\n")
            for key, info in report["env"]["keys"].items():
                if isinstance(info, dict):
                    status = (
                        "✅"
                        if info.get("has_value")
                        else ("⚠️" if info.get("present") else "❌")
                    )
                    state = (
                        "configured"
                        if info.get("has_value")
                        else ("empty" if info.get("present") else "missing")
                    )
                else:
                    status = "✅" if info else "❌"
                    state = "present" if info else "missing"
                f.write(f"- {status} `{key}` – {state}\n")
            f.write("\n")

        # Directory Structure
        if report.get("structure"):
            f.write("## 📁 Directory Structure\n\n")
            for directory, info in report["structure"].items():
                if isinstance(info, dict):
                    status = "✅" if info.get("exists") else "❌"
                    extra = " (created)" if info.get("created") else ""
                else:
                    status = "✅" if info else "❌"
                    extra = ""
                f.write(f"- {status} `{directory}/`{extra}\n")
            f.write("\n")

        # Programming Environment Paths
        if report.get("paths", {}).get("environments"):
            f.write("## 🛤️ Programming Environment Paths\n\n")
            envs = report["paths"]["environments"]
            for env_name, instances in envs.items():
                for instance in instances:
                    f.write(
                        f"- ✅ **{env_name}** ({instance['command']}) – {instance['version']}\n"
                    )
                    f.write(f"  - Path: `{instance['path']}`\n")
            f.write("\n")

            # PATH summary
            path_info = report["paths"].get("path_info", {})
            if path_info:
                f.write(
                    f"**PATH Summary:** {path_info.get('total_dirs', 0)} directories in PATH\n\n"
                )

        # Summary
        summary = report.get("summary", {})
        f.write("## 📊 Summary\n\n")
        if summary.get("total_issues", 0) > 0:
            f.write(f"- **Issues Found:** {summary['total_issues']}\n")
            if summary.get("fixed_issues", 0) > 0:
                f.write(f"- **Issues Fixed:** {summary['fixed_issues']}\n")
        else:
            f.write("- **Status:** ✅ No issues found!\n")


def save_html_report(report, file_path):
    """Save HTML report with styling."""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ReconCLI Doctor Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .status-ok {{ color: #27ae60; }}
        .status-warn {{ color: #f39c12; }}
        .status-error {{ color: #e74c3c; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ padding: 5px 0; border-bottom: 1px solid #eee; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🩺 ReconCLI Doctor Report</h1>
        <p class="timestamp">Generated: {report["timestamp"]}</p>
"""

    # Add system info if available
    if report.get("system_info"):
        sys_info = report["system_info"]
        html_content += f"""
        <h2>🖥️ System Information</h2>
        <ul>
            <li><strong>OS:</strong> {sys_info.get("os")} {sys_info.get("version")}</li>
            <li><strong>Python:</strong> {sys_info.get("python_version")}</li>
            <li><strong>Architecture:</strong> {sys_info.get("architecture")}</li>
        </ul>
"""

    # Add tools section
    if report.get("tools"):
        html_content += "<h2>🔧 Required Tools</h2><ul>"
        for tool in report["tools"]:
            status_class = "status-ok" if tool["found"] else "status-error"
            status_icon = "✅" if tool["found"] else "❌"
            version = f" – {tool.get('version', 'N/A')}" if tool["found"] else ""
            html_content += f'<li><span class="{status_class}">{status_icon} {tool["tool"]}</span>{version}</li>'
        html_content += "</ul>"

    # Add summary
    summary = report.get("summary", {})
    html_content += """
        <div class="summary">
            <h3>📊 Summary</h3>
"""
    if summary.get("total_issues", 0) > 0:
        html_content += (
            f"<p><strong>Issues Found:</strong> {summary['total_issues']}</p>"
        )
        if summary.get("fixed_issues", 0) > 0:
            html_content += (
                f"<p><strong>Issues Fixed:</strong> {summary['fixed_issues']}</p>"
            )
    else:
        html_content += (
            '<p class="status-ok"><strong>Status:</strong> ✅ No issues found!</p>'
        )

    html_content += """
        </div>
    </div>
</body>
</html>
"""

    with open(file_path, "w") as f:
        f.write(html_content)


if __name__ == "__main__":
    doctorcli()
