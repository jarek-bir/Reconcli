import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import click


@click.command()
@click.option(
    "--input", required=True, help="Input directory or file for code analysis"
)
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
):
    """🔍 Code Security Analysis with Semgrep, Bandit, and other SAST tools."""

    if not quiet:
        click.secho("🔍 ReconCLI Code Security Analysis", fg="bright_blue", bold=True)
        click.secho("=" * 50, fg="blue")

    # Create output directory
    os.makedirs(output, exist_ok=True)

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
