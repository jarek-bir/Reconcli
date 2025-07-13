"""
takeovercli.py - Subdomain takeover detection module for reconcli
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click

# Import utilities
try:
    from reconcli.utils.notifications import send_notification
except ImportError:
    send_notification = None

# Import resume utilities
try:
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
except ImportError:
    # Fallback if utils not available
    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def clear_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            os.remove(path)


OUTPUT_DIR = Path("output/takeover")
DEFAULT_TOOL = "subzy"


def check_tool_installed(tool):
    """Check if the specified tool is installed and available in PATH."""
    if not shutil.which(tool):
        click.echo(f"[!] Error: {tool} is not installed or not in PATH")
        click.echo(f"[!] Please install {tool} first:")
        if tool == "subzy":
            click.echo("    go install -v github.com/LukaSikic/subzy@latest")
        elif tool == "tko-subs":
            click.echo("    go install github.com/anshumanbh/tko-subs@latest")
        return False
    return True


def validate_input_file(input_file):
    """Validate that input file contains valid subdomains."""
    try:
        with open(input_file, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            click.echo(f"[!] Error: Input file {input_file} is empty")
            return False

        # Basic validation - check if lines look like domains
        valid_count = 0
        for line in lines[:10]:  # Check first 10 lines
            if "." in line and " " not in line:
                valid_count += 1

        if valid_count == 0:
            click.echo("[!] Warning: Input file may not contain valid domain names")

        click.echo(f"[+] Input file contains {len(lines)} entries")
        return True
    except Exception as e:
        click.echo(f"[!] Error reading input file: {e}")
        return False


def show_resume_status(output_dir):
    """Show status of previous scans from resume file."""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        click.echo(f"🔍 Scan: {scan_key}")
        click.echo(f"   Tool: {scan_data.get('tool', 'unknown')}")
        click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

        if scan_data.get("completed"):
            click.echo("   Status: ✅ Completed")
            click.echo(f"   Completed: {scan_data.get('completion_time', 'unknown')}")
            click.echo(
                f"   Vulnerabilities: {scan_data.get('vulnerabilities_found', 0)}"
            )
        else:
            click.echo("   Status: ⏳ Incomplete")
            if scan_data.get("last_error"):
                click.echo(f"   Last Error: {scan_data.get('last_error')}")

        click.echo()


@click.command()
@click.option(
    "--input",
    "-i",
    required=False,
    type=click.Path(exists=True),
    help="Input file with subdomains (one per line).",
)
@click.option(
    "--tool",
    "-t",
    default=DEFAULT_TOOL,
    type=click.Choice(["subzy", "tko-subs"], case_sensitive=False),
    help="Takeover tool to use.",
)
@click.option(
    "--output-dir",
    "-o",
    default=str(OUTPUT_DIR),
    show_default=True,
    help="Directory to store output files.",
)
@click.option("--markdown", is_flag=True, help="Export markdown report for Obsidian.")
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
@click.option("--verbose", is_flag=True, help="Enable verbose output.")
@click.option("--timeout", default=30, help="Timeout for tool execution (seconds).")
@click.option("--resume", is_flag=True, help="Resume previous takeover scan.")
@click.option(
    "--clear-resume",
    "clear_resume_flag",
    is_flag=True,
    help="Clear previous resume state and start fresh.",
)
@click.option("--show-resume", is_flag=True, help="Show status of previous scans.")
@click.option(
    "--slack-webhook",
    required=False,
    help="Slack webhook URL for notifications",
)
@click.option(
    "--discord-webhook",
    required=False,
    help="Discord webhook URL for notifications",
)
def takeovercli(
    input,
    tool,
    output_dir,
    markdown,
    json_output,
    verbose,
    timeout,
    resume,
    clear_resume_flag,
    show_resume,
    slack_webhook,
    discord_webhook,
):
    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir)
        return

    if clear_resume_flag:
        clear_resume(output_dir)
        click.echo("[+] Resume state cleared.")
        if not resume:
            return

    # Validate input is provided for normal operations
    if not input:
        raise click.UsageError(
            "--input is required unless using --show-resume or --clear-resume"
        )

    # Validate tool installation
    if not check_tool_installed(tool):
        sys.exit(1)

    # Validate input file
    if not validate_input_file(input):
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # Load resume state
    resume_state = load_resume(output_dir) if resume else {}

    # Check if we can resume this exact scan
    scan_key = f"{Path(input).stem}_{tool}"

    if resume and scan_key in resume_state:
        click.echo(f"[+] Resuming previous {tool} scan for {Path(input).stem}")
        if resume_state[scan_key].get("completed"):
            click.echo(
                "[!] Previous scan already completed. Use --clear-resume to start fresh."
            )
            return

        # Load previous scan details
        timestamp = resume_state[scan_key]["timestamp"]
        processed_count = resume_state[scan_key].get("processed_count", 0)
        click.echo(
            f"[+] Resuming from scan started at {timestamp}, processed {processed_count} entries"
        )
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Initialize resume state for new scan
        if resume:
            resume_state[scan_key] = {
                "timestamp": timestamp,
                "tool": tool,
                "input_file": str(input),
                "output_dir": output_dir,
                "processed_count": 0,
                "completed": False,
                "start_time": datetime.now().isoformat(),
            }
            save_resume_state(output_dir, resume_state)

    base_filename = Path(input).stem + f"_takeover_{tool}_{timestamp}"

    output_txt = Path(output_dir) / f"{base_filename}.txt"
    output_json = Path(output_dir) / f"{base_filename}.json"
    output_md = Path(output_dir) / f"{base_filename}.md"

    if tool == "subzy":
        cmd = [
            "subzy",
            "run",
            "--targets",
            input,
            "--hide_fails",
            "--vuln",
            "--output",
            str(output_txt),
        ]
    elif tool == "tko-subs":
        # Check if providers-data.csv exists, if not try to download or use default
        providers_file = "providers-data.csv"
        if not os.path.exists(providers_file):
            click.echo(
                f"[!] Warning: {providers_file} not found, using default providers"
            )
            providers_file = ""  # tko-subs will use default

        cmd = ["tko-subs", "-domains", input]
        if providers_file:
            cmd.extend(["-data", providers_file])

    if verbose:
        click.echo(f"[+] Running {tool} takeover scan on {input}")
        click.echo(f"[+] Output directory: {output_dir}")
        click.echo(f"[+] Command: {' '.join(cmd)}")
        if resume:
            click.echo("[+] Resume mode: enabled")

    # Update resume state - scan started
    if resume:
        resume_state[scan_key]["scan_started"] = datetime.now().isoformat()
        save_resume_state(output_dir, resume_state)

    # Run command and capture output
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        click.echo(f"[!] {tool} timed out after {timeout} seconds")
        # Update resume state with timeout info
        if resume:
            resume_state[scan_key]["last_error"] = f"Timeout after {timeout}s"
            resume_state[scan_key]["last_error_time"] = datetime.now().isoformat()
            save_resume_state(output_dir, resume_state)
        return
    except FileNotFoundError:
        click.echo(
            f"[!] {tool} command not found. Please ensure it's installed and in PATH."
        )
        # Update resume state with error info
        if resume:
            resume_state[scan_key]["last_error"] = f"{tool} command not found"
            resume_state[scan_key]["last_error_time"] = datetime.now().isoformat()
            save_resume_state(output_dir, resume_state)
        return

    if verbose:
        if result.stdout:
            click.echo("STDOUT:")
            click.echo(result.stdout)
        if result.stderr:
            click.echo("STDERR:")
            click.echo(result.stderr)

    if result.returncode != 0:
        click.echo(f"[!] {tool} exited with non-zero status code: {result.returncode}")
        if result.stderr:
            click.echo(f"[!] Error output: {result.stderr}")
        return

    # For tko-subs, save stdout to output file if no file was created
    if tool == "tko-subs" and not output_txt.exists() and result.stdout:
        with open(output_txt, "w") as f:
            f.write(result.stdout)

    vulnerable_findings = []

    # Process output file if it exists
    if output_txt.exists():
        with open(output_txt, "r") as f:
            content = f.read().strip()

        # Handle empty or null content from --vuln flag
        if not content or content == "null":
            lines = []
            vulnerable_findings = []
        else:
            lines = content.split("\n")

            # Parse results based on tool
            if tool == "subzy":
                vulnerable_findings = [
                    line.strip() for line in lines if "VULNERABLE" in line.upper()
                ]
            elif tool == "tko-subs":
                # tko-subs typically shows vulnerable domains in a different format
                vulnerable_findings = [
                    line.strip()
                    for line in lines
                    if line.strip() and "vulnerable" in line.lower()
                ]

        click.echo(
            f"[+] Found {len(vulnerable_findings)} potential takeover vulnerabilities"
        )

        if vulnerable_findings and verbose:
            click.echo("[+] Vulnerable findings:")
            for finding in vulnerable_findings:
                click.echo(f"    - {finding}")

        # Export JSON if requested
        if json_output:
            json_data = {
                "tool": tool,
                "scan_time": timestamp,
                "input_file": str(input),
                "total_vulnerable": len(vulnerable_findings),
                "vulnerable_domains": vulnerable_findings,
                "all_output": lines,
            }
            with open(output_json, "w") as out:
                json.dump(json_data, out, indent=2)
            click.echo(f"[+] JSON exported: {output_json}")

        # Export Markdown if requested
        if markdown:
            with open(output_md, "w") as md:
                md.write("# Subdomain Takeover Report\n\n")
                md.write(
                    f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                md.write(f"**Tool:** {tool}\n")
                md.write(f"**Input File:** {input}\n")
                md.write(f"**Total Vulnerable:** {len(vulnerable_findings)}\n\n")

                if vulnerable_findings:
                    md.write("## 🚨 Vulnerable Domains\n\n")
                    for finding in vulnerable_findings:
                        md.write(f"- ⚠️ `{finding}`\n")
                    md.write("\n")

                md.write("## 📋 Full Scan Output\n\n")
                md.write("```\n")
                md.write(content)
                md.write("\n```\n")

                md.write("\n## 🔧 Remediation\n\n")
                md.write("1. Verify the subdomain takeover vulnerability\n")
                md.write("2. Remove DNS record pointing to the vulnerable service\n")
                md.write("3. Claim the service if still needed\n")
                md.write("4. Monitor for similar issues\n")

            click.echo(f"[+] Markdown exported: {output_md}")
    else:
        click.echo(f"[!] Output file not found: {output_txt}. Nothing to export.")

    click.echo("[✓] Takeover scan completed.")

    # Update resume state - scan completed
    if resume:
        resume_state[scan_key]["completed"] = True
        resume_state[scan_key]["completion_time"] = datetime.now().isoformat()
        resume_state[scan_key]["vulnerabilities_found"] = len(vulnerable_findings)
        resume_state[scan_key]["output_files"] = {
            "txt": str(output_txt) if output_txt.exists() else None,
            "json": str(output_json) if json_output and output_json.exists() else None,
            "md": str(output_md) if markdown and output_md.exists() else None,
        }
        save_resume_state(output_dir, resume_state)
        click.echo("[+] Resume state updated: scan completed")

    if vulnerable_findings:
        click.echo(
            f"[!] ⚠️ ALERT: {len(vulnerable_findings)} potential takeover vulnerabilities found!"
        )
    else:
        click.echo("[+] ✅ No takeover vulnerabilities detected.")

    # Send notifications
    if (slack_webhook or discord_webhook) and send_notification:
        scan_metadata = {
            "tool": tool,
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "scan_duration": "completed",
            "resume_used": resume,
        }

        if verbose:
            click.echo("[+] 📱 Sending notifications...")

        send_notification(
            "takeover",
            results=vulnerable_findings,
            scan_metadata=scan_metadata,
            slack_webhook=slack_webhook,
            discord_webhook=discord_webhook,
            verbose=verbose,
        )


if __name__ == "__main__":
    takeovercli()
