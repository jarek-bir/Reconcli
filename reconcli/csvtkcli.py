#!/usr/bin/env python3
"""
CSVTK CLI for ReconCLI

Powerful CSV data analysis and manipulation using csvtk tool integration.
Provides advanced analytics for reconnaissance data exports.
"""

import click
import subprocess
import os
import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime


@click.group()
def csvtkcli():
    """ReconCLI CSVTK Integration

    Advanced CSV data analysis and manipulation for reconnaissance data.
    Requires csvtk to be installed: https://github.com/shenwei356/csvtk
    """
    if not _check_csvtk():
        sys.exit(1)


@csvtkcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option("--output", "-o", help="Output file for analysis results")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(csv_file, output, verbose):
    """Comprehensive analysis of CSV reconnaissance data

    Examples:
    python -m reconcli.csvtkcli analyze subdomains.csv
    python -m reconcli.csvtkcli analyze tesla_data.csv -o analysis_report.txt
    """
    click.echo(f"🔍 Analyzing {csv_file}")

    if output:
        with open(output, "w") as f:
            _run_comprehensive_analysis(csv_file, f, verbose)
        click.echo(f"📄 Analysis saved to {output}")
    else:
        _run_comprehensive_analysis(csv_file, sys.stdout, verbose)


@csvtkcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option("--field", "-f", required=True, help="Field name for frequency analysis")
@click.option("--top", "-n", type=int, default=10, help="Show top N results")
@click.option(
    "--sort-by-count", is_flag=True, help="Sort by count (default: alphabetical)"
)
def freq(csv_file, field, top, sort_by_count):
    """Frequency analysis of specific field

    Examples:
    python -m reconcli.csvtkcli freq subdomains.csv -f discovery_method
    python -m reconcli.csvtkcli freq domains.csv -f country --top 5 --sort-by-count
    """
    try:
        cmd = ["csvtk", "freq", "-f", field, csv_file]
        if sort_by_count:
            cmd = [
                "csvtk",
                "freq",
                "-f",
                field,
                csv_file,
                "|",
                "csvtk",
                "sort",
                "-k",
                "frequency:nr",
            ]
            if top:
                cmd.extend(["|", "csvtk", "head", "-n", str(top)])
            subprocess.run(" ".join(cmd), shell=True, check=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split("\n")

            if top and len(lines) > top + 1:  # +1 for header
                lines = lines[: top + 1]

            for line in lines:
                click.echo(line)

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Error: {e}")


@csvtkcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option("--field", "-f", required=True, help="Field to search in")
@click.option("--pattern", "-p", required=True, help="Search pattern (regex supported)")
@click.option("--ignore-case", "-i", is_flag=True, help="Case insensitive search")
@click.option("--regex", "-r", is_flag=True, help="Use regular expressions")
@click.option("--invert", "-v", is_flag=True, help="Invert match")
@click.option("--count", "-c", is_flag=True, help="Count matches only")
@click.option("--output", "-o", help="Save results to file")
def search(csv_file, field, pattern, ignore_case, regex, invert, count, output):
    """Search and filter CSV data

    Examples:
    python -m reconcli.csvtkcli search subdomains.csv -f subdomain -p "api" -i -r
    python -m reconcli.csvtkcli search data.csv -f tags -p "admin|security" --count -r
    """
    try:
        cmd = ["csvtk", "grep", "-f", field, "-p", pattern]

        if ignore_case:
            cmd.append("-i")
        if regex:
            cmd.append("-r")
        if invert:
            cmd.append("-v")

        if count:
            cmd.append(csv_file)
            cmd_str = " ".join(cmd) + " | wc -l"
            result = subprocess.run(
                cmd_str, shell=True, capture_output=True, text=True, check=True
            )
            # Subtract 1 for header if not inverted, or add logic to handle properly
            count_val = int(result.stdout.strip()) - (0 if invert else 1)
            click.echo(f"Matches: {max(0, count_val)}")
        else:
            cmd.append(csv_file)
            cmd_str = " ".join(cmd) + " | csvtk pretty"

            if output:
                with open(output, "w") as f:
                    subprocess.run(cmd_str, shell=True, stdout=f, check=True)
                click.echo(f"📄 Results saved to {output}")
            else:
                subprocess.run(cmd_str, shell=True, check=True)

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Error: {e}")


@csvtkcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option("--field", "-f", help="Field to categorize")
@click.option(
    "--security-focus", is_flag=True, help="Focus on security-relevant categories"
)
@click.option("--output", "-o", help="Save categorized data to file")
def categorize(csv_file, field, security_focus, output):
    """Categorize and analyze CSV data patterns

    Examples:
    python -m reconcli.csvtkcli categorize subdomains.csv -f subdomain --security-focus
    python -m reconcli.csvtkcli categorize data.csv -f domain -o categorized.csv
    """
    try:
        if security_focus:
            _security_categorization(csv_file, field or "subdomain", output)
        else:
            _general_categorization(csv_file, field, output)

    except Exception as e:
        click.echo(f"❌ Error: {e}")


@csvtkcli.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option(
    "--output-dir", "-o", default="csvtk_reports", help="Output directory for reports"
)
@click.option("--target-domain", help="Focus analysis on specific domain")
def security_report(csv_file, output_dir, target_domain):
    """Generate comprehensive security-focused report

    Examples:
    python -m reconcli.csvtkcli security-report subdomains.csv
    python -m reconcli.csvtkcli security-report tesla_data.csv --target-domain tesla.com
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    click.echo(f"🛡️ Generating security report for {csv_file}")

    # Generate multiple focused reports
    reports = [
        ("admin_domains", "admin|panel|control|manage", "Administrative Interfaces"),
        ("api_endpoints", "api|rest|graphql|service", "API Endpoints"),
        (
            "dev_environments",
            "dev|test|stage|staging|qa|uat",
            "Development Environments",
        ),
        ("databases", "db|database|mysql|postgres|mongo", "Database Services"),
        ("auth_services", "auth|sso|login|ldap", "Authentication Services"),
        ("sensitive_services", "backup|admin|root|secure", "Sensitive Services"),
    ]

    for report_name, pattern, description in reports:
        report_file = os.path.join(output_dir, f"{report_name}.csv")

        try:
            # Use subdomain field by default, but detect the correct field
            field = _detect_domain_field(csv_file)

            cmd = f'csvtk grep -f {field} -i -r -p "{pattern}" "{csv_file}" > "{report_file}"'
            subprocess.run(cmd, shell=True, check=True)

            # Check if file has content
            with open(report_file, "r") as f:
                lines = f.readlines()
                if len(lines) > 1:  # More than header
                    click.echo(
                        f"✅ {description}: {len(lines)-1} entries → {report_file}"
                    )
                else:
                    os.remove(report_file)  # Remove empty files

        except Exception as e:
            click.echo(f"⚠️ Could not generate {description} report: {e}")

    # Generate summary report
    summary_file = os.path.join(output_dir, "security_summary.md")
    _generate_security_summary(csv_file, summary_file, target_domain)

    click.echo(f"📋 Security summary: {summary_file}")
    click.echo(f"📁 All reports saved to: {output_dir}")


@csvtkcli.command()
@click.argument("csv_files", nargs=-1, required=True)
@click.option(
    "--output",
    "-o",
    default="combined_analysis.csv",
    help="Output file for combined data",
)
@click.option("--key-field", help="Field to join on (if combining)")
def combine(csv_files, output, key_field):
    """Combine multiple CSV files for analysis

    Examples:
    python -m reconcli.csvtkcli combine file1.csv file2.csv file3.csv
    python -m reconcli.csvtkcli combine *.csv --key-field domain
    """
    if len(csv_files) < 2:
        click.echo("❌ Need at least 2 CSV files to combine")
        return

    try:
        if key_field:
            # Join files on key field
            click.echo(f"🔗 Joining files on field: {key_field}")
            # This would need more complex logic for proper joins
            click.echo("⚠️ Advanced joining not implemented yet")
        else:
            # Simple concatenation
            click.echo(f"📎 Concatenating {len(csv_files)} files")
            cmd = f'csvtk concat {" ".join(csv_files)} > {output}'
            subprocess.run(cmd, shell=True, check=True)

        click.echo(f"✅ Combined data saved to: {output}")

        # Run quick analysis on combined data
        _run_quick_stats(output)

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Error combining files: {e}")


def _check_csvtk():
    """Check if csvtk is available"""
    try:
        result = subprocess.run(["csvtk", "version"], capture_output=True, check=True)
        version = result.stdout.decode().strip()
        click.echo(f"✅ csvtk found: {version}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo("❌ csvtk not found!")
        click.echo("📥 Install csvtk:")
        click.echo("   • Download: https://github.com/shenwei356/csvtk/releases")
        click.echo("   • Conda: conda install -c bioconda csvtk")
        click.echo("   • Homebrew: brew install csvtk")
        return False


def _run_comprehensive_analysis(csv_file, output_stream, verbose):
    """Run comprehensive analysis and write to stream"""

    def write(text):
        output_stream.write(text + "\n")
        if output_stream != sys.stdout:
            output_stream.flush()

    write(f"📊 COMPREHENSIVE CSV ANALYSIS: {os.path.basename(csv_file)}")
    write("=" * 60)

    try:
        # Basic info
        write("\n📋 BASIC INFORMATION:")
        result = subprocess.run(
            ["csvtk", "nrow", csv_file], capture_output=True, text=True, check=True
        )
        write(f"Rows: {result.stdout.strip()}")

        result = subprocess.run(
            ["csvtk", "ncol", csv_file], capture_output=True, text=True, check=True
        )
        write(f"Columns: {result.stdout.strip()}")

        result = subprocess.run(
            ["csvtk", "headers", csv_file], capture_output=True, text=True, check=True
        )
        headers = result.stdout.strip().split("\n")
        write(f"Headers: {', '.join(headers)}")

        # Column analysis
        write("\n🔍 COLUMN ANALYSIS:")
        for header in headers[:5]:  # Analyze first 5 columns
            if any(
                keyword in header.lower()
                for keyword in [
                    "domain",
                    "subdomain",
                    "method",
                    "status",
                    "country",
                    "org",
                ]
            ):
                write(f"\n📈 Frequency analysis for '{header}':")
                try:
                    result = subprocess.run(
                        ["csvtk", "freq", "-f", header, csv_file],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    lines = result.stdout.strip().split("\n")
                    for line in lines[:11]:  # Show top 10 + header
                        write(f"  {line}")
                except:
                    write(f"  (Could not analyze {header})")

        # Security-focused analysis
        domain_field = _detect_domain_field(csv_file)
        if domain_field:
            write(f"\n🛡️ SECURITY ANALYSIS (using field: {domain_field}):")

            security_patterns = [
                ("Admin interfaces", "admin|panel|control|manage"),
                ("API endpoints", "api|rest|graphql"),
                ("Development envs", "dev|test|stage|staging|qa"),
                ("Database services", "db|database|mysql|postgres"),
                ("Authentication", "auth|sso|login|ldap"),
            ]

            for desc, pattern in security_patterns:
                try:
                    cmd = f'csvtk grep -f {domain_field} -i -r -p "{pattern}" "{csv_file}" | wc -l'
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, check=True
                    )
                    count = int(result.stdout.strip()) - 1  # Subtract header
                    if count > 0:
                        write(f"  {desc}: {count} entries")
                except:
                    pass

        write(f"\n✅ Analysis complete for {os.path.basename(csv_file)}")

    except Exception as e:
        write(f"❌ Analysis error: {e}")


def _security_categorization(csv_file, field, output_file):
    """Perform security-focused categorization"""
    click.echo(f"🛡️ Security categorization of field: {field}")

    # Create categorized CSV with security labels
    temp_file = f"{csv_file}.categorized.tmp"

    try:
        # Add security category column
        cmd = f'''csvtk mutate -f {field} -n "security_category" "{csv_file}" | \\
                 csvtk replace -f security_category -p ".*admin.*|.*panel.*|.*control.*" -r "HIGH_RISK_ADMIN" | \\
                 csvtk replace -f security_category -p ".*api.*|.*rest.*|.*graphql.*" -r "MEDIUM_RISK_API" | \\
                 csvtk replace -f security_category -p ".*dev.*|.*test.*|.*stage.*" -r "MEDIUM_RISK_DEV" | \\
                 csvtk replace -f security_category -p ".*db.*|.*database.*" -r "HIGH_RISK_DATABASE" | \\
                 csvtk replace -f security_category -p ".*auth.*|.*sso.*|.*login.*" -r "HIGH_RISK_AUTH" | \\
                 csvtk replace -f security_category -p "^(?!.*HIGH_RISK|.*MEDIUM_RISK).*" -r "LOW_RISK_STANDARD"'''

        if output_file:
            cmd += f' > "{output_file}"'
            subprocess.run(cmd, shell=True, check=True)
            click.echo(f"✅ Categorized data saved to: {output_file}")
        else:
            cmd += " | csvtk pretty"
            subprocess.run(cmd, shell=True, check=True)

        # Show category statistics
        file_to_analyze = output_file if output_file else csv_file
        click.echo("\n📊 Security Category Distribution:")
        subprocess.run(
            ["csvtk", "freq", "-f", "security_category", file_to_analyze or temp_file],
            check=True,
        )

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Categorization failed: {e}")


def _general_categorization(csv_file, field, output_file):
    """Perform general categorization"""
    click.echo(f"📊 General categorization of field: {field or 'auto-detect'}")

    if not field:
        field = _detect_domain_field(csv_file)
        if not field:
            click.echo("❌ Could not detect domain field")
            return

    click.echo(f"🔍 Using field: {field}")

    # Show patterns found
    patterns = [
        ("Web services", "www|web|site"),
        ("Mail services", "mail|smtp|imap|pop"),
        ("FTP services", "ftp|sftp|files"),
        ("Database", "db|database"),
        ("API/Services", "api|service|rest"),
        ("Development", "dev|test|stage"),
        ("Admin/Management", "admin|manage|panel"),
    ]

    for desc, pattern in patterns:
        try:
            cmd = f'csvtk grep -f {field} -i -r -p "{pattern}" "{csv_file}" | wc -l'
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=True
            )
            count = int(result.stdout.strip()) - 1
            if count > 0:
                click.echo(f"  {desc}: {count} entries")
        except:
            pass


def _detect_domain_field(csv_file):
    """Auto-detect the domain/subdomain field"""
    try:
        result = subprocess.run(
            ["csvtk", "headers", csv_file], capture_output=True, text=True, check=True
        )
        headers = result.stdout.strip().split("\n")

        # Priority order for domain fields
        priority_fields = ["subdomain", "domain", "hostname", "host", "target"]

        for field in priority_fields:
            if field in headers:
                return field

        # Return first field if no standard names found
        return headers[0] if headers else None

    except:
        return None


def _generate_security_summary(csv_file, summary_file, target_domain):
    """Generate markdown security summary"""
    try:
        with open(summary_file, "w") as f:
            f.write(f"# Security Analysis Summary\n\n")
            f.write(f"**File:** {os.path.basename(csv_file)}\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if target_domain:
                f.write(f"**Target Domain:** {target_domain}\n")
            f.write("\n## Overview\n\n")

            # Get basic stats
            result = subprocess.run(
                ["csvtk", "nrow", csv_file], capture_output=True, text=True, check=True
            )
            total_rows = int(result.stdout.strip()) - 1  # Subtract header
            f.write(f"- **Total Records:** {total_rows:,}\n")

            # Security categories analysis
            domain_field = _detect_domain_field(csv_file)
            if domain_field:
                f.write(f"- **Analysis Field:** {domain_field}\n\n")

                f.write("## Security Risk Categories\n\n")

                categories = [
                    (
                        "🚨 **HIGH RISK** - Administrative Interfaces",
                        "admin|panel|control|manage|root",
                    ),
                    (
                        "🔴 **HIGH RISK** - Database Services",
                        "db|database|mysql|postgres|mongo|redis",
                    ),
                    (
                        "🟠 **MEDIUM RISK** - API Endpoints",
                        "api|rest|graphql|service|endpoint",
                    ),
                    (
                        "🟡 **MEDIUM RISK** - Development Environments",
                        "dev|test|stage|staging|qa|uat|beta",
                    ),
                    (
                        "🟣 **MEDIUM RISK** - Authentication Services",
                        "auth|sso|login|ldap|oauth",
                    ),
                    ("🔵 **LOW RISK** - Standard Web Services", "www|web|blog|site"),
                ]

                for desc, pattern in categories:
                    try:
                        cmd = f'csvtk grep -f {domain_field} -i -r -p "{pattern}" "{csv_file}" | wc -l'
                        result = subprocess.run(
                            cmd, shell=True, capture_output=True, text=True, check=True
                        )
                        count = int(result.stdout.strip()) - 1
                        if count > 0:
                            f.write(f"- {desc}: **{count}** entries\n")
                    except:
                        pass

                f.write("\n## Recommendations\n\n")
                f.write(
                    "1. 🔍 **Immediate Review**: Focus on HIGH RISK categories first\n"
                )
                f.write(
                    "2. 🛡️ **Security Testing**: Test administrative and database interfaces\n"
                )
                f.write(
                    "3. 🔐 **Access Control**: Verify authentication on sensitive services\n"
                )
                f.write(
                    "4. 🌐 **Network Segmentation**: Isolate development from production\n"
                )
                f.write(
                    "5. 📊 **Regular Monitoring**: Set up monitoring for these assets\n"
                )

    except Exception as e:
        click.echo(f"⚠️ Could not generate summary: {e}")


def _run_quick_stats(csv_file):
    """Run quick statistics on a CSV file"""
    try:
        click.echo(f"\n📊 Quick stats for {os.path.basename(csv_file)}:")
        subprocess.run(["csvtk", "nrow", csv_file], check=True)
        subprocess.run(["csvtk", "ncol", csv_file], check=True)
    except:
        pass


if __name__ == "__main__":
    csvtkcli()
