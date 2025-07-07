#!/usr/bin/env python3
"""
ReconCLI Status Check Script
Comprehensive health check for the ReconCLI toolkit
"""

import sys
import os
import subprocess
import importlib
from pathlib import Path
from datetime import datetime


def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}")


def print_section(title):
    """Print a formatted section."""
    print(f"\n📋 {title}")
    print("-" * 40)


def check_status(item, status, details=""):
    """Print status with consistent formatting."""
    status_icon = "✅" if status else "❌"
    print(f"{status_icon} {item}")
    if details:
        print(f"   {details}")


def check_python_version():
    """Check Python version compatibility."""
    print_section("Python Environment")

    version = sys.version_info
    supported = version >= (3, 8)
    check_status(
        f"Python {version.major}.{version.minor}.{version.micro}",
        supported,
        "Supported" if supported else "Requires Python 3.8+",
    )

    return supported


def check_core_modules():
    """Check if core ReconCLI modules can be imported."""
    print_section("Core Modules")

    modules = [
        ("reconcli.main", "Main CLI module"),
        ("reconcli.vulnsqlicli", "SQL Injection Scanner"),
        ("reconcli.apicli", "API Security Scanner"),
        ("reconcli.dnscli", "DNS Resolution"),
        ("reconcli.urlcli", "URL Discovery"),
        ("reconcli.vhostcli", "Virtual Host Discovery"),
    ]

    all_good = True
    for module_name, description in modules:
        try:
            importlib.import_module(module_name)
            check_status(f"{description} ({module_name})", True, "Available")
        except ImportError as e:
            check_status(f"{description} ({module_name})", False, f"Import error: {e}")
            all_good = False

    return all_good


def check_dependencies():
    """Check core dependencies."""
    print_section("Core Dependencies")

    dependencies = [
        ("click", "CLI framework"),
        ("requests", "HTTP library"),
        ("yaml", "YAML parser"),
        ("aiohttp", "Async HTTP"),
    ]

    all_good = True
    for dep, description in dependencies:
        try:
            importlib.import_module(dep)
            check_status(f"{description} ({dep})", True, "Available")
        except ImportError:
            check_status(f"{description} ({dep})", False, "Missing")
            all_good = False

    return all_good


def check_external_tools():
    """Check external security tools."""
    print_section("External Security Tools")

    tools = [
        ("sqlmap", "SQLMap SQL injection tool"),
        ("ghauri", "Ghauri SQL injection tool"),
        ("gf", "GF pattern matching"),
        ("nuclei", "Nuclei vulnerability scanner"),
        ("ffuf", "FFuf web fuzzer"),
        ("httpx", "HTTPx HTTP toolkit"),
        ("nmap", "Nmap network scanner"),
    ]

    available_count = 0
    for tool, description in tools:
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                check_status(f"{description} ({tool})", True, f"Found at: {path}")
                available_count += 1
            else:
                check_status(f"{description} ({tool})", False, "Not found in PATH")
        except Exception as e:
            check_status(f"{description} ({tool})", False, f"Check failed: {e}")

    print(f"\n📊 External Tools: {available_count}/{len(tools)} available")
    return available_count > 0


def check_cli_functionality():
    """Check CLI functionality."""
    print_section("CLI Functionality")

    try:
        # Test main CLI help
        result = subprocess.run(
            [sys.executable, "-m", "reconcli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=Path(__file__).parent,
        )
        check_status(
            "Main CLI help", result.returncode == 0, "Command executed successfully"
        )

        # Test vulnsqlicli help
        result = subprocess.run(
            [sys.executable, "-m", "reconcli", "vulnsqlicli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=Path(__file__).parent,
        )
        check_status(
            "VulnSQLiCLI help", result.returncode == 0, "Command executed successfully"
        )

        # Test apicli help
        result = subprocess.run(
            [sys.executable, "-m", "reconcli", "apicli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=Path(__file__).parent,
        )
        check_status(
            "ApiCLI help", result.returncode == 0, "Command executed successfully"
        )

        return True
    except Exception as e:
        check_status("CLI functionality", False, f"Error: {e}")
        return False


def check_tool_availability():
    """Check tool availability using vulnsqlicli."""
    print_section("Tool Availability Check")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "reconcli", "vulnsqlicli", "--check-tools"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=Path(__file__).parent,
        )

        if result.returncode == 0:
            check_status(
                "Tool availability check", True, "All tools checked successfully"
            )
            # Print tool status
            if result.stdout:
                print(f"\n📊 Tool Status:")
                for line in result.stdout.split("\n"):
                    if line.strip():
                        print(f"   {line}")
        else:
            check_status(
                "Tool availability check", False, f"Exit code: {result.returncode}"
            )

        return result.returncode == 0
    except Exception as e:
        check_status("Tool availability check", False, f"Error: {e}")
        return False


def check_file_structure():
    """Check project file structure."""
    print_section("Project Structure")

    current_dir = Path(__file__).parent
    important_files = [
        ("README.md", "Project documentation"),
        ("requirements.txt", "Python dependencies"),
        ("pyproject.toml", "Project configuration"),
        ("reconcli/__init__.py", "Package init"),
        ("reconcli/main.py", "Main CLI module"),
        ("reconcli/vulnsqlicli.py", "SQL injection scanner"),
        ("reconcli/apicli.py", "API security scanner"),
        (".github/workflows/ci.yml", "CI/CD workflow"),
        (".github/workflows/security-status.yml", "Security workflow"),
        (".github/workflows/release.yml", "Release workflow"),
    ]

    all_good = True
    for file_path, description in important_files:
        full_path = current_dir / file_path
        exists = full_path.exists()
        check_status(
            f"{description} ({file_path})",
            exists,
            f"Size: {full_path.stat().st_size} bytes" if exists else "Missing",
        )
        if not exists:
            all_good = False

    return all_good


def generate_summary():
    """Generate overall summary."""
    print_section("Summary")

    # Run all checks
    results = {
        "Python Version": check_python_version(),
        "Core Modules": check_core_modules(),
        "Dependencies": check_dependencies(),
        "External Tools": check_external_tools(),
        "CLI Functionality": check_cli_functionality(),
        "Tool Availability": check_tool_availability(),
        "Project Structure": check_file_structure(),
    }

    print_section("Overall Status")

    passed = sum(results.values())
    total = len(results)

    for check, status in results.items():
        check_status(check, status)

    print(f"\n📊 Health Score: {passed}/{total} ({passed/total*100:.1f}%)")

    if passed == total:
        print("🎉 All systems operational! ReconCLI is ready to use.")
        return 0
    elif passed >= total * 0.8:
        print("⚠️ Most systems operational with minor issues.")
        return 1
    else:
        print("❌ Critical issues detected. Please review and fix.")
        return 2


def main():
    """Main function."""
    print_header("ReconCLI Status Check")
    print(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python: {sys.version}")
    print(f"📂 Working Directory: {Path.cwd()}")

    exit_code = generate_summary()

    print_header("Status Check Complete")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
