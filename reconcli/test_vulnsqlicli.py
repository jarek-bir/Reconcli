#!/usr/bin/env python3
"""
Comprehensive test script for VulnSQLiCLI module
Tests all major functionality including tools, resume, and reporting
"""

import os
import sys
import json
import subprocess
from pathlib import Path
import tempfile
import shutil
import time


def run_command(cmd, timeout=30):
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def test_cli_help():
    """Test CLI help functionality."""
    print("🔍 Testing CLI Help...")

    # Test standalone help
    ret, out, err = run_command("python vulnsqlicli.py --help")
    assert ret == 0, f"Help command failed: {err}"
    assert "Advanced SQL Injection Vulnerability Scanner" in out
    print("✅ Standalone help works")

    # Test integrated help
    ret, out, err = run_command("python main.py vulnsqlicli --help")
    assert ret == 0, f"Integrated help command failed: {err}"
    assert "Advanced SQL Injection Vulnerability Scanner" in out
    print("✅ Integrated help works")


def test_tool_availability():
    """Test tool availability check."""
    print("🔍 Testing Tool Availability...")

    ret, out, err = run_command("python vulnsqlicli.py --check-tools")
    assert ret == 0, f"Tool check failed: {err}"

    # Should find at least one tool
    tools = ["sqlmap", "ghauri", "gf"]
    found_tools = [tool for tool in tools if tool in out]
    assert len(found_tools) > 0, f"No tools found. Output: {out}"
    print(f"✅ Found tools: {', '.join(found_tools)}")


def test_basic_scanning():
    """Test basic SQL injection scanning."""
    print("🔍 Testing Basic Scanning...")

    # Test with a known vulnerable URL
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    output_dir = f"/tmp/vulnsqlicli_test_{int(time.time())}"

    try:
        ret, out, err = run_command(
            f"python vulnsqlicli.py --url '{test_url}' --basic-test --output-dir {output_dir} --json-report --verbose",
            timeout=60,
        )

        # Should complete successfully (exit code 0, 1, or 2 are acceptable)
        assert ret in [0, 1, 2], f"Basic scan failed with exit code {ret}: {err}"

        # Check if output files were created
        output_path = Path(output_dir)
        assert output_path.exists(), "Output directory not created"

        json_files = list(output_path.glob("*.json"))
        assert len(json_files) > 0, "No JSON report generated"

        # Check JSON report content
        with open(json_files[0], "r") as f:
            report = json.load(f)

        assert "summary" in report, "JSON report missing summary"
        assert "total_targets" in report["summary"], "JSON report missing target count"
        assert report["summary"]["total_targets"] > 0, "No targets processed"

        print("✅ Basic scanning works")

    finally:
        # Cleanup
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)


def test_resume_functionality():
    """Test resume functionality."""
    print("🔍 Testing Resume Functionality...")

    output_dir = f"/tmp/vulnsqlicli_resume_test_{int(time.time())}"

    try:
        # Show resume status (should be empty)
        ret, out, err = run_command(
            f"python vulnsqlicli.py --show-resume --output-dir {output_dir}"
        )
        assert ret == 0, f"Show resume failed: {err}"
        assert "No previous scan state found" in out, "Should show no previous state"
        print("✅ Show resume works (empty state)")

        # Clear resume (should work even if no state exists)
        ret, out, err = run_command(
            f"python vulnsqlicli.py --clear-resume --output-dir {output_dir}"
        )
        assert ret == 0, f"Clear resume failed: {err}"
        print("✅ Clear resume works")

        # Test resume without previous state
        ret, out, err = run_command(
            f"python vulnsqlicli.py --resume --output-dir {output_dir}"
        )
        assert ret == 0, f"Resume without state failed: {err}"
        assert (
            "No previous scan state found" in out
        ), "Should handle missing state gracefully"
        print("✅ Resume handles missing state gracefully")

    finally:
        # Cleanup
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)


def test_report_formats():
    """Test different report formats."""
    print("🔍 Testing Report Formats...")

    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    output_dir = f"/tmp/vulnsqlicli_reports_test_{int(time.time())}"

    try:
        # Test all report formats
        ret, out, err = run_command(
            f"python vulnsqlicli.py --url '{test_url}' --basic-test --output-dir {output_dir} "
            f"--json-report --yaml-report --markdown-report --verbose",
            timeout=60,
        )

        assert ret in [0, 1, 2], f"Report generation failed with exit code {ret}: {err}"

        # Check if all report files were created
        output_path = Path(output_dir)

        json_files = list(output_path.glob("*.json"))
        yaml_files = list(output_path.glob("*.yaml"))
        md_files = list(output_path.glob("*.md"))

        assert len(json_files) > 0, "No JSON report generated"
        assert len(yaml_files) > 0, "No YAML report generated"
        assert len(md_files) > 0, "No Markdown report generated"

        print("✅ All report formats work")

    finally:
        # Cleanup
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)


def test_multiple_urls():
    """Test scanning multiple URLs from file."""
    print("🔍 Testing Multiple URLs...")

    # Create test URLs file
    urls_file = "/tmp/test_urls.txt"
    output_dir = f"/tmp/vulnsqlicli_multi_test_{int(time.time())}"

    try:
        with open(urls_file, "w") as f:
            f.write("http://testphp.vulnweb.com/artists.php?artist=1\n")
            f.write("http://testphp.vulnweb.com/listproducts.php?cat=1\n")
            f.write("# This is a comment\n")
            f.write("http://testphp.vulnweb.com/search.php?test=query\n")

        ret, out, err = run_command(
            f"python vulnsqlicli.py --urls-file {urls_file} --basic-test --output-dir {output_dir} "
            f"--json-report --verbose",
            timeout=120,
        )

        assert ret in [0, 1, 2], f"Multi-URL scan failed with exit code {ret}: {err}"

        # Check if output files were created
        output_path = Path(output_dir)
        json_files = list(output_path.glob("*.json"))
        assert len(json_files) > 0, "No JSON report generated"

        # Check JSON report content
        with open(json_files[0], "r") as f:
            report = json.load(f)

        assert report["summary"]["total_targets"] >= 3, "Should process at least 3 URLs"
        print("✅ Multiple URLs scanning works")

    finally:
        # Cleanup
        if os.path.exists(urls_file):
            os.remove(urls_file)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)


def main():
    """Run all tests."""
    print("🚀 Starting VulnSQLiCLI Comprehensive Tests")
    print("=" * 60)

    # Change to project directory
    os.chdir("/home/jarek/reconcli_dnscli_full/reconcli")

    tests = [
        test_cli_help,
        test_tool_availability,
        test_basic_scanning,
        test_resume_functionality,
        test_report_formats,
        test_multiple_urls,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {test_func.__name__} failed: {e}")
            failed += 1
        except AssertionError as e:
            print(f"❌ {test_func.__name__} assertion failed: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All tests passed! VulnSQLiCLI is working correctly.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please review and fix issues.")
        sys.exit(1)


if __name__ == "__main__":
    main()
