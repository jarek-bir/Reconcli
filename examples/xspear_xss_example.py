#!/usr/bin/env python3
"""
XSpear XSS Scanner Integration Example for ReconCLI
Advanced XSS testing with Ruby-based XSpear engine

Features:
- XSpear advanced XSS detection
- WAF bypass capabilities
- Blind XSS support
- Cache optimization
- AI-powered analysis
"""

import subprocess
import json
import time
from datetime import datetime


def demonstrate_xspear_integration():
    """Demonstrate XSpear integration with XSSCli."""

    print("🔍 XSpear XSS Scanner Integration Demo")
    print("=" * 60)

    # Test target (use a safe test target)
    test_target = "http://testphp.vulnweb.com/artists.php"

    print(f"Target: {test_target}")
    print()

    # 1. Basic XSpear scan
    print("1️⃣ Basic XSpear Scan")
    print("-" * 30)

    cmd = [
        "reconcli",
        "xsscli",
        "test-input",
        "--input",
        test_target,
        "--engine",
        "xspear",
        "--threads",
        "5",
        "--delay",
        "1",
        "--cache",
    ]

    print(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print("✅ XSpear scan completed")
        if result.stdout:
            print("📊 Results:")
            print(
                result.stdout[:500] + "..."
                if len(result.stdout) > 500
                else result.stdout
            )
    except subprocess.TimeoutExpired:
        print("⏰ Scan timed out")
    except Exception as e:
        print(f"❌ Error: {e}")

    print()

    # 2. XSpear with Blind XSS
    print("2️⃣ XSpear with Blind XSS")
    print("-" * 30)

    # Note: Replace with your actual blind XSS callback URL
    blind_url = "https://your-blind-xss-callback.com/callback"

    cmd = [
        "reconcli",
        "xsscli",
        "xspear",
        "--url",
        test_target,
        "--blind-url",
        blind_url,
        "--threads",
        "3",
        "--ai",
        "--cache",
    ]

    print(f"Command: {' '.join(cmd)}")
    print("📡 Note: Using example blind XSS URL (replace with real callback)")

    # 3. XSpear with AI Analysis
    print("\n3️⃣ XSpear with AI Analysis")
    print("-" * 30)

    cmd = [
        "reconcli",
        "xsscli",
        "test-input",
        "--input",
        test_target,
        "--engine",
        "xspear",
        "--ai",
        "--ai-provider",
        "openai",
        "--cache",
    ]

    print(f"Command: {' '.join(cmd)}")
    print("🤖 AI analysis will provide detailed insights")

    # 4. Multi-engine comparison
    print("\n4️⃣ Multi-Engine Comparison")
    print("-" * 30)

    engines = ["manual", "xspear", "dalfox", "kxss", "all"]

    for engine in engines:
        print(f"\n🔧 Engine: {engine}")
        cmd = [
            "reconcli",
            "xsscli",
            "test-input",
            "--input",
            test_target,
            "--engine",
            engine,
            "--cache",
            "--threads",
            "3",
        ]
        print(f"   Command: {' '.join(cmd)}")

    # 5. XSpear Installation Check
    print("\n5️⃣ XSpear Installation Check")
    print("-" * 30)

    try:
        result = subprocess.run(["xspear", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ XSpear is installed")
            print(f"Version info: {result.stdout.strip()}")
        else:
            print("❌ XSpear not found")
            print("📥 Install with: gem install XSpear")
    except FileNotFoundError:
        print("❌ XSpear not found")
        print("📥 Install with: gem install XSpear")
        print("📋 Prerequisites: Ruby, gem")

    # 6. Cache performance demonstration
    print("\n6️⃣ Cache Performance Demo")
    print("-" * 30)

    print("🔄 First scan (cache miss):")
    cmd = [
        "reconcli",
        "xsscli",
        "test-input",
        "--input",
        test_target,
        "--engine",
        "xspear",
        "--cache",
        "--cache-stats",
    ]
    print(f"   {' '.join(cmd)}")

    print("\n🚀 Second scan (cache hit):")
    print(f"   {' '.join(cmd)}")
    print("   Expected: 10-50x faster due to caching")

    # 7. Advanced XSpear options
    print("\n7️⃣ Advanced XSpear Configuration")
    print("-" * 30)

    advanced_options = {
        "WAF Bypass": ["--engine", "xspear", "--threads", "10"],
        "Blind XSS": ["--engine", "xspear", "--blind-url", "callback.com"],
        "Custom Payloads": ["--engine", "xspear", "--payloads-file", "custom.txt"],
        "Full Pipeline": ["--engine", "all", "--ai", "--cache"],
    }

    for name, options in advanced_options.items():
        print(f"🎯 {name}:")
        full_cmd = ["reconcli", "xsscli", "test-input", "--input", "target"] + options
        print(f"   {' '.join(full_cmd)}")

    print("\n" + "=" * 60)
    print("🎯 XSpear Integration Summary:")
    print("✅ Advanced XSS detection with Ruby engine")
    print("✅ WAF bypass capabilities")
    print("✅ Blind XSS support with callbacks")
    print("✅ Intelligent caching for performance")
    print("✅ AI-powered result analysis")
    print("✅ Multi-engine comparison capabilities")
    print("✅ Full integration with ReconCLI ecosystem")


def create_xspear_test_script():
    """Create a simple test script for XSpear."""

    script_content = """#!/bin/bash
# XSpear XSS Testing Script for ReconCLI

echo "🔍 XSpear XSS Testing with ReconCLI"
echo "=================================="

# Test target
TARGET="http://testphp.vulnweb.com"

echo "Target: $TARGET"
echo

# 1. Basic XSpear scan
echo "1. Basic XSpear Scan:"
reconcli xsscli test-input \\
    --input "$TARGET" \\
    --engine xspear \\
    --cache \\
    --threads 5

echo

# 2. XSpear with AI analysis
echo "2. XSpear with AI Analysis:"
reconcli xsscli test-input \\
    --input "$TARGET" \\
    --engine xspear \\
    --ai \\
    --cache

echo

# 3. Direct XSpear command
echo "3. Direct XSpear Command:"
reconcli xsscli xspear \\
    --url "$TARGET/artists.php?artist=test" \\
    --threads 3 \\
    --ai \\
    --cache

echo

# 4. Check dependencies
echo "4. Checking Dependencies:"
reconcli xsscli check-deps | grep -E "(xspear|ruby)"

echo
echo "✅ XSpear testing completed!"
"""

    with open("/home/jarek/reconcli_dnscli_full/examples/test_xspear.sh", "w") as f:
        f.write(script_content)

    # Make it executable
    subprocess.run(
        ["chmod", "+x", "/home/jarek/reconcli_dnscli_full/examples/test_xspear.sh"]
    )
    print("📝 Created XSpear test script: examples/test_xspear.sh")


if __name__ == "__main__":
    demonstrate_xspear_integration()
    create_xspear_test_script()
