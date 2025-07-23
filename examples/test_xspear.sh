#!/bin/bash
# XSpear XSS Testing Script for ReconCLI

echo "🔍 XSpear XSS Testing with ReconCLI"
echo "=================================="

# Test target
TARGET="http://testphp.vulnweb.com"

echo "Target: $TARGET"
echo

# 1. Basic XSpear scan
echo "1. Basic XSpear Scan:"
reconcli xsscli test-input \
    --input "$TARGET" \
    --engine xspear \
    --cache \
    --threads 5

echo

# 2. XSpear with AI analysis
echo "2. XSpear with AI Analysis:"
reconcli xsscli test-input \
    --input "$TARGET" \
    --engine xspear \
    --ai \
    --cache

echo

# 3. Direct XSpear command
echo "3. Direct XSpear Command:"
reconcli xsscli xspear \
    --url "$TARGET/artists.php?artist=test" \
    --threads 3 \
    --ai \
    --cache

echo

# 4. Check dependencies
echo "4. Checking Dependencies:"
reconcli xsscli check-deps | grep -E "(xspear|ruby)"

echo
echo "✅ XSpear testing completed!"
