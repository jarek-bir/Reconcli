#!/bin/bash
# Example 1: Basic IP Analysis
# Podstawowa analiza listy IP z enrichment i skanowaniem

echo "🔍 Example 1: Basic IP Analysis"
echo "================================="

# Create sample IP list
cat > sample_ips.txt << EOF
8.8.8.8
1.1.1.1
9.9.9.9
208.67.222.222
EOF

echo "Created sample_ips.txt with DNS servers"

# Run basic analysis
reconcli ipscli \
  --input sample_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan rustscan \
  --verbose \
  --markdown \
  --output-dir output/basic_analysis

echo "✅ Basic analysis completed!"
echo "📁 Check results in: output/basic_analysis/"
echo ""
