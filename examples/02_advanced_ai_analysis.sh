#!/bin/bash
# Example 2: Advanced Analysis with AI and Cache
# Zaawansowana analiza z AI, cache i filtrami

echo "🤖 Example 2: Advanced AI Analysis with Cache"
echo "=============================================="

# Create more comprehensive IP list
cat > advanced_ips.txt << EOF
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
4.4.4.4
4.4.8.8
EOF

echo "Created advanced_ips.txt with various DNS providers"

# Run comprehensive analysis with AI
reconcli ipscli \
  --input advanced_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan rustscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --filter-cdn \
  --honeypot \
  --ai-confidence-threshold 0.7 \
  --verbose \
  --markdown \
  --json \
  --output-dir output/advanced_analysis

echo "✅ Advanced AI analysis completed!"
echo "📁 Check results in: output/advanced_analysis/"
echo "🤖 AI executive summary: output/advanced_analysis/ai_executive_summary.md"
echo ""

# Show cache statistics
echo "📊 Cache Statistics:"
reconcli ipscli --ip-cache --ip-cache-stats
reconcli ipscli --ai-cache --ai-cache-stats
