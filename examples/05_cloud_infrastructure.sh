#!/bin/bash
# Example 5: Cloud Infrastructure Analysis
# Analiza infrastruktury chmurowej z AI i cache

echo "☁️ Example 5: Cloud Infrastructure Analysis"
echo "==========================================="

# Cloud provider analysis
cat > cloud_targets.txt << EOF
aws.amazon.com
console.aws.amazon.com
azure.microsoft.com
portal.azure.com
cloud.google.com
console.cloud.google.com
digitalocean.com
vultr.com
linode.com
EOF

echo "Created cloud_targets.txt with cloud provider endpoints"

# Comprehensive cloud infrastructure analysis
reconcli ipscli \
  --input cloud_targets.txt \
  --resolve-from chaos \
  --enrich \
  --scan rustscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --honeypot \
  --filter-cdn \
  --threads 20 \
  --scan-timeout 45 \
  --ai-confidence-threshold 0.8 \
  --verbose \
  --markdown \
  --json \
  --output-dir output/cloud_analysis

echo "✅ Cloud infrastructure analysis completed!"
echo ""

# Generate specialized cloud security report
echo "🔒 Generating Cloud Security Assessment..."
reconcli ipscli \
  --input cloud_targets.txt \
  --ai-mode \
  --ai-cache \
  --attack-surface-report \
  --ai-confidence-threshold 0.7 \
  --markdown \
  --output-dir output/cloud_analysis/security_assessment

echo "✅ Cloud security assessment completed!"
echo ""
echo "📁 Results:"
echo "  - Infrastructure Analysis: output/cloud_analysis/"
echo "  - Security Assessment: output/cloud_analysis/security_assessment/"
echo "🤖 AI Executive Summary: output/cloud_analysis/ai_executive_summary.md"
echo ""

# Cloud-specific cache analysis
echo "📊 Cloud Analysis Cache Performance:"
python -c "
import os
import json

def count_cache_entries(cache_dir):
    if os.path.exists(cache_dir):
        return len([f for f in os.listdir(cache_dir) if f.endswith('.json')])
    return 0

print(f'IP Cache entries: {count_cache_entries(\"ip_cache\")}')
print(f'AI Cache entries: {count_cache_entries(\"ai_cache\")}')
print('Cloud analysis benefits from caching due to repeated IP patterns')
"
