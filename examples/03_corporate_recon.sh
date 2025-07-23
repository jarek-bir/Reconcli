#!/bin/bash
# Example 3: Corporate Network Reconnaissance
# Rozpoznanie sieci korporacyjnej z wieloma narzędziami

echo "🏢 Example 3: Corporate Network Reconnaissance"
echo "=============================================="

# Corporate network analysis scenario
cat > corporate_targets.txt << EOF
microsoft.com
google.com
amazon.com
cloudflare.com
apple.com
EOF

echo "Created corporate_targets.txt with corporate domains"

# Comprehensive corporate analysis
reconcli ipscli \
  --input corporate_targets.txt \
  --resolve-from chaos \
  --enrich \
  --scan masscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --honeypot \
  --filter-cdn \
  --fast \
  --threads 10 \
  --scan-timeout 30 \
  --ai-confidence-threshold 0.8 \
  --markdown \
  --json \
  --output-dir output/corporate_recon

echo "✅ Corporate reconnaissance completed!"
echo ""

# Generate AI attack surface report
reconcli ipscli \
  --input corporate_targets.txt \
  --ai-mode \
  --ai-cache \
  --attack-surface-report \
  --ai-confidence-threshold 0.7 \
  --output-dir output/corporate_recon/attack_surface

echo "✅ Attack surface analysis completed!"
echo "📁 Check results in: output/corporate_recon/"
echo "🎯 Attack surface report: output/corporate_recon/attack_surface/"
echo ""

# Show comprehensive cache stats
echo "📊 Cache Performance:"
python -c "
import json
import os
if os.path.exists('ip_cache'):
    print('IP Cache entries:', len(os.listdir('ip_cache')))
if os.path.exists('ai_cache'):
    print('AI Cache entries:', len(os.listdir('ai_cache')))
"
