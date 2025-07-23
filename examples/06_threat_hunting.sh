#!/bin/bash
# Example 6: Threat Hunting and Intelligence
# Polowanie na zagrożenia z wykorzystaniem AI i cache

echo "🕵️ Example 6: Threat Hunting and Intelligence"
echo "============================================="

# Suspicious IP analysis (simulated threat intelligence)
cat > suspicious_ips.txt << EOF
192.168.1.1
10.0.0.1
172.16.0.1
127.0.0.1
185.220.101.1
185.220.102.1
199.87.154.255
62.102.148.68
89.248.167.131
45.128.232.1
EOF

echo "Created suspicious_ips.txt with potentially suspicious IPs"

# Threat hunting analysis with high AI confidence
reconcli ipscli \
  --input suspicious_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan masscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --honeypot \
  --scan-timeout 30 \
  --ai-confidence-threshold 0.9 \
  --threads 5 \
  --verbose \
  --markdown \
  --json \
  --output-dir output/threat_hunting

echo "✅ Threat hunting analysis completed!"
echo ""

# Generate threat intelligence report
echo "🚨 Generating Threat Intelligence Report..."
reconcli ipscli \
  --input suspicious_ips.txt \
  --ai-mode \
  --ai-cache \
  --attack-surface-report \
  --ai-confidence-threshold 0.8 \
  --markdown \
  --output-dir output/threat_hunting/intelligence

echo "✅ Threat intelligence report completed!"
echo ""

# Cache analysis for threat hunting
echo "📊 Threat Hunting Cache Analysis:"
python -c "
import os
import json
from datetime import datetime

def analyze_cache_for_threats(cache_dir):
    if not os.path.exists(cache_dir):
        print(f'{cache_dir} not found')
        return
    
    threat_indicators = 0
    total_entries = 0
    
    for filename in os.listdir(cache_dir):
        if filename.endswith('.json'):
            total_entries += 1
            filepath = os.path.join(cache_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    # Look for threat indicators in cached data
                    if isinstance(data, dict):
                        content = str(data).lower()
                        if any(indicator in content for indicator in ['malware', 'botnet', 'threat', 'suspicious', 'malicious']):
                            threat_indicators += 1
            except:
                continue
    
    print(f'Cache entries analyzed: {total_entries}')
    print(f'Potential threat indicators found: {threat_indicators}')
    if total_entries > 0:
        print(f'Threat indicator ratio: {(threat_indicators/total_entries)*100:.1f}%')

print('AI Cache Analysis:')
analyze_cache_for_threats('ai_cache')
"

echo ""
echo "📁 Threat Hunting Results:"
echo "  - Main Analysis: output/threat_hunting/"
echo "  - Intelligence Report: output/threat_hunting/intelligence/"
echo "🤖 AI Executive Summary: output/threat_hunting/ai_executive_summary.md"
echo ""
echo "🔍 Threat Hunting Tips:"
echo "  - Use high AI confidence thresholds (0.8-0.9) for threat hunting"
echo "  - Cache helps identify patterns across multiple investigations"
echo "  - Combine with honeypot detection for comprehensive analysis"
