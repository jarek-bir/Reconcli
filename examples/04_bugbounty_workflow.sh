#!/bin/bash
# Example 4: Bug Bounty Reconnaissance Workflow
# Workflow rozpoznania dla bug bounty z cache i AI

echo "🐛 Example 4: Bug Bounty Reconnaissance Workflow"
echo "================================================"

# Bug bounty target list
cat > bugbounty_targets.txt << EOF
hackerone.com
bugcrowd.com
intigriti.com
synack.com
yeswehack.com
EOF

echo "Created bugbounty_targets.txt with bug bounty platforms"

# Phase 1: Initial reconnaissance with cache
echo "🔍 Phase 1: Initial Reconnaissance"
reconcli ipscli \
  --input bugbounty_targets.txt \
  --resolve-from raw \
  --enrich \
  --ip-cache \
  --fast \
  --threads 15 \
  --verbose \
  --json \
  --output-dir output/bugbounty/phase1

# Phase 2: Deep scanning with AI analysis
echo "🎯 Phase 2: Deep Scanning with AI"
reconcli ipscli \
  --input bugbounty_targets.txt \
  --resolve-from chaos \
  --enrich \
  --scan nmap \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --honeypot \
  --filter-cdn \
  --scan-timeout 60 \
  --ai-confidence-threshold 0.6 \
  --markdown \
  --json \
  --output-dir output/bugbounty/phase2

# Phase 3: Attack surface mapping
echo "🗺️ Phase 3: Attack Surface Mapping"
reconcli ipscli \
  --input bugbounty_targets.txt \
  --ai-mode \
  --ai-cache \
  --attack-surface-report \
  --ai-confidence-threshold 0.7 \
  --markdown \
  --output-dir output/bugbounty/attack_surface

echo "✅ Bug bounty reconnaissance workflow completed!"
echo ""
echo "📁 Results structure:"
echo "  - Phase 1 (Initial): output/bugbounty/phase1/"
echo "  - Phase 2 (Deep): output/bugbounty/phase2/"
echo "  - Attack Surface: output/bugbounty/attack_surface/"
echo ""

# Show workflow summary
echo "📊 Workflow Summary:"
echo "Cache hits improve performance in multi-phase reconnaissance"
reconcli ipscli --ip-cache --ip-cache-stats
reconcli ipscli --ai-cache --ai-cache-stats
