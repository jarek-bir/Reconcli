#!/bin/bash
# Example 7: Cache Management and Optimization
# Zarządzanie cache i optymalizacja wydajności

echo "⚡ Example 7: Cache Management and Optimization"
echo "=============================================="

# Demonstrate cache management capabilities
echo "🗂️ Cache Management Operations:"

# Check initial cache state
echo "1. Initial cache status:"
reconcli ipscli --ip-cache --ip-cache-stats
reconcli ipscli --ai-cache --ai-cache-stats
echo ""

# Create test data for cache demonstration
cat > cache_test_ips.txt << EOF
8.8.8.8
1.1.1.1
9.9.9.9
4.4.4.4
EOF

echo "2. Running analysis to populate cache..."
reconcli ipscli \
  --input cache_test_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan rustscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --fast \
  --output-dir output/cache_test_run1

echo "✅ First run completed (cache populated)"
echo ""

# Check cache after population
echo "3. Cache status after population:"
reconcli ipscli --ip-cache --ip-cache-stats
reconcli ipscli --ai-cache --ai-cache-stats
echo ""

# Run same analysis again to demonstrate cache hits
echo "4. Running same analysis again (should show cache hits)..."
time reconcli ipscli \
  --input cache_test_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan rustscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --fast \
  --output-dir output/cache_test_run2

echo "✅ Second run completed (using cache)"
echo ""

# Check cache hit rates
echo "5. Final cache statistics:"
reconcli ipscli --ip-cache --ip-cache-stats
reconcli ipscli --ai-cache --ai-cache-stats
echo ""

# Demonstrate cache cleaning
echo "6. Cache cleaning operations:"
echo "  Current cache sizes:"
du -sh ip_cache/ 2>/dev/null || echo "  IP cache: Not found"
du -sh ai_cache/ 2>/dev/null || echo "  AI cache: Not found"

echo ""
echo "  To clean old cache entries (example commands):"
echo "  reconcli ipscli --ip-cache --ip-cache-clean"
echo "  reconcli ipscli --ai-cache --ai-cache-clean"
echo ""

# Cache optimization tips
echo "📋 Cache Optimization Tips:"
echo "  ✅ Use --ip-cache for repeated IP analysis"
echo "  ✅ Use --ai-cache for repeated AI analysis"
echo "  ✅ Cache improves performance on large datasets"
echo "  ✅ Cache persists between runs"
echo "  ✅ Use cache-stats to monitor performance"
echo "  ✅ Clean cache periodically to save disk space"
echo ""

# Performance comparison
echo "📊 Performance Analysis:"
python -c "
import os
import json

def get_cache_info(cache_dir):
    if not os.path.exists(cache_dir):
        return 0, 0
    
    files = [f for f in os.listdir(cache_dir) if f.endswith('.json')]
    total_size = sum(os.path.getsize(os.path.join(cache_dir, f)) for f in files)
    return len(files), total_size

ip_count, ip_size = get_cache_info('ip_cache')
ai_count, ai_size = get_cache_info('ai_cache')

print(f'IP Cache: {ip_count} entries, {ip_size/1024:.1f} KB')
print(f'AI Cache: {ai_count} entries, {ai_size/1024:.1f} KB')
print(f'Total cache size: {(ip_size + ai_size)/1024:.1f} KB')
print('')
print('Cache benefits:')
print('- Faster subsequent runs')
print('- Reduced API calls')
print('- Consistent results')
print('- Offline capability')
"
