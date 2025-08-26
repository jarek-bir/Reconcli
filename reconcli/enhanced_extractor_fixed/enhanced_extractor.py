#!/usr/bin/env python3
"""
Enhanced File Extractor with Advanced Pattern Detection and Concurrent Processing
Integrates all advanced features: enhanced patterns, URL probing, concurrent processing
"""

import os
import re
import json
import argparse
import logging
import time
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import asyncio
from urllib.parse import urlparse

# Import smart URL handler
try:
    from .smart_url_handler import sanitize_input_list
except ImportError:
    from smart_url_handler import sanitize_input_list
# Import all modules
try:
    from enhanced_patterns import EnhancedPatternDetector, analyze_content_enhanced
    from url_prober_v2 import AdvancedURLProber, probe_urls_from_list
    
    # Import plugins
    from plugins.aws_extractor import AWSExtractor
    from plugins.docker_extractor import DockerExtractor
    from plugins.git_extractor import GitExtractor
    from plugins.network_extractor import NetworkExtractor
    
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Some modules not available: {e}")
    MODULES_AVAILABLE = False


class EnhancedFileExtractor:
    """Enhanced file extractor with concurrent processing and advanced detection"""
    
    def __init__(self, 
                 max_workers: int = 4,
                 chunk_size: int = 1000,
                 enable_security_scan: bool = True,
                 enable_url_probing: bool = False):
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.enable_security_scan = enable_security_scan
        self.enable_url_probing = enable_url_probing
        
        # Initialize components
        self.pattern_detector = EnhancedPatternDetector() if MODULES_AVAILABLE else None
        self.url_prober = AdvancedURLProber() if MODULES_AVAILABLE else None
        
        # Initialize plugins
        self.plugins = {}
        if MODULES_AVAILABLE:
            try:
                self.plugins = {
                    'aws': AWSExtractor(),
                    'docker': DockerExtractor(), 
                    'git': GitExtractor(),
                    'network': NetworkExtractor()
                }
            except Exception as e:
                print(f"⚠️  Plugin initialization warning: {e}")
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Standard patterns (fallback)
        self.standard_patterns = {
            'urls': re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
            'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ips': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domains': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            'api_keys': re.compile(r'(?:api[_-]?key|apikey)[\'"\s]*[:=]\s*[\'"]?([a-zA-Z0-9_-]{15,})[\'"]?', re.IGNORECASE),
            'paths': re.compile(r'(?:/[a-zA-Z0-9._-]+)+/?'),
            'ports': re.compile(r':(\d{1,5})\b')
        }
    
    def extract_from_file(self, file_path: str) -> Dict[str, Any]:
        """Extract data from a single file with enhanced detection"""
        try:
            # Determine encoding
            encoding = self._detect_encoding(file_path)
            
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
            
            results = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'encoding': encoding,
                'extraction_time': time.time()
            }
            
            # Enhanced pattern detection
            if self.pattern_detector and self.enable_security_scan:
                enhanced_results = analyze_content_enhanced(content, file_path)
                results.update(enhanced_results)
            else:
                # Fallback to standard patterns
                results.update(self._extract_standard_patterns(content))
            
            # Plugin-based extraction
            for plugin_name, plugin in self.plugins.items():
                try:
                    plugin_results = plugin.extract(content, file_path)
                    if plugin_results:
                        results[f'{plugin_name}_data'] = plugin_results
                except Exception as e:
                    self.logger.warning(f"Plugin {plugin_name} failed for {file_path}: {e}")
            
            results['extraction_time'] = time.time() - results['extraction_time']
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
            return {
                'file_path': file_path,
                'error': str(e),
                'extraction_time': 0
            }
    
    def _detect_encoding(self, file_path: str) -> str:
        """Detect file encoding"""
        try:
            import chardet
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)  # Read first 10KB
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except ImportError:
            return 'utf-8'
        except Exception:
            return 'utf-8'
    
    def _extract_standard_patterns(self, content: str) -> Dict[str, Any]:
        """Extract using standard patterns (fallback)"""
        results = {}
        
        for pattern_name, pattern in self.standard_patterns.items():
            matches = pattern.findall(content)
            unique_matches = list(set(matches))
            results[pattern_name] = unique_matches
            results[f'{pattern_name}_count'] = len(unique_matches)
        
        return results
    
    def extract_from_files_concurrent(self, file_paths: List[str], 
                                    progress_callback=None) -> List[Dict[str, Any]]:
        """Extract from multiple files concurrently"""
        results = []
        total_files = len(file_paths)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.extract_from_file, file_path): file_path 
                for file_path in file_paths
            }
            
            # Collect results as they complete
            for i, future in enumerate(as_completed(future_to_file)):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if progress_callback:
                        progress_callback(i + 1, total_files, file_path, result)
                        
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {e}")
                    results.append({
                        'file_path': file_path,
                        'error': str(e),
                        'extraction_time': 0
                    })
        
        return results
    
    def process_directory_recursive(self, directory: str, 
                                  file_extensions: Optional[List[str]] = None,
                                  exclude_patterns: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Process directory recursively with filtering"""
        if file_extensions is None:
            file_extensions = ['.txt', '.log', '.json', '.xml', '.html', '.js', '.py', '.php', '.asp', '.jsp']
        
        if exclude_patterns is None:
            exclude_patterns = ['.git', '__pycache__', 'node_modules', '.venv']
        
        file_paths = []
        exclude_compiled = [re.compile(pattern) for pattern in exclude_patterns]
        
        for root, dirs, files in os.walk(directory):
            # Filter directories
            dirs[:] = [d for d in dirs if not any(pattern.search(d) for pattern in exclude_compiled)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check extension
                if file_extensions and not any(file.lower().endswith(ext) for ext in file_extensions):
                    continue
                
                # Check exclude patterns
                if any(pattern.search(file_path) for pattern in exclude_compiled):
                    continue
                
                file_paths.append(file_path)
        
        self.logger.info(f"Found {len(file_paths)} files to process in {directory}")
        
        def progress_callback(current, total, file_path, result):
            if current % 10 == 0 or current == total:
                print(f"📁 [{current}/{total}] Processed: {Path(file_path).name}")
        
        return self.extract_from_files_concurrent(file_paths, progress_callback)
    
    def aggregate_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate results from multiple files"""
        aggregated = {
            'total_files': len(results),
            'successful_extractions': len([r for r in results if 'error' not in r]),
            'failed_extractions': len([r for r in results if 'error' in r]),
            'total_extraction_time': sum(r.get('extraction_time', 0) for r in results),
            'unique_urls': set(),
            'unique_emails': set(),
            'unique_ips': set(),
            'unique_domains': set(),
            'unique_api_keys': set(),
            'unique_query_params': set(),
            'security_findings': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'technology_distribution': {},
            'plugin_data': {}
        }
        
        # Aggregate data from all files
        for result in results:
            if 'error' in result:
                continue
            
            # Standard aggregation
            for data_type in ['urls', 'emails', 'ips', 'domains', 'api_keys']:
                if data_type in result:
                    aggregated[f'unique_{data_type}'].update(result[data_type])
            
            # Enhanced pattern aggregation
            if 'unique_params' in result:
                aggregated['unique_query_params'].update(result['unique_params'])
            
            if 'findings_by_severity' in result:
                for severity, count in result['findings_by_severity'].items():
                    aggregated['security_findings'][severity] += count
            
            # Plugin data aggregation
            for key, value in result.items():
                if key.endswith('_data'):
                    plugin_name = key.replace('_data', '')
                    if plugin_name not in aggregated['plugin_data']:
                        aggregated['plugin_data'][plugin_name] = []
                    aggregated['plugin_data'][plugin_name].append(value)
        
        # Convert sets to lists for JSON serialization
        for key in aggregated:
            if isinstance(aggregated[key], set):
                aggregated[key] = list(aggregated[key])
        
        # Calculate statistics
        aggregated['unique_urls_count'] = len(aggregated['unique_urls'])
        aggregated['unique_emails_count'] = len(aggregated['unique_emails'])
        aggregated['unique_ips_count'] = len(aggregated['unique_ips'])
        aggregated['unique_domains_count'] = len(aggregated['unique_domains'])
        aggregated['unique_api_keys_count'] = len(aggregated['unique_api_keys'])
        aggregated['unique_query_params_count'] = len(aggregated['unique_query_params'])
        
        return aggregated
    
    def probe_extracted_urls(self, aggregated_results: Dict[str, Any], 
                           output_dir: str = "probe_results") -> Dict[str, Any]:
        """Probe extracted URLs using advanced URL prober"""
        if not self.enable_url_probing or not self.url_prober:
            return {"error": "URL probing not enabled or available"}
        
        urls = aggregated_results.get('unique_urls', [])
        if not urls:
            return {"error": "No URLs found to probe"}
        
        self.logger.info(f"🔍 Probing {len(urls)} extracted URLs...")
        
        # Probe URLs
        probe_results = probe_urls_from_list(
            urls, 
            output_dir=output_dir,
            verbose=True
        )
        
        return probe_results
    
    def generate_comprehensive_report(self, aggregated_results: Dict[str, Any], 
                                    probe_results: Optional[Dict[str, Any]] = None,
                                    output_file: str = "extraction_report.txt"):
        """Generate comprehensive extraction and security report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("ENHANCED FILE EXTRACTION REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            # Extraction Summary
            f.write("📊 EXTRACTION SUMMARY:\n")
            f.write(f"   Total files processed: {aggregated_results['total_files']}\n")
            f.write(f"   Successful extractions: {aggregated_results['successful_extractions']}\n")
            f.write(f"   Failed extractions: {aggregated_results['failed_extractions']}\n")
            f.write(f"   Total processing time: {aggregated_results['total_extraction_time']:.2f}s\n\n")
            
            # Data Discovery
            f.write("🔍 DATA DISCOVERY:\n")
            f.write(f"   Unique URLs: {aggregated_results['unique_urls_count']}\n")
            f.write(f"   Unique emails: {aggregated_results['unique_emails_count']}\n")
            f.write(f"   Unique IP addresses: {aggregated_results['unique_ips_count']}\n")
            f.write(f"   Unique domains: {aggregated_results['unique_domains_count']}\n")
            f.write(f"   Unique API keys: {aggregated_results['unique_api_keys_count']}\n")
            f.write(f"   Unique query parameters: {aggregated_results['unique_query_params_count']}\n\n")
            
            # Security Findings
            security_total = sum(aggregated_results['security_findings'].values())
            if security_total > 0:
                f.write("🔒 SECURITY FINDINGS:\n")
                for severity, count in aggregated_results['security_findings'].items():
                    if count > 0:
                        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                        f.write(f"   {emoji} {severity}: {count} findings\n")
                f.write(f"   Total security findings: {security_total}\n\n")
            
            # Plugin Results
            if aggregated_results['plugin_data']:
                f.write("🔌 PLUGIN ANALYSIS:\n")
                for plugin_name, plugin_data in aggregated_results['plugin_data'].items():
                    f.write(f"   {plugin_name.title()}: {len(plugin_data)} files with relevant data\n")
                f.write("\n")
            
            # URL Probing Results
            if probe_results and 'statistics' in probe_results:
                stats = probe_results['statistics']
                f.write("🌐 URL PROBING RESULTS:\n")
                f.write(f"   Total URLs probed: {stats['total_urls']}\n")
                f.write(f"   Alive URLs: {stats['alive_urls']} ({stats['success_rate']}%)\n")
                f.write(f"   Average response time: {stats['average_response_time']}s\n")
                
                if 'high_value_targets' in probe_results:
                    f.write(f"   High-value targets: {len(probe_results['high_value_targets'])}\n")
                f.write("\n")
            
            # Top Findings
            if aggregated_results['unique_urls']:
                f.write("🎯 TOP DISCOVERED URLS (first 10):\n")
                for url in list(aggregated_results['unique_urls'])[:10]:
                    f.write(f"   {url}\n")
                f.write("\n")
            
            if aggregated_results['unique_query_params']:
                f.write("🔑 UNIQUE QUERY PARAMETERS:\n")
                for param in list(aggregated_results['unique_query_params'])[:20]:
                    f.write(f"   {param}\n")
                f.write("\n")
            
            # Recommendations
            f.write("💡 RECOMMENDATIONS:\n")
            f.write("-" * 20 + "\n")
            
            if aggregated_results['security_findings']['CRITICAL'] > 0:
                f.write("🔴 CRITICAL: Immediate action required for security findings\n")
            
            if aggregated_results['unique_urls_count'] > 0:
                f.write("🌐 Consider probing discovered URLs for security assessment\n")
            
            if aggregated_results['unique_api_keys_count'] > 0:
                f.write("🔑 Review and rotate any exposed API keys\n")
            
            f.write("📋 Regular security audits recommended\n")
        
        print(f"📋 Comprehensive report saved to: {output_file}")
    
    def save_results(self, aggregated_results: Dict[str, Any], 
                    output_dir: str = "extraction_results"):
        """Save extraction results to multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = int(time.time())
        
        # Save complete results as JSON
        json_file = output_path / f"extraction_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(aggregated_results, f, indent=2, default=str)
        
        # Save individual data types
        data_types = ['unique_urls', 'unique_emails', 'unique_ips', 'unique_domains']
        for data_type in data_types:
            if aggregated_results.get(data_type):
                data_file = output_path / f"{data_type}_{timestamp}.txt"
                with open(data_file, 'w') as f:
                    f.write('\n'.join(aggregated_results[data_type]))
        
        print(f"📁 Results saved to {output_dir}:")
        print(f"   📄 Complete results: {json_file.name}")
        for data_type in data_types:
            if aggregated_results.get(data_type):
                print(f"   📄 {data_type.replace('_', ' ').title()}: {data_type}_{timestamp}.txt")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Enhanced File Extractor with Advanced Pattern Detection and Concurrent Processing"
    )
    
    parser.add_argument("target", nargs="?", help="File or directory to process")
    parser.add_argument("-i", "--input", dest="input_file",
                       help="File containing list of files/URLs to process (one per line)")
    parser.add_argument("-o", "--output", default="extraction_results", 
                       help="Output directory (default: extraction_results)")
    parser.add_argument("-w", "--workers", type=int, default=4,
                       help="Number of worker threads (default: 4)")
    parser.add_argument("-e", "--extensions", nargs="+", 
                       default=['.txt', '.log', '.json', '.xml', '.html', '.js', '.py', '.php'],
                       help="File extensions to process")
    parser.add_argument("--disable-security", action="store_true",
                       help="Disable enhanced security scanning")
    parser.add_argument("--enable-url-probing", action="store_true",
                       help="Enable URL probing of discovered URLs")
    parser.add_argument("--probe-output", default="probe_results",
                       help="URL probing output directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target and not args.input_file:
        parser.error("Either target or --input must be specified")
    
    if args.target and args.input_file:
        parser.error("Cannot specify both target and --input")
    
    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize extractor
    extractor = EnhancedFileExtractor(
        max_workers=args.workers,
        enable_security_scan=not args.disable_security,
        enable_url_probing=args.enable_url_probing
    )
    
    print("🚀 Enhanced File Extractor Starting...")
    print(f"📁 Target: {args.target}")
    print(f"🔧 Workers: {args.workers}")
    print(f"🔒 Security scanning: {'Enabled' if not args.disable_security else 'Disabled'}")
    print(f"🌐 URL probing: {'Enabled' if args.enable_url_probing else 'Disabled'}")
    
    start_time = time.time()
    
    try:
        # Process target
        if os.path.isfile(args.target):
            print("📄 Processing single file...")
            results = [extractor.extract_from_file(args.target)]
        elif os.path.isdir(args.target):
            print("📁 Processing directory recursively...")
            results = extractor.process_directory_recursive(args.target, args.extensions)
        else:
            print(f"❌ Target not found: {args.target}")
            return 1
        
        # Aggregate results
        print("📊 Aggregating results...")
        aggregated_results = extractor.aggregate_results(results)
        
        # URL probing
        probe_results = None
        if args.enable_url_probing:
            print("🌐 Starting URL probing...")
            probe_results = extractor.probe_extracted_urls(aggregated_results, args.probe_output)
        
        # Save results
        print("💾 Saving results...")
        extractor.save_results(aggregated_results, args.output)
        
        # Generate report
        report_file = Path(args.output) / "comprehensive_report.txt"
        extractor.generate_comprehensive_report(aggregated_results, probe_results, str(report_file))
        
        # Summary
        processing_time = time.time() - start_time
        print(f"\n✅ Processing completed in {processing_time:.2f} seconds!")
        print(f"📊 Processed {aggregated_results['total_files']} files")
        print(f"🔍 Found {aggregated_results['unique_urls_count']} unique URLs")
        print(f"📧 Found {aggregated_results['unique_emails_count']} unique emails")
        print(f"🌐 Found {aggregated_results['unique_ips_count']} unique IPs")
        
        security_total = sum(aggregated_results['security_findings'].values())
        if security_total > 0:
            print(f"🔒 Found {security_total} security findings")
        
        if probe_results and 'statistics' in probe_results:
            stats = probe_results['statistics']
            print(f"🌐 Probed URLs: {stats['alive_urls']}/{stats['total_urls']} alive ({stats['success_rate']}%)")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Processing interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
