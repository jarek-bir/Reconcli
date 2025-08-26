#!/usr/bin/env python3
"""
Enhanced File Extractor CLI with Smart URL Handling
Fixes the missing input file processing functionality.
"""

import os
import sys
import argparse
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules
from enhanced_extractor import EnhancedFileExtractor
from smart_url_handler import sanitize_input_list
from url_processor import process_input_file

def main():
    """Enhanced CLI with input file processing."""
    parser = argparse.ArgumentParser(
        description="Enhanced File Extractor with Smart URL Handling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s file.txt                           # Process single file
  %(prog)s /path/to/directory                 # Process directory
  %(prog)s -i urls.txt                        # Process URLs from file
  %(prog)s -i mixed_input.txt --enable-url-probing  # Process with URL probing
        """
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
    
    # Initialize extractor
    extractor = EnhancedFileExtractor(
        max_workers=args.workers,
        enable_security_scan=not args.disable_security,
        enable_url_probing=args.enable_url_probing
    )
    
    print("🚀 Enhanced File Extractor Starting...")
    if args.target:
        print(f"📁 Target: {args.target}")
    if args.input_file:
        print(f"📋 Input file: {args.input_file}")
    print(f"🔧 Workers: {args.workers}")
    print(f"🔒 Security scanning: {'Enabled' if not args.disable_security else 'Disabled'}")
    print(f"🌐 URL probing: {'Enabled' if args.enable_url_probing else 'Disabled'}")
    
    start_time = time.time()
    
    try:
        results = []
        
        # Process input file with smart URL handling
        if args.input_file:
            print("\n" + "="*60)
            print("📋 PROCESSING INPUT FILE WITH SMART URL HANDLING")
            print("="*60)
            results = process_input_file(extractor, args.input_file, verbose=args.verbose)
            
        # Process target (file or directory)
        elif args.target:
            if os.path.isfile(args.target):
                print("📄 Processing single file...")
                results = [extractor.extract_from_file(args.target)]
            elif os.path.isdir(args.target):
                print("📁 Processing directory recursively...")
                results = extractor.process_directory_recursive(args.target, args.extensions)
            else:
                print(f"❌ Target not found: {args.target}")
                return 1
        
        if not results:
            print("❌ No results to process")
            return 1
        
        # Aggregate results
        print("\n📊 Aggregating results...")
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
        print(f"\n" + "="*60)
        print("✅ PROCESSING COMPLETED SUCCESSFULLY!")
        print("="*60)
        print(f"⏱️  Total time: {processing_time:.2f} seconds")
        print(f"📊 Processed {aggregated_results['total_files']} files/URLs")
        print(f"🔍 Found {aggregated_results['unique_urls_count']} unique URLs")
        print(f"📧 Found {aggregated_results['unique_emails_count']} unique emails")
        print(f"🌐 Found {aggregated_results['unique_ips_count']} unique IPs")
        
        security_total = sum(aggregated_results['security_findings'].values())
        if security_total > 0:
            print(f"🔒 Found {security_total} security findings")
        
        if probe_results and 'statistics' in probe_results:
            stats = probe_results['statistics']
            print(f"🌐 Probed URLs: {stats['alive_urls']}/{stats['total_urls']} alive ({stats['success_rate']}%)")
        
        print(f"📁 Results saved to: {args.output}")
        if report_file.exists():
            print(f"📄 Report saved to: {report_file}")
        
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
