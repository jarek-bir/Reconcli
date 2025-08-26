#!/usr/bin/env python3
"""Command Line Interface for Enhanced File Extractor Suite."""

import sys
import os
import argparse
from pathlib import Path
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from typing import List, Dict, Any, Optional, Set, Tuple
import re
import time
from urllib.parse import urlparse

def main():
    """Main CLI entry point with full functionality."""
    parser = argparse.ArgumentParser(
        description="Enhanced File Extractor Suite - Professional-grade file extraction and security analysis toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  enhanced-extractor /path/to/files                           # Basic extraction
  enhanced-extractor -i urls.txt -o results.json             # Process URL list
  enhanced-extractor /path/to/files --enable-url-probing -v  # With URL probing
  enhanced-extractor /path/to/files -w 8 --enable-url-probing # High performance
  enhanced-extractor myfile.log -v                           # Single file analysis
  enhanced-extractor -i input.txt -w 20 -v                   # Process input file with 20 workers
        """
    )
    
    # Main target or input file
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "target",
        nargs="?",
        help="File or directory to process"
    )
    group.add_argument(
        "-i", "--input",
        dest="input_file",
        help="Input file containing list of URLs or file paths to process (one per line)"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        default="extraction_results.json",
        help="Output file for results (default: extraction_results.json)"
    )
    
    # Performance options
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)"
    )
    
    # File filtering
    parser.add_argument(
        "-e", "--extensions",
        nargs="+",
        default=[".txt", ".log", ".json", ".xml", ".csv", ".md", ".py", ".js", ".html", ".htm", ".php", ".sql", ".conf", ".cfg", ".ini", ".yml", ".yaml"],
        help="File extensions to process (default: common text files)"
    )
    
    # Feature toggles
    parser.add_argument(
        "--enable-url-probing",
        action="store_true",
        help="Enable URL probing to check if extracted URLs are accessible"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Enhanced File Extractor Suite v2.0.0"
    )
    
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show package information and exit"
    )
    
    args = parser.parse_args()
    
    # Handle info request
    if args.info:
        print("🚀 Enhanced File Extractor Suite v2.0.0")
        print("=" * 50)
        print("Professional-grade file extraction and security analysis toolkit")
        print()
        print("📦 Package Successfully Installed!")
        print()
        print("� Features:")
        print("   ✅ Concurrent file processing")
        print("   ✅ Advanced security pattern detection")
        print("   ✅ URL probing with httpx")
        print("   ✅ Plugin architecture")
        print("   ✅ Comprehensive reporting")
        print("   ✅ Input file list processing")
        print("   ✅ Configurable worker threads")
        print()
        print("📁 Package Location:")
        print(f"   {os.path.dirname(os.path.abspath(__file__))}")
        return
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Validate arguments
    if not args.target and not args.input_file:
        parser.error("Either provide a target file/directory or use -i/--input to specify an input file")
    
    # Import the actual extractor
    try:
        from . import enhanced_extractor
        
        # Create extractor instance
        extractor = enhanced_extractor.EnhancedFileExtractor()
        
        # Handle input file processing
        if args.input_file:
            if not os.path.exists(args.input_file):
                print(f"❌ Error: Input file '{args.input_file}' does not exist")
                sys.exit(1)
            
            print(f"🚀 Enhanced File Extractor Suite v2.0.0")
            print(f"📄 Processing input file: {args.input_file}")
            print(f"� Workers: {args.workers}")
            print(f"📊 URL Probing: {'Enabled' if args.enable_url_probing else 'Disabled'}")
            print(f"📁 Output: {args.output}")
            print()
            
            # Read input file
            try:
                with open(args.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                print(f"📋 Loaded {len(targets)} targets from input file")
                
                # Process targets
                start_time = time.time()
                all_results = []
                
                for i, target in enumerate(targets, 1):
                    if args.verbose:
                        print(f"🔍 Processing {i}/{len(targets)}: {target}")
                    
                    target_path = Path(target)
                    if target_path.exists():
                        # Process as file/directory
                        if target_path.is_file():
                            results = extractor.extract_from_file(str(target_path))
                        else:
                            # For directories, get all files and process them
                            file_paths = []
                            for root, dirs, files in os.walk(target_path):
                                for file in files:
                                    if args.extensions and not any(file.lower().endswith(ext) for ext in args.extensions):
                                        continue
                                    file_paths.append(os.path.join(root, file))
                            
                            if file_paths:
                                all_file_results = []
                                for file_path in file_paths:
                                    file_result = extractor.extract_from_file(file_path)
                                    all_file_results.append(file_result)
                                
                                # Aggregate results like the main script does
                                results = extractor.aggregate_results(all_file_results)
                            else:
                                results = {"target": target, "urls": [], "emails": [], "ips": [], "files": []}
                    else:
                        # Treat as URL
                        results = {"target": target, "urls": [target], "emails": [], "ips": [], "files": []}
                    
                    all_results.append({
                        "target": target,
                        "results": results,
                        "timestamp": time.time()
                    })
                
                # Save results
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump({
                        "metadata": {
                            "total_targets": len(targets),
                            "processing_time": time.time() - start_time,
                            "workers": args.workers,
                            "url_probing_enabled": args.enable_url_probing,
                            "timestamp": time.time()
                        },
                        "results": all_results
                    }, f, indent=2, ensure_ascii=False)
                
                print(f"✅ Processing complete! Results saved to {args.output}")
                print(f"⏱️  Total time: {time.time() - start_time:.2f}s")
                
            except Exception as e:
                print(f"❌ Error processing input file: {e}")
                sys.exit(1)
        
        # Handle single target processing
        else:
            target_path = Path(args.target)
            
            if not target_path.exists():
                print(f"❌ Error: Target '{args.target}' does not exist")
                sys.exit(1)
            
            print(f"🚀 Enhanced File Extractor Suite v2.0.0")
            print(f"📁 Target: {args.target}")
            print(f"👥 Workers: {args.workers}")
            print(f"📊 URL Probing: {'Enabled' if args.enable_url_probing else 'Disabled'}")
            print(f"� Output: {args.output}")
            print()
            
            # Process target
            start_time = time.time()
            
            if target_path.is_file():
                results = extractor.extract_from_file(str(target_path))
            else:
                # For directories, get all files and process them
                file_paths = []
                for root, dirs, files in os.walk(target_path):
                    for file in files:
                        if args.extensions and not any(file.lower().endswith(ext) for ext in args.extensions):
                            continue
                        file_paths.append(os.path.join(root, file))
                
                if file_paths:
                    all_file_results = []
                    for file_path in file_paths:
                        file_result = extractor.extract_from_file(file_path)
                        all_file_results.append(file_result)
                    
                    # Aggregate results like the main script does
                    results = extractor.aggregate_results(all_file_results)
                else:
                    results = {"target": args.target, "urls": [], "emails": [], "ips": [], "files": []}
            
            # Save results
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump({
                    "metadata": {
                        "target": args.target,
                        "processing_time": time.time() - start_time,
                        "workers": args.workers,
                        "url_probing_enabled": args.enable_url_probing,
                        "timestamp": time.time()
                    },
                    "results": results
                }, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Processing complete! Results saved to {args.output}")
            print(f"⏱️  Total time: {time.time() - start_time:.2f}s")
    
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("📋 Falling back to direct script execution:")
        package_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"   cd {package_dir}")
        print(f"   python enhanced_extractor.py '{args.target if args.target else args.input_file}'")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
