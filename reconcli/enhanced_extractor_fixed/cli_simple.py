#!/usr/bin/env python3
"""Command Line Interface for Enhanced File Extractor Suite."""

import sys
import argparse
import os
from pathlib import Path

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Enhanced File Extractor Suite - Professional-grade file extraction and security analysis toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  enhanced-extractor /path/to/files                    # Basic extraction
  enhanced-extractor /path/to/files --enable-url-probing -v  # With URL probing
  enhanced-extractor /path/to/files -w 8 --enable-url-probing  # High performance
  enhanced-extractor myfile.log -v                     # Single file analysis

Direct Script Usage:
  python enhanced_file_extractor/enhanced_extractor.py <target>
  python enhanced_file_extractor/url_prober_v2.py
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="File or directory to process"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Enhanced File Extractor Suite v2.0.0"
    )
    
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show package information and usage"
    )
    
    args = parser.parse_args()
    
    if args.info or not args.target:
        print("🚀 Enhanced File Extractor Suite v2.0.0")
        print("=" * 50)
        print("Professional-grade file extraction and security analysis toolkit")
        print()
        print("📦 Package Successfully Installed!")
        print()
        print("📋 Usage Options:")
        print("1. Direct Script Execution (Recommended):")
        print(f"   cd {os.path.dirname(os.path.abspath(__file__))}")
        print("   python enhanced_extractor.py <target_file_or_directory>")
        print("   python url_prober_v2.py")
        print()
        print("2. Module Import:")
        print("   from enhanced_file_extractor.enhanced_extractor import EnhancedFileExtractor")
        print("   extractor = EnhancedFileExtractor()")
        print()
        print("📁 Package Location:")
        print(f"   {os.path.dirname(os.path.abspath(__file__))}")
        print()
        print("🔧 Available Commands:")
        print("   enhanced-extractor --info    # Show this information")
        print("   enhanced-extractor --version # Show version")
        print("   file-extractor --info        # Alternative command")
        print()
        print("📊 Features:")
        print("   ✅ Concurrent file processing")
        print("   ✅ Advanced security pattern detection")
        print("   ✅ URL probing with httpx")
        print("   ✅ Plugin architecture")
        print("   ✅ Comprehensive reporting")
        print()
        print("For full functionality, use the direct script execution method.")
        return
    
    # Process target
    target_path = Path(args.target)
    
    if not target_path.exists():
        print(f"❌ Error: Target '{args.target}' does not exist")
        sys.exit(1)
    
    print(f"🚀 Enhanced File Extractor Suite v2.0.0")
    print(f"📁 Target: {args.target}")
    print()
    
    print("📋 To run the full extraction, use:")
    package_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"   cd {package_dir}")
    print(f"   python enhanced_extractor.py '{args.target}'")
    print(f"   python url_prober_v2.py")
    
    print()
    print("✅ Package is properly installed and ready to use!")


if __name__ == "__main__":
    main()
