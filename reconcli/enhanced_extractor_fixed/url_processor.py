"""
Enhanced File Extractor - URL Processing Functions
This module handles URL processing and input file handling with smart validation.
"""

import requests
import time
from pathlib import Path

def process_input_file(extractor, input_file, verbose=False):
    """Process input file containing URLs/files with smart URL handling."""
    print(f"📋 Processing input file: {input_file}")
    
    try:
        with open(input_file, 'r') as f:
            input_lines = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
        
        print(f"📥 Found {len(input_lines)} input items")
        
        # Use smart URL handler to categorize inputs
        from smart_url_handler import sanitize_input_list
        categorized = sanitize_input_list(input_lines, verbose=verbose)
        
        results = []
        
        # Process URLs
        if categorized['urls']:
            print(f"\n🌐 Processing {len(categorized['urls'])} URLs...")
            for url in categorized['urls']:
                try:
                    result = extract_from_url(extractor, url)
                    if result:
                        results.append(result)
                except Exception as e:
                    if verbose:
                        print(f"❌ Error processing {url}: {e}")
                    continue
        
        # Process any local files that were in the input
        local_files = [item for item in input_lines if Path(item).exists()]
        if local_files:
            print(f"\n📁 Processing {len(local_files)} local files...")
            for file_path in local_files:
                try:
                    result = extractor.extract_from_file(file_path)
                    if result:
                        results.append(result)
                except Exception as e:
                    if verbose:
                        print(f"❌ Error processing {file_path}: {e}")
                    continue
        
        print(f"✅ Successfully processed {len(results)} items")
        return results
        
    except FileNotFoundError:
        print(f"❌ Input file not found: {input_file}")
        return []
    except Exception as e:
        print(f"❌ Error reading input file: {e}")
        return []

def extract_from_url(extractor, url, timeout=10):
    """Extract content from a URL with error handling."""
    try:
        # Use smart URL validation before making request
        from smart_url_handler import validate_url_for_requests
        is_valid, reason = validate_url_for_requests(url)
        
        if not is_valid:
            print(f"⚠️  Skipping invalid URL {url}: {reason}")
            return None
        
        headers = {
            'User-Agent': 'Enhanced-File-Extractor/2.0 (Data Extraction Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        print(f"🌐 Fetching: {url}")
        response = requests.get(url, headers=headers, timeout=timeout, 
                              verify=False, allow_redirects=True)
        
        if response.status_code == 200:
            # Create a temporary result structure
            content = response.text
            
            # Extract data using the extractor's methods
            extracted_data = {
                'source_file': url,
                'source_type': 'url',
                'file_size': len(content),
                'processing_time': 0,
                'urls': [],
                'emails': [],
                'ips': [],
                'domains': [],
                'api_keys': [],
                'security_findings': {},
                'metadata': {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'content_length': len(content)
                }
            }
            
            # Use extractor's pattern matching
            start_time = time.time()
            
            # Extract patterns using extractor's methods
            if hasattr(extractor, 'enhanced_patterns'):
                patterns = extractor.enhanced_patterns.patterns
            else:
                patterns = extractor.standard_patterns
            
            for pattern_name, pattern in patterns.items():
                if pattern_name in extracted_data:
                    matches = list(set(pattern.findall(content)))
                    extracted_data[pattern_name] = matches
            
            extracted_data['processing_time'] = time.time() - start_time
            
            print(f"✅ Extracted from {url}: {len(extracted_data.get('urls', []))} URLs, {len(extracted_data.get('emails', []))} emails")
            return extracted_data
            
        else:
            print(f"⚠️  HTTP {response.status_code} for {url}")
            return None
            
    except requests.exceptions.SSLError as e:
        print(f"🔒 SSL Error for {url}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"🔌 Connection Error for {url}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"⏰ Timeout for {url}: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error for {url}: {e}")
        return None
