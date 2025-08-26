#!/usr/bin/env python3
"""Smart URL and input validation for Enhanced File Extractor."""

import re
from urllib.parse import urlparse

def is_valid_http_url(url):
    """Check if URL is a valid HTTP/HTTPS URL."""
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ['http', 'https'] and parsed.netloc
    except:
        return False

def is_email(text):
    """Check if text is an email address."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, text.strip()) is not None

def is_ip_address(text):
    """Check if text is an IP address."""
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(ip_pattern, text.strip()) is not None

def is_domain(text):
    """Check if text looks like a domain name."""
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(domain_pattern, text.strip()) is not None and '.' in text

def sanitize_input_list(input_list, verbose=False):
    """Sanitize and categorize input list items with smart handling."""
    urls = []
    emails = []
    ips = []
    domains = []
    skipped = []
    
    for item in input_list:
        item = item.strip()
        if not item or item.startswith('#'):
            continue
            
        # Already valid HTTP/HTTPS URLs
        if is_valid_http_url(item):
            urls.append(item)
            if verbose:
                print(f"✅ [URL] Valid: {item}")
                
        # Email addresses
        elif is_email(item):
            emails.append(item)
            if verbose:
                print(f"📧 [EMAIL] Found: {item}")
                
        # IP addresses - convert to HTTP URLs
        elif is_ip_address(item):
            http_url = f"http://{item}"
            https_url = f"https://{item}"
            urls.extend([http_url, https_url])  # Try both HTTP and HTTPS
            ips.append(item)
            if verbose:
                print(f"🌐 [IP->URL] Converting: {item} -> {http_url}, {https_url}")
                
        # Domain names - convert to HTTPS URLs
        elif is_domain(item):
            https_url = f"https://{item}"
            urls.append(https_url)
            domains.append(item)
            if verbose:
                print(f"🔧 [DOMAIN->URL] Converting: {item} -> {https_url}")
                
        # Skip unsupported protocols
        elif any(item.startswith(proto) for proto in ['smtp://', 'ftp://', 'ssh://', 'sftp://', 'ldap://']):
            skipped.append(item)
            if verbose:
                print(f"⚠️  [SKIP] Unsupported protocol: {item}")
                
        # Try to auto-fix malformed URLs
        else:
            # Maybe it's a URL without protocol
            if '.' in item and not ' ' in item:
                test_url = f"https://{item}"
                if is_valid_http_url(test_url):
                    urls.append(test_url)
                    if verbose:
                        print(f"🔧 [AUTO-FIX] Fixed: {item} -> {test_url}")
                else:
                    skipped.append(item)
                    if verbose:
                        print(f"❌ [INVALID] Skipping: {item}")
            else:
                skipped.append(item)
                if verbose:
                    print(f"❌ [UNKNOWN] Skipping: {item}")
    
    result = {
        'urls': list(set(urls)),  # Remove duplicates
        'emails': list(set(emails)),
        'ips': list(set(ips)), 
        'domains': list(set(domains)),
        'skipped': skipped,
        'stats': {
            'total_input': len(input_list),
            'valid_urls': len(set(urls)),
            'emails_found': len(set(emails)),
            'ips_converted': len(set(ips)),
            'domains_converted': len(set(domains)),
            'items_skipped': len(skipped)
        }
    }
    
    if verbose:
        print(f"\n📊 [SUMMARY] Input Processing:")
        print(f"   📥 Total inputs: {result['stats']['total_input']}")
        print(f"   ✅ Valid URLs: {result['stats']['valid_urls']}")
        print(f"   📧 Emails: {result['stats']['emails_found']}")
        print(f"   🌐 IPs converted: {result['stats']['ips_converted']}")
        print(f"   🔧 Domains converted: {result['stats']['domains_converted']}")
        print(f"   ⚠️  Skipped: {result['stats']['items_skipped']}")
    
    return result

def validate_url_for_requests(url):
    """Final validation before making HTTP request."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False, f"Unsupported scheme: {parsed.scheme}"
        if not parsed.netloc:
            return False, "No hostname found"
        return True, "Valid"
    except Exception as e:
        return False, f"Parse error: {e}"
