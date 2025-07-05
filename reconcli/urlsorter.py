#!/usr/bin/env python3
"""
URL Sorter for Reconcli Toolkit
Advanced URL categorization and pattern matching for security testing
"""

import click
import os
import re
import yaml
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any
import logging

# Import resume utilities
try:
    from reconcli.utils.resume import load_resume, save_resume_state, clear_resume
except ImportError:
    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def clear_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            os.remove(path)


def load_urls_from_source(input_source):
    """Load URLs from file or stdin"""
    if input_source == "-":
        # Read from stdin
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        # Read from file
        with open(input_source, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    return urls

# Enhanced patterns for comprehensive security testing
DEFAULT_PATTERNS = {
    # Cross-Site Scripting (XSS)
    "xss": r"(?i)(script|onerror|onload|alert|%3Cscript|<svg|xss=|javascript:|vbscript:|expression\(|%253Cscript)",
    
    # Local File Inclusion (LFI)
    "lfi": r"(?i)(\.\./|\.\.\\\\|etc/passwd|%2e%2e%2f|%2e%2e\\|windows/system32|boot\.ini)",
    
    # Server-Side Request Forgery (SSRF)
    "ssrf": r"(?i)(http:\/\/127\.|localhost|internal|0\.0\.0\.0|169\.254\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
    
    # Remote Code Execution (RCE)
    "rce": r"(?i)(cmd=|exec|shell=|run=|system=|command=|eval=|%20ping%20|whoami|id\;|cat%20)",
    
    # Open Redirect
    "redirect": r"(?i)(redirect=|url=|next=|target=|goto=|link=|forward=|return_url=)",
    
    # SQL Injection
    "sqli": r"(?i)(union select|select .* from|or 1=1|and 1=1|'|\"|%27|%22|order by|group by|having)",
    
    # Privilege Bypass
    "bypass": r"(?i)(admin=true|is_admin|access=granted|role=admin|user_type=admin|level=admin)",
    
    # Authentication Tokens
    "token": r"(?i)(access_token|auth_token|jwt|bearer|api_key|session_id|csrf_token)",
    
    # Callback Functions (JSONP)
    "callback": r"(?i)(callback=|jsonp=|return=|continue=|_callback=)",
    
    # GraphQL
    "graphql": r"(?i)(graphql|graphiql|query=|mutation=|subscription=)",
    
    # Information Disclosure
    "sitemap": r"(?i)(sitemap\.xml|robots\.txt|\.well-known|crossdomain\.xml|security\.txt)",
    
    # File Upload
    "upload": r"(?i)(upload|file=|filename=|attachment=|document=|image=|photo=)",
    
    # API Endpoints
    "api": r"(?i)(\/api\/|\/v[0-9]+\/|\.json|\.xml|rest\/|graphql\/|swagger)",
    
    # Admin Panels
    "admin": r"(?i)(\/admin|\/administrator|\/wp-admin|\/control|\/manage|\/backend|\/dashboard)",
    
    # Database Operations
    "database": r"(?i)(backup|dump|export|import|migrate|restore|schema|table)",
    
    # File Extensions of Interest
    "sensitive_files": r"(?i)\.(config|conf|ini|env|bak|backup|old|tmp|log|sql|db)(\?|$)",
    
    # Parameter Pollution
    "param_pollution": r"(?i)([?&][^=]+=.*&[^=]+=)",
    
    # Testing Parameters
    "test_params": r"(?i)(test=|debug=|dev=|demo=|example=|sample=|mock=)",
    
    # Version Disclosure
    "version": r"(?i)(version=|v=|ver=|build=|release=)",
}


@click.group()
def cli():
    """URL Sorter - Advanced URL categorization and pattern matching"""
    pass


@cli.command()
@click.option("-i", "--input", help="Input file with URLs (one per line). Use '-' for stdin.")
@click.option("-o", "--output-dir", default="output_urlsort", help="Output directory")
@click.option("-p", "--patterns", help="Optional custom pattern file (YAML)")
@click.option("--json", "export_json", is_flag=True, help="Export summary to JSON")
@click.option("--markdown", is_flag=True, help="Export summary to Markdown")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--dedupe", is_flag=True, help="Remove duplicate URLs")
@click.option("--sort", is_flag=True, help="Sort URLs alphabetically")
@click.option("--filter-params", help="Filter URLs by parameter patterns (regex)")
@click.option("--filter-domains", help="Filter URLs by domain patterns (regex)")
@click.option("--exclude-patterns", help="Exclude URLs matching patterns (regex)")
@click.option("--min-params", type=int, help="Minimum number of parameters required")
@click.option("--max-params", type=int, help="Maximum number of parameters allowed")
@click.option("--resume", is_flag=True, help="Resume from previous run")
@click.option("--clear-resume", "clear_resume_flag", is_flag=True, help="Clear previous resume state")
@click.option("--show-resume", is_flag=True, help="Show status of previous runs")
def sort(input, output_dir, patterns, export_json, markdown, verbose, dedupe, sort, 
         filter_params, filter_domains, exclude_patterns, min_params, max_params,
         resume, clear_resume_flag, show_resume):
    """Sort URLs by security testing patterns"""
    
    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir, "urlsort")
        return

    if clear_resume_flag:
        clear_resume(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Check if we can read from stdin when no input file provided
    import sys
    if not input:
        if not sys.stdin.isatty():
            input = "-"  # stdin
        else:
            click.echo("❌ Error: Input file is required for URL sorting")
            click.echo("Usage: python urlsorter.py sort -i <file> OR echo 'urls' | python urlsorter.py sort")
            raise click.Abort()

    if verbose:
        click.echo(f"[+] 🚀 Starting URL sorting")
        click.echo(f"[+] 📁 Input source: {input if input != '-' else 'stdin'}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
    
    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"urlsort_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_state = load_resume(output_dir)

    if resume and resume_state:
        if verbose:
            click.echo(f"[+] 📁 Loading resume state with {len(resume_state)} previous scan(s)")
        # Find the most recent incomplete scan
        for key, data in sorted(resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True):
            if key.startswith("urlsort_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "input_file": input,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "processed_count": 0,
            "configuration": {
                "dedupe": dedupe,
                "sort": sort,
                "filter_params": filter_params,
                "filter_domains": filter_domains,
                "exclude_patterns": exclude_patterns,
                "min_params": min_params,
                "max_params": max_params,
            },
        }
        save_resume_state(output_dir, resume_state)

    # Load patterns
    if patterns:
        if verbose:
            click.echo(f"[+] 📋 Loading custom patterns from {patterns}")
        with open(patterns, "r") as f:
            pattern_dict = yaml.safe_load(f)
    else:
        pattern_dict = DEFAULT_PATTERNS
        if verbose:
            click.echo(f"[+] 📋 Using {len(pattern_dict)} default patterns")

    # Load and process URLs
    urls = load_urls_from_source(input)
    
    if verbose:
        click.echo(f"[+] 🌐 Loaded {len(urls)} URLs")

    # Apply filters and processing
    processed_urls = process_urls(urls, filter_params, filter_domains, exclude_patterns, 
                                min_params, max_params, dedupe, sort, verbose)
    
    if verbose:
        click.echo(f"[+] ✅ After processing: {len(processed_urls)} URLs")

    # Categorize URLs by patterns
    matches, analysis = categorize_urls(processed_urls, pattern_dict, verbose)

    # Save categorized URLs
    save_categorized_urls(matches, output_dir, verbose)

    # Generate comprehensive statistics
    stats = generate_comprehensive_stats(processed_urls, matches, analysis, pattern_dict)

    # Save outputs
    if export_json:
        save_json_output(stats, output_dir, verbose)
    
    if markdown:
        save_markdown_output(stats, analysis, output_dir, verbose)

    # Update resume state
    current_scan = resume_state[scan_key]
    current_scan["processed_count"] = len(processed_urls)
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()
    save_resume_state(output_dir, resume_state)

    if verbose:
        click.echo(f"\n[+] 📊 Sorting Summary:")
        click.echo(f"   - Total URLs processed: {len(processed_urls)}")
        click.echo(f"   - Categories with matches: {len([k for k, v in matches.items() if v])}")
        click.echo(f"   - Total matches: {sum(len(v) for v in matches.values())}")

    click.echo(f"\n[+] ✅ URL sorting completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


@cli.command()
@click.option("-i", "--input", help="Input file with URLs (one per line). Use '-' for stdin.")
@click.option("-o", "--output-dir", default="output_url_analysis", help="Output directory")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--json", "export_json", is_flag=True, help="Export analysis to JSON")
@click.option("--markdown", is_flag=True, help="Export analysis to Markdown")
def analyze(input, output_dir, verbose, export_json, markdown):
    """Perform advanced URL analysis and statistics"""
    
    # Check if we can read from stdin when no input file provided
    if not input:
        if not sys.stdin.isatty():
            input = "-"  # stdin
        else:
            click.echo("❌ Error: Input file is required for URL analysis")
            click.echo("Usage: python urlsorter.py analyze -i <file> OR echo 'urls' | python urlsorter.py analyze")
            raise click.Abort()
    
    if verbose:
        click.echo(f"[+] 🔍 Starting URL analysis")
        click.echo(f"[+] 📁 Input source: {input if input != '-' else 'stdin'}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Load URLs
    urls = load_urls_from_source(input)

    if verbose:
        click.echo(f"[+] 🌐 Loaded {len(urls)} URLs for analysis")

    # Perform comprehensive analysis
    analysis_results = perform_url_analysis(urls, verbose)

    # Save analysis results
    if export_json:
        save_analysis_json(analysis_results, output_dir, verbose)
    
    if markdown:
        save_analysis_markdown(analysis_results, output_dir, verbose)

    if verbose:
        click.echo(f"\n[+] ✅ URL analysis completed!")
        click.echo(f"[+] 📁 Analysis results saved to: {output_dir}")


def process_urls(urls: List[str], filter_params: str, filter_domains: str, 
                exclude_patterns: str, min_params: int, max_params: int,
                dedupe: bool, sort_urls: bool, verbose: bool) -> List[str]:
    """Process URLs with various filters and transformations"""
    
    processed = urls.copy()
    original_count = len(processed)

    # Apply domain filter
    if filter_domains:
        domain_regex = re.compile(filter_domains, re.IGNORECASE)
        processed = [url for url in processed if domain_regex.search(urlparse(url).netloc)]
        if verbose:
            click.echo(f"[+] 🔍 Domain filter: {len(processed)}/{original_count} URLs remaining")

    # Apply parameter filter
    if filter_params:
        param_regex = re.compile(filter_params, re.IGNORECASE)
        processed = [url for url in processed if param_regex.search(url)]
        if verbose:
            click.echo(f"[+] 🔍 Parameter filter: {len(processed)}/{original_count} URLs remaining")

    # Apply exclusion patterns
    if exclude_patterns:
        exclude_regex = re.compile(exclude_patterns, re.IGNORECASE)
        processed = [url for url in processed if not exclude_regex.search(url)]
        if verbose:
            click.echo(f"[+] 🔍 Exclusion filter: {len(processed)}/{original_count} URLs remaining")

    # Filter by parameter count
    if min_params is not None or max_params is not None:
        filtered = []
        for url in processed:
            parsed = urlparse(url)
            param_count = len(parse_qs(parsed.query))
            
            if min_params is not None and param_count < min_params:
                continue
            if max_params is not None and param_count > max_params:
                continue
            filtered.append(url)
        
        processed = filtered
        if verbose:
            click.echo(f"[+] 🔍 Parameter count filter: {len(processed)}/{original_count} URLs remaining")

    # Remove duplicates
    if dedupe:
        processed = list(dict.fromkeys(processed))  # Preserves order
        if verbose:
            click.echo(f"[+] 🔍 Deduplication: {len(processed)}/{original_count} URLs remaining")

    # Sort URLs
    if sort_urls:
        processed.sort()
        if verbose:
            click.echo(f"[+] 🔍 URLs sorted alphabetically")

    return processed


def categorize_urls(urls: List[str], pattern_dict: Dict[str, str], verbose: bool) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    """Categorize URLs based on patterns and provide detailed analysis"""
    
    matches = {k: [] for k in pattern_dict}
    url_details = []
    
    for url in urls:
        url_analysis = analyze_single_url(url)
        url_details.append(url_analysis)
        
        for name, regex in pattern_dict.items():
            if re.search(regex, url):
                matches[name].append(url)
    
    # Generate analysis
    analysis = {
        "url_details": url_details,
        "pattern_matches": {name: len(urls) for name, urls in matches.items()},
        "top_domains": get_top_domains(urls),
        "parameter_analysis": analyze_parameters(urls),
        "file_extension_analysis": analyze_file_extensions(urls),
        "protocol_analysis": analyze_protocols(urls),
    }
    
    if verbose:
        click.echo(f"[+] 📊 Analysis completed:")
        for name, count in analysis["pattern_matches"].items():
            if count > 0:
                click.echo(f"   - {name.upper()}: {count} matches")

    return matches, analysis


def analyze_single_url(url: str) -> Dict[str, Any]:
    """Analyze a single URL and extract detailed information"""
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "param_count": len(params),
        "parameter_names": list(params.keys()),
        "has_fragment": bool(parsed.fragment),
        "file_extension": get_file_extension(parsed.path),
        "path_depth": len([p for p in parsed.path.split('/') if p]),
        "suspicious_chars": detect_suspicious_characters(url),
    }


def get_file_extension(path: str) -> str:
    """Extract file extension from URL path"""
    if '.' in path:
        return path.split('.')[-1].lower()
    return ""


def detect_suspicious_characters(url: str) -> List[str]:
    """Detect suspicious characters in URL"""
    suspicious = []
    if '%' in url:
        suspicious.append('url_encoded')
    if '<' in url or '>' in url:
        suspicious.append('html_tags')
    if 'javascript:' in url.lower():
        suspicious.append('javascript_protocol')
    if re.search(r'[\'"]', url):
        suspicious.append('quotes')
    return suspicious


def get_top_domains(urls: List[str]) -> List[Tuple[str, int]]:
    """Get top domains from URL list"""
    domain_counts = defaultdict(int)
    for url in urls:
        domain = urlparse(url).netloc
        domain_counts[domain] += 1
    
    return sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]


def analyze_parameters(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL parameters"""
    param_counts = defaultdict(int)
    param_names = defaultdict(int)
    
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_counts[len(params)] += 1
        
        for param_name in params.keys():
            param_names[param_name] += 1
    
    return {
        "parameter_count_distribution": dict(param_counts),
        "most_common_parameters": sorted(param_names.items(), key=lambda x: x[1], reverse=True)[:20],
        "total_unique_parameters": len(param_names),
    }


def analyze_file_extensions(urls: List[str]) -> Dict[str, int]:
    """Analyze file extensions in URLs"""
    extensions = defaultdict(int)
    
    for url in urls:
        ext = get_file_extension(urlparse(url).path)
        if ext:
            extensions[ext] += 1
    
    return dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True))


def analyze_protocols(urls: List[str]) -> Dict[str, int]:
    """Analyze protocols used in URLs"""
    protocols = defaultdict(int)
    
    for url in urls:
        scheme = urlparse(url).scheme
        protocols[scheme] += 1
    
    return dict(protocols)


def save_categorized_urls(matches: Dict[str, List[str]], output_dir: str, verbose: bool):
    """Save categorized URLs to separate files"""
    
    for name, urls in matches.items():
        if urls:
            filepath = os.path.join(output_dir, f"{name}.txt")
            with open(filepath, "w") as f:
                for url in urls:
                    f.write(url + "\n")
            
            if verbose:
                click.echo(f"[+] 💾 Saved {len(urls)} {name} URLs to {filepath}")


def generate_comprehensive_stats(urls: List[str], matches: Dict[str, List[str]], 
                                analysis: Dict[str, Any], pattern_dict: Dict[str, str]) -> Dict[str, Any]:
    """Generate comprehensive statistics"""
    
    return {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_urls": len(urls),
            "total_patterns": len(pattern_dict),
            "tool": "urlsorter",
        },
        "pattern_matches": {name: len(urls) for name, urls in matches.items()},
        "category_summary": {
            "categories_with_matches": len([k for k, v in matches.items() if v]),
            "total_matches": sum(len(v) for v in matches.values()),
            "unmatched_urls": len(urls) - len(set().union(*matches.values())),
        },
        "url_analysis": analysis,
        "top_categories": sorted(
            [(name, len(urls)) for name, urls in matches.items() if urls],
            key=lambda x: x[1], reverse=True
        )[:10],
    }


def save_json_output(stats: Dict[str, Any], output_dir: str, verbose: bool):
    """Save comprehensive JSON output"""
    
    json_path = os.path.join(output_dir, "urlsort_results.json")
    with open(json_path, "w") as f:
        json.dump(stats, f, indent=2)
    
    if verbose:
        click.echo(f"[+] 📄 Saved JSON results to {json_path}")


def save_markdown_output(stats: Dict[str, Any], analysis: Dict[str, Any], output_dir: str, verbose: bool):
    """Save comprehensive Markdown report"""
    
    md_path = os.path.join(output_dir, "urlsort_report.md")
    with open(md_path, "w") as f:
        f.write("# 🧪 URL Sorter Analysis Report\n\n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total URLs:** {stats['scan_metadata']['total_urls']}\n")
        f.write(f"**Total Patterns:** {stats['scan_metadata']['total_patterns']}\n\n")
        
        # Pattern matches summary
        f.write("## 📊 Pattern Matches Summary\n\n")
        f.write("| Category | Matches | Description |\n")
        f.write("|----------|---------|-------------|\n")
        
        category_descriptions = {
            "xss": "Cross-Site Scripting vulnerabilities",
            "sqli": "SQL Injection vulnerabilities", 
            "lfi": "Local File Inclusion vulnerabilities",
            "ssrf": "Server-Side Request Forgery vulnerabilities",
            "rce": "Remote Code Execution vulnerabilities",
            "redirect": "Open Redirect vulnerabilities",
            "admin": "Administrative panels and interfaces",
            "api": "API endpoints and services",
            "token": "Authentication tokens and sessions",
            "upload": "File upload functionality",
        }
        
        for name, count in stats["pattern_matches"].items():
            desc = category_descriptions.get(name, "Security-related patterns")
            f.write(f"| {name.upper()} | {count} | {desc} |\n")
        
        f.write("\n")
        
        # Top categories
        f.write("## 🏆 Top Categories\n\n")
        for name, count in stats["top_categories"]:
            f.write(f"- **{name.upper()}**: {count} URLs\n")
        
        f.write("\n")
        
        # Domain analysis
        f.write("## 🌐 Domain Analysis\n\n")
        f.write("### Top Domains\n")
        for domain, count in analysis["top_domains"][:5]:
            f.write(f"- {domain}: {count} URLs\n")
        
        f.write("\n")
        
        # Parameter analysis
        f.write("## 🔧 Parameter Analysis\n\n")
        param_analysis = analysis["parameter_analysis"]
        f.write(f"**Total Unique Parameters:** {param_analysis['total_unique_parameters']}\n\n")
        
        f.write("### Most Common Parameters\n")
        for param, count in param_analysis["most_common_parameters"][:10]:
            f.write(f"- {param}: {count} occurrences\n")
        
        f.write("\n")
        
        # File extensions
        if analysis["file_extension_analysis"]:
            f.write("## 📄 File Extension Analysis\n\n")
            for ext, count in list(analysis["file_extension_analysis"].items())[:10]:
                f.write(f"- .{ext}: {count} files\n")
            f.write("\n")
        
        # Protocol analysis
        f.write("## 🔒 Protocol Analysis\n\n")
        for protocol, count in analysis["protocol_analysis"].items():
            f.write(f"- {protocol.upper()}: {count} URLs\n")
    
    if verbose:
        click.echo(f"[+] 📝 Saved Markdown report to {md_path}")


def perform_url_analysis(urls: List[str], verbose: bool) -> Dict[str, Any]:
    """Perform comprehensive URL analysis"""
    
    if verbose:
        click.echo("[+] 🔍 Analyzing URL structure and patterns...")
    
    analysis = {
        "total_urls": len(urls),
        "unique_domains": len(set(urlparse(url).netloc for url in urls)),
        "protocol_distribution": analyze_protocols(urls),
        "domain_analysis": {
            "top_domains": get_top_domains(urls),
            "subdomain_analysis": analyze_subdomains(urls),
        },
        "path_analysis": analyze_paths(urls),
        "parameter_analysis": analyze_parameters(urls),
        "file_extension_analysis": analyze_file_extensions(urls),
        "security_indicators": analyze_security_indicators(urls),
        "complexity_analysis": analyze_url_complexity(urls),
    }
    
    return analysis


def analyze_subdomains(urls: List[str]) -> Dict[str, Any]:
    """Analyze subdomain patterns"""
    subdomains = defaultdict(int)
    
    for url in urls:
        domain = urlparse(url).netloc
        parts = domain.split('.')
        if len(parts) > 2:
            subdomain = parts[0]
            subdomains[subdomain] += 1
    
    return {
        "total_subdomains": len(subdomains),
        "most_common_subdomains": sorted(subdomains.items(), key=lambda x: x[1], reverse=True)[:10],
    }


def analyze_paths(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL path patterns"""
    path_depths = defaultdict(int)
    common_paths = defaultdict(int)
    
    for url in urls:
        path = urlparse(url).path
        depth = len([p for p in path.split('/') if p])
        path_depths[depth] += 1
        
        # Analyze first path component
        if path and path != '/':
            first_component = path.split('/')[1] if len(path.split('/')) > 1 else ''
            if first_component:
                common_paths[first_component] += 1
    
    return {
        "path_depth_distribution": dict(path_depths),
        "most_common_first_paths": sorted(common_paths.items(), key=lambda x: x[1], reverse=True)[:10],
        "average_path_depth": sum(k * v for k, v in path_depths.items()) / len(urls) if urls else 0,
    }


def analyze_security_indicators(urls: List[str]) -> Dict[str, Any]:
    """Analyze security-related indicators in URLs"""
    indicators = {
        "potentially_vulnerable": 0,
        "suspicious_parameters": 0,
        "encoded_content": 0,
        "javascript_protocols": 0,
        "long_urls": 0,
        "unusual_characters": 0,
    }
    
    for url in urls:
        if len(url) > 500:
            indicators["long_urls"] += 1
        
        if '%' in url:
            indicators["encoded_content"] += 1
        
        if 'javascript:' in url.lower():
            indicators["javascript_protocols"] += 1
        
        if re.search(r'[<>"\'&]', url):
            indicators["unusual_characters"] += 1
        
        # Check for suspicious parameter patterns
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        suspicious_params = ['cmd', 'exec', 'eval', 'system', 'shell', 'id', 'cat', 'ls']
        if any(param.lower() in suspicious_params for param in params.keys()):
            indicators["suspicious_parameters"] += 1
        
        # General vulnerability indicators
        vuln_patterns = [r'\.\./', r'<script', r'javascript:', r'SELECT.*FROM', r'UNION.*SELECT']
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in vuln_patterns):
            indicators["potentially_vulnerable"] += 1
    
    return indicators


def analyze_url_complexity(urls: List[str]) -> Dict[str, Any]:
    """Analyze URL complexity metrics"""
    lengths = [len(url) for url in urls]
    param_counts = []
    
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_counts.append(len(params))
    
    return {
        "length_statistics": {
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0,
            "average_length": sum(lengths) / len(lengths) if lengths else 0,
        },
        "parameter_statistics": {
            "min_params": min(param_counts) if param_counts else 0,
            "max_params": max(param_counts) if param_counts else 0,
            "average_params": sum(param_counts) / len(param_counts) if param_counts else 0,
        },
    }


def save_analysis_json(analysis: Dict[str, Any], output_dir: str, verbose: bool):
    """Save analysis results to JSON"""
    
    json_path = os.path.join(output_dir, "url_analysis.json")
    with open(json_path, "w") as f:
        json.dump({
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "tool": "urlsorter-analyze"
            },
            "analysis_results": analysis
        }, f, indent=2)
    
    if verbose:
        click.echo(f"[+] 📄 Saved analysis JSON to {json_path}")


def save_analysis_markdown(analysis: Dict[str, Any], output_dir: str, verbose: bool):
    """Save analysis results to Markdown"""
    
    md_path = os.path.join(output_dir, "url_analysis_report.md")
    with open(md_path, "w") as f:
        f.write("# 🔍 URL Analysis Report\n\n")
        f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Overview
        f.write("## 📊 Overview\n\n")
        f.write(f"- **Total URLs:** {analysis['total_urls']}\n")
        f.write(f"- **Unique Domains:** {analysis['unique_domains']}\n")
        f.write(f"- **Average URL Length:** {analysis['complexity_analysis']['length_statistics']['average_length']:.1f}\n")
        f.write(f"- **Average Parameters:** {analysis['complexity_analysis']['parameter_statistics']['average_params']:.1f}\n\n")
        
        # Security indicators
        f.write("## 🚨 Security Indicators\n\n")
        security = analysis['security_indicators']
        f.write(f"- **Potentially Vulnerable URLs:** {security['potentially_vulnerable']}\n")
        f.write(f"- **Suspicious Parameters:** {security['suspicious_parameters']}\n")
        f.write(f"- **URLs with Encoded Content:** {security['encoded_content']}\n")
        f.write(f"- **JavaScript Protocol URLs:** {security['javascript_protocols']}\n")
        f.write(f"- **Long URLs (>500 chars):** {security['long_urls']}\n")
        f.write(f"- **URLs with Unusual Characters:** {security['unusual_characters']}\n\n")
        
        # Domain analysis
        f.write("## 🌐 Domain Analysis\n\n")
        f.write("### Top Domains\n")
        for domain, count in analysis['domain_analysis']['top_domains'][:10]:
            f.write(f"- {domain}: {count} URLs\n")
        f.write("\n")
        
        # Path analysis
        f.write("## 📁 Path Analysis\n\n")
        path_analysis = analysis['path_analysis']
        f.write(f"**Average Path Depth:** {path_analysis['average_path_depth']:.1f}\n\n")
        f.write("### Most Common First Path Components\n")
        for path, count in path_analysis['most_common_first_paths']:
            f.write(f"- /{path}: {count} URLs\n")
        f.write("\n")
        
        # Parameter analysis
        f.write("## 🔧 Parameter Analysis\n\n")
        param_analysis = analysis['parameter_analysis']
        f.write(f"**Total Unique Parameters:** {param_analysis['total_unique_parameters']}\n\n")
        f.write("### Most Common Parameters\n")
        for param, count in param_analysis['most_common_parameters'][:15]:
            f.write(f"- {param}: {count} occurrences\n")
    
    if verbose:
        click.echo(f"[+] 📝 Saved analysis report to {md_path}")


def show_resume_status(output_dir: str, tool_prefix: str):
    """Show status of previous scans from resume file"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    matching_scans = [k for k in resume_state.keys() if k.startswith(tool_prefix)]
    
    if not matching_scans:
        click.echo(f"[+] No previous {tool_prefix} scans found.")
        return

    click.echo(f"[+] Found {len(matching_scans)} previous scan(s):")
    click.echo()

    for scan_key in matching_scans:
        scan_data = resume_state[scan_key]
        click.echo(f"🔍 Scan: {scan_key}")
        click.echo(f"   Input: {scan_data.get('input_file', 'unknown')}")
        click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

        if scan_data.get("completed"):
            click.echo(f"   Status: ✅ Completed")
            click.echo(f"   Completed: {scan_data.get('completion_time', 'unknown')}")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
        else:
            click.echo(f"   Status: ⏳ Incomplete")
            click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

        click.echo()


# Backward compatibility
run_urlsort = sort

if __name__ == "__main__":
    cli()
