import click
import json
import os
import dns.resolver
import requests
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time

# Known vulnerable CNAME patterns and providers
TAKEOVER_PATTERNS = {
    'heroku': {
        'patterns': ['herokuapp.com', 'herokussl.com'],
        'error_messages': ['no such app', 'not found'],
        'status_codes': [404],
        'description': 'Heroku App'
    },
    'github': {
        'patterns': ['github.io', 'githubusercontent.com'],
        'error_messages': ['there isn\'t a github pages site here', '404'],
        'status_codes': [404],
        'description': 'GitHub Pages'
    },
    'aws-s3': {
        'patterns': ['amazonaws.com', 's3.amazonaws.com', 's3-website'],
        'error_messages': ['nosuchbucket', 'the specified bucket does not exist'],
        'status_codes': [404],
        'description': 'AWS S3 Bucket'
    },
    'azure': {
        'patterns': ['azurewebsites.net', 'cloudapp.azure.com', 'trafficmanager.net'],
        'error_messages': ['not found', 'web app doesn\'t exist'],
        'status_codes': [404],
        'description': 'Microsoft Azure'
    },
    'cloudfront': {
        'patterns': ['cloudfront.net'],
        'error_messages': ['bad request', 'the request could not be satisfied'],
        'status_codes': [403, 404],
        'description': 'AWS CloudFront'
    },
    'fastly': {
        'patterns': ['fastly.com', 'fastlylb.net'],
        'error_messages': ['fastly error: unknown domain'],
        'status_codes': [404],
        'description': 'Fastly CDN'
    },
    'netlify': {
        'patterns': ['netlify.app', 'netlify.com'],
        'error_messages': ['not found', 'site not found'],
        'status_codes': [404],
        'description': 'Netlify'
    },
    'pantheon': {
        'patterns': ['pantheonsite.io', 'pantheon.io'],
        'error_messages': ['the gods are wise'],
        'status_codes': [404],
        'description': 'Pantheon'
    },
    'surge': {
        'patterns': ['surge.sh'],
        'error_messages': ['project not found'],
        'status_codes': [404],
        'description': 'Surge.sh'
    },
    'bitbucket': {
        'patterns': ['bitbucket.io'],
        'error_messages': ['repository not found'],
        'status_codes': [404],
        'description': 'Bitbucket Pages'
    },
    'shopify': {
        'patterns': ['myshopify.com'],
        'error_messages': ['sorry, this shop is currently unavailable'],
        'status_codes': [404],
        'description': 'Shopify'
    },
    'unbounce': {
        'patterns': ['unbouncepages.com'],
        'error_messages': ['the requested url was not found'],
        'status_codes': [404],
        'description': 'Unbounce'
    },
    'wordpress': {
        'patterns': ['wordpress.com'],
        'error_messages': ['do you want to register'],
        'status_codes': [404],
        'description': 'WordPress.com'
    },
    'squarespace': {
        'patterns': ['squarespace.com'],
        'error_messages': ['no such account'],
        'status_codes': [404],
        'description': 'Squarespace'
    },
    'tumblr': {
        'patterns': ['tumblr.com'],
        'error_messages': ['whatever you were looking for doesn\'t currently exist'],
        'status_codes': [404],
        'description': 'Tumblr'
    },
    'webflow': {
        'patterns': ['webflow.io'],
        'error_messages': ['the page you are looking for doesn\'t exist'],
        'status_codes': [404],
        'description': 'Webflow'
    },
    'ghost': {
        'patterns': ['ghost.io'],
        'error_messages': ['the thing you were looking for is no longer here'],
        'status_codes': [404],
        'description': 'Ghost.io'
    },
    'helpjuice': {
        'patterns': ['helpjuice.com'],
        'error_messages': ['we could not find what you\'re looking for'],
        'status_codes': [404],
        'description': 'HelpJuice'
    },
    'helpscout': {
        'patterns': ['helpscoutdocs.com'],
        'error_messages': ['no help site found'],
        'status_codes': [404],
        'description': 'Help Scout'
    },
    'cargocollective': {
        'patterns': ['cargocollective.com'],
        'error_messages': ['404 not found'],
        'status_codes': [404],
        'description': 'Cargo Collective'
    },
    'statuspage': {
        'patterns': ['statuspage.io'],
        'error_messages': ['you are being redirected'],
        'status_codes': [404],
        'description': 'StatusPage'
    },
    'uservoice': {
        'patterns': ['uservoice.com'],
        'error_messages': ['this uservoice subdomain is currently available'],
        'status_codes': [404],
        'description': 'UserVoice'
    },
    'zendesk': {
        'patterns': ['zendesk.com'],
        'error_messages': ['help center closed'],
        'status_codes': [404],
        'description': 'Zendesk'
    }
}

def resolve_cname(domain, verbose=False):
    """Resolve CNAME record for domain"""
    try:
        # Use query method for dnspython < 2.0 compatibility
        answers = dns.resolver.query(domain, 'CNAME')
        cname_target = str(answers[0]).rstrip('.')
        if verbose:
            print(f"[CNAME] {domain} -> {cname_target}")
        return cname_target
    except dns.resolver.NXDOMAIN:
        if verbose:
            print(f"[NXDOMAIN] {domain}")
        return None
    except dns.resolver.NoAnswer:
        if verbose:
            print(f"[NO_CNAME] {domain}")
        return None
    except Exception as e:
        if verbose:
            print(f"[ERROR] {domain}: {e}")
        return None

def identify_provider(cname_target):
    """Identify service provider from CNAME target"""
    if not cname_target:
        return None, "Unknown"
    
    cname_lower = cname_target.lower()
    for provider, config in TAKEOVER_PATTERNS.items():
        for pattern in config['patterns']:
            if pattern in cname_lower:
                return provider, config['description']
    
    # Additional provider patterns
    if 'cloudflare' in cname_lower:
        return 'cloudflare', 'Cloudflare CDN'
    elif 'akamai' in cname_lower:
        return 'akamai', 'Akamai CDN'
    elif 'edgecast' in cname_lower:
        return 'edgecast', 'Edgecast CDN'
    elif 'maxcdn' in cname_lower:
        return 'maxcdn', 'MaxCDN'
    elif 'incapsula' in cname_lower:
        return 'incapsula', 'Incapsula'
    elif 'sucuri' in cname_lower:
        return 'sucuri', 'Sucuri CDN'
    elif 'keycdn' in cname_lower:
        return 'keycdn', 'KeyCDN'
    elif 'stackpath' in cname_lower:
        return 'stackpath', 'StackPath CDN'
    elif 'jsdelivr' in cname_lower:
        return 'jsdelivr', 'jsDelivr CDN'
    elif 'bunnycdn' in cname_lower:
        return 'bunnycdn', 'BunnyCDN'
    elif 'googleusercontent' in cname_lower:
        return 'google-cloud', 'Google Cloud'
    elif 'azure' in cname_lower or 'windows.net' in cname_lower:
        return 'azure', 'Microsoft Azure'
    elif 'digitalocean' in cname_lower:
        return 'digitalocean', 'DigitalOcean'
    elif 'linode' in cname_lower:
        return 'linode', 'Linode'
    elif 'vultr' in cname_lower:
        return 'vultr', 'Vultr'
    elif 'ovh' in cname_lower:
        return 'ovh', 'OVH'
    
    return None, "Unknown Provider"

def check_takeover_vulnerability(domain, cname_target, provider_id, verbose=False):
    """Check if domain is vulnerable to subdomain takeover"""
    if not cname_target or not provider_id:
        return False, "No CNAME or provider detected"
    
    if provider_id not in TAKEOVER_PATTERNS:
        return False, "Provider not in vulnerability database"
    
    config = TAKEOVER_PATTERNS[provider_id]
    
    try:
        # Try HTTP request
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                # Check status codes
                if response.status_code in config['status_codes']:
                    content = response.text.lower()
                    
                    # Check error messages
                    for error_msg in config['error_messages']:
                        if error_msg.lower() in content:
                            if verbose:
                                print(f"[VULNERABLE] {domain} - Found error: '{error_msg}'")
                            return True, f"Vulnerable - Found error pattern: '{error_msg}'"
                
                if verbose:
                    print(f"[CHECK] {domain} - HTTP {response.status_code}")
                break
                
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"[ERROR] {domain} - Request failed: {e}")
                continue
        
        return False, "No vulnerability indicators found"
        
    except Exception as e:
        return False, f"Check failed: {str(e)}"

def analyze_domain(domain, check_resolution=True, check_takeover=True, verbose=False):
    """Comprehensive CNAME analysis for a single domain"""
    result = {
        'domain': domain,
        'cname': None,
        'provider_id': None,
        'provider_name': "Unknown",
        'resolves': None,
        'vulnerable': False,
        'vulnerability_details': None,
        'timestamp': datetime.utcnow().isoformat(),
        'risk_level': 'low',
        'status': 'unknown'
    }
    
    # Step 1: Resolve CNAME
    cname_target = resolve_cname(domain, verbose)
    result['cname'] = cname_target
    
    if not cname_target:
        result['vulnerability_details'] = "No CNAME record found"
        result['status'] = 'no_cname'
        
        # Check if domain resolves directly (A/AAAA record)
        if check_resolution:
            try:
                socket.gethostbyname(domain)
                result['resolves'] = True
                result['status'] = 'no_cname'  # Direct A record resolution
            except socket.gaierror:
                result['resolves'] = False
                result['status'] = 'dead'  # Doesn't resolve at all
        
        return result
    
    # Step 2: Identify provider
    provider_id, provider_name = identify_provider(cname_target)
    result['provider_id'] = provider_id
    result['provider_name'] = provider_name
    
    # Step 3: Check if domain resolves
    if check_resolution:
        try:
            socket.gethostbyname(domain)
            result['resolves'] = True
        except socket.gaierror:
            result['resolves'] = False
    
    # Step 4: Determine status based on resolution and provider
    if result['resolves'] is True:
        if provider_id in TAKEOVER_PATTERNS:
            result['status'] = 'resolves_ok'  # CNAME resolves but points to potentially vulnerable service
        else:
            result['status'] = 'resolves_ok'  # CNAME resolves normally
    elif result['resolves'] is False:
        if provider_id in TAKEOVER_PATTERNS:
            result['status'] = 'potential_takeover'  # Dangerous: CNAME to vulnerable service but doesn't resolve
        else:
            result['status'] = 'not_resolving'  # CNAME doesn't resolve
    else:
        result['status'] = 'unknown'
    
    # Step 5: Check for takeover vulnerability
    if check_takeover and provider_id:
        is_vulnerable, details = check_takeover_vulnerability(domain, cname_target, provider_id, verbose)
        result['vulnerable'] = is_vulnerable
        result['vulnerability_details'] = details
        
        # Override status if confirmed vulnerable
        if is_vulnerable:
            result['status'] = 'potential_takeover'
            result['risk_level'] = 'critical'
        elif result['status'] == 'potential_takeover':
            result['risk_level'] = 'high'
        elif provider_id in TAKEOVER_PATTERNS and result['resolves']:
            result['risk_level'] = 'medium'
        
        # Special case: if domain is dead (no CNAME, no A record)
        if not cname_target and result['resolves'] is False:
            result['status'] = 'dead'
            result['risk_level'] = 'low'
    
    return result

def generate_markdown_report(results, output_path):
    """Generate detailed markdown report"""
    with open(output_path, 'w') as f:
        f.write(f"# 🔍 CNAME Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"**Total Domains:** {len(results)}\n\n")
        
        # Statistics
        vulnerable_count = sum(1 for r in results if r['vulnerable'])
        critical_count = sum(1 for r in results if r['risk_level'] == 'critical')
        high_count = sum(1 for r in results if r['risk_level'] == 'high')
        
        # Status statistics
        status_counts = {}
        for result in results:
            status = result.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        f.write(f"## 📊 Summary Statistics\n")
        f.write(f"- **🚨 Critical Risk:** {critical_count} domains\n")
        f.write(f"- **⚠️ High Risk:** {high_count} domains\n")
        f.write(f"- **🔓 Confirmed Vulnerable:** {vulnerable_count} domains\n")
        f.write(f"- **📈 Total Analyzed:** {len(results)} domains\n\n")
        
        # Status breakdown
        f.write(f"## 📈 Status Breakdown\n")
        status_emojis = {
            'no_cname': '🔵',
            'resolves_ok': '✅', 
            'not_resolving': '❌',
            'potential_takeover': '🚨',
            'dead': '💀',
            'error': '⚠️',
            'unknown': '❓'
        }
        
        for status, count in status_counts.items():
            emoji = status_emojis.get(status, '❓')
            f.write(f"- **{emoji} {status.replace('_', ' ').title()}:** {count} domains\n")
        f.write("\n")
        
        # Vulnerable domains first
        if vulnerable_count > 0:
            f.write(f"## 🚨 Critical Vulnerabilities\n\n")
            for result in results:
                if result['vulnerable']:
                    f.write(f"### 🔴 {result['domain']}\n")
                    f.write(f"- **CNAME Target:** `{result['cname']}`\n")
                    f.write(f"- **Provider:** {result['provider_name']}\n")
                    f.write(f"- **Status:** ⚠️ **VULNERABLE TO TAKEOVER**\n")
                    f.write(f"- **Details:** {result['vulnerability_details']}\n")
                    f.write(f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No'}\n\n")
        
        # High risk domains
        high_risk = [r for r in results if r['risk_level'] == 'high' and not r['vulnerable']]
        if high_risk:
            f.write(f"## ⚠️ High Risk Domains\n\n")
            for result in high_risk:
                f.write(f"### 🟡 {result['domain']}\n")
                f.write(f"- **CNAME Target:** `{result['cname']}`\n")
                f.write(f"- **Provider:** {result['provider_name']}\n")
                f.write(f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No'}\n")
                f.write(f"- **Risk:** Domain points to potentially vulnerable service\n\n")
        
        # All results
        f.write(f"## 📋 Complete Analysis Results\n\n")
        for result in results:
            risk_emoji = {'critical': '🔴', 'high': '🟡', 'medium': '🟠', 'low': '🟢'}
            status_emojis = {
                'no_cname': '🔵',
                'resolves_ok': '✅', 
                'not_resolving': '❌',
                'potential_takeover': '🚨',
                'dead': '💀',
                'error': '⚠️',
                'unknown': '❓'
            }
            
            risk_emoji_char = risk_emoji.get(result['risk_level'], '⚪')
            status_emoji_char = status_emojis.get(result.get('status', 'unknown'), '❓')
            
            f.write(f"### {risk_emoji_char} {result['domain']} {status_emoji_char}\n")
            f.write(f"- **CNAME:** `{result['cname'] or 'None'}`\n")
            f.write(f"- **Provider:** {result['provider_name']}\n")
            f.write(f"- **Status:** {result.get('status', 'unknown').replace('_', ' ').title()}\n")
            f.write(f"- **Resolves:** {'✅ Yes' if result['resolves'] else '❌ No' if result['resolves'] is False else '❓ Unknown'}\n")
            f.write(f"- **Risk Level:** {result['risk_level'].title()}\n")
            if result['vulnerability_details']:
                f.write(f"- **Details:** {result['vulnerability_details']}\n")
            f.write("\n")

# CNAME Record Analysis and Takeover Detection
@click.command()
@click.option('--domains', type=click.Path(exists=True), help='Path to file with list of domains')
@click.option('--check', is_flag=True, help='Check if CNAME resolves')
@click.option('--provider-tags', is_flag=True, help='Attempt to identify cloud/service provider')
@click.option('--takeover-check', is_flag=True, help='Check for subdomain takeover vulnerabilities')
@click.option('--status-filter', type=click.Choice(['no_cname', 'resolves_ok', 'not_resolving', 'potential_takeover', 'dead', 'error']), 
              help='Filter results by status type')
@click.option('--json', 'json_output', is_flag=True, help='Output results in JSON format')
@click.option('--markdown', is_flag=True, help='Output results in Markdown format')
@click.option('--output-dir', default='output/cnamecli', help='Directory to store output files')
@click.option('--resume', is_flag=True, help='Resume previous scan')
@click.option('--clear-resume', is_flag=True, help='Clear resume state')
@click.option('--show-resume', is_flag=True, help='Show resume status')
@click.option('--threads', type=int, default=10, help='Number of concurrent threads')
@click.option('--timeout', type=int, default=10, help='Request timeout in seconds')
@click.option('--verbose', is_flag=True, help='Verbose output')
def cnamecli(domains, check, provider_tags, takeover_check, status_filter, json_output, markdown, output_dir, resume, clear_resume, show_resume, threads, timeout, verbose):
    """
    🔍 Advanced CNAME Analysis and Subdomain Takeover Detection
    
    Analyzes CNAME records for potential subdomain takeover vulnerabilities by:
    - Resolving CNAME targets 
    - Identifying service providers (Heroku, GitHub, AWS S3, Azure, etc.)
    - Checking for vulnerable configurations
    - Testing for takeover indicators
    
    Status Types:
    - no_cname: Domain has no CNAME record (direct A/AAAA)
    - resolves_ok: CNAME exists and resolves properly
    - not_resolving: CNAME exists but doesn't resolve 
    - potential_takeover: CNAME points to vulnerable service and doesn't resolve
    - dead: Domain doesn't resolve at all (no DNS records)
    - error: Analysis failed due to technical issues
    
    Examples:
        # Basic CNAME analysis
        reconcli cnamecli --domains subdomains.txt --provider-tags
        
        # Full vulnerability scan
        reconcli cnamecli --domains targets.txt --check --takeover-check --markdown
        
        # Filter only potential takeover candidates
        reconcli cnamecli --domains targets.txt --takeover-check --status-filter potential_takeover
        
        # High-performance concurrent scan
        reconcli cnamecli --domains large_list.txt --takeover-check --threads 20 --json
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Resume functionality placeholders
    resume_file = os.path.join(output_dir, 'cnamecli_resume.json')
    
    if clear_resume:
        if os.path.exists(resume_file):
            os.remove(resume_file)
            click.echo("🧹 Resume state cleared.")
        else:
            click.echo("ℹ️ No resume state to clear.")
        return

    if show_resume:
        if os.path.exists(resume_file):
            with open(resume_file) as f:
                data = json.load(f)
                click.echo(f"📄 Resume state: Last run {data.get('timestamp', 'unknown')}")
        else:
            click.echo("ℹ️ No resume file found.")
        return

    # Load domains
    if not domains:
        click.echo("❌ Error: --domains file is required")
        return
        
    try:
        with open(domains) as f:
            domain_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        click.echo(f"❌ Error reading domains file: {e}")
        return

    if not domain_list:
        click.echo("❌ No domains found in input file")
        return
        
    click.echo(f"🎯 Analyzing {len(domain_list)} domains...")
    if verbose:
        click.echo(f"📁 Output directory: {output_dir}")
        click.echo(f"🧵 Threads: {threads}")

    # Analyze domains concurrently
    results = []
    
    def analyze_single_domain(domain):
        return analyze_domain(
            domain, 
            check_resolution=check,
            check_takeover=takeover_check,
            verbose=verbose
        )
    
    # Use ThreadPoolExecutor for concurrent analysis
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {executor.submit(analyze_single_domain, domain): domain for domain in domain_list}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
                
                # Progress output
                if verbose:
                    risk_emoji = {'critical': '🔴', 'high': '🟡', 'medium': '🟠', 'low': '🟢'}
                    status_emojis = {
                        'no_cname': '🔵',
                        'resolves_ok': '✅', 
                        'not_resolving': '❌',
                        'potential_takeover': '🚨',
                        'dead': '💀',
                        'error': '⚠️',
                        'unknown': '❓'
                    }
                    
                    risk_emoji_char = risk_emoji.get(result['risk_level'], '⚪')
                    status_emoji_char = status_emojis.get(result.get('status', 'unknown'), '❓')
                    cname_info = f" -> {result['cname']}" if result['cname'] else ""
                    status_info = f" [{result.get('status', 'unknown').replace('_', ' ').title()}]"
                    
                    click.echo(f"{risk_emoji_char}{status_emoji_char} {domain}{cname_info}{status_info}")
                else:
                    # Simple progress for non-verbose mode
                    status_emojis = {
                        'no_cname': '🔵',
                        'resolves_ok': '✅', 
                        'not_resolving': '❌',
                        'potential_takeover': '🚨',
                        'dead': '💀',
                        'error': '⚠️',
                        'unknown': '❓'
                    }
                    status_emoji_char = status_emojis.get(result.get('status', 'unknown'), '❓')
                    click.echo(f"{status_emoji_char} {domain}", nl=False)
                    if len(results) % 10 == 0:  # New line every 10 domains
                        click.echo("")
                    
            except Exception as e:
                if verbose:
                    click.echo(f"❌ Error analyzing {domain}: {e}")
                # Add error result
                results.append({
                    'domain': domain,
                    'cname': None,
                    'provider_id': None,
                    'provider_name': "Error",
                    'resolves': None,
                    'vulnerable': False,
                    'vulnerability_details': f"Analysis failed: {str(e)}",
                    'timestamp': datetime.utcnow().isoformat(),
                    'risk_level': 'low',
                    'status': 'error'
                })

    # Apply status filter if specified
    if status_filter:
        original_count = len(results)
        results = [r for r in results if r.get('status') == status_filter]
        filtered_count = len(results)
        if verbose:
            click.echo(f"🔍 Filtered by status '{status_filter}': {filtered_count}/{original_count} domains")

    # Generate outputs
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(os.path.basename(domains))[0] if domains else "cname_scan"
    
    # Statistics
    vulnerable_count = sum(1 for r in results if r['vulnerable'])
    critical_count = sum(1 for r in results if r['risk_level'] == 'critical')
    high_count = sum(1 for r in results if r['risk_level'] == 'high')
    
    # Save JSON output
    if json_output:
        json_path = os.path.join(output_dir, f"{base_name}_cname_{timestamp}.json")
        analysis_data = {
            'metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'total_domains': len(results),
                'vulnerable_count': vulnerable_count,
                'critical_count': critical_count,
                'high_count': high_count,
                'scan_options': {
                    'check_resolution': check,
                    'provider_identification': provider_tags,
                    'takeover_check': takeover_check
                }
            },
            'results': results
        }
        
        with open(json_path, 'w') as jf:
            json.dump(analysis_data, jf, indent=2)
        click.echo(f"📄 JSON results saved to: {json_path}")

    # Save Markdown report
    if markdown:
        md_path = os.path.join(output_dir, f"{base_name}_cname_{timestamp}.md")
        generate_markdown_report(results, md_path)
        click.echo(f"📝 Markdown report saved to: {md_path}")

    # Save resume state
    resume_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'domains_analyzed': len(results),
        'last_domain': domain_list[-1] if domain_list else None
    }
    with open(resume_file, 'w') as rf:
        json.dump(resume_data, rf, indent=2)

    # Final summary
    click.echo(f"\n✅ CNAME Analysis Complete!")
    click.echo(f"📊 Total domains analyzed: {len(results)}")
    if vulnerable_count > 0:
        click.echo(f"🚨 Critical vulnerabilities found: {vulnerable_count}")
    if high_count > 0:
        click.echo(f"⚠️ High-risk domains: {high_count}")
    click.echo(f"� Results saved to: {output_dir}")
    
    if vulnerable_count > 0:
        click.echo(f"\n🔥 ATTENTION: {vulnerable_count} domains may be vulnerable to subdomain takeover!")


if __name__ == "__main__":
    cnamecli()
