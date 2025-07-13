import socket
import json
import requests
import ssl
import re
import logging
from urllib.parse import urlparse
from typing import Dict, List, Optional
import shutil


def find_executable(name):
    """Helper function to find executable path securely"""
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"Executable '{name}' not found in PATH")
    return path


# Rozszerzona baza cloud providers z dodatkową informacją
CLOUD_KEYWORDS = {
    # AWS
    "amazon": "AWS",
    "amazonaws": "AWS",
    "cloudfront": "AWS CloudFront",
    "aws": "AWS",
    "ec2": "AWS EC2",
    "s3": "AWS S3",
    "elb": "AWS ELB",
    "elasticbeanstalk": "AWS Elastic Beanstalk",
    "rds": "AWS RDS",
    "lambda": "AWS Lambda",
    # Google Cloud
    "google": "GCP",
    "googleapis": "GCP",
    "googleusercontent": "GCP",
    "appspot": "GCP App Engine",
    "firebase": "Firebase",
    "gcp": "GCP",
    "cloud.google": "GCP",
    "googlehosted": "GCP",
    "googlesyndication": "Google Ads",
    # Microsoft Azure
    "azure": "Azure",
    "microsoft": "Azure",
    "azurewebsites": "Azure Web Apps",
    "azureedge": "Azure CDN",
    "cloudapp": "Azure",
    "windows": "Azure",
    "office365": "Microsoft Office 365",
    "outlook": "Microsoft",
    "msn": "Microsoft",
    # Cloudflare
    "cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "cfdata": "Cloudflare",
    # CDN & Edge providers
    "fastly": "Fastly",
    "akamai": "Akamai",
    "maxcdn": "MaxCDN",
    "keycdn": "KeyCDN",
    "bunnycdn": "BunnyCDN",
    "stackpath": "StackPath",
    "jsdelivr": "jsDelivr CDN",
    "unpkg": "unpkg CDN",
    # Platform-as-a-Service
    "github": "GitHub Pages",
    "githubusercontent": "GitHub",
    "herokuapp": "Heroku",
    "heroku": "Heroku",
    "netlify": "Netlify",
    "vercel": "Vercel",
    "now.sh": "Vercel (Zeit)",
    "surge": "Surge.sh",
    "firebase": "Firebase Hosting",
    "appspot": "Google App Engine",
    # Infrastructure providers
    "digitalocean": "DigitalOcean",
    "vultr": "Vultr",
    "linode": "Linode",
    "ovh": "OVH",
    "scaleway": "Scaleway",
    "hetzner": "Hetzner",
    "contabo": "Contabo",
    "godaddy": "GoDaddy",
    "namecheap": "Namecheap",
    "cpanel": "cPanel",
    # Chinese cloud providers
    "aliyun": "Alibaba Cloud",
    "alicdn": "Alibaba Cloud CDN",
    "tencent": "Tencent Cloud",
    "qcloud": "Tencent Cloud",
    "baidu": "Baidu Cloud",
    "huawei": "Huawei Cloud",
    # Other notable providers
    "rackspace": "Rackspace",
    "ibm": "IBM Cloud",
    "oracle": "Oracle Cloud",
    "salesforce": "Salesforce",
    "zendesk": "Zendesk",
    "shopify": "Shopify",
    "wordpress": "WordPress.com",
    "wix": "Wix",
    "squarespace": "Squarespace",
}

# ASN-based detection for major cloud providers
CLOUD_ASN_KEYWORDS = {
    "amazon": "AWS",
    "google": "GCP",
    "microsoft": "Azure",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "linode": "Linode",
    "vultr": "Vultr",
    "ovh": "OVH",
}


def detect_cloud_provider(
    domain: str, ip: Optional[str] = None, verbose: bool = False
) -> Dict:
    """
    Detect cloud provider for a given domain using multiple techniques:
    - DNS CNAME records
    - PTR records
    - ASN information
    - HTTP headers (optional)
    - SSL certificate information (optional)
    """
    result = {
        "domain": domain,
        "ip": None,
        "ptr": None,
        "cname": [],
        "asn_info": {},
        "http_headers": {},
        "ssl_info": {},
        "cloud_guess": [],
        "detection_methods": [],
    }

    if verbose:
        print(f"[DEBUG] Starting cloud detection for: {domain}")

    try:
        # Resolve IP if not provided
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
                if verbose:
                    print(f"[DEBUG] Resolved IP: {ip}")
            except socket.gaierror as e:
                if verbose:
                    print(f"[DEBUG] DNS resolution failed: {e}")
                result["error"] = f"DNS resolution failed: {e}"
                return result

        result["ip"] = ip

        # PTR lookup
        try:
            ptr_result = socket.gethostbyaddr(ip)
            result["ptr"] = ptr_result[0]
            if verbose:
                print(f"[DEBUG] PTR record: {result['ptr']}")
        except (socket.herror, socket.gaierror) as e:
            if verbose:
                print(f"[DEBUG] PTR lookup failed: {e}")
            result["ptr"] = None

        # CNAME lookup with better error handling
        try:
            # Try dnspython first, fallback to system resolver
            try:
                import dns.resolver
                import dns.exception

                try:
                    answers = dns.resolver.resolve(domain, "CNAME")
                    for rdata in answers:
                        cname_target = str(rdata).strip(".")
                        result["cname"].append(cname_target)
                        if verbose:
                            print(f"[DEBUG] CNAME found: {cname_target}")
                except dns.exception.DNSException:
                    # No CNAME record found or other DNS error
                    pass
                except AttributeError:
                    # Older dnspython version - try query instead of resolve
                    try:
                        answers = dns.resolver.query(domain, "CNAME")
                        for rdata in answers:
                            cname_target = str(rdata).strip(".")
                            result["cname"].append(cname_target)
                            if verbose:
                                print(f"[DEBUG] CNAME found (legacy): {cname_target}")
                    except dns.exception.DNSException:
                        pass

            except ImportError:
                # Fallback to dig command if dnspython not available
                import subprocess

                try:
                    dig_result = subprocess.run(
                        [find_executable("dig"), "+short", "CNAME", domain],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if dig_result.returncode == 0 and dig_result.stdout.strip():
                        cnames = [
                            line.strip(".")
                            for line in dig_result.stdout.strip().split("\n")
                            if line.strip()
                        ]
                        result["cname"].extend(cnames)
                        if verbose:
                            print(f"[DEBUG] CNAME via dig: {cnames}")
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    if verbose:
                        print("[DEBUG] dig command failed or not available")
                    pass

        except Exception as e:
            if verbose:
                print(f"[DEBUG] CNAME lookup error: {e}")
            pass

        # ASN info via multiple sources
        asn_detected = False

        # Try ipinfo.io first
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if resp.status_code == 200:
                asn_info = resp.json()
                result["asn_info"] = asn_info
                asn_detected = True

                as_org = asn_info.get("org", "").lower()
                if verbose:
                    print(f"[DEBUG] ASN org from ipinfo.io: {as_org}")

                # Check ASN organization for cloud keywords
                for keyword, provider in CLOUD_KEYWORDS.items():
                    if keyword in as_org:
                        if provider not in result["cloud_guess"]:
                            result["cloud_guess"].append(provider)
                            result["detection_methods"].append(f"ASN:{keyword}")
                            if verbose:
                                print(
                                    f"[DEBUG] Cloud detected via ASN: {provider} (keyword: {keyword})"
                                )

        except requests.RequestException as e:
            if verbose:
                print(f"[DEBUG] ipinfo.io lookup failed: {e}")

            # Fallback to ipapi.co
            try:
                resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
                if resp.status_code == 200:
                    asn_info = resp.json()
                    result["asn_info"] = asn_info
                    asn_detected = True

                    as_org = asn_info.get("org", "").lower()
                    if verbose:
                        print(f"[DEBUG] ASN org from ipapi.co: {as_org}")

                    for keyword, provider in CLOUD_KEYWORDS.items():
                        if keyword in as_org:
                            if provider not in result["cloud_guess"]:
                                result["cloud_guess"].append(provider)
                                result["detection_methods"].append(f"ASN:{keyword}")
                                if verbose:
                                    print(
                                        f"[DEBUG] Cloud detected via ASN (fallback): {provider}"
                                    )

            except requests.RequestException as e2:
                if verbose:
                    print(f"[DEBUG] Both ASN lookups failed: {e}, {e2}")

        # Check PTR record for cloud hints
        if result["ptr"]:
            ptr_lower = result["ptr"].lower()
            for keyword, provider in CLOUD_KEYWORDS.items():
                if keyword in ptr_lower:
                    if provider not in result["cloud_guess"]:
                        result["cloud_guess"].append(provider)
                        result["detection_methods"].append(f"PTR:{keyword}")
                        if verbose:
                            print(
                                f"[DEBUG] Cloud detected via PTR: {provider} (keyword: {keyword})"
                            )

        # Check CNAME records for cloud hints
        for cname in result["cname"]:
            cname_lower = cname.lower()
            for keyword, provider in CLOUD_KEYWORDS.items():
                if keyword in cname_lower:
                    if provider not in result["cloud_guess"]:
                        result["cloud_guess"].append(provider)
                        result["detection_methods"].append(f"CNAME:{keyword}")
                        if verbose:
                            print(
                                f"[DEBUG] Cloud detected via CNAME: {provider} (keyword: {keyword})"
                            )

        # Optional: HTTP headers detection
        try:
            resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            headers = dict(resp.headers)
            result["http_headers"] = headers

            # Check specific headers for cloud providers
            cloud_headers = {
                "cf-ray": "Cloudflare",
                "x-amz-": "AWS",
                "x-azure-": "Azure",
                "x-google-": "GCP",
                "server": "",  # Will check server header content
                "x-served-by": "Fastly",
                "x-cache": "",  # Various CDNs use this
                "x-github-request-id": "GitHub",
            }

            for header_key, provider in cloud_headers.items():
                for h_name, h_value in headers.items():
                    h_name_lower = h_name.lower()
                    h_value_lower = str(h_value).lower()

                    if header_key in h_name_lower or header_key in h_value_lower:
                        if provider and provider not in result["cloud_guess"]:
                            result["cloud_guess"].append(provider)
                            result["detection_methods"].append(f"HTTP:{header_key}")
                            if verbose:
                                print(
                                    f"[DEBUG] Cloud detected via HTTP header: {provider}"
                                )
                        elif header_key == "server" or header_key == "x-cache":
                            # Check server/cache header content for keywords
                            for keyword, kw_provider in CLOUD_KEYWORDS.items():
                                if keyword in h_value_lower:
                                    if kw_provider not in result["cloud_guess"]:
                                        result["cloud_guess"].append(kw_provider)
                                        result["detection_methods"].append(
                                            f"HTTP:{keyword}"
                                        )
                                        if verbose:
                                            print(
                                                f"[DEBUG] Cloud detected via HTTP {h_name}: {kw_provider}"
                                            )

        except requests.RequestException as e:
            if verbose:
                print(f"[DEBUG] HTTP headers lookup failed: {e}")
            pass

        # Optional: SSL certificate detection
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Simplified SSL info extraction
                        subject_dict = {}
                        issuer_dict = {}

                        # Parse subject safely
                        subject = cert.get("subject", [])
                        if subject:
                            for item in subject:
                                if isinstance(item, tuple) and len(item) >= 2:
                                    subject_dict[item[0][0]] = item[0][1]

                        # Parse issuer safely
                        issuer = cert.get("issuer", [])
                        if issuer:
                            for item in issuer:
                                if isinstance(item, tuple) and len(item) >= 2:
                                    issuer_dict[item[0][0]] = item[0][1]

                        result["ssl_info"] = {
                            "subject": subject_dict,
                            "issuer": issuer_dict,
                            "san": cert.get("subjectAltName", []),
                        }

                        # Check certificate issuer for cloud providers
                        issuer_org = issuer_dict.get("organizationName", "").lower()
                        for keyword, provider in CLOUD_KEYWORDS.items():
                            if keyword in issuer_org:
                                if provider not in result["cloud_guess"]:
                                    result["cloud_guess"].append(provider)
                                    result["detection_methods"].append(f"SSL:{keyword}")
                                    if verbose:
                                        print(
                                            f"[DEBUG] Cloud detected via SSL issuer: {provider}"
                                        )

        except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            if verbose:
                print(f"[DEBUG] SSL certificate lookup failed: {e}")
            pass

        # Remove duplicates and return
        result["cloud_guess"] = list(set(result["cloud_guess"]))
        result["detection_methods"] = list(set(result["detection_methods"]))

        if verbose:
            print(f"[DEBUG] Final cloud guess: {result['cloud_guess']}")
            print(f"[DEBUG] Detection methods: {result['detection_methods']}")

        return result

    except Exception as e:
        error_msg = f"Cloud detection failed: {str(e)}"
        if verbose:
            print(f"[DEBUG] {error_msg}")
        return {"domain": domain, "error": error_msg}


def print_cloud_detection_results(result: Dict, verbose: bool = False) -> None:
    """Pretty print cloud detection results."""
    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return

    domain = result.get("domain", "Unknown")
    ip = result.get("ip", "Unknown")

    print(f"\n🔍 Cloud Detection Results for: {domain}")
    print(f"📍 IP Address: {ip}")

    # PTR record
    ptr = result.get("ptr")
    if ptr:
        print(f"🔄 PTR Record: {ptr}")

    # CNAME records
    cnames = result.get("cname", [])
    if cnames:
        print(f"🔗 CNAME Records: {', '.join(cnames)}")

    # ASN information
    asn_info = result.get("asn_info", {})
    if asn_info:
        org = asn_info.get("org", "Unknown")
        city = asn_info.get("city", "")
        country = asn_info.get("country", "")
        location = (
            f"{city}, {country}" if city and country else country or city or "Unknown"
        )
        print(f"🏢 ASN Organization: {org}")
        print(f"📍 Location: {location}")

    # Cloud provider detection
    cloud_providers = result.get("cloud_guess", [])
    if cloud_providers:
        print(f"☁️  Detected Cloud Providers: {', '.join(cloud_providers)}")

        if verbose:
            detection_methods = result.get("detection_methods", [])
            if detection_methods:
                print(f"🔍 Detection Methods: {', '.join(detection_methods)}")
    else:
        print("☁️  No cloud providers detected")

    # Additional info only in verbose mode
    if verbose:
        # HTTP headers - show only important ones
        http_headers = result.get("http_headers", {})
        if http_headers:
            server = http_headers.get("Server") or http_headers.get("server")
            if server:
                print(f"🌐 Server: {server}")

        # SSL information
        ssl_info = result.get("ssl_info", {})
        if ssl_info:
            issuer = ssl_info.get("issuer", {})
            if issuer:
                issuer_org = issuer.get("organizationName", "Unknown")
                print(f"� SSL Issuer: {issuer_org}")


def batch_detect_cloud_providers(
    domains: List[str], verbose: bool = False
) -> List[Dict]:
    """Detect cloud providers for multiple domains."""
    results = []

    for i, domain in enumerate(domains, 1):
        if verbose:
            print(f"\n[{i}/{len(domains)}] Processing: {domain}")

        result = detect_cloud_provider(domain, verbose=verbose)
        results.append(result)

        if not verbose:
            # Show simple progress
            cloud_providers = result.get("cloud_guess", [])
            if cloud_providers:
                print(f"✅ {domain}: {', '.join(cloud_providers)}")
            else:
                print(f"❌ {domain}: No cloud providers detected")

    return results
