import json
import os
import shutil
import subprocess
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from os.path import exists as path_exists
from os.path import expanduser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import click
import requests


def find_executable(name):
    """Helper function to find executable path securely"""
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"Executable '{name}' not found in PATH")
    return path


def send_notification(webhook_url, message, service="slack", ssl_verify=True):
    """Send notification to Slack or Discord webhook."""
    try:
        if "discord" in webhook_url.lower() or service == "discord":
            payload = {"content": message}
        else:  # Slack
            payload = {"text": message}

        response = requests.post(
            webhook_url, json=payload, timeout=10, verify=ssl_verify
        )
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False


def detect_technology(url, custom_headers=None, timeout=30):
    """Detect web technologies for a given URL."""
    try:
        headers = {"User-Agent": "VulnCLI/1.0 ReconCLI Security Scanner"}
        if custom_headers:
            for header in custom_headers.split(","):
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

        response = requests.get(url, headers=headers, timeout=timeout, verify=True)

        tech_stack = []

        # Server header detection
        server = response.headers.get("Server", "").lower()
        if "nginx" in server:
            tech_stack.append("Nginx")
        if "apache" in server:
            tech_stack.append("Apache")
        if "iis" in server:
            tech_stack.append("IIS")
        if "cloudflare" in server:
            tech_stack.append("Cloudflare")

        # X-Powered-By detection
        powered_by = response.headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            tech_stack.append("PHP")
        if "asp.net" in powered_by:
            tech_stack.append("ASP.NET")

        # Content analysis
        content = response.text.lower()
        if "wordpress" in content or "wp-content" in content:
            tech_stack.append("WordPress")
        if "drupal" in content:
            tech_stack.append("Drupal")
        if "joomla" in content:
            tech_stack.append("Joomla")
        if "react" in content:
            tech_stack.append("React")
        if "angular" in content:
            tech_stack.append("Angular")
        if "vue" in content:
            tech_stack.append("Vue.js")

        return {
            "url": url,
            "status_code": response.status_code,
            "technologies": tech_stack,
            "response_size": len(response.content),
            "response_time": response.elapsed.total_seconds(),
        }
    except Exception as e:
        return {"url": url, "status_code": 0, "technologies": [], "error": str(e)}


def check_wayback_machine(url, ssl_verify=True):
    """Check if URL exists in Wayback Machine."""
    try:
        wayback_url = f"http://archive.org/wayback/available?url={url}"
        response = requests.get(wayback_url, timeout=10, verify=ssl_verify)
        data = response.json()
        return (
            data.get("archived_snapshots", {})
            .get("closest", {})
            .get("available", False)
        )
    except Exception:
        return False


def generate_json_report(output_dir, stats, scan_results):
    """Generate comprehensive JSON report."""
    report = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "scanner": "VulnCLI",
            "version": "1.0",
        },
        "statistics": stats,
        "scan_results": scan_results,
    }

    json_file = Path(output_dir) / "vulncli_report.json"
    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)
    return json_file


def generate_markdown_report(output_dir, stats, scan_results):
    """Generate comprehensive Markdown report."""
    md_content = f"""# 🎯 VulnCLI Vulnerability Scan Report

## 📊 Scan Statistics

- **🕐 Scan Time**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **📁 Total URLs Processed**: {stats.get("total_urls", 0)}
- **🔍 Patterns Matched**: {stats.get("patterns_matched", 0)}
- **⚡ Vulnerabilities Found**: {stats.get("vulnerabilities_found", 0)}
- **🌐 Technologies Detected**: {len(stats.get("technologies", []))}

## 🎯 Scan Results by Tool

"""

    if scan_results.get("dalfox"):
        md_content += f"""### 🔥 Dalfox (XSS Scanner)
- **Status**: ✅ Completed
- **Findings**: {scan_results["dalfox"].get("findings", 0)}
- **Output File**: `dalfox.txt`

"""

    if scan_results.get("nuclei"):
        nuclei_data = scan_results["nuclei"]
        ai_info = ""
        if nuclei_data.get("ai_enhanced"):
            ai_info = " 🤖"
            if nuclei_data.get("original_findings"):
                ai_info += f" (AI filtered: {nuclei_data['original_findings']} → {nuclei_data['findings']})"

        md_content += f"""### ⚡ Nuclei (Multi-Vulnerability Scanner){ai_info}
- **Status**: ✅ Completed
- **Templates Used**: {nuclei_data.get("templates", "Default")}
- **Findings**: {nuclei_data.get("findings", 0)}
- **Output File**: `nuclei.txt`

"""

    if scan_results.get("jaeles"):
        md_content += f"""### 🔧 Jaeles (Signature-based Scanner)
- **Status**: ✅ Completed
- **Signatures Used**: {scan_results["jaeles"].get("signatures", "Default")}
- **Findings**: {scan_results["jaeles"].get("findings", 0)}
- **Output File**: `jaeles.txt`

"""

    if scan_results.get("shef"):
        shef_data = scan_results["shef"]
        md_content += f"""### 🔍 Shef (Shodan-based Reconnaissance)
- **Status**: ✅ Completed
- **Query**: {shef_data.get("query", "N/A")}
- **Facet**: {shef_data.get("facet", "domain")}
- **Format**: {shef_data.get("format", "text")}
- **Findings**: {shef_data.get("findings", 0)}
- **Output File**: `shef.txt`

"""

    if stats.get("technologies"):
        md_content += """## 🛠️ Detected Technologies

| Technology | Count |
|------------|-------|
"""
        for tech, count in stats.get("technologies", {}).items():
            md_content += f"| {tech} | {count} |\n"

    # AI Features section
    if stats.get("ai_features_used"):
        md_content += f"""
## 🤖 AI-Enhanced Analysis

**AI Features Used**: {", ".join(stats["ai_features_used"])}

"""
        if "smart_templates" in stats["ai_features_used"]:
            md_content += "- **Smart Template Selection**: AI analyzed target characteristics to select optimal Nuclei templates\n"
        if "false_positive_reduction" in stats["ai_features_used"]:
            md_content += "- **False Positive Reduction**: AI filtered scan results to reduce noise and improve accuracy\n"
        if "vulnerability_classification" in stats["ai_features_used"]:
            md_content += "- **Vulnerability Classification**: AI classified and scored vulnerabilities for better prioritization\n"
        if "executive_summary" in stats["ai_features_used"]:
            md_content += "- **Executive Summary**: AI generated risk assessment and recommendations\n"

    md_content += f"""
## 📝 Notes

- Scan performed using VulnCLI - Advanced Vulnerability Scanner
- Results may contain false positives - manual verification recommended
- For detailed findings, check individual tool output files

---
**Generated by**: VulnCLI v1.0 | **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    md_file = Path(output_dir) / "vulncli_report.md"
    with open(md_file, "w") as f:
        f.write(md_content)
    return md_file


def ai_classify_vulnerability(finding, tech_stack=None):
    """AI-powered vulnerability classification and risk scoring."""
    try:
        # Extract vulnerability type and severity
        vuln_type = "unknown"
        severity = "info"
        confidence = 0.5
        risk_score = 1.0

        finding_lower = finding.lower()

        # AI-like pattern matching for vulnerability classification
        vuln_patterns = {
            "sql injection": {"severity": "critical", "risk": 9.0, "confidence": 0.9},
            "xss": {"severity": "high", "risk": 7.5, "confidence": 0.8},
            "path traversal": {"severity": "high", "risk": 8.0, "confidence": 0.85},
            "command injection": {
                "severity": "critical",
                "risk": 9.5,
                "confidence": 0.9,
            },
            "authentication bypass": {
                "severity": "critical",
                "risk": 9.0,
                "confidence": 0.8,
            },
            "sensitive disclosure": {
                "severity": "medium",
                "risk": 6.0,
                "confidence": 0.7,
            },
            "misconfiguration": {"severity": "medium", "risk": 5.5, "confidence": 0.6},
            "cve-": {"severity": "high", "risk": 7.0, "confidence": 0.8},
            "exposure": {"severity": "medium", "risk": 5.0, "confidence": 0.6},
        }

        for pattern, attrs in vuln_patterns.items():
            if pattern in finding_lower:
                vuln_type = pattern
                severity = attrs["severity"]
                risk_score = attrs["risk"]
                confidence = attrs["confidence"]
                break

        # Adjust risk based on technology stack
        if tech_stack:
            if "wordpress" in [t.lower() for t in tech_stack]:
                risk_score += 0.5  # WordPress sites often have more attack surface
            if "php" in [t.lower() for t in tech_stack]:
                risk_score += 0.3  # PHP apps may have more injection risks

        # Cap risk score at 10.0
        risk_score = min(risk_score, 10.0)

        return {
            "type": vuln_type,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": confidence,
            "ai_enhanced": True,
        }

    except Exception:
        return {
            "type": "unknown",
            "severity": "info",
            "risk_score": 1.0,
            "confidence": 0.3,
            "ai_enhanced": False,
        }


def ai_reduce_false_positives(findings, tech_stack=None, url_context=None):
    """AI-powered false positive reduction using context analysis."""
    filtered_findings = []

    for finding in findings:
        keep_finding = True
        confidence_adjustment = 0.0

        finding_lower = finding.lower()

        # Common false positive patterns
        false_positive_patterns = [
            "test.html",
            "example.com",
            "localhost",
            "127.0.0.1",
            "demo",
            "placeholder",
        ]

        # Check for false positive indicators
        for fp_pattern in false_positive_patterns:
            if fp_pattern in finding_lower:
                confidence_adjustment -= 0.3

        # Context-based filtering
        if url_context:
            # If finding doesn't match URL context, likely false positive
            if "sql" in finding_lower and not any(
                param in url_context for param in ["id", "search", "query"]
            ):
                confidence_adjustment -= 0.2

        # Technology stack validation
        if tech_stack:
            if "asp.net" in finding_lower and "PHP" in tech_stack:
                confidence_adjustment -= 0.4  # ASP.NET finding on PHP site
            if "wordpress" in finding_lower and "WordPress" not in tech_stack:
                confidence_adjustment -= 0.3

        # Keep finding if confidence is still reasonable
        if confidence_adjustment > -0.5:
            filtered_findings.append(
                {
                    "original": finding,
                    "confidence_adjustment": confidence_adjustment,
                    "likely_valid": True,
                }
            )
        else:
            filtered_findings.append(
                {
                    "original": finding,
                    "confidence_adjustment": confidence_adjustment,
                    "likely_valid": False,
                    "reason": "AI flagged as likely false positive",
                }
            )

    return filtered_findings


def ai_smart_template_selection_cached(url_list, tech_stack=None, target_types=None, ai_cache_manager=None, max_age_seconds=86400):
    """AI-powered smart template selection with caching support"""
    
    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {"urls": url_list[:100], "tech_stack": tech_stack or [], "target_types": target_types or []}
        cached_result = ai_cache_manager.get_cached_analysis(
            "smart_template_selection", cache_input, "", max_age_seconds
        )
        
        if cached_result:
            return cached_result['result']
    
    # If no cache hit, run actual AI analysis
    result = ai_smart_template_selection(url_list, tech_stack, target_types)
    
    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("smart_template_selection", cache_input, result)
    
    return result


def ai_reduce_false_positives_cached(findings, tech_stack=None, url_context=None, ai_cache_manager=None, max_age_seconds=86400):
    """AI-powered false positive reduction with caching support"""
    
    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {"findings": findings[:500], "tech_stack": tech_stack or [], "url_context": url_context or ""}
        cached_result = ai_cache_manager.get_cached_analysis(
            "false_positive_reduction", cache_input, "", max_age_seconds
        )
        
        if cached_result:
            return cached_result['result']
    
    # If no cache hit, run actual AI analysis
    result = ai_reduce_false_positives(findings, tech_stack, url_context)
    
    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("false_positive_reduction", cache_input, result)
    
    return result


def ai_classify_vulnerability_cached(finding, tech_stack=None, ai_cache_manager=None, max_age_seconds=86400):
    """AI-powered vulnerability classification with caching support"""
    
    # Try to get cached result if cache is enabled
    if ai_cache_manager:
        cache_input = {"finding": finding, "tech_stack": tech_stack or []}
        cached_result = ai_cache_manager.get_cached_analysis(
            "vulnerability_classification", cache_input, "", max_age_seconds
        )
        
        if cached_result:
            return cached_result['result']
    
    # If no cache hit, run actual AI analysis
    result = ai_classify_vulnerability(finding, tech_stack)
    
    # Store result in cache if cache is enabled
    if ai_cache_manager:
        ai_cache_manager.store_analysis("vulnerability_classification", cache_input, result)
    
    return result


def ai_smart_template_selection(url_list, tech_stack=None, target_types=None):
    """AI-powered smart template selection based on target analysis."""
    recommended_templates = []

    # Analyze URL patterns
    url_patterns = {
        "admin": 0,
        "api": 0,
        "login": 0,
        "upload": 0,
        "search": 0,
        "download": 0,
        "file": 0,
        "config": 0,
    }

    # Count pattern occurrences
    for url in url_list[:100]:  # Sample first 100 URLs
        url_lower = url.lower()
        for pattern in url_patterns:
            if pattern in url_lower:
                url_patterns[pattern] += 1

    # Technology-based template recommendations
    tech_templates = {
        "WordPress": ["http/cms/wordpress/", "http/vulnerabilities/wordpress/"],
        "Drupal": ["http/cms/drupal/", "http/vulnerabilities/drupal/"],
        "PHP": ["http/vulnerabilities/php/", "http/file-upload/"],
        "Apache": ["http/misconfiguration/apache/", "http/exposures/configs/"],
        "Nginx": ["http/misconfiguration/nginx/", "http/exposures/configs/"],
        "IIS": ["http/misconfiguration/iis/", "http/vulnerabilities/microsoft/"],
    }

    # Add tech-specific templates
    if tech_stack:
        for tech in tech_stack:
            if tech in tech_templates:
                recommended_templates.extend(tech_templates[tech])

    # Pattern-based template recommendations
    if url_patterns["admin"] > 2:
        recommended_templates.extend(["http/exposures/panels/", "http/default-logins/"])
    if url_patterns["api"] > 3:
        recommended_templates.extend(["http/exposures/apis/", "http/misconfiguration/"])
    if url_patterns["upload"] > 1:
        recommended_templates.extend(
            ["http/file-upload/", "http/vulnerabilities/generic/"]
        )
    if url_patterns["login"] > 1:
        recommended_templates.extend(
            ["http/default-logins/", "http/vulnerabilities/auth/"]
        )

    # Always include safe essentials
    essential_templates = [
        "http/exposures/configs/",
        "http/exposures/files/",
        "http/technologies/",
        "http/misconfiguration/",
    ]
    recommended_templates.extend(essential_templates)

    # Remove duplicates and return
    return list(set(recommended_templates))


def ai_generate_executive_summary(stats, scan_results, tech_stack=None):
    """AI-powered executive summary generation."""
    total_vulns = stats.get("vulnerabilities_found", 0)
    total_urls = stats.get("total_urls", 0)

    # Risk level assessment
    if total_vulns == 0:
        risk_level = "LOW"
        risk_color = "🟢"
    elif total_vulns <= 5:
        risk_level = "MEDIUM"
        risk_color = "🟡"
    elif total_vulns <= 15:
        risk_level = "HIGH"
        risk_color = "🟠"
    else:
        risk_level = "CRITICAL"
        risk_color = "🔴"

    # Generate recommendations
    recommendations = []

    if total_vulns > 0:
        recommendations.append("Immediate manual verification of all findings required")
        recommendations.append("Implement security headers and input validation")

    if tech_stack:
        if "WordPress" in tech_stack:
            recommendations.append("Update WordPress core, themes, and plugins")
        if "PHP" in tech_stack:
            recommendations.append(
                "Review PHP configuration and disable dangerous functions"
            )
        if "Apache" in tech_stack or "Nginx" in tech_stack:
            recommendations.append(
                "Review web server configuration for security misconfigurations"
            )

    if total_vulns > 10:
        recommendations.append("Consider engaging professional security assessment")

    # Coverage assessment
    coverage_score = min((total_urls / 100) * 100, 100)  # Simple coverage metric

    summary = f"""
## 🤖 AI-Powered Executive Summary

### Risk Assessment
- **Overall Risk Level**: {risk_color} **{risk_level}**
- **Vulnerability Density**: {total_vulns}/{total_urls} URLs ({(total_vulns / max(total_urls, 1) * 100):.1f}%)
- **Coverage Score**: {coverage_score:.0f}%

### Key Findings
- Total vulnerabilities detected: **{total_vulns}**
- Target technologies: {", ".join(tech_stack) if tech_stack else "Not detected"}
- Scan coverage: {total_urls} URLs processed

### AI Recommendations
"""

    for i, rec in enumerate(recommendations, 1):
        summary += f"{i}. {rec}\n"

    summary += """
### Next Steps
1. **Immediate**: Verify high/critical severity findings manually
2. **Short-term**: Implement recommended security controls
3. **Long-term**: Establish regular security testing schedule

*This summary was generated using AI-enhanced analysis of scan results.*
"""

    return summary


class ShefCacheManager:
    """Cache manager for Shef reconnaissance results"""
    
    def __init__(self, cache_dir="shef_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "shef_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}
    
    def _generate_cache_key(self, query, facet, json_format=False):
        """Generate SHA256 cache key from query parameters"""
        key_data = f"{query}:{facet}:{json_format}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except:
            pass
    
    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        entry_time = cache_entry['timestamp']
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds
    
    def get_cached_result(self, query, facet, json_format=False, max_age_seconds=86400):
        """Retrieve cached Shef result if available and valid"""
        self.stats["total_requests"] += 1
        cache_key = self._generate_cache_key(query, facet, json_format)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        index = self._load_index()
        
        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                    
                    self.stats["hits"] += 1
                    return {
                        'results': cached_data.get('results', []),
                        'findings_count': cached_data.get('findings_count', 0),
                        'cached': True,
                        'cache_timestamp': cache_entry['timestamp']
                    }
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass
        
        self.stats["misses"] += 1
        return None
    
    def store_result(self, query, facet, results, findings_count, json_format=False):
        """Store Shef results in cache"""
        cache_key = self._generate_cache_key(query, facet, json_format)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cache_data = {
            'results': results,
            'findings_count': findings_count,
            'query': query,
            'facet': facet,
            'json_format': json_format,
            'timestamp': time.time()
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update index
            index = self._load_index()
            index[cache_key] = {
                'timestamp': time.time(),
                'query': query,
                'facet': facet,
                'json_format': json_format,
                'findings_count': findings_count
            }
            self._save_index(index)
            
        except Exception as e:
            pass  # Fail silently on cache storage errors
    
    def clear_cache(self):
        """Clear all cached Shef results"""
        try:
            import shutil
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False
    
    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size 
            for key in index.keys() 
            if (self.cache_dir / f"{key}.json").exists()
        )
        
        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100
        
        return {
            'total_entries': len(index),
            'cache_size_mb': round(total_size / (1024 * 1024), 2),
            'hit_rate_percent': round(hit_rate, 1),
            'hits': self.stats["hits"],
            'misses': self.stats["misses"],
            'total_requests': self.stats["total_requests"]
        }


class NucleiCacheManager:
    """Cache manager for Nuclei scan results"""
    
    def __init__(self, cache_dir="nuclei_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "nuclei_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}
    
    def _generate_cache_key(self, url_list_hash, templates="", tags="", severity="", excludes=""):
        """Generate SHA256 cache key from scan parameters"""
        key_data = f"{url_list_hash}:{templates}:{tags}:{severity}:{excludes}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_url_list_hash(self, url_file_path):
        """Generate hash from URL list file content"""
        try:
            with open(url_file_path, 'r') as f:
                content = f.read()
            return hashlib.sha256(content.encode()).hexdigest()
        except:
            return hashlib.sha256(str(time.time()).encode()).hexdigest()
    
    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except:
            pass
    
    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        entry_time = cache_entry['timestamp']
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds
    
    def get_cached_result(self, url_file_path, templates="", tags="", severity="", excludes="", max_age_seconds=86400):
        """Retrieve cached Nuclei result if available and valid"""
        self.stats["total_requests"] += 1
        url_list_hash = self._get_url_list_hash(url_file_path)
        cache_key = self._generate_cache_key(url_list_hash, templates, tags, severity, excludes)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        index = self._load_index()
        
        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                    
                    self.stats["hits"] += 1
                    return {
                        'results': cached_data.get('results', []),
                        'findings_count': cached_data.get('findings_count', 0),
                        'template_info': cached_data.get('template_info', 'Default'),
                        'cached': True,
                        'cache_timestamp': cache_entry['timestamp']
                    }
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass
        
        self.stats["misses"] += 1
        return None
    
    def store_result(self, url_file_path, results, findings_count, template_info, templates="", tags="", severity="", excludes=""):
        """Store Nuclei results in cache"""
        url_list_hash = self._get_url_list_hash(url_file_path)
        cache_key = self._generate_cache_key(url_list_hash, templates, tags, severity, excludes)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cache_data = {
            'results': results,
            'findings_count': findings_count,
            'template_info': template_info,
            'url_list_hash': url_list_hash,
            'templates': templates,
            'tags': tags,
            'severity': severity,
            'excludes': excludes,
            'timestamp': time.time()
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update index
            index = self._load_index()
            index[cache_key] = {
                'timestamp': time.time(),
                'url_list_hash': url_list_hash,
                'template_info': template_info,
                'findings_count': findings_count
            }
            self._save_index(index)
            
        except Exception as e:
            pass  # Fail silently on cache storage errors
    
    def clear_cache(self):
        """Clear all cached Nuclei results"""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False
    
    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size 
            for key in index.keys() 
            if (self.cache_dir / f"{key}.json").exists()
        )
        
        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100
        
        return {
            'total_entries': len(index),
            'cache_size_mb': round(total_size / (1024 * 1024), 2),
            'hit_rate_percent': round(hit_rate, 1),
            'hits': self.stats["hits"],
            'misses': self.stats["misses"],
            'total_requests': self.stats["total_requests"]
        }


class JaelesCacheManager:
    """Cache manager for Jaeles scan results"""
    
    def __init__(self, cache_dir="jaeles_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "jaeles_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}
    
    def _generate_cache_key(self, url_list_hash, signatures="", selector="", excludes="", level=1):
        """Generate SHA256 cache key from scan parameters"""
        key_data = f"{url_list_hash}:{signatures}:{selector}:{excludes}:{level}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_url_list_hash(self, url_file_path):
        """Generate hash from URL list file content"""
        try:
            with open(url_file_path, 'r') as f:
                content = f.read()
            return hashlib.sha256(content.encode()).hexdigest()
        except:
            return hashlib.sha256(str(time.time()).encode()).hexdigest()
    
    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except:
            pass
    
    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        entry_time = cache_entry['timestamp']
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds
    
    def get_cached_result(self, url_file_path, signatures="", selector="", excludes="", level=1, max_age_seconds=86400):
        """Retrieve cached Jaeles result if available and valid"""
        self.stats["total_requests"] += 1
        url_list_hash = self._get_url_list_hash(url_file_path)
        cache_key = self._generate_cache_key(url_list_hash, signatures, selector, excludes, level)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        index = self._load_index()
        
        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                    
                    self.stats["hits"] += 1
                    return {
                        'results': cached_data.get('results', []),
                        'findings_count': cached_data.get('findings_count', 0),
                        'signature_info': cached_data.get('signature_info', 'Default'),
                        'cached': True,
                        'cache_timestamp': cache_entry['timestamp']
                    }
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass
        
        self.stats["misses"] += 1
        return None
    
    def store_result(self, url_file_path, results, findings_count, signature_info, signatures="", selector="", excludes="", level=1):
        """Store Jaeles results in cache"""
        url_list_hash = self._get_url_list_hash(url_file_path)
        cache_key = self._generate_cache_key(url_list_hash, signatures, selector, excludes, level)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cache_data = {
            'results': results,
            'findings_count': findings_count,
            'signature_info': signature_info,
            'url_list_hash': url_list_hash,
            'signatures': signatures,
            'selector': selector,
            'excludes': excludes,
            'level': level,
            'timestamp': time.time()
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update index
            index = self._load_index()
            index[cache_key] = {
                'timestamp': time.time(),
                'url_list_hash': url_list_hash,
                'signature_info': signature_info,
                'findings_count': findings_count
            }
            self._save_index(index)
            
        except Exception as e:
            pass  # Fail silently on cache storage errors
    
    def clear_cache(self):
        """Clear all cached Jaeles results"""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False
    
    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size 
            for key in index.keys() 
            if (self.cache_dir / f"{key}.json").exists()
        )
        
        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100
        
        return {
            'total_entries': len(index),
            'cache_size_mb': round(total_size / (1024 * 1024), 2),
            'hit_rate_percent': round(hit_rate, 1),
            'hits': self.stats["hits"],
            'misses': self.stats["misses"],
            'total_requests': self.stats["total_requests"]
        }


class AICacheManager:
    """Cache manager for AI-powered analysis results"""
    
    def __init__(self, cache_dir="ai_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.index_file = self.cache_dir / "ai_cache_index.json"
        self.stats = {"hits": 0, "misses": 0, "total_requests": 0}
    
    def _generate_cache_key(self, analysis_type, input_data_hash, parameters=""):
        """Generate SHA256 cache key from AI analysis parameters"""
        key_data = f"{analysis_type}:{input_data_hash}:{parameters}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_data_hash(self, data):
        """Generate hash from input data"""
        if isinstance(data, (list, tuple)):
            data_str = "|".join(str(item) for item in data)
        else:
            data_str = str(data)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _load_index(self):
        """Load cache index with entry metadata"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_index(self, index):
        """Save cache index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except:
            pass
    
    def _is_cache_valid(self, cache_entry, max_age_seconds=86400):
        """Check if cache entry is still valid (default: 24 hours)"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        entry_time = cache_entry['timestamp']
        current_time = time.time()
        return (current_time - entry_time) < max_age_seconds
    
    def get_cached_analysis(self, analysis_type, input_data, parameters="", max_age_seconds=86400):
        """Retrieve cached AI analysis result if available and valid"""
        self.stats["total_requests"] += 1
        input_hash = self._get_data_hash(input_data)
        cache_key = self._generate_cache_key(analysis_type, input_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        index = self._load_index()
        
        if cache_key in index and cache_file.exists():
            cache_entry = index[cache_key]
            if self._is_cache_valid(cache_entry, max_age_seconds):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                    
                    self.stats["hits"] += 1
                    return {
                        'result': cached_data.get('result'),
                        'analysis_type': cached_data.get('analysis_type'),
                        'cached': True,
                        'cache_timestamp': cache_entry['timestamp']
                    }
                except:
                    # Remove corrupted cache entry
                    try:
                        cache_file.unlink()
                        del index[cache_key]
                        self._save_index(index)
                    except:
                        pass
        
        self.stats["misses"] += 1
        return None
    
    def store_analysis(self, analysis_type, input_data, result, parameters=""):
        """Store AI analysis result in cache"""
        input_hash = self._get_data_hash(input_data)
        cache_key = self._generate_cache_key(analysis_type, input_hash, parameters)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cache_data = {
            'result': result,
            'analysis_type': analysis_type,
            'input_hash': input_hash,
            'parameters': parameters,
            'timestamp': time.time()
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update index
            index = self._load_index()
            index[cache_key] = {
                'timestamp': time.time(),
                'analysis_type': analysis_type,
                'input_hash': input_hash,
                'parameters': parameters
            }
            self._save_index(index)
            
        except Exception as e:
            pass  # Fail silently on cache storage errors
    
    def clear_cache(self):
        """Clear all cached AI analysis results"""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                return True
        except:
            pass
        return False
    
    def get_cache_stats(self):
        """Get cache performance statistics"""
        index = self._load_index()
        total_size = sum(
            (self.cache_dir / f"{key}.json").stat().st_size 
            for key in index.keys() 
            if (self.cache_dir / f"{key}.json").exists()
        )
        
        hit_rate = (self.stats["hits"] / max(self.stats["total_requests"], 1)) * 100
        
        return {
            'total_entries': len(index),
            'cache_size_mb': round(total_size / (1024 * 1024), 2),
            'hit_rate_percent': round(hit_rate, 1),
            'hits': self.stats["hits"],
            'misses': self.stats["misses"],
            'total_requests': self.stats["total_requests"]
        }


@click.command()
@click.option("--input-file", "-i", required=True, help="Input file with URLs.")
@click.option("--output-dir", "-o", required=True, help="Directory to save results.")
@click.option(
    "--patterns", "-p", default="xss,lfi,sqli", help="Comma-separated gf patterns."
)
@click.option(
    "--gf-dir",
    default=os.path.abspath(os.path.join(os.path.dirname(__file__), "gf_patterns")),
    help="Local GF pattern directory.",
)
@click.option(
    "--gf-mode",
    type=click.Choice(["local", "global", "both"]),
    default="local",
    help="Choose gf mode.",
)
@click.option("--run-dalfox", is_flag=True, help="Run Dalfox on xss.txt.")
@click.option("--run-jaeles", is_flag=True, help="Run Jaeles scan.")
@click.option("--run-nuclei", is_flag=True, help="Run Nuclei scan.")
@click.option("--run-shef", is_flag=True, help="Run Shef reconnaissance with facets.")
@click.option("--resume", is_flag=True, help="Skip steps if output exists.")
@click.option(
    "--resume-stat", is_flag=True, help="Show detailed resume statistics and progress"
)
@click.option(
    "--resume-reset", is_flag=True, help="Reset and clear all resume data completely"
)
@click.option("--dedup", is_flag=True, help="Deduplicate URLs.")
@click.option(
    "--extract-params", is_flag=True, help="Filter URLs with query parameters."
)
@click.option(
    "--param-filter", help="Comma-separated param names to keep (e.g. id,file,path)"
)
@click.option("--blind", help="Blind XSS listener for Dalfox.")
@click.option("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080).")
@click.option("--jaeles-signatures", help="Path to custom Jaeles signatures.")
@click.option(
    "--jaeles-select",
    help="Jaeles signature selector (e.g., 'fuzz/sqli/.*', 'common/.*', 'sensitive/.*').",
)
@click.option(
    "--jaeles-exclude",
    help="Jaeles signature exclusion selector (e.g., 'experimental/.*').",
)
@click.option(
    "--jaeles-level",
    type=int,
    default=1,
    help="Filter Jaeles signatures by level (1-5).",
)
@click.option("--nuclei-tags", help="Comma-separated tags for Nuclei.")
@click.option("--nuclei-templates", help="Path to custom Nuclei templates.")
@click.option(
    "--nuclei-select",
    help="Nuclei template selector (e.g., 'http/cves/', 'http/exposures/', 'network/').",
)
@click.option(
    "--nuclei-exclude",
    help="Nuclei template exclusion selector (e.g., 'http/fuzzing/').",
)
@click.option(
    "--nuclei-severity", help="Nuclei severity filter (e.g., 'critical,high,medium')."
)
@click.option(
    "--severity-filter",
    help="Comma-separated severities to keep (e.g. critical,high,info)",
)
@click.option("--rl", type=int, help="Rate limit (requests per second).")
@click.option("--concurrency", type=int, help="Number of concurrent threads.")
@click.option("--retry", type=int, help="Retry attempts for supported tools.")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output with progress tracking.",
)
@click.option(
    "--json", "output_json", is_flag=True, help="Generate JSON report with statistics."
)
@click.option(
    "--markdown",
    "output_markdown",
    is_flag=True,
    help="Generate comprehensive Markdown report.",
)
@click.option("--slack-webhook", help="Slack webhook URL for notifications.")
@click.option("--discord-webhook", help="Discord webhook URL for notifications.")
@click.option(
    "--live-stats", is_flag=True, help="Show live statistics during scanning."
)
@click.option(
    "--custom-headers", help="Custom headers for HTTP requests (key:value,key2:value)."
)
@click.option("--timeout", type=int, default=30, help="HTTP timeout for requests.")
@click.option(
    "--timeout-nuclei",
    type=int,
    default=300,
    help="Timeout for Nuclei scan in seconds.",
)
@click.option("--shef-query", help="Shef search query (e.g., 'hackerone', 'example.com').")
@click.option(
    "--shef-facet", 
    default="domain", 
    help="Shef facet type: domain, ip, org, port, etc. (default: domain)."
)
@click.option("--shef-json", is_flag=True, help="Output Shef results in JSON format.")
@click.option("--shef-cache", is_flag=True, help="Enable caching for Shef reconnaissance results.")
@click.option("--shef-cache-dir", default="shef_cache", help="Directory for Shef cache files.")
@click.option("--shef-cache-max-age", type=int, default=86400, help="Cache expiration time in seconds (default: 24h).")
@click.option("--shef-clear-cache", is_flag=True, help="Clear all Shef cached results.")
@click.option("--shef-cache-stats", is_flag=True, help="Show Shef cache statistics.")
@click.option("--nuclei-cache", is_flag=True, help="Enable caching for Nuclei scan results.")
@click.option("--nuclei-cache-dir", default="nuclei_cache", help="Directory for Nuclei cache files.")
@click.option("--nuclei-cache-max-age", type=int, default=86400, help="Cache expiration time in seconds (default: 24h).")
@click.option("--nuclei-clear-cache", is_flag=True, help="Clear all Nuclei cached results.")
@click.option("--nuclei-cache-stats", is_flag=True, help="Show Nuclei cache statistics.")
@click.option("--jaeles-cache", is_flag=True, help="Enable caching for Jaeles scan results.")
@click.option("--jaeles-cache-dir", default="jaeles_cache", help="Directory for Jaeles cache files.")
@click.option("--jaeles-cache-max-age", type=int, default=86400, help="Cache expiration time in seconds (default: 24h).")
@click.option("--jaeles-clear-cache", is_flag=True, help="Clear all Jaeles cached results.")
@click.option("--jaeles-cache-stats", is_flag=True, help="Show Jaeles cache statistics.")
@click.option("--ai-cache", is_flag=True, help="Enable caching for AI-powered analysis results.")
@click.option("--ai-cache-dir", default="ai_cache", help="Directory for AI cache files.")
@click.option("--ai-cache-max-age", type=int, default=86400, help="Cache expiration time in seconds (default: 24h).")
@click.option("--ai-clear-cache", is_flag=True, help="Clear all AI cached results.")
@click.option("--ai-cache-stats", is_flag=True, help="Show AI cache statistics.")
@click.option(
    "--exclude-extensions",
    help="Comma-separated extensions to exclude (e.g. css,js,png).",
)
@click.option(
    "--include-status-codes",
    help="Comma-separated HTTP status codes to include (e.g. 200,302,403).",
)
@click.option(
    "--technology-detect",
    is_flag=True,
    help="Detect web technologies on discovered URLs.",
)
@click.option(
    "--wayback-filter", is_flag=True, help="Filter URLs by Wayback Machine presence."
)
@click.option(
    "--wordlist-fuzz", help="Wordlist for additional fuzzing (e.g. common endpoints)."
)
@click.option(
    "--ai-mode",
    is_flag=True,
    help="Enable AI-powered vulnerability analysis and template selection.",
)
@click.option(
    "--ai-reduce-fp",
    is_flag=True,
    help="Use AI to reduce false positives in scan results.",
)
@click.option(
    "--ai-smart-templates",
    is_flag=True,
    help="AI-powered smart Nuclei template selection based on target analysis.",
)
@click.option(
    "--ai-executive-summary",
    is_flag=True,
    help="Generate AI-powered executive summary with risk assessment.",
)
@click.option(
    "--ai-confidence-threshold",
    type=float,
    default=0.6,
    help="Minimum confidence threshold for AI findings (0.0-1.0).",
)
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (auto-detected if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
@click.option(
    "--insecure",
    is_flag=True,
    help="Disable SSL certificate verification (security risk)",
)
def vulncli(
    input_file,
    output_dir,
    patterns,
    gf_dir,
    gf_mode,
    run_dalfox,
    run_jaeles,
    run_nuclei,
    run_shef,
    resume,
    resume_stat,
    resume_reset,
    dedup,
    extract_params,
    param_filter,
    blind,
    proxy,
    jaeles_signatures,
    jaeles_select,
    jaeles_exclude,
    jaeles_level,
    nuclei_tags,
    nuclei_templates,
    nuclei_select,
    nuclei_exclude,
    nuclei_severity,
    severity_filter,
    rl,
    concurrency,
    retry,
    verbose,
    output_json,
    output_markdown,
    slack_webhook,
    discord_webhook,
    live_stats,
    custom_headers,
    timeout,
    timeout_nuclei,
    shef_query,
    shef_facet,
    shef_json,
    shef_cache,
    shef_cache_dir,
    shef_cache_max_age,
    shef_clear_cache,
    shef_cache_stats,
    nuclei_cache,
    nuclei_cache_dir,
    nuclei_cache_max_age,
    nuclei_clear_cache,
    nuclei_cache_stats,
    jaeles_cache,
    jaeles_cache_dir,
    jaeles_cache_max_age,
    jaeles_clear_cache,
    jaeles_cache_stats,
    ai_cache,
    ai_cache_dir,
    ai_cache_max_age,
    ai_clear_cache,
    ai_cache_stats,
    exclude_extensions,
    include_status_codes,
    technology_detect,
    wayback_filter,
    wordlist_fuzz,
    ai_mode,
    ai_reduce_fp,
    ai_smart_templates,
    ai_executive_summary,
    ai_confidence_threshold,
    store_db,
    target_domain,
    program,
    insecure,
):
    """🎯 Advanced vulnerability scanning with GF, Dalfox, Jaeles, Nuclei, and Shef

    Comprehensive URL filtering and vulnerability scanning pipeline with:
    • GF pattern matching (XSS, LFI, SQLi, etc.)
    • Parameter extraction and filtering
    • Technology detection and analysis
    • Multi-tool vulnerability scanning with selective template/signature usage
    • 🔍 Shef reconnaissance with facets (domain, ip, org, port, etc.)
    • Professional reporting (JSON/Markdown)
    • Real-time notifications (Slack/Discord)
    • Resume functionality for large scans
    • 🤖 AI-powered vulnerability analysis and false positive reduction

    AI Features:
    --ai-mode                       # Enable all AI capabilities
    --ai-smart-templates            # AI selects optimal Nuclei templates
    --ai-reduce-fp                  # Reduce false positives using AI
    --ai-executive-summary          # Generate AI-powered executive summary
    --ai-confidence-threshold 0.8   # Set AI confidence threshold

    Shef Reconnaissance Examples:
    --run-shef --shef-query 'hackerone' --shef-facet 'domain'    # Domain facets
    --run-shef --shef-query 'bugcrowd' --shef-facet 'ip' --shef-json  # IP facets in JSON
    --run-shef --shef-query 'example.com' --shef-facet 'org'     # Organization facets
    --run-shef --shef-query 'port:443' --shef-facet 'port'       # Port facets

    Jaeles Signature Examples:
    --jaeles-select 'sensitive/.*'     # Only sensitive signatures
    --jaeles-select 'fuzz/sqli/.*'     # Only SQL injection fuzzing
    --jaeles-select 'common/.*'        # Only common vulnerability checks
    --jaeles-exclude 'experimental/.*' # Exclude experimental signatures
    --jaeles-level 2                   # Only level 2+ signatures

    Nuclei Template Examples:
    --nuclei-select 'http/cves/'       # Only CVE templates
    --nuclei-select 'http/exposures/'  # Only exposure templates
    --nuclei-select 'http/cves/,dns/'  # CVE and DNS templates
    --nuclei-exclude 'http/fuzzing/'   # Exclude fuzzing templates
    --nuclei-severity 'critical,high'  # Only critical/high severity
    --nuclei-tags 'exposure,misconfig' # Use specific tags

    Cache Examples:
    --nuclei-cache --nuclei-cache-dir './nuclei_cache'      # Enable Nuclei caching
    --jaeles-cache --jaeles-cache-max-age 7200              # Enable Jaeles cache (2h TTL)
    --shef-cache --shef-cache-stats                         # Enable Shef cache and show stats
    --ai-cache --ai-cache-dir './ai_analysis_cache'         # Enable AI analysis caching
    --ai-mode --ai-cache                                    # Enable AI mode with caching
    --nuclei-clear-cache                                    # Clear Nuclei cache
    --jaeles-cache-stats                                    # Show Jaeles cache statistics
    --ai-clear-cache                                        # Clear AI analysis cache
    --ai-cache-stats                                        # Show AI cache statistics
    """

    # Initialize Shef cache manager if cache is enabled
    shef_cache_manager = None
    if shef_cache or shef_clear_cache or shef_cache_stats:
        shef_cache_manager = ShefCacheManager(shef_cache_dir)
    
    # Initialize Nuclei cache manager if cache is enabled
    nuclei_cache_manager = None
    if nuclei_cache or nuclei_clear_cache or nuclei_cache_stats:
        nuclei_cache_manager = NucleiCacheManager(nuclei_cache_dir)
    
    # Initialize Jaeles cache manager if cache is enabled
    jaeles_cache_manager = None
    if jaeles_cache or jaeles_clear_cache or jaeles_cache_stats:
        jaeles_cache_manager = JaelesCacheManager(jaeles_cache_dir)
    
    # Initialize AI cache manager if cache is enabled
    ai_cache_manager = None
    if ai_cache or ai_clear_cache or ai_cache_stats:
        ai_cache_manager = AICacheManager(ai_cache_dir)
    
    # Handle cache-only commands
    if shef_clear_cache:
        if shef_cache_manager and shef_cache_manager.clear_cache():
            click.echo("✅ [SHEF-CACHE] All cached results cleared successfully")
        else:
            click.echo("❌ [SHEF-CACHE] Failed to clear cache")
        return
    
    if nuclei_clear_cache:
        if nuclei_cache_manager and nuclei_cache_manager.clear_cache():
            click.echo("✅ [NUCLEI-CACHE] All cached results cleared successfully")
        else:
            click.echo("❌ [NUCLEI-CACHE] Failed to clear cache")
        return
    
    if jaeles_clear_cache:
        if jaeles_cache_manager and jaeles_cache_manager.clear_cache():
            click.echo("✅ [JAELES-CACHE] All cached results cleared successfully")
        else:
            click.echo("❌ [JAELES-CACHE] Failed to clear cache")
        return
    
    if ai_clear_cache:
        if ai_cache_manager and ai_cache_manager.clear_cache():
            click.echo("✅ [AI-CACHE] All cached AI analysis results cleared successfully")
        else:
            click.echo("❌ [AI-CACHE] Failed to clear cache")
        return
    
    if shef_cache_stats:
        if shef_cache_manager:
            stats = shef_cache_manager.get_cache_stats()
            click.echo("📊 [SHEF-CACHE] Cache Statistics:")
            click.echo(f"  Total entries: {stats['total_entries']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Hit rate: {stats['hit_rate_percent']}%")
            click.echo(f"  Hits: {stats['hits']}")
            click.echo(f"  Misses: {stats['misses']}")
            click.echo(f"  Total requests: {stats['total_requests']}")
        else:
            click.echo("ℹ️ [SHEF-CACHE] No cache statistics available")
        return

    if nuclei_cache_stats:
        if nuclei_cache_manager:
            stats = nuclei_cache_manager.get_cache_stats()
            click.echo("📊 [NUCLEI-CACHE] Cache Statistics:")
            click.echo(f"  Total entries: {stats['total_entries']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Hit rate: {stats['hit_rate_percent']}%")
            click.echo(f"  Hits: {stats['hits']}")
            click.echo(f"  Misses: {stats['misses']}")
            click.echo(f"  Total requests: {stats['total_requests']}")
        else:
            click.echo("ℹ️ [NUCLEI-CACHE] No cache statistics available")
        return

    if jaeles_cache_stats:
        if jaeles_cache_manager:
            stats = jaeles_cache_manager.get_cache_stats()
            click.echo("📊 [JAELES-CACHE] Cache Statistics:")
            click.echo(f"  Total entries: {stats['total_entries']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Hit rate: {stats['hit_rate_percent']}%")
            click.echo(f"  Hits: {stats['hits']}")
            click.echo(f"  Misses: {stats['misses']}")
            click.echo(f"  Total requests: {stats['total_requests']}")
        else:
            click.echo("ℹ️ [JAELES-CACHE] No cache statistics available")
        return

    if ai_cache_stats:
        if ai_cache_manager:
            stats = ai_cache_manager.get_cache_stats()
            click.echo("📊 [AI-CACHE] Cache Statistics:")
            click.echo(f"  Total entries: {stats['total_entries']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Hit rate: {stats['hit_rate_percent']}%")
            click.echo(f"  Hits: {stats['hits']}")
            click.echo(f"  Misses: {stats['misses']}")
            click.echo(f"  Total requests: {stats['total_requests']}")
        else:
            click.echo("ℹ️ [AI-CACHE] No cache statistics available")
        return

    # Initialize scan statistics
    start_time = time.time()
    stats = {
        "total_urls": 0,
        "patterns_matched": 0,
        "vulnerabilities_found": 0,
        "technologies": {},
        "scan_tools": [],
        "ai_features_used": [],
    }
    scan_results = {}

    # SSL verification settings
    ssl_verify = not insecure
    if insecure:
        click.echo(
            "⚠️  [SECURITY] SSL certificate verification disabled! Use with caution."
        )

    # Track AI features
    if ai_mode:
        stats["ai_features_used"].extend(
            [
                "smart_templates",
                "false_positive_reduction",
                "executive_summary",
                "vulnerability_classification",
            ]
        )
    else:
        if ai_smart_templates:
            stats["ai_features_used"].append("smart_templates")
        if ai_reduce_fp:
            stats["ai_features_used"].append("false_positive_reduction")
        if ai_executive_summary:
            stats["ai_features_used"].append("executive_summary")

    if verbose:
        click.echo(
            f"🎯 [VulnCLI] Starting vulnerability scan at {datetime.now().strftime('%H:%M:%S')}"
        )
        click.echo(f"📁 Input file: {input_file}")
        click.echo(f"📂 Output directory: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Handle new resume functionality
    if resume_stat:
        show_detailed_resume_stats(output_dir)
        return

    if resume_reset:
        reset_all_resume_data(output_dir)
        return
    patterns = patterns.split(",")
    all_urls = []

    # Check if local GF patterns directory exists and has content
    if not os.path.isdir(gf_dir) or not os.listdir(gf_dir):
        if verbose:
            click.echo(
                "⚠️ [GF] Local GF patterns not found or empty – falling back to global (~/.gf/)"
            )
        else:
            click.echo(
                "[!] Local GF patterns not found or empty – falling back to global (~/.gf/)"
            )
        gf_mode = "global"

    # Send start notification
    if slack_webhook or discord_webhook:
        start_msg = f"🎯 VulnCLI scan started\\nInput: {input_file}\\nPatterns: {', '.join(patterns)}"
        if slack_webhook:
            send_notification(slack_webhook, start_msg, "slack", ssl_verify)
        if discord_webhook:
            send_notification(discord_webhook, start_msg, "discord", ssl_verify)

    # === GF FILTERING ===
    if verbose:
        click.echo(f"🔍 [GF] Processing {len(patterns)} patterns...")

    for i, pattern in enumerate(patterns, 1):
        if verbose:
            click.echo(f"🔍 [GF] [{i}/{len(patterns)}] Processing pattern: {pattern}")

        out_path = Path(output_dir) / f"{pattern}.txt"
        combined = ""

        if gf_mode in ["local", "both"]:
            try:
                # Set GF_PATTERNS environment variable for local patterns
                env = os.environ.copy()
                env["GF_PATTERNS"] = gf_dir
                result = subprocess.run(
                    [find_executable("gf"), pattern],
                    input=open(input_file, "rb").read(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    check=True,
                )
                combined += result.stdout.decode("utf-8", errors="ignore")
                if verbose:
                    click.echo(
                        f"  ✅ Local pattern matched: {len(result.stdout.decode('utf-8', errors='ignore').splitlines())} URLs"
                    )
            except subprocess.CalledProcessError:
                if verbose:
                    click.echo("  ❌ Local pattern failed")

        if gf_mode in ["global", "both"]:
            try:
                result = subprocess.run(
                    [find_executable("gf"), pattern],
                    input=open(input_file, "rb").read(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                combined += result.stdout.decode("utf-8", errors="ignore")
                if verbose:
                    click.echo(
                        f"  ✅ Global pattern matched: {len(result.stdout.decode('utf-8', errors='ignore').splitlines())} URLs"
                    )
            except subprocess.CalledProcessError:
                if verbose:
                    click.echo("  ❌ Global pattern failed")

        with open(out_path, "w") as f:
            f.write(combined)
        pattern_urls = combined.splitlines()
        all_urls.extend(pattern_urls)
        stats["patterns_matched"] += len(pattern_urls)

        if verbose:
            click.echo(f"  💾 Saved: {pattern}.txt ({len(pattern_urls)} URLs)")
        else:
            click.echo(f"[+] Saved: {pattern}.txt")

    if dedup:
        original_count = len(all_urls)
        all_urls = list(set(all_urls))
        if verbose:
            click.echo(
                f"🔄 [DEDUP] Removed {original_count - len(all_urls)} duplicates"
            )
        click.echo(f"[✓] Deduplicated: {len(all_urls)} URLs")

    # === ADVANCED URL FILTERING ===
    if exclude_extensions:
        original_count = len(all_urls)
        excluded_exts = exclude_extensions.split(",")
        all_urls = [
            url
            for url in all_urls
            if not any(url.lower().endswith(f".{ext}") for ext in excluded_exts)
        ]
        if verbose:
            click.echo(
                f"🚫 [FILTER] Excluded {original_count - len(all_urls)} URLs with extensions: {exclude_extensions}"
            )

    # === WAYBACK MACHINE FILTERING ===
    if wayback_filter:
        if verbose:
            click.echo("🕰️ [WAYBACK] Filtering URLs through Wayback Machine...")
        wayback_filtered = []
        with ThreadPoolExecutor(max_workers=concurrency or 10) as executor:
            future_to_url = {
                executor.submit(check_wayback_machine, url, ssl_verify): url
                for url in all_urls[:100]
            }  # Limit for demo
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    if future.result():
                        wayback_filtered.append(url)
                except Exception:
                    pass
        all_urls = wayback_filtered
        if verbose:
            click.echo(
                f"🕰️ [WAYBACK] Kept {len(all_urls)} URLs found in Wayback Machine"
            )

    stats["total_urls"] = len(all_urls)

    # === TECHNOLOGY DETECTION ===
    if technology_detect and all_urls:
        if verbose:
            click.echo(
                f"🛠️ [TECH] Detecting technologies on {min(len(all_urls), 50)} URLs..."
            )

        tech_results = []
        urls_to_check = all_urls[:50]  # Limit for performance

        with ThreadPoolExecutor(max_workers=concurrency or 5) as executor:
            future_to_url = {
                executor.submit(detect_technology, url, custom_headers, timeout): url
                for url in urls_to_check
            }

            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    tech_results.append(result)

                    # Count technologies
                    for tech in result.get("technologies", []):
                        stats["technologies"][tech] = (
                            stats["technologies"].get(tech, 0) + 1
                        )

                    if verbose and result.get("technologies"):
                        click.echo(
                            f"  🛠️ {result['url'][:50]}... → {', '.join(result['technologies'])}"
                        )
                except Exception:
                    pass

        # Save technology detection results
        tech_file = Path(output_dir) / "technology_detection.json"
        with open(tech_file, "w") as f:
            json.dump(tech_results, f, indent=2)

        if verbose:
            click.echo(
                f"🛠️ [TECH] Detected {len(stats['technologies'])} unique technologies"
            )

    # === PARAMETER EXTRACTION ===
    if extract_params:
        param_summary = {}
        param_filter_set = set(param_filter.split(",")) if param_filter else set()
        params_dir = Path(output_dir) / "params"
        params_dir.mkdir(exist_ok=True)
        filtered_urls = []

        with open(params_dir / "params.txt", "w") as pf:
            for url in all_urls:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                matched = False
                for key in qs:
                    pf.write(f"{url} → param: {key}\n")
                    # Sanitize parameter name for filename
                    safe_key = (
                        key.replace("/", "_")
                        .replace("\\", "_")
                        .replace(":", "_")
                        .replace("*", "_")
                        .replace("?", "_")
                        .replace('"', "_")
                        .replace("<", "_")
                        .replace(">", "_")
                        .replace("|", "_")
                    )
                    param_file = params_dir / f"params_{safe_key}.txt"
                    with open(param_file, "a") as single:
                        single.write(url + "\n")
                    if not param_filter_set or key in param_filter_set:
                        matched = True
                        param_summary[key] = param_summary.get(key, 0) + 1
                if matched:
                    filtered_urls.append(url)

        if param_filter_set:
            all_urls = list(set(filtered_urls))
            with open(params_dir / "filtered_params.txt", "w") as ff:
                ff.write("\n".join(all_urls))
            click.echo(f"[✓] Filtered parameters: {len(all_urls)} URLs")

    all_file = Path(output_dir) / "all.txt"
    with open(all_file, "w") as f:
        f.write("\n".join(all_urls))

    # === DALFOX ===
    if run_dalfox:
        stats["scan_tools"].append("Dalfox")
        xss_file = Path(output_dir) / "xss.txt"
        dalfox_out = Path(output_dir) / "dalfox.txt"
        if resume and dalfox_out.exists():
            if verbose:
                click.echo("🔄 [DALFOX] Skipping Dalfox (resume mode)")
            else:
                click.echo("[↻] Skipping Dalfox (resume mode)")
        elif xss_file.exists() and os.path.getsize(xss_file) > 0:
            if verbose:
                click.echo(f"🔥 [DALFOX] Starting XSS scan on {xss_file}...")

            dalfox_cmd = ["dalfox", "file", str(xss_file), "--silence"]
            if proxy:
                dalfox_cmd += ["--proxy", proxy]
            if blind:
                dalfox_cmd += ["--blind", blind]
            if rl:
                dalfox_cmd += ["--delay", str(1 / rl)]
            if concurrency:
                dalfox_cmd += ["--worker", str(concurrency)]
            if retry:
                dalfox_cmd += ["--retry", str(retry)]

            with open(dalfox_out, "w") as out:
                result = subprocess.run(
                    dalfox_cmd, stdout=out, stderr=subprocess.DEVNULL
                )

            # Count findings
            if dalfox_out.exists():
                with open(dalfox_out, "r") as f:
                    findings = len(
                        [line for line in f if "VULN" in line or "POC" in line]
                    )
                scan_results["dalfox"] = {"findings": findings}
                stats["vulnerabilities_found"] += findings

                if verbose:
                    click.echo(
                        f"🔥 [DALFOX] Completed! Found {findings} potential XSS vulnerabilities"
                    )

            click.echo(f"[✓] Dalfox done: {dalfox_out}")
        else:
            if verbose:
                click.echo("⚠️ [DALFOX] No XSS patterns found, skipping Dalfox")

    # === JAELES ===
    if run_jaeles:
        stats["scan_tools"].append("Jaeles")
        jaeles_out = Path(output_dir) / "jaeles.txt"
        if resume and jaeles_out.exists():
            if verbose:
                click.echo("🔄 [JAELES] Skipping Jaeles (resume mode)")
            else:
                click.echo("[↻] Skipping Jaeles (resume mode)")
        else:
            # Determine signature selection
            signature_info = "Default"
            if jaeles_signatures:
                signature_info = f"Custom: {jaeles_signatures}"
            elif jaeles_select:
                signature_info = f"Selected: {jaeles_select}"
                if jaeles_exclude:
                    signature_info += f" (excluding: {jaeles_exclude})"

            if verbose:
                click.echo("🔧 [JAELES] Starting signature-based scan...")
                click.echo(f"🔧 [JAELES] Signatures: {signature_info}")

            jaeles_cmd = ["jaeles", "scan", "-u", str(all_file)]

            # Add signature selection
            if jaeles_signatures:
                jaeles_cmd += ["--sig", jaeles_signatures]
            elif jaeles_select:
                jaeles_cmd += ["-s", jaeles_select]
            else:
                # Use professional signatures if available
                pro_signatures = expanduser("~/Documents/pro-signatures/")
                if path_exists(pro_signatures):
                    jaeles_cmd += ["-s", f"{pro_signatures}/sensitive/.*"]
                    signature_info = "Pro: sensitive signatures"
                    if verbose:
                        click.echo(
                            f"🔧 [JAELES] Using pro signatures: {pro_signatures}"
                        )
                else:
                    # Use passive mode for safety when no specific signatures
                    jaeles_cmd += ["--passive"]

            # Add exclusions
            if jaeles_exclude:
                jaeles_cmd += ["-x", jaeles_exclude]

            # Add level filter
            if jaeles_level != 1:
                jaeles_cmd += ["-L", str(jaeles_level)]
            # Add other options
            if proxy:
                jaeles_cmd += ["--proxy", proxy]
            if rl:
                jaeles_cmd += ["--delay", str(1000 / rl)]  # Convert to milliseconds
            if concurrency:
                jaeles_cmd += ["-c", str(concurrency)]
            if retry:
                if verbose:
                    click.echo(
                        "[!] Retry not supported in Jaeles – skipping retry flag."
                    )

            # Try to get cached results first if cache is enabled
            cached_result = None
            if jaeles_cache and jaeles_cache_manager:
                signatures_key = jaeles_signatures or ""
                selector_key = jaeles_select or ""
                excludes_key = jaeles_exclude or ""
                
                cached_result = jaeles_cache_manager.get_cached_result(
                    str(all_file), signatures_key, selector_key, excludes_key, jaeles_level, jaeles_cache_max_age
                )
                
                if cached_result:
                    if verbose:
                        cache_time = datetime.fromtimestamp(cached_result['cache_timestamp']).strftime('%H:%M:%S')
                        click.echo(f"💾 [JAELES-CACHE] Using cached results from {cache_time} ({cached_result['findings_count']} findings)")
                    
                    # Use cached data
                    scan_results["jaeles"] = {
                        "findings": cached_result['findings_count'],
                        "signatures": cached_result['signature_info'],
                        "cached": True
                    }
                    stats["vulnerabilities_found"] += cached_result['findings_count']
                    
                    # Write cached results to output file for consistency
                    with open(jaeles_out, "w") as f:
                        f.write("\n".join(cached_result['results']))
                    
                    if verbose:
                        click.echo(f"🔧 [JAELES] Cache hit! Found {cached_result['findings_count']} vulnerabilities (cached)")
                    
                    click.echo(f"[✓] Jaeles done (cached): {jaeles_out}")

            # If no cache hit or cache disabled, run actual jaeles command
            if not cached_result:
                with open(jaeles_out, "w") as out:
                    subprocess.run(jaeles_cmd, stdout=out, stderr=subprocess.DEVNULL)

                # Count findings
                if jaeles_out.exists():
                    with open(jaeles_out, "r") as f:
                        raw_findings = [line.strip() for line in f if "[VULN]" in line or "[INFO]" in line]
                        findings = len(raw_findings)
                    
                    scan_results["jaeles"] = {
                        "findings": findings,
                        "signatures": signature_info,
                    }
                    stats["vulnerabilities_found"] += findings

                    # Store results in cache if cache is enabled
                    if jaeles_cache and jaeles_cache_manager:
                        signatures_key = jaeles_signatures or ""
                        selector_key = jaeles_select or ""
                        excludes_key = jaeles_exclude or ""
                        
                        # Read all lines for caching
                        with open(jaeles_out, "r") as f:
                            all_lines = [line.strip() for line in f]
                        
                        jaeles_cache_manager.store_result(
                            str(all_file), all_lines, findings, signature_info,
                            signatures_key, selector_key, excludes_key, jaeles_level
                        )
                        
                        if verbose:
                            click.echo(f"💾 [JAELES-CACHE] Results cached for future use")

                    if verbose:
                        click.echo(
                            f"🔧 [JAELES] Completed! Found {findings} potential vulnerabilities"
                        )

                click.echo(f"[✓] Jaeles done: {jaeles_out}")

    # === NUCLEI ===
    if run_nuclei:
        stats["scan_tools"].append("Nuclei")
        nuclei_out = Path(output_dir) / "nuclei.txt"
        if resume and nuclei_out.exists():
            if verbose:
                click.echo("🔄 [NUCLEI] Skipping Nuclei (resume mode)")
            else:
                click.echo("[↻] Skipping Nuclei (resume mode)")
        else:
            # AI-powered smart template selection
            if ai_mode or ai_smart_templates:
                if verbose:
                    click.echo(
                        "🤖 [AI] Analyzing targets for smart template selection..."
                    )

                # Get technology stack for AI analysis
                tech_list = list(stats.get("technologies", {}).keys())
                smart_templates = ai_smart_template_selection_cached(
                    all_urls, tech_list, None, ai_cache_manager, ai_cache_max_age
                )

                if verbose:
                    click.echo(
                        f"🤖 [AI] Recommended {len(smart_templates)} template categories"
                    )
                    for template in smart_templates[:5]:  # Show first 5
                        click.echo(f"  🎯 {template}")
                    if len(smart_templates) > 5:
                        click.echo(f"  ... and {len(smart_templates) - 5} more")

            # Determine template selection
            template_info = "Default"
            if nuclei_templates:
                template_info = f"Custom: {nuclei_templates}"
            elif nuclei_select:
                template_info = f"Selected: {nuclei_select}"
                if nuclei_exclude:
                    template_info += f" (excluding: {nuclei_exclude})"
            elif nuclei_tags:
                template_info = f"Tags: {nuclei_tags}"
            elif nuclei_severity:
                template_info = f"Severity: {nuclei_severity}"
            elif ai_mode or ai_smart_templates:
                template_info = f"AI-Selected: {len(smart_templates)} categories"

            if verbose:
                click.echo("⚡ [NUCLEI] Starting multi-vulnerability scan...")
                click.echo(f"⚡ [NUCLEI] Templates: {template_info}")

            nuclei_cmd = ["nuclei", "-l", str(all_file)]

            # Add template selection
            if nuclei_templates:
                nuclei_cmd += ["-t", nuclei_templates]
            elif nuclei_select:
                # Handle multiple selectors separated by comma
                selectors = nuclei_select.split(",")
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    for selector in selectors:
                        selector = selector.strip()
                        # Remove leading slash if present to avoid double slashes
                        if selector.startswith("/"):
                            selector = selector[1:]
                        template_path = f"{default_tpl.rstrip('/')}/{selector}"
                        if path_exists(template_path):
                            nuclei_cmd += ["-t", template_path]
                            if verbose:
                                click.echo(
                                    f"⚡ [NUCLEI] Added templates: {template_path}"
                                )
                        else:
                            if verbose:
                                click.echo(
                                    f"⚠️ [NUCLEI] Template path not found: {template_path}"
                                )
            elif ai_mode or ai_smart_templates:
                # Use AI-recommended templates
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    templates_added = 0
                    for template in smart_templates:
                        template_path = f"{default_tpl.rstrip('/')}/{template}"
                        if path_exists(template_path):
                            nuclei_cmd += ["-t", template_path]
                            templates_added += 1
                            if verbose:
                                click.echo(f"🤖 [AI] Added template: {template}")

                    if templates_added == 0:
                        # Fallback to safe defaults if AI templates not found
                        safe_defaults = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                        ]
                        for template in safe_defaults:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
            else:
                # Smart defaults based on options
                default_tpl = expanduser("~/nuclei-templates/")
                if path_exists(default_tpl):
                    if nuclei_tags:
                        # Use tags mode
                        nuclei_cmd += ["-tags", nuclei_tags]
                        template_info = f"Tags: {nuclei_tags}"
                    elif nuclei_severity:
                        # Use severity filtering with safe template categories
                        safe_templates = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                            "http/cves/",
                            "dns/",
                            "ssl/",
                        ]
                        for template in safe_templates:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
                    else:
                        # Conservative default - only safe categories
                        safe_defaults = [
                            "http/exposures/",
                            "http/misconfiguration/",
                            "http/technologies/",
                        ]
                        for template in safe_defaults:
                            template_path = f"{default_tpl.rstrip('/')}/{template}"
                            if path_exists(template_path):
                                nuclei_cmd += ["-t", template_path]
                        template_info = "Safe defaults: exposures, misconfig, tech"

                    if verbose:
                        click.echo(
                            f"⚡ [NUCLEI] Using default templates: {default_tpl}"
                        )

            # Add exclusions
            if nuclei_exclude:
                # Handle multiple exclusions separated by comma
                exclusions = nuclei_exclude.split(",")
                for exclusion in exclusions:
                    nuclei_cmd += ["-exclude-templates", exclusion.strip()]

            # Add severity filtering
            if nuclei_severity:
                nuclei_cmd += ["-severity", nuclei_severity]

            # Add other options
            if proxy:
                nuclei_cmd += ["-proxy", proxy]
            if rl:
                nuclei_cmd += ["-rate-limit", str(rl)]
            if concurrency:
                nuclei_cmd += ["-c", str(concurrency)]
            if retry:
                nuclei_cmd += ["-retries", str(retry)]

            # Add timeout
            nuclei_cmd += ["-timeout", str(timeout_nuclei)]

            # Try to get cached results first if cache is enabled
            cached_result = None
            if nuclei_cache and nuclei_cache_manager:
                template_key = nuclei_templates or ""
                tags_key = nuclei_tags or ""
                severity_key = nuclei_severity or ""
                excludes_key = nuclei_exclude or ""
                
                cached_result = nuclei_cache_manager.get_cached_result(
                    str(all_file), template_key, tags_key, severity_key, excludes_key, nuclei_cache_max_age
                )
                
                if cached_result:
                    if verbose:
                        cache_time = datetime.fromtimestamp(cached_result['cache_timestamp']).strftime('%H:%M:%S')
                        click.echo(f"💾 [NUCLEI-CACHE] Using cached results from {cache_time} ({cached_result['findings_count']} findings)")
                    
                    # Use cached data
                    scan_results["nuclei"] = {
                        "findings": cached_result['findings_count'],
                        "templates": cached_result['template_info'],
                        "ai_enhanced": False,
                        "cached": True
                    }
                    stats["vulnerabilities_found"] += cached_result['findings_count']
                    
                    # Write cached results to output file for consistency
                    with open(nuclei_out, "w") as f:
                        f.write("\n".join(cached_result['results']))
                    
                    if verbose:
                        click.echo(f"⚡ [NUCLEI] Cache hit! Found {cached_result['findings_count']} vulnerabilities (cached)")
                    
                    click.echo(f"[✓] Nuclei done (cached): {nuclei_out}")

            # If no cache hit or cache disabled, run actual nuclei command
            if not cached_result:
                with open(nuclei_out, "w") as out:
                    subprocess.run(nuclei_cmd, stdout=out, stderr=subprocess.DEVNULL)

            # Count findings and apply AI analysis
            if nuclei_out.exists() and not cached_result:
                with open(nuclei_out, "r") as f:
                    raw_findings = [
                        line.strip() for line in f if "[" in line and "]" in line
                    ]

                findings_count = len(raw_findings)
                ai_analyzed_findings = []

                # AI-powered analysis of findings
                if (ai_mode or ai_reduce_fp) and raw_findings:
                    if verbose:
                        click.echo(
                            f"🤖 [AI] Analyzing {findings_count} findings for false positives..."
                        )

                    # Analyze findings with AI
                    tech_list = list(stats.get("technologies", {}).keys())
                    filtered_findings = ai_reduce_false_positives_cached(
                        raw_findings, tech_list, str(all_file), ai_cache_manager, ai_cache_max_age
                    )

                    # Classify vulnerabilities
                    for i, finding_data in enumerate(filtered_findings):
                        if finding_data["likely_valid"]:
                            classification = ai_classify_vulnerability_cached(
                                finding_data["original"], tech_list, ai_cache_manager, ai_cache_max_age
                            )
                            ai_analyzed_findings.append(
                                {
                                    "original": finding_data["original"],
                                    "classification": classification,
                                    "confidence": classification["confidence"]
                                    + finding_data["confidence_adjustment"],
                                }
                            )

                    # Filter by confidence threshold
                    high_confidence_findings = [
                        f
                        for f in ai_analyzed_findings
                        if f["confidence"] >= ai_confidence_threshold
                    ]

                    # Save AI analysis results
                    ai_analysis_file = Path(output_dir) / "nuclei_ai_analysis.json"
                    with open(ai_analysis_file, "w") as f:
                        json.dump(
                            {
                                "total_findings": findings_count,
                                "ai_filtered_findings": len(high_confidence_findings),
                                "false_positives_removed": findings_count
                                - len(high_confidence_findings),
                                "confidence_threshold": ai_confidence_threshold,
                                "detailed_analysis": ai_analyzed_findings,
                            },
                            f,
                            indent=2,
                        )

                    if verbose:
                        removed_count = findings_count - len(high_confidence_findings)
                        click.echo(
                            f"🤖 [AI] Removed {removed_count} likely false positives"
                        )
                        click.echo(
                            f"🤖 [AI] {len(high_confidence_findings)} high-confidence findings remain"
                        )

                final_findings = (
                    len(high_confidence_findings)
                    if (ai_mode or ai_reduce_fp) and raw_findings
                    else findings_count
                )

                scan_results["nuclei"] = {
                    "findings": final_findings,
                    "templates": template_info,
                    "ai_enhanced": ai_mode or ai_reduce_fp or ai_smart_templates,
                    "original_findings": (
                        findings_count if (ai_mode or ai_reduce_fp) else None
                    ),
                }
                stats["vulnerabilities_found"] += final_findings

                # Store results in cache if cache is enabled
                if nuclei_cache and nuclei_cache_manager:
                    template_key = nuclei_templates or ""
                    tags_key = nuclei_tags or ""
                    severity_key = nuclei_severity or ""
                    excludes_key = nuclei_exclude or ""
                    
                    nuclei_cache_manager.store_result(
                        str(all_file), raw_findings, final_findings, template_info,
                        template_key, tags_key, severity_key, excludes_key
                    )
                    
                    if verbose:
                        click.echo(f"💾 [NUCLEI-CACHE] Results cached for future use")

                if verbose:
                    if ai_mode or ai_reduce_fp:
                        click.echo(
                            f"⚡ [NUCLEI] Completed! Found {final_findings} high-confidence vulnerabilities (was {findings_count})"
                        )
                    else:
                        click.echo(
                            f"⚡ [NUCLEI] Completed! Found {final_findings} potential vulnerabilities"
                        )

            click.echo(f"[✓] Nuclei done: {nuclei_out}")

    # === SHEF RECONNAISSANCE ===
    if run_shef and shef_query:
        stats["scan_tools"].append("shef")
        
        # Try to get cached results first if cache is enabled
        cached_result = None
        if shef_cache and shef_cache_manager:
            cached_result = shef_cache_manager.get_cached_result(
                shef_query, shef_facet, shef_json, shef_cache_max_age
            )
            
            if cached_result:
                if verbose:
                    cache_time = datetime.fromtimestamp(cached_result['cache_timestamp']).strftime('%H:%M:%S')
                    click.echo(f"🎯 [SHEF-CACHE] Found cached results from {cache_time}")
                    click.echo(f"🔍 [SHEF] Using cached reconnaissance results...")
                
                # Use cached results
                findings_count = cached_result['findings_count']
                
                # Write cached results to output file
                shef_out = Path(output_dir) / "shef.txt"
                try:
                    if shef_json:
                        with open(shef_out, "w") as f:
                            json.dump(cached_result['results'], f, indent=2)
                    else:
                        with open(shef_out, "w") as f:
                            if isinstance(cached_result['results'], list):
                                f.write('\n'.join(str(item) for item in cached_result['results']))
                            else:
                                f.write(str(cached_result['results']))
                except Exception as e:
                    if verbose:
                        click.echo(f"⚠️ [SHEF-CACHE] Error writing cached results: {e}")

        # If no cache hit or cache disabled, run actual shef command
        if not cached_result:
            if verbose:
                click.echo("🔍 [SHEF] Running reconnaissance with facets...")

            shef_out = Path(output_dir) / "shef.txt"
            if not (resume and shef_out.exists()):
                try:
                    # Build shef command
                    shef_cmd = ["shef", "-q", shef_query, "-f", shef_facet]
                    if shef_json:
                        shef_cmd.append("-json")

                    if verbose:
                        click.echo(f"🔍 [SHEF] Command: {' '.join(shef_cmd)}")

                    with open(shef_out, "w") as out:
                        result = subprocess.run(
                            shef_cmd, 
                            stdout=out, 
                            stderr=subprocess.DEVNULL,
                            timeout=300  # 5 minutes timeout
                        )

                    # Read and count findings
                    findings_count = 0
                    results_data = []
                    
                    if shef_out.exists():
                        with open(shef_out, "r") as f:
                            if shef_json:
                                try:
                                    results_data = json.load(f)
                                    findings_count = len(results_data) if isinstance(results_data, list) else 1
                                except:
                                    content = f.read()
                                    findings_count = len([line for line in content.split('\n') if line.strip()])
                                    results_data = content.split('\n')
                            else:
                                results_data = [line.strip() for line in f if line.strip()]
                                findings_count = len(results_data)

                    # Store in cache if cache is enabled
                    if shef_cache and shef_cache_manager and results_data:
                        shef_cache_manager.store_result(
                            shef_query, shef_facet, results_data, findings_count, shef_json
                        )
                        if verbose:
                            click.echo(f"� [SHEF-CACHE] Results stored in cache")

                except subprocess.TimeoutExpired:
                    if verbose:
                        click.echo("⚠️  [SHEF] Timeout - scan took too long")
                    findings_count = 0
                except FileNotFoundError:
                    if verbose:
                        click.echo("❌ [SHEF] Error: shef command not found")
                    findings_count = 0
                except Exception as e:
                    if verbose:
                        click.echo(f"❌ [SHEF] Error: {e}")
                    findings_count = 0
            else:
                if verbose:
                    click.echo("🔍 [SHEF] Output exists, skipping...")
                # Count existing file results
                try:
                    with open(shef_out, "r") as f:
                        if shef_json:
                            try:
                                data = json.load(f)
                                findings_count = len(data) if isinstance(data, list) else 1
                            except:
                                findings_count = sum(1 for line in f if line.strip())
                        else:
                            findings_count = sum(1 for line in f if line.strip())
                except:
                    findings_count = 0

        # Store scan results
        scan_results["shef"] = {
            "findings": findings_count,
            "query": shef_query,
            "facet": shef_facet,
            "format": "json" if shef_json else "text",
            "cached": bool(cached_result)
        }
        stats["vulnerabilities_found"] += findings_count

        if verbose:
            cache_indicator = " (cached)" if cached_result else ""
            click.echo(f"🔍 [SHEF] Found {findings_count} results{cache_indicator}")
            
            # Show cache stats if cache is enabled
            if shef_cache and shef_cache_manager:
                cache_stats = shef_cache_manager.get_cache_stats()
                click.echo(f"📊 [SHEF-CACHE] Hit rate: {cache_stats['hit_rate_percent']}% ({cache_stats['hits']}/{cache_stats['total_requests']})")

    # === SEVERITY FILTERING ===
    def filter_by_severity(path, out_path, sevs):
        sevs = [s.lower() for s in sevs]
        with open(path, "r") as inp, open(out_path, "w") as out:
            for line in inp:
                if any(f"severity: {s}" in line.lower() for s in sevs):
                    out.write(line)

    if severity_filter:
        sevs = severity_filter.split(",")
        if run_nuclei:
            path = Path(output_dir) / "nuclei.txt"
            out = Path(output_dir) / "nuclei_filtered.txt"
            filter_by_severity(path, out, sevs)
            click.echo(f"[✓] Filtered nuclei → {out}")
        if run_jaeles:
            path = Path(output_dir) / "jaeles.txt"
            out = Path(output_dir) / "jaeles_filtered.txt"
            filter_by_severity(path, out, sevs)
            click.echo(f"[✓] Filtered jaeles → {out}")

    # === FINAL REPORTING AND NOTIFICATIONS ===
    scan_time = time.time() - start_time

    if verbose:
        click.echo(f"\n📊 [SUMMARY] Scan completed in {scan_time:.2f} seconds")
        click.echo(f"📁 Total URLs processed: {stats['total_urls']}")
        click.echo(f"🎯 Patterns matched: {stats['patterns_matched']}")
        click.echo(f"⚡ Vulnerabilities found: {stats['vulnerabilities_found']}")
        click.echo(f"🛠️ Technologies detected: {len(stats['technologies'])}")
        click.echo(f"🔧 Tools used: {', '.join(stats['scan_tools'])}")
        if stats["ai_features_used"]:
            click.echo(f"🤖 AI features: {', '.join(stats['ai_features_used'])}")

    # Generate reports
    if output_json:
        json_file = generate_json_report(output_dir, stats, scan_results)
        if verbose:
            click.echo(f"📄 [JSON] Report saved: {json_file}")

    if output_markdown:
        md_file = generate_markdown_report(output_dir, stats, scan_results)
        if verbose:
            click.echo(f"📝 [MARKDOWN] Report saved: {md_file}")

    # Generate AI-powered executive summary
    if ai_mode or ai_executive_summary:
        if verbose:
            click.echo("🤖 [AI] Generating executive summary...")

        tech_list = list(stats.get("technologies", {}).keys())
        ai_summary = ai_generate_executive_summary(stats, scan_results, tech_list)

        # Save AI summary to file
        ai_summary_file = Path(output_dir) / "ai_executive_summary.md"
        with open(ai_summary_file, "w") as f:
            f.write("# 🤖 AI-Enhanced Vulnerability Assessment Report\n")
            f.write(
                f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            f.write(ai_summary)

        if verbose:
            click.echo(f"🤖 [AI] Executive summary saved: {ai_summary_file}")
        else:
            click.echo(f"[🤖] AI summary: {ai_summary_file}")

        # Show brief AI summary in console
        if ai_mode:
            click.echo("\n" + "=" * 60)
            click.echo("🤖 AI EXECUTIVE SUMMARY")
            click.echo("=" * 60)
            # Extract just the risk assessment part
            summary_lines = ai_summary.split("\n")
            for line in summary_lines[3:8]:  # Show risk assessment section
                if line.strip():
                    click.echo(line)
            click.echo("=" * 60)

    # Send completion notification
    if slack_webhook or discord_webhook:
        completion_msg = "✅ VulnCLI scan completed!\\n"
        completion_msg += f"🕐 Duration: {scan_time:.1f}s\\n"
        completion_msg += f"📁 URLs: {stats['total_urls']}\\n"
        completion_msg += f"⚡ Vulnerabilities: {stats['vulnerabilities_found']}\\n"
        completion_msg += f"🔧 Tools: {', '.join(stats['scan_tools'])}"

        if slack_webhook:
            send_notification(slack_webhook, completion_msg, "slack", ssl_verify)
        if discord_webhook:
            send_notification(discord_webhook, completion_msg, "discord", ssl_verify)

    # Critical findings notification
    if stats["vulnerabilities_found"] > 10 and (slack_webhook or discord_webhook):
        critical_msg = "🚨 HIGH VULNERABILITY COUNT DETECTED!\\n"
        critical_msg += (
            f"Found {stats['vulnerabilities_found']} potential vulnerabilities\\n"
        )
        critical_msg += "Immediate review recommended!"

        if slack_webhook:
            send_notification(slack_webhook, critical_msg, "slack", ssl_verify)
        if discord_webhook:
            send_notification(discord_webhook, critical_msg, "discord", ssl_verify)

    if verbose:
        click.echo("\n🎉 [COMPLETE] VulnCLI scan finished successfully!")
        click.echo(f"📂 All results saved in: {output_dir}")
    else:
        click.echo(f"\n[✓] Scan complete! Results in: {output_dir}")

    # Database storage
    if store_db:
        try:
            from urllib.parse import parse_qs, urlparse

            from reconcli.db.operations import store_target, store_vulnerability

            # Auto-detect target domain from input file if not provided
            if not target_domain and input_file:
                try:
                    with open(input_file, "r") as f:
                        first_url = f.readline().strip()
                        if first_url:
                            parsed = urlparse(first_url)
                            target_domain = parsed.netloc
                except:
                    pass

            if target_domain:
                # Ensure target exists in database
                target_id = store_target(target_domain, program=program)

                # Store vulnerability summary data
                stored_count = 0

                # Store summary for each tool that found vulnerabilities
                if scan_results.get("dalfox", {}).get("findings", 0) > 0:
                    vuln_data = {
                        "title": "Dalfox XSS Scan Results",
                        "description": f"Dalfox found {scan_results['dalfox']['findings']} potential XSS vulnerabilities",
                        "severity": "high",
                        "vuln_type": "xss",
                        "evidence": f"Dalfox scan identified {scan_results['dalfox']['findings']} findings",
                    }
                    store_vulnerability(target_domain, vuln_data, "dalfox")
                    stored_count += 1

                if scan_results.get("jaeles", {}).get("findings", 0) > 0:
                    vuln_data = {
                        "title": "Jaeles Security Scan Results",
                        "description": f"Jaeles found {scan_results['jaeles']['findings']} potential security issues",
                        "severity": "medium",
                        "vuln_type": "security-misc",
                        "evidence": f"Jaeles scan identified {scan_results['jaeles']['findings']} findings",
                    }
                    store_vulnerability(target_domain, vuln_data, "jaeles")
                    stored_count += 1

                if scan_results.get("nuclei", {}).get("findings", 0) > 0:
                    vuln_data = {
                        "title": "Nuclei Vulnerability Scan Results",
                        "description": f"Nuclei found {scan_results['nuclei']['findings']} potential vulnerabilities",
                        "severity": "medium",
                        "vuln_type": "security-misc",
                        "evidence": f"Nuclei scan identified {scan_results['nuclei']['findings']} findings",
                    }
                    store_vulnerability(target_domain, vuln_data, "nuclei")
                    stored_count += 1

                if stored_count > 0:
                    if verbose:
                        click.echo(
                            f"🗄️ Stored {stored_count} vulnerability summaries in database for {target_domain}"
                        )
                        if program:
                            click.echo(f"   Program: {program}")
                        click.echo(
                            f"   Total findings: {stats['vulnerabilities_found']}"
                        )
                else:
                    if verbose:
                        click.echo("⚠️ No vulnerabilities to store in database")
            else:
                if verbose:
                    click.echo(
                        "⚠️ Could not determine target domain for database storage"
                    )

        except ImportError:
            if verbose:
                click.echo(
                    "⚠️ Database module not available. Install with: pip install sqlalchemy>=2.0.0"
                )
        except Exception as e:
            if verbose:
                click.echo(f"❌ Error storing to database: {e}")


def create_resume_state(output_dir, scan_config):
    """Create resume state file for vulnerability scan continuation."""
    import hashlib

    resume_dir = Path(output_dir) / "resume"
    resume_dir.mkdir(parents=True, exist_ok=True)

    state = {
        "scan_id": hashlib.md5(
            str(datetime.now()).encode(), usedforsecurity=False
        ).hexdigest()[:8],
        "created_at": datetime.now().isoformat(),
        "scan_type": "vulnerability_scan",
        "config": scan_config,
        "completed_tools": [],
        "pending_tools": [],
        "scan_statistics": {
            "total_urls": 0,
            "patterns_matched": 0,
            "vulnerabilities_found": 0,
            "technologies": {},
            "scan_tools": [],
        },
        "status": "in_progress",
    }

    state_file = resume_dir / "vuln_scan_state.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state_file


def load_resume_state(output_dir):
    """Load existing vulnerability scan resume state."""
    resume_dir = Path(output_dir) / "resume"
    state_file = resume_dir / "vuln_scan_state.json"

    if not state_file.exists():
        return None

    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        return state, state_file
    except Exception as e:
        print(f"❌ [RESUME] Failed to load resume state: {e}")
        return None


def update_resume_state(state_file, tool_name, stats_update):
    """Update resume state with completed tool results."""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)

        # Update completed tools
        if tool_name not in state["completed_tools"]:
            state["completed_tools"].append(tool_name)

        # Remove from pending if exists
        if tool_name in state["pending_tools"]:
            state["pending_tools"].remove(tool_name)

        # Update statistics
        state["scan_statistics"].update(stats_update)
        state["last_updated"] = datetime.now().isoformat()

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️ [RESUME] Failed to update state: {e}")


def show_detailed_resume_stats(output_dir):
    """Show detailed resume statistics and progress information for vulnerability scans."""
    resume_state = load_resume_state(output_dir)
    if not resume_state:
        print("📋 [RESUME-STAT] No resume state found")
        return

    state, _ = resume_state

    print("=" * 70)
    print("📊 [RESUME-STAT] Detailed Vulnerability Scan Resume Statistics")
    print("=" * 70)

    # Basic information
    print(f"🆔 Scan ID: {state.get('scan_id', 'Unknown')}")
    print(f"📅 Created: {state.get('created_at', 'Unknown')}")
    print(f"🔄 Status: {state.get('status', 'Unknown')}")
    print(f"📝 Last Update: {state.get('updated_at', 'Never')}")
    print(f"🎯 Scan Type: {state.get('scan_type', 'Unknown')}")

    # Scan configuration
    config = state.get("config", {})
    print("\n🔧 Scan Configuration:")
    print(f"   📁 Input file: {config.get('input_file', 'Unknown')}")
    print(f"   📂 Output directory: {config.get('output_dir', 'Unknown')}")
    print(f"   🔍 Patterns: {config.get('patterns', 'Unknown')}")
    print(f"   🔥 Dalfox: {'Yes' if config.get('run_dalfox') else 'No'}")
    print(f"   🔧 Jaeles: {'Yes' if config.get('run_jaeles') else 'No'}")
    print(f"   ⚡ Nuclei: {'Yes' if config.get('run_nuclei') else 'No'}")
    print(f"   🤖 AI Mode: {'Yes' if config.get('ai_mode') else 'No'}")

    # Tool progress
    completed_tools = state.get("completed_tools", [])
    pending_tools = state.get("pending_tools", [])
    total_tools = len(completed_tools) + len(pending_tools)

    print("\n📈 Tool Progress:")
    print(f"   ✅ Completed tools: {len(completed_tools)}")
    print(f"   ⏳ Pending tools: {len(pending_tools)}")
    if total_tools > 0:
        print(f"   📊 Progress: {len(completed_tools) / total_tools * 100:.1f}%")

    if completed_tools:
        print(f"   🔧 Completed: {', '.join(completed_tools)}")
    if pending_tools:
        print(f"   ⏱️  Pending: {', '.join(pending_tools)}")

    # Scan statistics
    stats = state.get("scan_statistics", {})
    print("\n🔍 Scan Statistics:")
    print(f"   🎯 Total URLs: {stats.get('total_urls', 0)}")
    print(f"   📊 Patterns matched: {stats.get('patterns_matched', 0)}")
    print(f"   ⚡ Vulnerabilities found: {stats.get('vulnerabilities_found', 0)}")
    print(f"   🛠️ Technologies detected: {len(stats.get('technologies', {}))}")

    # Technology breakdown
    technologies = stats.get("technologies", {})
    if technologies:
        print("\n🛠️ Technology Breakdown:")
        for tech, count in sorted(
            technologies.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            print(f"   • {tech}: {count}")
        if len(technologies) > 10:
            print(f"   ... and {len(technologies) - 10} more")

    # Output files status
    output_dir_path = Path(config.get("output_dir", output_dir))
    if output_dir_path.exists():
        print("\n📁 Output Files Status:")

        # Check for common output files
        output_files = {
            "all.txt": "Combined URLs",
            "xss.txt": "XSS patterns",
            "sqli.txt": "SQLi patterns",
            "lfi.txt": "LFI patterns",
            "dalfox.txt": "Dalfox results",
            "jaeles.txt": "Jaeles results",
            "nuclei.txt": "Nuclei results",
            "vulncli_report.json": "JSON report",
            "vulncli_report.md": "Markdown report",
            "ai_executive_summary.md": "AI summary",
        }

        for filename, description in output_files.items():
            file_path = output_dir_path / filename
            if file_path.exists():
                size = file_path.stat().st_size
                size_str = f"{size} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
                print(f"   ✅ {filename} ({description}): {size_str}")
            else:
                print(f"   ❌ {filename} ({description}): Not found")

    print("\n" + "=" * 70)


def reset_all_resume_data(output_dir):
    """Reset and clear all vulnerability scan resume data completely."""
    resume_dir = Path(output_dir) / "resume"

    if not resume_dir.exists():
        print("📋 [RESUME-RESET] No resume data found to reset")
        return

    try:
        # Remove all files in resume directory
        file_count = 0
        for file_path in resume_dir.glob("*"):
            if file_path.is_file():
                file_path.unlink()
                file_count += 1
                print(f"🗑️  [RESUME-RESET] Removed: {file_path.name}")

        # Remove the resume directory itself
        resume_dir.rmdir()
        print(
            "✅ [RESUME-RESET] All vulnerability scan resume data has been completely reset"
        )
        print(f"🔄 [RESUME-RESET] Removed {file_count} files and resume directory")
        print("🆕 [RESUME-RESET] You can now start a fresh vulnerability scan")

    except Exception as e:
        print(f"❌ [RESUME-RESET] Error resetting resume data: {e}")


if __name__ == "__main__":
    vulncli()
