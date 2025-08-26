#!/usr/bin/env python3
"""
Advanced URL prober with httpx for checking endpoint availability and technology detection
Integrates with enhanced pattern detection for comprehensive security analysis
"""

import asyncio
import httpx
import time
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Any, Optional, Tuple
import json
import re
from pathlib import Path

# Import enhanced pattern detection
try:
    from .enhanced_patterns import EnhancedPatternDetector, DetectionResult
except ImportError:
    try:
        from enhanced_patterns import EnhancedPatternDetector, DetectionResult
    except ImportError:
        # Create a simple fallback
        class DetectionResult:
            def __init__(self, pattern_type, content, context="", severity="LOW", file_path=""):
                self.pattern_type = pattern_type
                self.content = content
                self.context = context
                self.severity = severity
                self.file_path = file_path
        
        class EnhancedPatternDetector:
            def __init__(self):
                pass
            def detect_patterns(self, content, file_path=""):
                return []


@dataclass
class ProbeResult:
    """Result of URL probe"""
    url: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    title: Optional[str] = None
    technologies: Optional[List[str]] = None
    security_findings: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    redirect_url: Optional[str] = None
    is_alive: bool = False
    security_score: int = 0
    priority: str = "LOW"

    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []
        if self.security_findings is None:
            self.security_findings = []


class AdvancedURLProber:
    """Advanced URL prober with enhanced detection capabilities"""
    
    def __init__(self, 
                 timeout: int = 10,
                 max_concurrent: int = 50,
                 follow_redirects: bool = True,
                 user_agent: str = "Mozilla/5.0 (Security Scanner) httpx/0.24.0"):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent
        self.session_limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        
        # Initialize enhanced detector if available
        self.pattern_detector = EnhancedPatternDetector() if EnhancedPatternDetector else None
        
        # Technology detection patterns
        self.tech_patterns = self._initialize_tech_patterns()
        
    def _initialize_tech_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize technology detection patterns"""
        return {
            'swagger': re.compile(r'swagger|openapi', re.IGNORECASE),
            'jenkins': re.compile(r'jenkins|hudson', re.IGNORECASE),
            'grafana': re.compile(r'grafana', re.IGNORECASE),
            'prometheus': re.compile(r'prometheus', re.IGNORECASE),
            'kibana': re.compile(r'kibana', re.IGNORECASE),
            'elasticsearch': re.compile(r'elasticsearch', re.IGNORECASE),
            'apache': re.compile(r'apache', re.IGNORECASE),
            'nginx': re.compile(r'nginx', re.IGNORECASE),
            'tomcat': re.compile(r'tomcat', re.IGNORECASE),
            'jboss': re.compile(r'jboss', re.IGNORECASE),
            'wordpress': re.compile(r'wp-content|wordpress', re.IGNORECASE),
            'drupal': re.compile(r'drupal', re.IGNORECASE),
            'joomla': re.compile(r'joomla', re.IGNORECASE),
            'phpmyadmin': re.compile(r'phpmyadmin', re.IGNORECASE),
            'adminer': re.compile(r'adminer', re.IGNORECASE),
            'docker': re.compile(r'docker', re.IGNORECASE),
            'kubernetes': re.compile(r'kubernetes|k8s', re.IGNORECASE),
            'rails': re.compile(r'ruby on rails|rails', re.IGNORECASE),
            'django': re.compile(r'django', re.IGNORECASE),
            'flask': re.compile(r'flask', re.IGNORECASE),
            'spring': re.compile(r'spring framework|spring boot', re.IGNORECASE),
            'react': re.compile(r'react', re.IGNORECASE),
            'angular': re.compile(r'angular', re.IGNORECASE),
            'vue': re.compile(r'vue\.js|vuejs', re.IGNORECASE),
            'mongodb': re.compile(r'mongodb', re.IGNORECASE),
            'redis': re.compile(r'redis', re.IGNORECASE),
            'mysql': re.compile(r'mysql', re.IGNORECASE),
            'postgresql': re.compile(r'postgresql|postgres', re.IGNORECASE),
            'graphql': re.compile(r'graphql', re.IGNORECASE),
            'api_gateway': re.compile(r'api gateway|kong|zuul', re.IGNORECASE),
            'load_balancer': re.compile(r'haproxy|f5|bigip', re.IGNORECASE)
        }
    
    async def probe_single_url(self, session: httpx.AsyncClient, url: str) -> ProbeResult:
        """Probe a single URL asynchronously"""
        start_time = time.time()
        result = ProbeResult(url=url)
        
        try:
            response = await session.get(url, follow_redirects=self.follow_redirects)
            response_time = time.time() - start_time
            
            result.status_code = response.status_code
            result.response_time = response_time
            result.content_length = len(response.content) if response.content else 0
            result.content_type = response.headers.get('content-type', '')
            result.server = response.headers.get('server', '')
            result.is_alive = 200 <= response.status_code < 500
            
            if response.history:
                result.redirect_url = str(response.url)
            
            # Extract title from HTML
            if result.content_type and 'text/html' in result.content_type.lower():
                result.title = self._extract_title(response.text)
            
            # Detect technologies
            result.technologies = self._detect_technologies(response)
            
            # Enhanced security analysis
            if self.pattern_detector:
                security_findings = self._analyze_security(response, url)
                result.security_findings = [asdict(finding) for finding in security_findings]
                
                # Calculate security score and priority
                score, priority = self.pattern_detector.score_endpoint(
                    url, response.status_code, dict(response.headers)
                )
                result.security_score = score
                result.priority = priority
            
        except httpx.TimeoutException:
            result.error = "Timeout"
        except httpx.ConnectError:
            result.error = "Connection failed"
        except httpx.HTTPStatusError as e:
            result.status_code = e.response.status_code
            result.error = f"HTTP {e.response.status_code}"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _extract_title(self, html_content: str) -> Optional[str]:
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return None
    
    def _detect_technologies(self, response: httpx.Response) -> List[str]:
        """Detect technologies from response"""
        technologies = []
        
        # Check headers
        server = response.headers.get('server', '').lower()
        x_powered_by = response.headers.get('x-powered-by', '').lower()
        
        # Check response content
        content = response.text.lower() if hasattr(response, 'text') else ''
        
        # Combine all text for analysis
        all_text = f"{server} {x_powered_by} {content}"
        
        # Match against patterns
        for tech_name, pattern in self.tech_patterns.items():
            if pattern.search(all_text):
                technologies.append(tech_name)
        
        return list(set(technologies))  # Remove duplicates
    
    def _analyze_security(self, response: httpx.Response, url: str) -> List[DetectionResult]:
        """Analyze response for security issues"""
        if not self.pattern_detector:
            return []
        
        findings = []
        
        # Analyze response headers
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
        header_findings = self.pattern_detector.detect_patterns(headers_text, f"{url} (headers)")
        findings.extend(header_findings)
        
        # Analyze response body (limit to first 10KB for performance)
        if hasattr(response, 'text'):
            content = response.text[:10240]  # First 10KB
            content_findings = self.pattern_detector.detect_patterns(content, url)
            findings.extend(content_findings)
        
        return findings
    
    async def probe_urls_batch(self, urls: List[str], progress_callback=None) -> List[ProbeResult]:
        """Probe multiple URLs concurrently"""
        if not urls:
            return []
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []
        
        async def probe_with_semaphore(session: httpx.AsyncClient, url: str, index: int) -> ProbeResult:
            async with semaphore:
                result = await self.probe_single_url(session, url)
                if progress_callback:
                    progress_callback(index + 1, len(urls), result)
                return result
        
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=self.session_limits,
            headers={'User-Agent': self.user_agent}
        ) as session:
            tasks = [
                probe_with_semaphore(session, url, i) 
                for i, url in enumerate(urls)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = ProbeResult(url=urls[i], error=str(result))
                valid_results.append(error_result)
            else:
                valid_results.append(result)
        
        return valid_results
    
    def probe_urls_sync(self, urls: List[str], verbose: bool = False) -> List[ProbeResult]:
        """Synchronous wrapper for URL probing"""
        def progress_callback(current: int, total: int, result: ProbeResult):
            if verbose:
                status = "✅" if result.is_alive else "❌"
                error_info = f" ({result.error})" if result.error else ""
                print(f"{status} [{current}/{total}] {result.url}{error_info}")
        
        return asyncio.run(self.probe_urls_batch(urls, progress_callback))
    
    def filter_alive_urls(self, results: List[ProbeResult]) -> List[str]:
        """Filter and return only alive URLs"""
        return [result.url for result in results if result.is_alive]
    
    def filter_by_technology(self, results: List[ProbeResult], technology: str) -> List[ProbeResult]:
        """Filter results by detected technology"""
        return [result for result in results 
                if result.technologies and technology.lower() in [t.lower() for t in result.technologies]]
    
    def filter_by_security_score(self, results: List[ProbeResult], min_score: int = 50) -> List[ProbeResult]:
        """Filter results by minimum security score"""
        return [result for result in results if result.security_score >= min_score]
    
    def get_statistics(self, results: List[ProbeResult]) -> Dict[str, Any]:
        """Generate statistics from probe results"""
        total = len(results)
        alive = sum(1 for r in results if r.is_alive)
        with_errors = sum(1 for r in results if r.error)
        
        # Status code distribution
        status_codes = {}
        for result in results:
            if result.status_code:
                status_codes[result.status_code] = status_codes.get(result.status_code, 0) + 1
        
        # Technology distribution
        tech_count = {}
        for result in results:
            if result.technologies:
                for tech in result.technologies:
                    tech_count[tech] = tech_count.get(tech, 0) + 1
        
        # Security findings summary
        security_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_findings = 0
        
        for result in results:
            if result.security_findings:
                total_findings += len(result.security_findings)
                for finding in result.security_findings:
                    severity = finding.get('severity', 'LOW')
                    security_summary[severity] = security_summary.get(severity, 0) + 1
        
        return {
            "total_urls": total,
            "alive_urls": alive,
            "dead_urls": total - alive,
            "error_count": with_errors,
            "success_rate": round((alive / total * 100), 2) if total > 0 else 0,
            "status_code_distribution": status_codes,
            "technology_distribution": dict(sorted(tech_count.items(), key=lambda x: x[1], reverse=True)),
            "security_findings": security_summary,
            "total_security_findings": total_findings,
            "average_response_time": round(
                sum(r.response_time for r in results if r.response_time) / 
                len([r for r in results if r.response_time]), 3
            ) if any(r.response_time for r in results) else 0
        }
    
    def save_results(self, output_dir: str, results: List[ProbeResult]):
        """Save results to multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = int(time.time())
        
        # Save detailed JSON results
        json_file = output_path / f"probe_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump([asdict(result) for result in results], f, indent=2, default=str)
        
        # Save alive URLs only
        alive_urls = self.filter_alive_urls(results)
        alive_file = output_path / f"alive_urls_{timestamp}.txt"
        with open(alive_file, 'w') as f:
            f.write('\n'.join(alive_urls))
        
        # Save high-value targets
        high_value = self.filter_by_security_score(results, min_score=60)
        if high_value:
            high_value_file = output_path / f"high_value_targets_{timestamp}.json"
            with open(high_value_file, 'w') as f:
                json.dump([asdict(result) for result in high_value], f, indent=2, default=str)
        
        # Generate comprehensive report
        self._generate_comprehensive_report(output_path / f"probe_report_{timestamp}.txt", results)
        
        print(f"📁 Results saved to {output_dir}:")
        print(f"   📄 JSON: {json_file.name}")
        print(f"   📄 Alive URLs: {alive_file.name}")
        if high_value:
            print(f"   🎯 High-value targets: {high_value_file.name}")
        print(f"   📋 Report: probe_report_{timestamp}.txt")
    
    def _generate_comprehensive_report(self, output_file: Path, results: List[ProbeResult]):
        """Generate comprehensive probe report"""
        stats = self.get_statistics(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("ADVANCED URL PROBE REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Executive Summary
            f.write("📊 EXECUTIVE SUMMARY:\n")
            f.write(f"   Total URLs probed: {stats['total_urls']}\n")
            f.write(f"   Alive URLs: {stats['alive_urls']} ({stats['success_rate']}%)\n")
            f.write(f"   Dead URLs: {stats['dead_urls']}\n")
            f.write(f"   Average response time: {stats['average_response_time']}s\n")
            f.write(f"   Security findings: {stats['total_security_findings']}\n\n")
            
            # Security Summary
            if stats['total_security_findings'] > 0:
                f.write("🔒 SECURITY OVERVIEW:\n")
                for severity, count in stats['security_findings'].items():
                    if count > 0:
                        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                        f.write(f"   {emoji} {severity}: {count} findings\n")
                f.write("\n")
            
            # Technology Distribution
            if stats['technology_distribution']:
                f.write("🛠️  TECHNOLOGY DETECTION:\n")
                for tech, count in list(stats['technology_distribution'].items())[:10]:
                    f.write(f"   {tech}: {count} instances\n")
                f.write("\n")
            
            # High-Value Targets
            high_value = self.filter_by_security_score(results, min_score=60)
            if high_value:
                f.write("🎯 HIGH-VALUE TARGETS:\n")
                for result in sorted(high_value, key=lambda x: x.security_score, reverse=True)[:10]:
                    f.write(f"   {result.url} (Score: {result.security_score}, Priority: {result.priority})\n")
                    if result.technologies:
                        f.write(f"      Technologies: {', '.join(result.technologies)}\n")
                f.write("\n")
            
            # Status Code Distribution
            f.write("📈 STATUS CODE DISTRIBUTION:\n")
            for code, count in sorted(stats['status_code_distribution'].items()):
                f.write(f"   {code}: {count} responses\n")
            f.write("\n")
            
            # Critical Security Findings
            critical_findings = [r for r in results 
                               if r.security_findings and any(f.get('severity') == 'CRITICAL' for f in r.security_findings)]
            if critical_findings:
                f.write("🚨 CRITICAL SECURITY FINDINGS:\n")
                for result in critical_findings[:5]:
                    f.write(f"   URL: {result.url}\n")
                    if result.security_findings:
                        critical = [f for f in result.security_findings if f.get('severity') == 'CRITICAL']
                        for finding in critical[:3]:
                            f.write(f"      ⚠️  {finding.get('pattern_type', 'Unknown')}: {finding.get('value', 'N/A')}\n")
                    f.write("\n")


def probe_urls_from_list(urls: List[str], 
                        output_dir: str = "probe_results",
                        timeout: int = 10,
                        max_concurrent: int = 50,
                        verbose: bool = False) -> Dict[str, Any]:
    """
    Probe URLs and return comprehensive results
    
    Args:
        urls: List of URLs to probe
        output_dir: Directory to save results
        timeout: Request timeout in seconds
        max_concurrent: Maximum concurrent requests
        verbose: Enable verbose output
    
    Returns:
        Dictionary with probe results and statistics
    """
    # Clean and validate URLs
    clean_urls = []
    for url in urls:
        url = url.strip()
        if url and (url.startswith('http://') or url.startswith('https://')):
            clean_urls.append(url)
    
    if not clean_urls:
        return {"error": "No valid URLs provided"}
    
    print(f"🔍 Starting advanced probe of {len(clean_urls)} URLs...")
    
    # Initialize prober
    prober = AdvancedURLProber(
        timeout=timeout,
        max_concurrent=max_concurrent
    )
    
    # Probe URLs
    results = prober.probe_urls_sync(clean_urls, verbose=verbose)
    
    # Save results
    prober.save_results(output_dir, results)
    
    # Get statistics
    stats = prober.get_statistics(results)
    
    return {
        "results": results,
        "statistics": stats,
        "alive_urls": prober.filter_alive_urls(results),
        "high_value_targets": prober.filter_by_security_score(results, min_score=60)
    }


def main():
    """Main CLI entry point for url-prober command"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: url-prober <urls_file> [output_dir]")
        print("\nAdvanced URL prober with technology detection and security analysis")
        print("\nArguments:")
        print("  urls_file    Path to file containing URLs (one per line)")
        print("  output_dir   Output directory for results (default: probe_results)")
        print("\nExample:")
        print("  url-prober urls.txt")
        print("  url-prober urls.txt results/")
        sys.exit(1)
    
    urls_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "probe_results"
    
    try:
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        results = probe_urls_from_list(urls, output_dir, verbose=True)
        
        print(f"\n✅ Probe completed!")
        print(f"📊 Results: {results['statistics']}")
        
    except FileNotFoundError:
        print(f"❌ File not found: {urls_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
