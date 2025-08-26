#!/usr/bin/env python3
"""
Enhanced pattern detection for sensitive data and credentials
"""

import re
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs


@dataclass
class DetectionResult:
    """Result of pattern detection"""
    pattern_type: str
    value: str
    context: str
    confidence: str  # HIGH, MEDIUM, LOW
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    severity: str = "MEDIUM"


class EnhancedPatternDetector:
    """Enhanced pattern detection for credentials, tokens, and sensitive data"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.scoring_rules = self._initialize_scoring()
        
    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize enhanced detection patterns"""
        return {
            # JWT and Tokens
            "jwt_tokens": {
                "pattern": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', re.IGNORECASE),
                "description": "JWT Token",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "bearer_tokens": {
                "pattern": re.compile(r'Bearer\s+([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
                "description": "Bearer Token", 
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "base64_tokens": {
                "pattern": re.compile(r'[\'"][a-zA-Z0-9+/]{40,}={0,2}[\'"]'),
                "description": "Base64 Token",
                "severity": "MEDIUM",
                "confidence": "MEDIUM"
            },
            
            # AWS/Cloud Credentials
            "aws_access_key": {
                "pattern": re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
                "description": "AWS Access Key ID",
                "severity": "CRITICAL",
                "confidence": "HIGH"
            },
            "aws_secret_key": {
                "pattern": re.compile(r'aws_secret_access_key[\'"\s]*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?', re.IGNORECASE),
                "description": "AWS Secret Access Key",
                "severity": "CRITICAL", 
                "confidence": "HIGH"
            },
            "aws_session_token": {
                "pattern": re.compile(r'aws_session_token[\'"\s]*[:=]\s*[\'"]?([A-Za-z0-9/+=]{100,})[\'"]?', re.IGNORECASE),
                "description": "AWS Session Token",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            
            # Google Cloud
            "google_oauth": {
                "pattern": re.compile(r'ya29\.[0-9A-Za-z\-_]+', re.IGNORECASE),
                "description": "Google OAuth Token",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "google_api_key": {
                "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.IGNORECASE),
                "description": "Google API Key",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            
            # Azure
            "azure_storage": {
                "pattern": re.compile(r'DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([^;]+)', re.IGNORECASE),
                "description": "Azure Storage Connection String",
                "severity": "CRITICAL",
                "confidence": "HIGH"
            },
            "azure_key": {
                "pattern": re.compile(r'[\'"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[\'"]', re.IGNORECASE),
                "description": "Azure Key/GUID",
                "severity": "MEDIUM",
                "confidence": "MEDIUM"
            },
            
            # Database Connection Strings
            "postgres_connection": {
                "pattern": re.compile(r'postgres(?:ql)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^\s\'"]+)', re.IGNORECASE),
                "description": "PostgreSQL Connection String",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "mysql_connection": {
                "pattern": re.compile(r'mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^\s\'"]+)', re.IGNORECASE),
                "description": "MySQL Connection String", 
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "mongodb_connection": {
                "pattern": re.compile(r'mongodb://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^\s\'"]+)', re.IGNORECASE),
                "description": "MongoDB Connection String",
                "severity": "HIGH", 
                "confidence": "HIGH"
            },
            "jdbc_connection": {
                "pattern": re.compile(r'jdbc:[^:]+://([^:/]+)(?::(\d+))?/([^\s\'"?]+)', re.IGNORECASE),
                "description": "JDBC Connection String",
                "severity": "MEDIUM",
                "confidence": "MEDIUM"
            },
            
            # Sensitive Files
            "git_directory": {
                "pattern": re.compile(r'\.git[/\\]', re.IGNORECASE),
                "description": "Git Directory Reference",
                "severity": "MEDIUM",
                "confidence": "HIGH"
            },
            "env_file": {
                "pattern": re.compile(r'\.env(?:\.|$)', re.IGNORECASE),
                "description": "Environment File",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            "config_file": {
                "pattern": re.compile(r'config\.(?:php|xml|json|yaml|yml)', re.IGNORECASE),
                "description": "Configuration File",
                "severity": "MEDIUM", 
                "confidence": "MEDIUM"
            },
            "private_key": {
                "pattern": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE),
                "description": "Private Key",
                "severity": "CRITICAL",
                "confidence": "HIGH"
            },
            "ssh_key": {
                "pattern": re.compile(r'ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]+[=]{0,2}', re.IGNORECASE),
                "description": "SSH Public Key",
                "severity": "MEDIUM",
                "confidence": "HIGH"
            },
            "aws_credentials_file": {
                "pattern": re.compile(r'\.aws[/\\]credentials', re.IGNORECASE),
                "description": "AWS Credentials File",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            
            # API Keys and Secrets
            "generic_api_key": {
                "pattern": re.compile(r'(?:api[_-]?key|apikey)[\'"\s]*[:=]\s*[\'"]?([a-zA-Z0-9_-]{15,})[\'"]?', re.IGNORECASE),
                "description": "Generic API Key", 
                "severity": "HIGH",
                "confidence": "MEDIUM"
            },
            "secret_key": {
                "pattern": re.compile(r'(?:secret[_-]?key|secretkey)[\'"\s]*[:=]\s*[\'"]?([a-zA-Z0-9_-]{15,})[\'"]?', re.IGNORECASE),
                "description": "Secret Key",
                "severity": "HIGH",
                "confidence": "MEDIUM"
            },
            "auth_token": {
                "pattern": re.compile(r'(?:auth[_-]?token|authtoken)[\'"\s]*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?', re.IGNORECASE),
                "description": "Auth Token",
                "severity": "HIGH",
                "confidence": "MEDIUM"
            },
            
            # Hardcoded Passwords
            "password_assignment": {
                "pattern": re.compile(r'(?:password|passwd|pwd)[\'"\s]*[:=]\s*[\'"]([^\'"\s]{6,})[\'"]', re.IGNORECASE),
                "description": "Hardcoded Password",
                "severity": "HIGH",
                "confidence": "MEDIUM"
            },
            
            # GitHub/GitLab Tokens
            "github_token": {
                "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}', re.IGNORECASE),
                "description": "GitHub Token",
                "severity": "CRITICAL",
                "confidence": "HIGH"
            },
            "gitlab_token": {
                "pattern": re.compile(r'gl[poas]_[A-Za-z0-9_-]{20,255}', re.IGNORECASE),
                "description": "GitLab Token",
                "severity": "CRITICAL",
                "confidence": "HIGH"
            },
            
            # Slack Tokens
            "slack_token": {
                "pattern": re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}', re.IGNORECASE),
                "description": "Slack Token",
                "severity": "HIGH",
                "confidence": "HIGH"
            },
            
            # Email Addresses (enhanced)
            "email_addresses": {
                "pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                "description": "Email Address",
                "severity": "LOW",
                "confidence": "HIGH"
            },
            
            # IP Addresses (enhanced)
            "private_ips": {
                "pattern": re.compile(r'\b(?:10\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))\b'),
                "description": "Private IP Address",
                "severity": "LOW",
                "confidence": "HIGH"
            }
        }
    
    def _initialize_scoring(self) -> Dict[str, int]:
        """Initialize endpoint scoring rules"""
        return {
            # High value endpoints
            "graphql": 90,
            "swagger": 85,
            "openapi": 85,
            "/admin": 80,
            "/internal": 75,
            "/debug": 70,
            "/test": 65,
            "/dev": 65,
            "/api/v1": 60,
            "/api/v2": 60,
            
            # Medium value
            "/api": 50,
            "/rest": 45,
            "/service": 40,
            
            # Status codes impact
            "401": 15,  # Authentication required
            "403": 15,  # Forbidden
            "500": -10,  # Server error
            "404": -20,  # Not found
        }
    
    def extract_context(self, content: str, match_start: int, match_end: int, context_size: int = 50) -> str:
        """Extract context around a match"""
        start = max(0, match_start - context_size)
        end = min(len(content), match_end + context_size)
        context = content[start:end]
        
        # Clean up context
        context = context.replace('\n', ' ').replace('\r', ' ').strip()
        if len(context) > 150:
            context = context[:150] + "..."
        
        return context
    
    def get_line_number(self, content: str, position: int) -> int:
        """Get line number for position in content"""
        return content[:position].count('\n') + 1
    
    def detect_patterns(self, content: str, file_path: Optional[str] = None) -> List[DetectionResult]:
        """Detect all patterns in content"""
        results = []
        
        for pattern_name, pattern_info in self.patterns.items():
            pattern = pattern_info["pattern"]
            description = pattern_info["description"]
            severity = pattern_info["severity"]
            confidence = pattern_info["confidence"]
            
            for match in pattern.finditer(content):
                value = match.group(0)
                context = self.extract_context(content, match.start(), match.end())
                line_number = self.get_line_number(content, match.start())
                
                # Skip false positives
                if self._is_false_positive(pattern_name, value, context):
                    continue
                
                result = DetectionResult(
                    pattern_type=pattern_name,
                    value=value,
                    context=context,
                    confidence=confidence,
                    line_number=line_number,
                    file_path=file_path,
                    severity=severity
                )
                
                results.append(result)
        
        return results
    
    def _is_false_positive(self, pattern_name: str, value: str, context: str) -> bool:
        """Check if detection is likely a false positive"""
        context_lower = context.lower()
        
        # Skip examples and documentation
        false_positive_indicators = [
            'example', 'sample', 'demo', 'test', 'placeholder',
            'your_api_key', 'your_secret', 'replace_with',
            'xxxxxxxx', '12345', 'abcdef', 'lorem ipsum'
        ]
        
        for indicator in false_positive_indicators:
            if indicator in context_lower or indicator in value.lower():
                return True
        
        # Pattern-specific false positive checks
        if pattern_name == "jwt_tokens":
            # Skip obviously fake JWTs
            if "example" in value.lower() or len(value) < 50:
                return True
        
        if pattern_name in ["aws_access_key", "aws_secret_key"]:
            # Skip example AWS keys
            if "AKIAIOSFODNN7EXAMPLE" in value or "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in value:
                return True
        
        return False
    
    def extract_query_parameters(self, urls: List[str]) -> Dict[str, Set[str]]:
        """Extract unique query parameters from URLs"""
        params = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    for key in query_params.keys():
                        if key not in params:
                            params[key] = set()
                        params[key].update(query_params[key])
            except:
                continue
        
        return params
    
    def score_endpoint(self, url: str, status_code: Optional[int] = None, response_headers: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        """Score endpoint based on various factors"""
        score = 0
        reasons = []
        
        url_lower = url.lower()
        
        # Check for high-value indicators
        for indicator, points in self.scoring_rules.items():
            if indicator.startswith("/") and indicator in url_lower:
                score += points
                reasons.append(f"Contains {indicator} (+{points})")
                break
            elif not indicator.startswith("/") and indicator in url_lower:
                score += points
                reasons.append(f"Contains {indicator} (+{points})")
        
        # Status code impact
        if status_code and str(status_code) in self.scoring_rules:
            points = self.scoring_rules[str(status_code)]
            score += points
            reasons.append(f"Status {status_code} ({'+' if points > 0 else ''}{points})")
        
        # Response header analysis
        if response_headers:
            server = response_headers.get("server", "").lower()
            if "swagger" in server:
                score += 20
                reasons.append("Swagger server (+20)")
            
            content_type = response_headers.get("content-type", "").lower()
            if "application/json" in content_type:
                score += 5
                reasons.append("JSON content (+5)")
        
        # Determine priority level
        if score >= 80:
            priority = "HIGH"
        elif score >= 50:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        
        return score, priority
    
    def categorize_findings(self, results: List[DetectionResult]) -> Dict[str, List[DetectionResult]]:
        """Categorize findings by type and severity"""
        categories = {
            "CRITICAL": [],
            "HIGH": [], 
            "MEDIUM": [],
            "LOW": []
        }
        
        for result in results:
            categories[result.severity].append(result)
        
        return categories
    
    def generate_security_report(self, results: List[DetectionResult], output_file: str):
        """Generate comprehensive security report"""
        categories = self.categorize_findings(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("ENHANCED SECURITY ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            # Summary
            total_findings = len(results)
            f.write(f"📊 SUMMARY:\n")
            f.write(f"   Total security findings: {total_findings}\n")
            
            for severity, findings in categories.items():
                if findings:
                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                    f.write(f"   {emoji} {severity}: {len(findings)} findings\n")
            f.write("\n")
            
            # Detailed findings by severity
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                findings = categories[severity]
                if not findings:
                    continue
                
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                f.write(f"{emoji} {severity} SEVERITY FINDINGS:\n")
                f.write("─" * 50 + "\n")
                
                # Group by pattern type
                by_type = {}
                for finding in findings:
                    if finding.pattern_type not in by_type:
                        by_type[finding.pattern_type] = []
                    by_type[finding.pattern_type].append(finding)
                
                for pattern_type, type_findings in by_type.items():
                    f.write(f"\n📍 {pattern_type.replace('_', ' ').title()} ({len(type_findings)} found):\n")
                    
                    for finding in type_findings[:5]:  # Limit to 5 per type
                        f.write(f"   Value: {finding.value}\n")
                        f.write(f"   Context: {finding.context}\n")
                        if finding.file_path:
                            f.write(f"   File: {finding.file_path}")
                            if finding.line_number:
                                f.write(f" (line {finding.line_number})")
                            f.write("\n")
                        f.write(f"   Confidence: {finding.confidence}\n")
                        f.write("\n")
                    
                    if len(type_findings) > 5:
                        f.write(f"   ... and {len(type_findings) - 5} more {pattern_type} findings\n\n")
                
                f.write("\n")
            
            # Recommendations
            f.write("💡 RECOMMENDATIONS:\n")
            f.write("-" * 20 + "\n")
            
            if categories["CRITICAL"]:
                f.write("🔴 CRITICAL ISSUES REQUIRE IMMEDIATE ACTION:\n")
                f.write("   • Rotate all exposed credentials immediately\n")
                f.write("   • Remove hardcoded secrets from code\n")
                f.write("   • Implement proper secret management\n\n")
            
            if categories["HIGH"]:
                f.write("🟠 HIGH PRIORITY ISSUES:\n")
                f.write("   • Review and secure API endpoints\n")
                f.write("   • Implement proper authentication\n")
                f.write("   • Remove sensitive files from public access\n\n")
            
            if categories["MEDIUM"] or categories["LOW"]:
                f.write("🟡 MEDIUM/LOW PRIORITY IMPROVEMENTS:\n")
                f.write("   • Review configuration files\n")
                f.write("   • Implement security headers\n")
                f.write("   • Regular security audits\n\n")
        
        print(f"📋 Enhanced security report saved to: {output_file}")


def analyze_content_enhanced(content: str, file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze content with enhanced pattern detection
    
    Args:
        content: File content to analyze
        file_path: Optional file path for context
    
    Returns:
        Dictionary with detection results and analysis
    """
    detector = EnhancedPatternDetector()
    results = detector.detect_patterns(content, file_path)
    
    # Categorize results
    categories = detector.categorize_findings(results)
    
    # Extract URLs for parameter analysis
    url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    urls = url_pattern.findall(content)
    unique_urls = list(set(urls))
    query_params = detector.extract_query_parameters(urls)
    
    # Extract other basic patterns for compatibility
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    emails = list(set(email_pattern.findall(content)))
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = list(set(ip_pattern.findall(content)))
    
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    domains = list(set(domain_pattern.findall(content)))
    
    # Extract API keys
    api_keys = []
    for result in results:
        if "api_key" in result.pattern_type or "secret" in result.pattern_type:
            api_keys.append(result.value)
    
    return {
        "total_findings": len(results),
        "findings_by_severity": {k: len(v) for k, v in categories.items()},
        "detailed_findings": results,
        "query_parameters": query_params,
        "unique_params": list(query_params.keys()),
        "urls_found": len(urls),
        # Add compatibility with standard extractor
        "urls": unique_urls,
        "emails": emails,
        "ips": ips,
        "domains": domains,
        "api_keys": list(set(api_keys)),
        "paths": [],  # Will be extracted separately if needed
        "ports": []   # Will be extracted separately if needed
    }
