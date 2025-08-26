#!/usr/bin/env python3
"""
Network and security information extractor plugin
"""

import re
from typing import Dict, Set, List
from .base_plugin import BasePlugin


class NetworkExtractor(BasePlugin):
    """Extract network and security-related information"""
    
    def __init__(self):
        super().__init__()
        self.name = "Network Extractor"
        self.patterns = {
            "ipv4_addresses": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "ipv6_addresses": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            "mac_addresses": re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b', re.IGNORECASE),
            "ports": re.compile(r':([0-9]{1,5})\b'),
            "ssl_certificates": re.compile(r'-----BEGIN CERTIFICATE-----', re.IGNORECASE),
            "ssl_keys": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----', re.IGNORECASE),
            "jwt_tokens": re.compile(r'ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            "api_keys": re.compile(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', re.IGNORECASE),
            "bearer_tokens": re.compile(r'Bearer\s+([A-Za-z0-9_.-]+)', re.IGNORECASE),
            "basic_auth": re.compile(r'Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE),
            "ssh_connections": re.compile(r'ssh\s+(?:-[a-z]\s+)*([a-zA-Z0-9@.-]+)', re.IGNORECASE),
            "database_urls": re.compile(r'(?:mysql|postgresql|mongodb|redis)://[^\s<>"\']+', re.IGNORECASE),
            "ldap_urls": re.compile(r'ldaps?://[^\s<>"\']+', re.IGNORECASE),
            "network_shares": re.compile(r'\\\\[a-zA-Z0-9.-]+\\[a-zA-Z0-9$_.-]+', re.IGNORECASE),
            "vpn_configs": re.compile(r'(?:openvpn|ipsec|wireguard|l2tp)', re.IGNORECASE),
        }
    
    def extract(self, content: str, file_path: str) -> Dict[str, Set]:
        """Extract network and security information"""
        results = {
            "ipv4_addresses": set(),
            "ipv6_addresses": set(),
            "mac_addresses": set(),
            "open_ports": set(),
            "ssl_certificates": set(),
            "ssl_private_keys": set(),
            "jwt_tokens": set(),
            "api_keys": set(),
            "bearer_tokens": set(),
            "basic_auth": set(),
            "ssh_connections": set(),
            "database_connections": set(),
            "ldap_connections": set(),
            "network_shares": set(),
            "vpn_configurations": set(),
            "private_networks": set(),
            "security_issues": set(),
        }
        
        # Extract basic patterns
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            
            if pattern_name == "ports":
                # Filter common ports and validate range
                valid_ports = []
                for port in matches:
                    try:
                        port_num = int(port)
                        if 1 <= port_num <= 65535:
                            valid_ports.append(port)
                    except ValueError:
                        continue
                results["open_ports"].update(valid_ports)
            
            elif pattern_name == "ipv4_addresses":
                # Filter private networks and validate IPs
                for ip in matches:
                    parts = ip.split('.')
                    try:
                        if all(0 <= int(part) <= 255 for part in parts):
                            results["ipv4_addresses"].add(ip)
                            # Check if it's a private network
                            if (parts[0] == '10' or 
                                (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
                                (parts[0] == '192' and parts[1] == '168')):
                                results["private_networks"].add(ip)
                    except ValueError:
                        continue
            
            elif pattern_name == "ssl_certificates":
                results["ssl_certificates"].update(["SSL Certificate found"] * len(matches))
            
            elif pattern_name == "ssl_keys":
                results["ssl_private_keys"].update(["SSL Private Key found"] * len(matches))
                results["security_issues"].add("SSL private keys found in file")
            
            elif pattern_name == "jwt_tokens":
                # Validate JWT structure
                for token in matches:
                    if token.count('.') == 2:
                        results["jwt_tokens"].add(f"JWT:{token[:50]}...")
                        results["security_issues"].add("JWT tokens found in file")
            
            elif pattern_name == "api_keys":
                for key in matches:
                    results["api_keys"].add(f"API Key: {key[:20]}...")
                    results["security_issues"].add("API keys found in file")
            
            elif pattern_name == "database_urls":
                results["database_connections"].update(matches)
                results["security_issues"].add("Database connection strings found")
            
            else:
                # Map to appropriate result key
                result_key = pattern_name
                if pattern_name == "ldap_urls":
                    result_key = "ldap_connections"
                elif pattern_name == "vpn_configs":
                    result_key = "vpn_configurations"
                
                results[result_key].update(matches)
        
        # Look for hardcoded passwords
        password_patterns = [
            re.compile(r'password["\']?\s*[:=]\s*["\']?([^"\'\s,}]{4,})', re.IGNORECASE),
            re.compile(r'passwd["\']?\s*[:=]\s*["\']?([^"\'\s,}]{4,})', re.IGNORECASE),
            re.compile(r'secret["\']?\s*[:=]\s*["\']?([^"\'\s,}]{8,})', re.IGNORECASE),
        ]
        
        for pattern in password_patterns:
            matches = pattern.findall(content)
            if matches:
                results["security_issues"].add("Hardcoded passwords/secrets found")
                break
        
        return results
    
    def get_security_issues(self, extracted_data: Dict[str, Set]) -> List[Dict]:
        """Identify network security issues"""
        issues = []
        
        if extracted_data.get("ssl_private_keys"):
            issues.append({
                "severity": "CRITICAL",
                "type": "SSL Private Key Exposure",
                "description": "SSL private keys found in files",
                "count": len(extracted_data["ssl_private_keys"]),
                "recommendation": "Remove SSL private keys and store them securely"
            })
        
        if extracted_data.get("jwt_tokens"):
            issues.append({
                "severity": "HIGH",
                "type": "JWT Token Exposure",
                "description": "JWT tokens found in files",
                "count": len(extracted_data["jwt_tokens"]),
                "recommendation": "Remove hardcoded JWT tokens and implement proper token management"
            })
        
        if extracted_data.get("api_keys"):
            issues.append({
                "severity": "HIGH",
                "type": "API Key Exposure",
                "description": "API keys found in files",
                "count": len(extracted_data["api_keys"]),
                "recommendation": "Remove hardcoded API keys and use environment variables or secret management"
            })
        
        if extracted_data.get("database_connections"):
            issues.append({
                "severity": "MEDIUM",
                "type": "Database Connection Exposure",
                "description": "Database connection strings found",
                "count": len(extracted_data["database_connections"]),
                "recommendation": "Use environment variables for database connections and avoid hardcoding credentials"
            })
        
        # Check for suspicious ports
        dangerous_ports = {'22', '23', '25', '53', '80', '110', '143', '443', '993', '995'}
        open_ports = extracted_data.get("open_ports", set())
        if any(port in dangerous_ports for port in open_ports):
            issues.append({
                "severity": "MEDIUM",
                "type": "Potentially Exposed Services",
                "description": "Common service ports found in configuration",
                "count": len(open_ports.intersection(dangerous_ports)),
                "recommendation": "Review port configurations and ensure proper firewall rules"
            })
        
        return issues
