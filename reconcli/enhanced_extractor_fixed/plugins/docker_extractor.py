#!/usr/bin/env python3
"""
Docker and container-specific content extractor plugin
"""

import re
from typing import Dict, Set, List
from .base_plugin import BasePlugin


class DockerExtractor(BasePlugin):
    """Extract Docker and container-related information"""
    
    def __init__(self):
        super().__init__()
        self.name = "Docker Extractor"
        self.patterns = {
            "docker_images": re.compile(r'(?:FROM|image:)\s*([a-z0-9._/-]+(?::[a-z0-9._-]+)?)', re.IGNORECASE | re.MULTILINE),
            "docker_registries": re.compile(r'([a-z0-9.-]+)/[a-z0-9._/-]+', re.IGNORECASE),
            "docker_ports": re.compile(r'(?:EXPOSE|ports?:)\s*([0-9]+(?::[0-9]+)?)', re.IGNORECASE),
            "docker_volumes": re.compile(r'(?:VOLUME|volumes?:)\s*([/\w.-]+)', re.IGNORECASE),
            "docker_env": re.compile(r'(?:ENV|environment:)\s*([A-Z_][A-Z0-9_]*)\s*[=:]\s*([^\s\n]+)', re.IGNORECASE),
            "docker_secrets": re.compile(r'(?:ENV|environment:)\s*(PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*[=:]\s*([^\s\n]+)', re.IGNORECASE),
            "kubernetes_resources": re.compile(r'kind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress)', re.IGNORECASE),
            "container_commands": re.compile(r'(?:RUN|CMD|ENTRYPOINT)\s+(.+)', re.IGNORECASE | re.MULTILINE),
            "docker_compose": re.compile(r'version:\s*["\']?([0-9.]+)["\']?', re.IGNORECASE),
        }
    
    def extract(self, content: str, file_path: str) -> Dict[str, Set]:
        """Extract Docker/container-specific content"""
        results = {
            "docker_images": set(),
            "docker_registries": set(),
            "docker_ports": set(),
            "docker_volumes": set(),
            "docker_env_vars": set(),
            "docker_secrets": set(),
            "kubernetes_resources": set(),
            "container_commands": set(),
            "docker_compose_versions": set(),
            "container_vulnerabilities": set(),
        }
        
        # Extract basic patterns
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            
            if pattern_name == "docker_images":
                for match in matches:
                    results["docker_images"].add(match)
                    # Extract registry if present
                    if '/' in match and '.' in match.split('/')[0]:
                        registry = match.split('/')[0]
                        results["docker_registries"].add(registry)
            
            elif pattern_name == "docker_env":
                for match in matches:
                    if isinstance(match, tuple) and len(match) == 2:
                        results["docker_env_vars"].add(f"{match[0]}={match[1]}")
            
            elif pattern_name == "docker_secrets":
                for match in matches:
                    if isinstance(match, tuple) and len(match) == 2:
                        results["docker_secrets"].add(f"{match[0]}={match[1][:20]}...")
            
            elif pattern_name == "docker_compose":
                results["docker_compose_versions"].update(matches)
            
            else:
                results[pattern_name].update(matches)
        
        # Look for vulnerable images
        vulnerable_images = {
            "node:8", "node:10", "ubuntu:14.04", "ubuntu:16.04", 
            "centos:6", "centos:7", "python:2.7", "php:5.6",
            "mysql:5.5", "postgres:9.6"
        }
        
        for image in results["docker_images"]:
            for vuln_image in vulnerable_images:
                if vuln_image in image.lower():
                    results["container_vulnerabilities"].add(f"Potentially vulnerable image: {image}")
        
        return results
    
    def get_security_issues(self, extracted_data: Dict[str, Set]) -> List[Dict]:
        """Identify container security issues"""
        issues = []
        
        if extracted_data.get("docker_secrets"):
            issues.append({
                "severity": "HIGH",
                "type": "Hardcoded Secrets in Container Config",
                "description": "Secrets found in Docker/container configuration",
                "count": len(extracted_data["docker_secrets"]),
                "recommendation": "Use Docker secrets, Kubernetes secrets, or environment variables from secure sources"
            })
        
        if extracted_data.get("container_vulnerabilities"):
            issues.append({
                "severity": "MEDIUM",
                "type": "Potentially Vulnerable Container Images",
                "description": "Old or vulnerable container images detected",
                "count": len(extracted_data["container_vulnerabilities"]),
                "recommendation": "Update to latest stable versions and scan images for vulnerabilities"
            })
        
        # Check for root user usage
        for cmd in extracted_data.get("container_commands", set()):
            if "USER root" in cmd or "sudo" in cmd:
                issues.append({
                    "severity": "MEDIUM",
                    "type": "Root User in Container",
                    "description": "Container may be running as root user",
                    "count": 1,
                    "recommendation": "Use non-root user in containers for better security"
                })
                break
        
        return issues
