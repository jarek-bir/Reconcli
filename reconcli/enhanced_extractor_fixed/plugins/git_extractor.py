 #!/usr/bin/env python3
"""
Git and source code repository extractor plugin
"""

import re
from typing import Dict, Set, List
from .base_plugin import BasePlugin


class GitExtractor(BasePlugin):
    """Extract Git repository and source code information"""
    
    def __init__(self):
        super().__init__()
        self.name = "Git Extractor"
        self.patterns = {
            "git_repos": re.compile(r'git@([a-z0-9.-]+):([a-zA-Z0-9._/-]+)\.git', re.IGNORECASE),
            "github_repos": re.compile(r'https?://github\.com/([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)', re.IGNORECASE),
            "gitlab_repos": re.compile(r'https?://gitlab\.com/([a-zA-Z0-9._/-]+)', re.IGNORECASE),
            "git_urls": re.compile(r'https?://[a-z0-9.-]+/[a-zA-Z0-9._/-]+\.git', re.IGNORECASE),
            "commit_hashes": re.compile(r'\b[a-f0-9]{7,40}\b'),
            "github_tokens": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
            "gitlab_tokens": re.compile(r'gl[poas]_[A-Za-z0-9_-]{20,255}'),
            "ssh_keys": re.compile(r'ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]+[=]{0,2}', re.IGNORECASE),
            "private_keys": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE),
            "branch_names": re.compile(r'(?:origin/|refs/heads/)([a-zA-Z0-9._/-]+)', re.IGNORECASE),
        }
    
    def extract(self, content: str, file_path: str) -> Dict[str, Set]:
        """Extract Git/repository-specific content"""
        results = {
            "git_repositories": set(),
            "github_repositories": set(),
            "gitlab_repositories": set(),
            "commit_hashes": set(),
            "github_tokens": set(),
            "gitlab_tokens": set(),
            "ssh_keys": set(),
            "private_keys": set(),
            "branch_names": set(),
            "git_security_issues": set(),
        }
        
        # Extract Git repositories
        git_matches = self.patterns["git_repos"].findall(content)
        for match in git_matches:
            if isinstance(match, tuple) and len(match) == 2:
                repo = f"{match[0]}/{match[1]}"
                results["git_repositories"].add(repo)
        
        # Extract GitHub repositories
        github_matches = self.patterns["github_repos"].findall(content)
        for match in github_matches:
            if isinstance(match, tuple) and len(match) == 2:
                repo = f"{match[0]}/{match[1]}"
                results["github_repositories"].add(repo)
        
        # Extract other patterns
        for pattern_name, pattern in self.patterns.items():
            if pattern_name not in ["git_repos", "github_repos"]:
                matches = pattern.findall(content)
                if pattern_name == "gitlab_repos":
                    results["gitlab_repositories"].update(matches)
                elif pattern_name == "commit_hashes":
                    # Filter out non-commit looking hashes
                    valid_hashes = [h for h in matches if len(h) >= 7]
                    results["commit_hashes"].update(valid_hashes)
                else:
                    results[pattern_name].update(matches)
        
        # Check for security issues
        if results["github_tokens"] or results["gitlab_tokens"]:
            results["git_security_issues"].add("API tokens found in repository")
        
        if results["private_keys"]:
            results["git_security_issues"].add("Private keys found in repository")
        
        if results["ssh_keys"]:
            results["git_security_issues"].add("SSH keys found in repository")
        
        # Look for .git directory references
        if ".git/" in content or "/.git" in content:
            results["git_security_issues"].add("Git directory references found")
        
        return results
    
    def get_security_issues(self, extracted_data: Dict[str, Set]) -> List[Dict]:
        """Identify Git/repository security issues"""
        issues = []
        
        if extracted_data.get("github_tokens"):
            issues.append({
                "severity": "CRITICAL",
                "type": "GitHub Token Exposure",
                "description": "GitHub API tokens found in repository",
                "count": len(extracted_data["github_tokens"]),
                "recommendation": "Immediately revoke these tokens and use GitHub secrets or environment variables"
            })
        
        if extracted_data.get("gitlab_tokens"):
            issues.append({
                "severity": "CRITICAL",
                "type": "GitLab Token Exposure",
                "description": "GitLab API tokens found in repository",
                "count": len(extracted_data["gitlab_tokens"]),
                "recommendation": "Immediately revoke these tokens and use GitLab CI variables"
            })
        
        if extracted_data.get("private_keys"):
            issues.append({
                "severity": "CRITICAL",
                "type": "Private Key Exposure",
                "description": "Private SSH/cryptographic keys found",
                "count": len(extracted_data["private_keys"]),
                "recommendation": "Remove private keys from repository and regenerate them"
            })
        
        if extracted_data.get("ssh_keys"):
            issues.append({
                "severity": "HIGH",
                "type": "SSH Key Exposure",
                "description": "SSH public keys found in repository",
                "count": len(extracted_data["ssh_keys"]),
                "recommendation": "Review if SSH keys should be in repository and remove sensitive ones"
            })
        
        return issues
