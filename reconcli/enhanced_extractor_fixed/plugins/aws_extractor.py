#!/usr/bin/env python3
"""
AWS-specific content extractor plugin
Extracts AWS resources, ARNs, S3 buckets, etc.
"""

import re
from typing import Dict, Set, List
from .base_plugin import BasePlugin


class AWSExtractor(BasePlugin):
    """Extract AWS-specific resources and credentials"""
    
    def __init__(self):
        super().__init__()
        self.name = "AWS Extractor"
        self.patterns = {
            "aws_access_keys": re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            "aws_secret_keys": re.compile(r'[A-Za-z0-9/+=]{40}'),
            "aws_session_tokens": re.compile(r'[A-Za-z0-9/+=]{300,}'),
            "s3_buckets": re.compile(r's3://([a-z0-9.-]+)', re.IGNORECASE),
            "s3_urls": re.compile(r'https?://([a-z0-9.-]+)\.s3[.\-a-z0-9]*\.amazonaws\.com', re.IGNORECASE),
            "aws_regions": re.compile(r'(us|eu|ap|sa|ca|me|af|il)-(east|west|north|south|central)-[1-9]', re.IGNORECASE),
            "aws_arns": re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9-_/:.]+', re.IGNORECASE),
            "ec2_instances": re.compile(r'i-[0-9a-f]{8,17}', re.IGNORECASE),
            "lambda_functions": re.compile(r'arn:aws:lambda:[a-z0-9-]*:[0-9]{12}:function:[a-zA-Z0-9-_]+', re.IGNORECASE),
            "rds_endpoints": re.compile(r'[a-z0-9-]+\.([a-z0-9-]+\.)?rds\.amazonaws\.com', re.IGNORECASE),
            "cloudfront_domains": re.compile(r'[a-z0-9]+\.cloudfront\.net', re.IGNORECASE),
            "aws_account_ids": re.compile(r'\b[0-9]{12}\b'),
        }
    
    def extract(self, content: str, file_path: str) -> Dict[str, Set]:
        """Extract AWS-specific content"""
        results = {
            "aws_access_keys": set(),
            "aws_secret_keys": set(),
            "aws_session_tokens": set(),
            "s3_buckets": set(),
            "s3_urls": set(),
            "aws_regions": set(),
            "aws_arns": set(),
            "ec2_instances": set(),
            "lambda_functions": set(),
            "rds_endpoints": set(),
            "cloudfront_domains": set(),
            "aws_account_ids": set(),
            "aws_services": set(),
        }
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            if pattern_name == "s3_buckets":
                # Extract bucket names
                results[pattern_name].update(matches)
            elif pattern_name == "s3_urls":
                # Extract bucket names from URLs
                results["s3_buckets"].update(matches)
                results[pattern_name].update([f"https://{match}.s3.amazonaws.com" for match in matches])
            else:
                results[pattern_name].update(matches)
        
        # Extract AWS service names from ARNs
        aws_services = set()
        for arn in results["aws_arns"]:
            parts = arn.split(":")
            if len(parts) > 2:
                aws_services.add(parts[2])
        results["aws_services"] = aws_services
        
        # Look for AWS CLI commands and configs
        aws_cli_pattern = re.compile(r'aws\s+([a-z0-9-]+)', re.IGNORECASE)
        cli_matches = aws_cli_pattern.findall(content)
        results["aws_services"].update(cli_matches)
        
        return results
    
    def get_security_issues(self, extracted_data: Dict[str, Set]) -> List[Dict]:
        """Identify potential security issues"""
        issues = []
        
        if extracted_data.get("aws_access_keys"):
            issues.append({
                "severity": "HIGH",
                "type": "AWS Access Key Exposure",
                "description": "AWS access keys found in file",
                "count": len(extracted_data["aws_access_keys"]),
                "recommendation": "Remove hardcoded AWS credentials and use IAM roles or environment variables"
            })
        
        if extracted_data.get("aws_secret_keys"):
            issues.append({
                "severity": "CRITICAL",
                "type": "AWS Secret Key Exposure", 
                "description": "AWS secret keys found in file",
                "count": len(extracted_data["aws_secret_keys"]),
                "recommendation": "Immediately rotate these credentials and use AWS IAM roles"
            })
        
        if extracted_data.get("s3_buckets"):
            issues.append({
                "severity": "MEDIUM",
                "type": "S3 Bucket Reference",
                "description": "S3 bucket names found - check if publicly accessible",
                "count": len(extracted_data["s3_buckets"]),
                "recommendation": "Verify S3 bucket permissions and enable bucket encryption"
            })
        
        return issues
