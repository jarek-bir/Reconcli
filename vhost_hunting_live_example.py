#!/usr/bin/env python3
"""
🎯 Praktyczny VHost Hunting - Live Example
Hands-on example z real bug bounty target
"""

import subprocess
import sys
import json
import requests
from pathlib import Path


def show_legal_targets():
    """Show current legal targets for practice"""
    print(
        """
🎯 LIVE LEGAL TARGETS FOR PRACTICE:
═══════════════════════════════════

🟢 HACKERONE PUBLIC PROGRAMS (Always check current scope!):
• Yahoo - yahoo.com (massive scope)
• GitLab - gitlab.com (web apps)
• Shopify - shopify.com (e-commerce)
• Twitter - twitter.com (social media)
• Dropbox - dropbox.com (file storage)
• Spotify - spotify.com (streaming)
• Grammarly - grammarly.com (writing tools)

🟢 BUGCROWD PROGRAMS:
• Tesla - tesla.com (automotive)
• Fitbit - fitbit.com (health tech)
• Mozilla - mozilla.org (browser/tools)
• Atlassian - atlassian.com (dev tools)

⚠️ ZAWSZE SPRAWDŹ AKTUALNY SCOPE PRZED TESTOWANIEM!
"""
    )


def demonstrate_recon_workflow():
    """Demonstrate complete reconnaissance workflow"""
    print(
        """
🔍 PRAKTYCZNY WORKFLOW - KROK PO KROKU:
═════════════════════════════════════

Załóżmy że testujemy program: example-corp.com (fictional)

KROK 1: INITIAL RECONNAISSANCE
──────────────────────────────
"""
    )

    example_commands = [
        "# Subdomain enumeration",
        "subfinder -d example-corp.com -silent | tee subdomains.txt",
        "",
        "# Certificate transparency",
        "curl -s 'https://crt.sh/?q=%.example-corp.com&output=json' | jq -r '.[].name_value' | sort -u",
        "",
        "# ASN enumeration",
        "whois example-corp.com | grep -i 'origin as'",
        "",
        "# IP range discovery",
        "amass intel -asn AS12345 -ip",
    ]

    for cmd in example_commands:
        print(f"   {cmd}")

    print(
        """
KROK 2: PORT DISCOVERY
─────────────────────
"""
    )

    port_commands = [
        "# Quick port scan na discovered IPs",
        "cat subdomains.txt | httpx -silent -ports 80,443,8080,8443,3000,5000,8000,9000 | tee web_services.txt",
        "",
        "# Deep port scan z jfscan",
        "jfscan 192.168.1.100 --yummy-ports -q | grep ':'",
    ]

    for cmd in port_commands:
        print(f"   {cmd}")


def create_target_specific_wordlist():
    """Create wordlist specific to target"""
    print(
        """
KROK 3: TARGET-SPECIFIC WORDLIST
───────────────────────────────

🎯 Customization based on target research:
"""
    )

    # Company-specific terms
    company_terms = """
# Company-specific (example for tech company)
company-api
company-admin  
company-dev
company-staging
company-internal
company-jenkins
company-grafana
company-elastic
company-kibana
company-prometheus
company-vault
company-gitlab
company-jira
company-confluence
company-docker
company-k8s
company-monitoring
"""

    # Technology stack terms
    tech_terms = """
# Technology stack specific
react-app
vue-app
angular-app
node-api
python-api
django-admin
flask-admin
rails-admin
spring-boot
tomcat-manager
nginx-status
apache-status
php-admin
wordpress-admin
drupal-admin
magento-admin
"""

    # Environment variations
    env_terms = """
# Environment variations
api-dev
api-staging
api-prod
api-test
api-demo
admin-dev
admin-staging
admin-prod
internal-dev
internal-staging
jenkins-dev
jenkins-staging
monitoring-dev
monitoring-prod
"""

    wordlist_content = company_terms + tech_terms + env_terms

    with open("target_specific_wordlist.txt", "w") as f:
        f.write(wordlist_content)

    print("✅ Created target-specific wordlist")
    print(f"📁 File: target_specific_wordlist.txt")


def show_vhost_hunting_command():
    """Show enhanced VHostCLI command"""
    print(
        """
KROK 4: VHOST DISCOVERY Z ENHANCED VHOSTCLI
──────────────────────────────────────────

🚀 Basic scan:
"""
    )

    basic_cmd = """reconcli vhostcli \\
    --domain example-corp.com \\
    --ip 192.168.1.100 \\
    --wordlist target_specific_wordlist.txt \\
    --verbose"""

    print(f"   {basic_cmd}")

    print(
        """
🔥 Enhanced scan z port discovery:
"""
    )

    enhanced_cmd = """reconcli vhostcli \\
    --domain example-corp.com \\
    --ip 192.168.1.100 \\
    --wordlist target_specific_wordlist.txt \\
    --port-scan --port-scanner jfscan \\
    --verbose"""

    print(f"   {enhanced_cmd}")

    print(
        """
💥 Full security assessment:
"""
    )

    full_cmd = """reconcli vhostcli \\
    --domain example-corp.com \\
    --ip 192.168.1.100 \\
    --wordlist target_specific_wordlist.txt \\
    --port-scan --port-scanner jfscan \\
    --nuclei-scan --nuclei-severity medium,high,critical \\
    --screenshot --ai-mode \\
    --store-db --program "Example Corp" \\
    --verbose"""

    print(f"   {full_cmd}")


def analyze_results_guide():
    """Guide for analyzing results"""
    print(
        """
KROK 5: ANALIZA REZULTATÓW
─────────────────────────

🔍 CO SPRAWDZAĆ W ZNALEZIONYCH VHOSTS:

📋 IMMEDIATE CHECKS:
• Response codes: 200, 403, 401, 302
• Content-Length: różne od baseline
• Server headers: różne technology stacks
• Title tags: admin panels, login forms
• Redirects: do login pages

🎯 HIGH PRIORITY FINDINGS:
• admin.example-corp.com → Admin panel!
• api.example-corp.com → API endpoints
• dev.example-corp.com → Development environment
• staging.example-corp.com → Staging environment  
• jenkins.example-corp.com → CI/CD system
• grafana.example-corp.com → Monitoring dashboard

⚡ MANUAL TESTING WORKFLOW:
"""
    )

    manual_tests = [
        "1. Browse to found vhost in browser",
        "2. Check for default credentials (admin/admin, admin/password)",
        "3. Look for sensitive information disclosure",
        "4. Test for common vulnerabilities:",
        "   • SQL injection in login forms",
        "   • XSS in search/input fields",
        "   • Directory traversal (/admin, /.git, /backup)",
        "   • File upload vulnerabilities",
        "   • Authentication bypass",
        "5. Check for API endpoints (/api/v1/, /graphql, /swagger)",
        "6. Screenshot everything for reporting",
    ]

    for test in manual_tests:
        print(f"   {test}")


def show_reporting_template():
    """Show vulnerability reporting template"""
    print(
        """
KROK 6: DOKUMENTACJA I REPORTING
───────────────────────────────

📝 TEMPLATE RAPORTU:

**Title:** Virtual Host Discovery - Exposed Admin Panel

**Severity:** High

**Description:**
During virtual host enumeration, I discovered an exposed admin panel at admin.example-corp.com that was not linked from the main application.

**Steps to Reproduce:**
1. Perform virtual host discovery on IP 192.168.1.100
2. Send request with Host header: admin.example-corp.com
3. Observe exposed admin interface

**Impact:**
- Unauthorized access to administrative functions
- Potential data breach
- System compromise

**Proof of Concept:**
```
curl -H "Host: admin.example-corp.com" http://192.168.1.100/
```

**Recommendation:**
- Implement proper access controls
- Remove or secure admin interfaces
- Use IP whitelisting for administrative access

**Screenshots:** [Attach screenshots]
"""
    )


def create_automation_script():
    """Create automation script for vhost hunting"""
    script_content = """#!/bin/bash

# 🎯 Automated VHost Hunter
# Usage: ./vhost_hunter.sh domain.com ip_address

DOMAIN=$1
IP=$2

if [ -z "$DOMAIN" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <domain> <ip>"
    echo "Example: $0 example.com 192.168.1.100"
    exit 1
fi

echo "🎯 Starting VHost hunting for $DOMAIN ($IP)"

# Create output directory
OUTPUT_DIR="vhost_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "📁 Output directory: $OUTPUT_DIR"

# Step 1: Basic enumeration
echo "🔍 Step 1: Basic VHost discovery..."
reconcli vhostcli \\
    --domain "$DOMAIN" \\
    --ip "$IP" \\
    --wordlist vhost_training_wordlist.txt \\
    --output-dir "$OUTPUT_DIR/basic" \\
    --verbose

# Step 2: Enhanced scan with port discovery
echo "🚀 Step 2: Enhanced scan with port discovery..."
reconcli vhostcli \\
    --domain "$DOMAIN" \\
    --ip "$IP" \\
    --wordlist target_specific_wordlist.txt \\
    --port-scan --port-scanner jfscan \\
    --output-dir "$OUTPUT_DIR/enhanced" \\
    --verbose

# Step 3: Security assessment
echo "🔒 Step 3: Security assessment..."
reconcli vhostcli \\
    --domain "$DOMAIN" \\
    --ip "$IP" \\
    --wordlist vhost_training_wordlist.txt \\
    --nuclei-scan --nuclei-severity medium,high,critical \\
    --screenshot \\
    --output-dir "$OUTPUT_DIR/security" \\
    --verbose

echo "✅ VHost hunting completed!"
echo "📊 Results in: $OUTPUT_DIR"
"""

    with open("vhost_hunter.sh", "w") as f:
        f.write(script_content)

    # Make executable
    import os

    os.chmod("vhost_hunter.sh", 0o755)

    print("✅ Created automation script: vhost_hunter.sh")


def main():
    """Main function"""
    print("🎯 PRAKTYCZNY VHOST HUNTING - LIVE EXAMPLE")
    print("=" * 60)

    show_legal_targets()
    demonstrate_recon_workflow()
    create_target_specific_wordlist()
    show_vhost_hunting_command()
    analyze_results_guide()
    show_reporting_template()
    create_automation_script()

    print(
        """
🎯 READY TO START HUNTING!
═════════════════════════

1️⃣ Choose a target from legal bug bounty programs
2️⃣ Follow the workflow step by step
3️⃣ Use the automation script: ./vhost_hunter.sh domain.com ip
4️⃣ Analyze results manually
5️⃣ Report findings responsibly

⚡ PRO TIP: Start with smaller programs for practice!

🔥 HAPPY HUNTING! Remember - always stay ethical and within scope!
"""
    )


if __name__ == "__main__":
    main()
