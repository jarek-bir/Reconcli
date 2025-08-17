🎯 REAL EXAMPLE: GitLab Bug Bounty Program
═══════════════════════════════════════

SCOPE CHECK FIRST:
• Program: https://hackerone.com/gitlab  
• Scope: *.gitlab.com, *.gitlab.io, gitlab.com
• Out of scope: gitlab-org/*, third-party integrations

PRAKTYCZNY WORKFLOW:

1️⃣ SUBDOMAIN DISCOVERY:
   # Safe passive recon (allowed)
   curl -s 'https://crt.sh/?q=%.gitlab.com&output=json' | jq -r '.[].name_value' | sort -u | head -10

2️⃣ EXAMPLE DISCOVERED SUBDOMAINS:
   • about.gitlab.com
   • docs.gitlab.com
   • forum.gitlab.com  
   • status.gitlab.com
   • customers.gitlab.com

3️⃣ IP RESOLUTION:
   # Get IP for vhost discovery
   dig +short gitlab.com

4️⃣ VHOST HUNTING COMMAND:
   # Example command (do NOT run on real targets without permission!)
   # ./vhost_hunter.sh gitlab.com $(dig +short gitlab.com)

5️⃣ CO SZUKAĆ SPECIFICALLY FOR GITLAB:
   • admin-gitlab.com (admin panels)
   • api-gitlab.com (API endpoints)
   • staging-gitlab.com (staging env)
   • jenkins-gitlab.com (CI/CD)
   • monitoring-gitlab.com (dashboards)
   • internal-gitlab.com (internal tools)

6️⃣ WHAT TO LOOK FOR IN RESULTS:
   • 200 responses with different content
   • Admin/login interfaces
   • API endpoints without authentication
   • Development/staging environments
   • Monitoring dashboards
   • CI/CD interfaces

7️⃣ MANUAL TESTING PRIORITIES:
   • Default credentials on admin panels
   • API endpoint enumeration
   • Development environment access
   • Information disclosure
   • Authentication bypass

⚠️ LEGAL NOTICE: This is EXAMPLE ONLY - always get permission first!

🎯 REAL FINDINGS EXAMPLES (from public reports):
• Hidden admin panels on non-standard ports
• Staging environments with debug enabled
• API endpoints without rate limiting
• Monitoring dashboards with sensitive info
• CI/CD systems with exposed credentials

💡 PRO TIPS FOR GITLAB-STYLE TARGETS:
• Look for GitLab-specific endpoints (/admin, /-/admin)
• Check for API v4 endpoints (/api/v4/)
• Search for CI/CD related vhosts (runners, registry)
• Monitor for new GitLab releases (new features = new attack surface)
