#!/usr/bin/env python3
"""
🎯 VHost Hunting Training Guide
Guide for finding and exploiting virtual hosts in bug bounty programs
"""

import subprocess
import sys
import json
from pathlib import Path


def print_vhost_hunting_guide():
    """Print comprehensive guide for vhost hunting"""
    print(
        """
🎯 VIRTUAL HOST HUNTING - TRAINING GUIDE
═══════════════════════════════════════════════════════════════

🔍 CO TO SĄ VIRTUAL HOSTS?
──────────────────────────
Virtual hosts to mechanizm pozwalający jednej maszynie obsługiwać wiele domen/subdomen.
Serwer sprawdza nagłówek 'Host:' w requestach HTTP i kieruje do odpowiedniej aplikacji.

🎯 DLACZEGO TO WAŻNE W BUG BOUNTY?
─────────────────────────────────
✅ Często nieudokumentowane i zapomniane aplikacje
✅ Mniej testowane = więcej vulnerabilities
✅ Staging/dev environments na production IP
✅ Admin panels i internal tools
✅ Legacy applications z known vulnerabilities
✅ Bypass IP restrictions przez Host header manipulation

🔥 CO SZUKAĆ - PRIORITY TARGETS:
───────────────────────────────

🚨 HIGH PRIORITY:
• admin.* / administrator.* - admin panels
• api.* / api-* - API endpoints (często bez auth)
• dev.* / development.* - development environments  
• staging.* / stage.* - staging environments
• test.* / testing.* - test environments
• internal.* / intranet.* - internal applications
• jenkins.* / ci.* - CI/CD systems
• grafana.* / monitoring.* - monitoring dashboards
• phpmyadmin.* / adminer.* - database management
• cpanel.* / plesk.* - hosting control panels

🔥 MEDIUM PRIORITY:
• mail.* / webmail.* - email interfaces
• portal.* / login.* - authentication portals
• dashboard.* / panel.* - management interfaces
• ftp.* / files.* - file management
• backup.* / backups.* - backup systems
• old.* / legacy.* - legacy applications
• beta.* / alpha.* - pre-release versions
• mobile.* / m.* - mobile versions
• support.* / help.* - support systems
• blog.* / cms.* - content management

⚡ SPECIALIZED TARGETS:
• elasticsearch.* / kibana.* - search/analytics
• redis.* / memcache.* - cache systems  
• prometheus.* / alertmanager.* - monitoring
• vault.* / secrets.* - secret management
• docker.* / k8s.* / kubernetes.* - container management
• git.* / gitlab.* / github.* - version control
• jira.* / confluence.* - project management
• vpn.* / openvpn.* - VPN interfaces
• proxy.* / gateway.* - proxy/gateway interfaces

🔍 RECONNAISSANCE TECHNIQUES:
────────────────────────────

1️⃣ DNS ENUMERATION:
   • Subdomain enumeration (subfinder, amass, assetfinder)
   • DNS zone transfers
   • Certificate transparency logs
   • DNS brute forcing

2️⃣ PORT SCANNING:
   • Find web services on non-standard ports
   • Look for 8080, 8443, 3000, 5000, 9000, etc.
   • Use nmap, naabu, masscan, jfscan

3️⃣ VIRTUAL HOST DISCOVERY:
   • ffuf, gobuster, VhostFinder
   • Custom wordlists based on target
   • IP ranges scanning

4️⃣ CERTIFICATE ANALYSIS:
   • SSL certificate Subject Alternative Names (SANs)
   • Certificate transparency monitoring
   • Expired/wildcard certificates

🎯 PRACTICAL HUNTING WORKFLOW:
─────────────────────────────

STEP 1: Information Gathering
• Company research (employees, technology stack)
• ASN enumeration for IP ranges  
• Historical DNS data (SecurityTrails, etc.)

STEP 2: Subdomain Discovery
• Passive: crt.sh, Shodan, DNS databases
• Active: DNS bruteforcing, permutations

STEP 3: Port Discovery  
• Full port scan on discovered IPs
• Focus on web ports (80, 443, 8080, 8443, etc.)

STEP 4: Virtual Host Hunting
• Use comprehensive wordlists
• Target-specific terms (company name, products)
• Technology-specific terms (based on stack)

STEP 5: Content Discovery
• Directory/file enumeration on found vhosts
• Look for sensitive files (/admin, /.git, /backup)

STEP 6: Vulnerability Assessment
• Nuclei scans for known CVEs
• Manual testing for logic flaws
• Authentication bypass attempts

🔥 ADVANCED TECHNIQUES:
──────────────────────

🎯 HOST HEADER INJECTION:
• Try different Host headers to bypass restrictions
• Cache poisoning attacks
• Password reset poisoning

🎯 HTTP/2 SMUGGLING:
• Virtual host confusion via HTTP/2
• Request smuggling through vhosts

🎯 WILDCARD BYPASSES:
• *.example.com configurations
• Subdomain takeover opportunities

🎯 PORT-BASED DISCOVERY:
• Same IP, different ports = different apps
• Load balancer misconfigurations

💡 PRO TIPS:
───────────
✅ Automate everything - create scripts
✅ Use multiple wordlists and techniques
✅ Look for patterns in naming conventions
✅ Check historical/cached versions
✅ Monitor for new additions regularly
✅ Document everything for reporting

⚠️ LEGAL CONSIDERATIONS:
───────────────────────
• Only test targets in your bug bounty scope
• Read program rules carefully
• Respect rate limits and don't DOS
• Don't access sensitive data
• Report responsibly

🔧 RECOMMENDED TOOLS:
────────────────────
• ffuf - Fast vhost fuzzing
• gobuster - Directory/vhost brute forcing  
• httpx - HTTP toolkit
• nuclei - Vulnerability scanning
• burp suite - Manual testing
• subfinder - Subdomain enumeration
• naabu - Port scanning
• aquatone - Screenshots
"""
    )


def get_training_targets():
    """Suggest legal training targets"""
    print(
        """
🎯 LEGAL TRAINING TARGETS:
═════════════════════════

🟢 INTENTIONALLY VULNERABLE:
• DVWA (Damn Vulnerable Web Application)
• WebGoat (OWASP)
• VulnHub VMs
• TryHackMe platforms
• HackTheBox (with VIP)

🟢 BUG BOUNTY PROGRAMS:
• HackerOne public programs
• Bugcrowd programs  
• Synack (invite only)
• YesWeHack programs

🟢 CTF PLATFORMS:
• OverTheWire
• PicoCTF
• SANS Holiday Hack
• Google CTF

⚠️ ALWAYS CHECK SCOPE FIRST!
"""
    )


def create_vhost_wordlist():
    """Create specialized vhost wordlist"""
    wordlist_content = """admin
administrator
api
dev
development
staging
stage
test
testing
internal
intranet
jenkins
ci
cd
grafana
monitoring
phpmyadmin
adminer
cpanel
plesk
mail
webmail
portal
login
dashboard
panel
ftp
files
backup
backups
old
legacy
beta
alpha
mobile
m
support
help
blog
cms
elasticsearch
kibana
redis
memcache
prometheus
alertmanager
vault
secrets
docker
k8s
kubernetes
git
gitlab
github
jira
confluence
vpn
openvpn
proxy
gateway
app
application
service
server
host
node
cluster
db
database
mysql
postgres
mongo
secure
private
public
www2
www3
cdn
static
assets
media
images
js
css
upload
download
share
shared
temp
tmp
cache
log
logs
stats
analytics
reports
reporting
metrics
health
status
ping
test1
test2
dev1
dev2
stage1
stage2
prod
production
live
demo
sandbox
lab
research
training
education
learn
docs
documentation
wiki
forum
community
shop
store
cart
ecommerce
payment
billing
invoice
account
profile
user
users
member
members
client
clients
customer
customers
partner
partners
vendor
suppliers
hr
human-resources
finance
accounting
legal
compliance
security
audit
risk
governance
operations
ops
infrastructure
infra
network
net
system
sys
platform
cloud
aws
azure
gcp
office
workspace
collaboration
chat
communication
video
conference
meeting
calendar
schedule
task
project
workflow
automation
integration
webhook
notification
alert
email
smtp
imap
pop3
dns
dhcp
ldap
radius
sso
oauth
saml
federation
identity
access
permission
role
group
policy
firewall
router
switch
load-balancer
proxy-server
reverse-proxy
cache-server
file-server
print-server
time-server
backup-server
archive
repository
registry
catalog
inventory
asset
resource
quota
limit
threshold
benchmark
performance
optimization
tuning
configuration
setting
parameter
variable
constant
flag
feature
module
component
service-mesh
microservice
container
pod
deployment
replica
scaling
horizontal
vertical
canary
blue-green
rolling
pipeline
build
compile
package
deploy
release
version
branch
tag
commit
merge
pull
push
clone
fork
issue
ticket
bug
feature-request
enhancement
improvement
fix
patch
hotfix
maintenance
upgrade
migration
rollback
restore
recovery
disaster
incident
outage
downtime
availability
reliability
durability
consistency
integrity
confidentiality
authentication
authorization
encryption
decryption
certificate
key
token
session
cookie
header
payload
response
request
endpoint
route
path
query
parameter
body
json
xml
yaml
csv
pdf
excel
word
powerpoint
image
video
audio
file
document
data
information
content
message
notification
alert
warning
error
exception
fault
failure
success
ok
health-check
readiness
liveness
startup
shutdown
restart
reload
refresh
sync
async
queue
worker
job
task
scheduler
cron
timer
event
trigger
handler
processor
transformer
validator
sanitizer
formatter
parser
serializer
deserializer
encoder
decoder
compressor
decompressor
minifier
optimizer
bundler
transpiler
compiler
interpreter
runtime
framework
library
dependency
package
module
plugin
extension
addon
widget
component
element
control
input
output
stream
buffer
cache
memory
storage
disk
volume
mount
bind
link
symlink
alias
shortcut
reference
pointer
index
search
filter
sort
group
aggregate
sum
count
average
minimum
maximum
median
percentile
statistic
metric
dimension
measure
kpi
sla
slo
rto
rpo
mttr
mtbf
uptime
downtime
latency
throughput
bandwidth
capacity
utilization
efficiency
effectiveness
productivity
quality
accuracy
precision
recall
sensitivity
specificity
coverage
completeness
consistency
reliability
availability
scalability
performance
security
privacy
compliance
governance
auditability
traceability
observability
monitoring
logging
alerting
debugging
profiling
testing
validation
verification
certification
accreditation
approval
authorization
permission
access-control
role-based
attribute-based
policy-based
rule-based
risk-based
context-aware
adaptive
dynamic
static
real-time
batch
stream
event-driven
message-driven
data-driven
model-driven
configuration-driven
template-driven
convention-over-configuration
infrastructure-as-code
platform-as-a-service
software-as-a-service
function-as-a-service
backend-as-a-service
database-as-a-service
monitoring-as-a-service
security-as-a-service
identity-as-a-service
analytics-as-a-service
machine-learning-as-a-service
artificial-intelligence-as-a-service"""

    wordlist_path = Path("vhost_training_wordlist.txt")
    with open(wordlist_path, "w") as f:
        f.write(wordlist_content)

    print(f"✅ Created comprehensive vhost wordlist: {wordlist_path}")
    print(f"📊 Contains {len(wordlist_content.split())} entries")
    return wordlist_path


def main():
    """Main function"""
    print_vhost_hunting_guide()
    get_training_targets()
    create_vhost_wordlist()

    print(
        """
🚀 NEXT STEPS FOR TRAINING:
══════════════════════════

1️⃣ Choose a legal target from bug bounty programs
2️⃣ Start with subdomain enumeration
3️⃣ Use our enhanced VHostCLI:
   
   reconcli vhostcli --domain target.com --ip TARGET_IP \\
       --wordlist vhost_training_wordlist.txt \\
       --port-scan --port-scanner jfscan \\
       --nuclei-scan --screenshot \\
       --verbose

4️⃣ Analyze results for interesting findings
5️⃣ Manual testing on discovered vhosts
6️⃣ Document and report vulnerabilities

⚡ REMEMBER: Always stay within scope and be ethical!
"""
    )


if __name__ == "__main__":
    main()
