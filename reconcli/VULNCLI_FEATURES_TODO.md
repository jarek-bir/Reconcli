# 🎯 VulnCLI - Immediate Implementation Proposals

**Ready for Implementation**: Features that can be added to current vulncli.py  
**Status**: Detailed specifications with code examples  
**Priority**: High-impact, low-complexity enhancements

---

## 🔧 **1. YAML Pipeline Configuration** 
**Complexity**: Medium | **Value**: High | **Timeline**: 2-3 weeks

### Implementation Plan:

```python
# Add to imports
import yaml
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class PipelineStage:
    name: str
    tools: List[str]
    depends_on: Optional[List[str]] = None
    parallel: bool = False
    ai_enhanced: bool = False
    conditions: Optional[Dict] = None

@dataclass 
class PipelineConfig:
    name: str
    stages: List[PipelineStage]
    global_settings: Optional[Dict] = None

def load_pipeline_config(config_path: str) -> PipelineConfig:
    """Load and validate pipeline configuration from YAML"""
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    
    stages = []
    for stage_data in config_data.get('stages', []):
        stage = PipelineStage(
            name=stage_data['name'],
            tools=stage_data['tools'],
            depends_on=stage_data.get('depends_on'),
            parallel=stage_data.get('parallel', False),
            ai_enhanced=stage_data.get('ai_enhanced', False),
            conditions=stage_data.get('conditions')
        )
        stages.append(stage)
    
    return PipelineConfig(
        name=config_data.get('name', 'Default Pipeline'),
        stages=stages,
        global_settings=config_data.get('global_settings', {})
    )

def execute_pipeline(config: PipelineConfig, base_args):
    """Execute pipeline stages with dependency resolution"""
    completed_stages = set()
    
    for stage in config.stages:
        # Check dependencies
        if stage.depends_on:
            missing_deps = set(stage.depends_on) - completed_stages
            if missing_deps:
                raise Exception(f"Stage {stage.name} missing dependencies: {missing_deps}")
        
        # Execute stage tools
        if stage.parallel:
            execute_stage_parallel(stage, base_args)
        else:
            execute_stage_sequential(stage, base_args)
            
        completed_stages.add(stage.name)
```

### New CLI Options:
```python
@click.option("--pipeline-config", help="YAML pipeline configuration file")
@click.option("--stage-only", help="Execute only specified stage")
@click.option("--skip-stage", help="Skip specified stage")
@click.option("--pipeline-dry-run", is_flag=True, help="Show pipeline execution plan")
```

### Example Pipeline Config:
```yaml
# vulncli_pipeline.yaml
name: "Web Application Security Assessment"
global_settings:
  timeout: 300
  concurrency: 10
  ai_mode: true

stages:
  - name: "reconnaissance"
    tools: ["httpx", "technology_detect"]
    parallel: true
    
  - name: "pattern_analysis"
    tools: ["gf_filtering"]
    depends_on: ["reconnaissance"]
    
  - name: "vulnerability_scanning"
    tools: ["nuclei", "jaeles"]
    depends_on: ["pattern_analysis"]
    ai_enhanced: true
    conditions:
      min_urls: 10
      
  - name: "specialized_testing"
    tools: ["dalfox"]
    depends_on: ["pattern_analysis"]
    conditions:
      has_xss_patterns: true
      
  - name: "reporting"
    tools: ["markdown_report", "ai_summary"]
    depends_on: ["vulnerability_scanning", "specialized_testing"]
```

---

## 📊 **2. Enhanced Risk Scoring & CVSS Integration**
**Complexity**: Low | **Value**: High | **Timeline**: 1 week

### Implementation:

```python
import re
from dataclasses import dataclass
from enum import Enum

class SeverityLevel(Enum):
    CRITICAL = 10.0
    HIGH = 7.5
    MEDIUM = 5.0
    LOW = 2.5
    INFO = 1.0

@dataclass
class CVSSScore:
    base_score: float
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    vector_string: Optional[str] = None

@dataclass
class VulnerabilityRisk:
    id: str
    type: str
    severity: SeverityLevel
    cvss: Optional[CVSSScore] = None
    exploitability: float = 0.5
    business_impact: float = 0.5
    confidence: float = 0.5
    risk_score: float = 0.0

def calculate_cvss_from_cve(cve_id: str) -> Optional[CVSSScore]:
    """Fetch CVSS score from CVE database"""
    try:
        # Integration with NVD API or local CVE database
        import requests
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        if response.status_code == 200:
            data = response.json()
            # Parse CVSS data from response
            # ... implementation details
            pass
    except Exception:
        return None

def calculate_risk_score(vuln: VulnerabilityRisk, tech_stack: List[str] = None) -> float:
    """Calculate comprehensive risk score"""
    base_risk = vuln.severity.value
    
    # CVSS integration
    if vuln.cvss:
        base_risk = max(base_risk, vuln.cvss.base_score)
    
    # Exploitability factor
    exploitability_factor = vuln.exploitability
    
    # Business impact (configurable per asset)
    business_factor = vuln.business_impact
    
    # Confidence in finding
    confidence_factor = vuln.confidence
    
    # Technology stack multiplier
    tech_multiplier = 1.0
    if tech_stack:
        high_risk_techs = ['php', 'wordpress', 'apache', 'old_versions']
        if any(tech.lower() in high_risk_techs for tech in tech_stack):
            tech_multiplier = 1.2
    
    final_score = (
        base_risk * 0.4 +
        exploitability_factor * 3.0 +
        business_factor * 2.0 +
        confidence_factor * 1.0
    ) * tech_multiplier
    
    return min(final_score, 10.0)

def enhance_nuclei_findings_with_risk(findings_file: str, tech_stack: List[str]) -> List[VulnerabilityRisk]:
    """Parse Nuclei output and enhance with risk scoring"""
    vulnerabilities = []
    
    with open(findings_file, 'r') as f:
        for line in f:
            if '[' in line and ']' in line:
                # Parse Nuclei output format
                severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line.lower())
                cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
                
                severity = SeverityLevel.INFO
                if severity_match:
                    severity_str = severity_match.group(1).upper()
                    severity = SeverityLevel[severity_str] if severity_str in SeverityLevel.__members__ else SeverityLevel.INFO
                
                cvss_score = None
                if cve_match:
                    cve_id = cve_match.group(1)
                    cvss_score = calculate_cvss_from_cve(cve_id)
                
                vuln = VulnerabilityRisk(
                    id=hashlib.md5(line.encode()).hexdigest()[:8],
                    type=extract_vulnerability_type(line),
                    severity=severity,
                    cvss=cvss_score,
                    confidence=0.8  # Default confidence
                )
                
                vuln.risk_score = calculate_risk_score(vuln, tech_stack)
                vulnerabilities.append(vuln)
    
    return vulnerabilities
```

### New CLI Options:
```python
@click.option("--risk-scoring", is_flag=True, help="Enable advanced risk scoring")
@click.option("--cvss-lookup", is_flag=True, help="Lookup CVSS scores for CVEs")
@click.option("--business-impact", type=float, default=0.5, help="Business impact weight (0.0-1.0)")
@click.option("--risk-threshold", type=float, default=7.0, help="Minimum risk score to report")
```

---

## 🛠️ **3. Additional Security Tools Integration**
**Complexity**: Medium | **Value**: Medium | **Timeline**: 2-3 weeks

### Implementation:

```python
def run_httpx(input_file: str, output_dir: str, verbose: bool = False) -> Dict:
    """Run httpx for HTTP probing and technology detection"""
    httpx_out = Path(output_dir) / "httpx.json"
    
    if verbose:
        click.echo("🌐 [HTTPX] Starting HTTP probing...")
    
    httpx_cmd = [
        "httpx", "-l", input_file,
        "-json", "-tech-detect", "-status-code",
        "-content-length", "-response-time",
        "-o", str(httpx_out)
    ]
    
    result = subprocess.run(httpx_cmd, capture_output=True, text=True)
    
    # Parse results
    live_hosts = []
    technologies = {}
    
    if httpx_out.exists():
        with open(httpx_out, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get('status_code'):
                        live_hosts.append(data['url'])
                        if 'tech' in data:
                            for tech in data['tech']:
                                technologies[tech] = technologies.get(tech, 0) + 1
                except json.JSONDecodeError:
                    continue
    
    return {
        "live_hosts": live_hosts,
        "technologies": technologies,
        "output_file": str(httpx_out)
    }

def run_subfinder(domain: str, output_dir: str, verbose: bool = False) -> Dict:
    """Run subfinder for subdomain discovery"""
    subfinder_out = Path(output_dir) / "subfinder.txt"
    
    if verbose:
        click.echo(f"🔍 [SUBFINDER] Discovering subdomains for {domain}...")
    
    subfinder_cmd = [
        "subfinder", "-d", domain,
        "-o", str(subfinder_out),
        "-silent"
    ]
    
    subprocess.run(subfinder_cmd, capture_output=True)
    
    subdomains = []
    if subfinder_out.exists():
        with open(subfinder_out, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    
    return {
        "subdomains": subdomains,
        "count": len(subdomains),
        "output_file": str(subfinder_out)
    }

def run_gobuster(url: str, wordlist: str, output_dir: str, verbose: bool = False) -> Dict:
    """Run gobuster for directory discovery"""
    gobuster_out = Path(output_dir) / "gobuster.txt"
    
    if verbose:
        click.echo(f"📂 [GOBUSTER] Directory brute force on {url}...")
    
    gobuster_cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-o", str(gobuster_out),
        "-q"  # Quiet mode
    ]
    
    subprocess.run(gobuster_cmd, capture_output=True)
    
    directories = []
    if gobuster_out.exists():
        with open(gobuster_out, 'r') as f:
            for line in f:
                if 'Status:' in line:
                    directories.append(line.strip())
    
    return {
        "directories": directories,
        "count": len(directories),
        "output_file": str(gobuster_out)
    }
```

### New CLI Options:
```python
@click.option("--run-httpx", is_flag=True, help="Run httpx for HTTP probing")
@click.option("--run-subfinder", help="Run subfinder for domain (provide domain)")
@click.option("--run-gobuster", is_flag=True, help="Run gobuster directory discovery")
@click.option("--httpx-tech-detect", is_flag=True, help="Enable httpx technology detection")
@click.option("--gobuster-wordlist", help="Wordlist file for gobuster")
```

---

## 📊 **4. Advanced Reporting & Visualization**
**Complexity**: Low | **Value**: High | **Timeline**: 1-2 weeks

### Implementation:

```python
def generate_risk_heatmap(vulnerabilities: List[VulnerabilityRisk], output_dir: str):
    """Generate risk heatmap visualization"""
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        import pandas as pd
        
        # Prepare data
        risk_data = []
        for vuln in vulnerabilities:
            risk_data.append({
                'Type': vuln.type,
                'Severity': vuln.severity.name,
                'Risk Score': vuln.risk_score,
                'Confidence': vuln.confidence
            })
        
        df = pd.DataFrame(risk_data)
        
        # Create heatmap
        plt.figure(figsize=(12, 8))
        pivot_table = df.pivot_table(values='Risk Score', index='Type', columns='Severity', aggfunc='mean')
        sns.heatmap(pivot_table, annot=True, cmap='Reds', cbar_kws={'label': 'Risk Score'})
        plt.title('Vulnerability Risk Heatmap')
        plt.tight_layout()
        
        heatmap_file = Path(output_dir) / "risk_heatmap.png"
        plt.savefig(heatmap_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(heatmap_file)
        
    except ImportError:
        click.echo("⚠️ [VISUALIZATION] matplotlib/seaborn not installed - skipping heatmap")
        return None

def generate_executive_dashboard(stats: Dict, scan_results: Dict, output_dir: str) -> str:
    """Generate executive dashboard HTML"""
    dashboard_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VulnCLI Executive Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 20px; border: 1px solid #ccc; border-radius: 5px; }}
        .critical {{ background-color: #ffebee; }}
        .high {{ background-color: #fff3e0; }}
        .medium {{ background-color: #f3e5f5; }}
        .low {{ background-color: #e8f5e8; }}
        .chart {{ width: 100%; height: 300px; margin: 20px 0; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>🎯 Security Assessment Dashboard</h1>
    
    <div class="metrics">
        <div class="metric critical">
            <h3>Total Vulnerabilities</h3>
            <h2>{stats.get('vulnerabilities_found', 0)}</h2>
        </div>
        <div class="metric high">
            <h3>URLs Scanned</h3>
            <h2>{stats.get('total_urls', 0)}</h2>
        </div>
        <div class="metric medium">
            <h3>Technologies</h3>
            <h2>{len(stats.get('technologies', {}))}</h2>
        </div>
        <div class="metric low">
            <h3>Tools Used</h3>
            <h2>{len(stats.get('scan_tools', []))}</h2>
        </div>
    </div>
    
    <div class="chart">
        <canvas id="vulnerabilityChart"></canvas>
    </div>
    
    <script>
        // Vulnerability distribution chart
        const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [5, 12, 8, 3, 2],
                    backgroundColor: ['#f44336', '#ff9800', '#ffeb3b', '#4caf50', '#2196f3']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Vulnerability Distribution by Severity'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    
    dashboard_file = Path(output_dir) / "executive_dashboard.html"
    with open(dashboard_file, 'w') as f:
        f.write(dashboard_html)
    
    return str(dashboard_file)

def generate_detailed_report(vulnerabilities: List[VulnerabilityRisk], output_dir: str) -> str:
    """Generate detailed vulnerability report"""
    report_content = "# 📋 Detailed Vulnerability Report\\n\\n"
    
    # Group by severity
    by_severity = {}
    for vuln in vulnerabilities:
        severity = vuln.severity.name
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(vuln)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if severity in by_severity:
            report_content += f"## {severity} Severity ({len(by_severity[severity])} findings)\\n\\n"
            
            for vuln in by_severity[severity]:
                report_content += f"### {vuln.type}\\n"
                report_content += f"- **Risk Score**: {vuln.risk_score:.1f}/10\\n"
                report_content += f"- **Confidence**: {vuln.confidence:.1%}\\n"
                if vuln.cvss:
                    report_content += f"- **CVSS Score**: {vuln.cvss.base_score}\\n"
                report_content += "\\n"
    
    report_file = Path(output_dir) / "detailed_vulnerability_report.md"
    with open(report_file, 'w') as f:
        f.write(report_content)
    
    return str(report_file)
```

### New CLI Options:
```python
@click.option("--generate-heatmap", is_flag=True, help="Generate risk heatmap visualization")
@click.option("--executive-dashboard", is_flag=True, help="Generate HTML executive dashboard")
@click.option("--detailed-report", is_flag=True, help="Generate detailed vulnerability report")
```

---

## 🔄 **5. Resume & Progress Tracking Enhancement**
**Complexity**: Low | **Value**: Medium | **Timeline**: 1 week

### Implementation:

```python
import pickle
from datetime import datetime, timedelta

@dataclass
class ScanProgress:
    session_id: str
    started_at: datetime
    current_stage: str
    completed_stages: List[str]
    total_stages: List[str]
    urls_processed: int
    total_urls: int
    last_checkpoint: datetime

def save_scan_progress(progress: ScanProgress, output_dir: str):
    """Save scan progress for resume functionality"""
    progress_file = Path(output_dir) / ".vulncli_progress"
    with open(progress_file, 'wb') as f:
        pickle.dump(progress, f)

def load_scan_progress(output_dir: str) -> Optional[ScanProgress]:
    """Load previous scan progress"""
    progress_file = Path(output_dir) / ".vulncli_progress"
    if progress_file.exists():
        try:
            with open(progress_file, 'rb') as f:
                return pickle.load(f)
        except Exception:
            return None
    return None

def should_resume_stage(stage_name: str, output_dir: str, max_age_hours: int = 24) -> bool:
    """Check if stage should be resumed based on existing output and age"""
    stage_outputs = {
        'gf_filtering': ['xss.txt', 'lfi.txt', 'sqli.txt'],
        'nuclei': ['nuclei.txt'],
        'jaeles': ['jaeles.txt'],
        'dalfox': ['dalfox.txt']
    }
    
    if stage_name not in stage_outputs:
        return False
    
    output_path = Path(output_dir)
    for output_file in stage_outputs[stage_name]:
        file_path = output_path / output_file
        if file_path.exists():
            # Check if file is recent enough
            file_age = datetime.now() - datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_age < timedelta(hours=max_age_hours):
                return True
    
    return False

def display_progress_bar(current: int, total: int, stage: str, prefix: str = "Progress"):
    """Display progress bar in terminal"""
    percent = (current / total) * 100 if total > 0 else 0
    bar_length = 50
    filled_length = int(bar_length * percent // 100)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    click.echo(f"\\r{prefix} [{bar}] {percent:.1f}% - {stage} ({current}/{total})", nl=False)
    
    if current == total:
        click.echo()  # New line when complete
```

### New CLI Options:
```python
@click.option("--resume-max-age", type=int, default=24, help="Max age in hours for resume")
@click.option("--force-restart", is_flag=True, help="Force restart ignoring previous progress")
@click.option("--show-progress", is_flag=True, help="Show detailed progress bars")
@click.option("--checkpoint-interval", type=int, default=100, help="Save progress every N URLs")
```

---

## 🔍 **6. Smart URL Filtering & Deduplication**
**Complexity**: Low | **Value**: Medium | **Timeline**: 1 week

### Implementation:

```python
import urllib.parse
from collections import defaultdict

def smart_url_deduplication(urls: List[str], similarity_threshold: float = 0.8) -> List[str]:
    """Advanced URL deduplication with similarity detection"""
    unique_urls = []
    url_signatures = {}
    
    for url in urls:
        signature = generate_url_signature(url)
        
        # Check similarity with existing URLs
        is_duplicate = False
        for existing_sig, existing_url in url_signatures.items():
            similarity = calculate_url_similarity(signature, existing_sig)
            if similarity > similarity_threshold:
                is_duplicate = True
                # Keep the shorter URL (usually more generic)
                if len(url) < len(existing_url):
                    url_signatures[signature] = url
                    unique_urls[unique_urls.index(existing_url)] = url
                break
        
        if not is_duplicate:
            url_signatures[signature] = url
            unique_urls.append(url)
    
    return unique_urls

def generate_url_signature(url: str) -> str:
    """Generate URL signature for similarity comparison"""
    parsed = urllib.parse.urlparse(url)
    
    # Normalize path
    path_parts = [part for part in parsed.path.split('/') if part]
    normalized_path = '/'.join(path_parts)
    
    # Extract parameter names only (ignore values)
    param_names = sorted(urllib.parse.parse_qs(parsed.query).keys())
    
    signature = f"{parsed.netloc}:{normalized_path}:{','.join(param_names)}"
    return signature

def calculate_url_similarity(sig1: str, sig2: str) -> float:
    """Calculate similarity between URL signatures"""
    parts1 = sig1.split(':')
    parts2 = sig2.split(':')
    
    if len(parts1) != len(parts2):
        return 0.0
    
    similarities = []
    for p1, p2 in zip(parts1, parts2):
        if p1 == p2:
            similarities.append(1.0)
        else:
            # Use Levenshtein distance for partial similarity
            similarity = 1.0 - (levenshtein_distance(p1, p2) / max(len(p1), len(p2), 1))
            similarities.append(max(0.0, similarity))
    
    return sum(similarities) / len(similarities)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def intelligent_parameter_extraction(urls: List[str]) -> Dict[str, List[str]]:
    """Extract and categorize parameters intelligently"""
    param_categories = {
        'id_params': ['id', 'uid', 'user_id', 'post_id', 'item_id'],
        'file_params': ['file', 'path', 'filename', 'dir', 'folder'],
        'search_params': ['q', 'query', 'search', 'term', 'keyword'],
        'filter_params': ['filter', 'category', 'type', 'sort', 'order'],
        'page_params': ['page', 'limit', 'offset', 'start', 'end'],
        'security_params': ['token', 'key', 'hash', 'signature', 'auth']
    }
    
    categorized_urls = defaultdict(list)
    
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for category, param_list in param_categories.items():
            if any(param in params for param in param_list):
                categorized_urls[category].append(url)
    
    return dict(categorized_urls)
```

### New CLI Options:
```python
@click.option("--smart-dedup", is_flag=True, help="Use smart URL deduplication")
@click.option("--similarity-threshold", type=float, default=0.8, help="URL similarity threshold")
@click.option("--categorize-params", is_flag=True, help="Categorize URLs by parameter types")
@click.option("--max-urls-per-pattern", type=int, help="Limit URLs per pattern type")
```

---

## 📱 **7. Real-time Notifications & Webhooks**
**Complexity**: Low | **Value**: Medium | **Timeline**: 1 week

### Implementation:

```python
import asyncio
import aiohttp
from typing import Union

class NotificationManager:
    def __init__(self):
        self.webhooks = []
        self.notification_queue = asyncio.Queue()
    
    def add_webhook(self, url: str, service: str = "generic"):
        self.webhooks.append({"url": url, "service": service})
    
    async def send_notification(self, message: str, severity: str = "info", 
                              attachment: Optional[str] = None):
        """Send notification to all configured webhooks"""
        notification = {
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "attachment": attachment
        }
        
        await self.notification_queue.put(notification)
    
    async def process_notifications(self):
        """Process notification queue asynchronously"""
        while True:
            try:
                notification = await self.notification_queue.get()
                await self._send_to_webhooks(notification)
                self.notification_queue.task_done()
            except Exception as e:
                click.echo(f"⚠️ Notification error: {e}")
    
    async def _send_to_webhooks(self, notification: Dict):
        """Send notification to all webhooks"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for webhook in self.webhooks:
                task = self._send_webhook(session, webhook, notification)
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_webhook(self, session: aiohttp.ClientSession, 
                           webhook: Dict, notification: Dict):
        """Send individual webhook"""
        try:
            payload = self._format_payload(webhook["service"], notification)
            
            async with session.post(
                webhook["url"], 
                json=payload, 
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return True
                    
        except Exception as e:
            click.echo(f"⚠️ Webhook failed {webhook['url']}: {e}")
            return False
    
    def _format_payload(self, service: str, notification: Dict) -> Dict:
        """Format payload for different services"""
        message = notification["message"]
        severity = notification["severity"]
        
        # Severity emojis
        emoji_map = {
            "critical": "🚨",
            "high": "⚠️", 
            "medium": "ℹ️",
            "low": "✅",
            "info": "📋"
        }
        
        emoji = emoji_map.get(severity, "📋")
        formatted_message = f"{emoji} {message}"
        
        if service == "slack":
            return {
                "text": formatted_message,
                "attachments": [{
                    "color": self._get_color(severity),
                    "fields": [{
                        "title": "Severity",
                        "value": severity.upper(),
                        "short": True
                    }, {
                        "title": "Timestamp", 
                        "value": notification["timestamp"],
                        "short": True
                    }]
                }] if notification.get("attachment") else []
            }
        elif service == "discord":
            return {
                "content": formatted_message,
                "embeds": [{
                    "title": "VulnCLI Alert",
                    "description": message,
                    "color": int(self._get_color(severity).replace("#", ""), 16),
                    "timestamp": notification["timestamp"]
                }] if notification.get("attachment") else []
            }
        else:  # Generic webhook
            return notification
    
    def _get_color(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            "critical": "#ff0000",
            "high": "#ff6600", 
            "medium": "#ffcc00",
            "low": "#00cc00",
            "info": "#0066cc"
        }
        return colors.get(severity, "#808080")

# Integration with main scanner
async def notify_scan_progress(notification_manager: NotificationManager, 
                             stage: str, progress: int, total: int):
    """Send scan progress notifications"""
    if progress == 0:
        await notification_manager.send_notification(
            f"🎯 Started {stage} stage", "info"
        )
    elif progress == total:
        await notification_manager.send_notification(
            f"✅ Completed {stage} stage - processed {total} items", "info"
        )
    elif progress % 100 == 0:  # Every 100 items
        await notification_manager.send_notification(
            f"📊 {stage} progress: {progress}/{total} ({progress/total*100:.1f}%)", "info"
        )

async def notify_critical_finding(notification_manager: NotificationManager, 
                                 vulnerability: VulnerabilityRisk):
    """Send immediate notification for critical findings"""
    if vulnerability.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
        await notification_manager.send_notification(
            f"🚨 {vulnerability.severity.name} vulnerability found: {vulnerability.type} "
            f"(Risk Score: {vulnerability.risk_score:.1f}/10)",
            severity=vulnerability.severity.name.lower()
        )
```

### New CLI Options:
```python
@click.option("--notify-progress", is_flag=True, help="Send progress notifications")
@click.option("--notify-critical-only", is_flag=True, help="Only notify for critical/high findings")
@click.option("--notification-interval", type=int, default=100, help="Progress notification interval")
@click.option("--webhook-timeout", type=int, default=10, help="Webhook timeout in seconds")
```

---

## 🎯 **Implementation Priority Ranking**

| Feature | Complexity | Business Value | User Demand | Implementation Order |
|---------|------------|----------------|-------------|---------------------|
| Enhanced Risk Scoring | Low | High | High | **1st** |
| Smart URL Filtering | Low | Medium | High | **2nd** |
| Resume Enhancement | Low | Medium | Medium | **3rd** |
| Advanced Reporting | Low | High | Medium | **4th** |
| YAML Pipeline Config | Medium | High | High | **5th** |
| Additional Tools | Medium | Medium | High | **6th** |
| Real-time Notifications | Low | Medium | Low | **7th** |

---

## 🔧 **Quick Implementation Guide**

### Step 1: Risk Scoring (Week 1)
1. Add `VulnerabilityRisk` dataclass
2. Implement `calculate_risk_score()` function
3. Add CLI options: `--risk-scoring`, `--cvss-lookup`
4. Integrate with existing Nuclei output parsing

### Step 2: Smart Filtering (Week 2) 
1. Add `smart_url_deduplication()` function
2. Implement `intelligent_parameter_extraction()`
3. Add CLI options: `--smart-dedup`, `--categorize-params`
4. Integrate with existing URL processing

### Step 3: Enhanced Reports (Week 3)
1. Add visualization functions (optional matplotlib)
2. Implement HTML dashboard generation
3. Add CLI options: `--generate-heatmap`, `--executive-dashboard`
4. Enhance existing markdown reports

### Next Steps: Continue with pipeline configuration and additional tools based on user feedback and requirements.

---

*Ready for immediate implementation - all features designed to integrate with existing codebase with minimal changes.*
