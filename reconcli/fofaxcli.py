#!/usr/bin/env python3
"""
FOFA CLI - Advanced Python implementation of FOFA search tool

A command-line interface for querying FOFA search engine with AI, caching, and database features.
This module provides comprehensive FOFA API integration with advanced features including:

- Intelligent query enhancement with fuzzy matching and smart context
- High-performance caching system with TTL management
- Database storage for persistent result management
- AI-powered query optimization and result analysis
- Multi-tool chaining with httpx, nuclei, kscan, and uncover
- FX rules system for cybersecurity pattern discovery
- Certificate and icon hash calculations for fingerprinting
- Rich terminal output with progress tracking and statistics

Author: ReconCLI Team
Version: 2.0.0
License: MIT

Example Usage:
    Basic search:
        reconcli fofacli search --query "apache" --fetch-size 100

    Enhanced search with AI and caching:
        reconcli fofacli advanced-search --query "jenkins" --ai --cache --store-db

    Tool chaining workflow:
        reconcli fofacli chain --query "gitlab" --httpx --nuclei --fuzzy

    FX rules for cybersecurity patterns:
        reconcli fofacli fx search "jenkins-unauth" --fetch-size 50
"""

import json
import base64
import hashlib
import requests
import click
import sys
import os
import yaml
import sqlite3
import threading
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
import ssl
import socket
from datetime import datetime, timedelta
import webbrowser
import time
import concurrent.futures

console = Console()


@dataclass
class FOFAConfig:
    """FOFA configuration dataclass

    Stores configuration parameters for FOFA API client including authentication,
    caching, database, and AI features.

    Attributes:
        email: FOFA account email address
        key: FOFA API key
        fofa_url: FOFA base URL (default: https://fofa.info)
        proxy: HTTP/HTTPS proxy URL (optional)
        debug: Enable debug logging
        cache_enabled: Enable result caching
        cache_ttl: Cache time-to-live in seconds
        ai_enabled: Enable AI-powered features
        ai_model: AI model to use for analysis
        db_enabled: Enable database storage
        db_path: SQLite database file path
    """

    email: str = ""
    key: str = ""
    fofa_url: str = "https://fofa.info"
    proxy: Optional[str] = None
    debug: bool = False
    cache_enabled: bool = True
    cache_ttl: int = 3600  # 1 hour
    ai_enabled: bool = False
    ai_model: str = "gpt-3.5-turbo"
    db_enabled: bool = False
    db_path: str = "~/.config/fofax/fofax.db"


@dataclass
class FOFAResult:
    """FOFA search result dataclass

    Represents a single result from FOFA search API with all available fields.

    Attributes:
        protocol: Service protocol (http, https, ftp, etc.)
        ip: IP address of the target
        port: Port number
        host: Hostname or domain
        title: HTTP page title
        domain: Domain name
        server: Server software banner
        country: Country code/name
        city: City name
        lastupdatetime: Last update timestamp
    """

    protocol: str = ""
    ip: str = ""
    port: str = ""
    host: str = ""
    title: str = ""
    domain: str = ""
    server: str = ""
    country: str = ""
    city: str = ""
    lastupdatetime: str = ""


class CacheEntry:
    """Cache entry with TTL"""

    def __init__(self, data: Any, timestamp: datetime, ttl: int):
        self.data = data
        self.timestamp = timestamp
        self.ttl = ttl

    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        return datetime.now() > (self.timestamp + timedelta(seconds=self.ttl))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "ttl": self.ttl,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary for JSON deserialization"""
        return cls(
            data=data["data"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            ttl=data["ttl"],
        )


class FOFACacheManager:
    """Advanced cache manager for FOFA results"""

    def __init__(self, cache_dir: str = "~/.cache/fofax"):
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cache.json"
        self.cache = self._load_cache()
        self._lock = threading.Lock()

    def _load_cache(self) -> Dict[str, CacheEntry]:
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                    return {k: CacheEntry.from_dict(v) for k, v in cache_data.items()}
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to load cache: {e}[/yellow]")
        return {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            cache_data = {k: v.to_dict() for k, v in self.cache.items()}
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to save cache: {e}[/yellow]")

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                if not entry.is_expired():
                    return entry.data
                else:
                    del self.cache[key]
        return None

    def set(self, key: str, data: Any, ttl: int = 3600):
        """Set item in cache"""
        with self._lock:
            self.cache[key] = CacheEntry(data=data, timestamp=datetime.now(), ttl=ttl)
            self._save_cache()

    def clear(self):
        """Clear all cache"""
        with self._lock:
            self.cache.clear()
            self._save_cache()

    def cleanup(self):
        """Remove expired entries"""
        with self._lock:
            expired_keys = [k for k, v in self.cache.items() if v.is_expired()]
            for key in expired_keys:
                del self.cache[key]
            if expired_keys:
                self._save_cache()

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = len(self.cache)
        expired = sum(1 for v in self.cache.values() if v.is_expired())
        size = self.cache_file.stat().st_size if self.cache_file.exists() else 0

        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "cache_size_bytes": size,
            "cache_file": str(self.cache_file),
        }


class FOFADatabaseManager:
    """Database manager for persistent storage of FOFA results"""

    def __init__(self, db_path: str = "~/.config/fofax/fofax.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fofa_searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_results INTEGER NOT NULL,
                    search_params TEXT NOT NULL
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fofa_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL,
                    protocol TEXT,
                    ip TEXT,
                    port TEXT,
                    host TEXT,
                    title TEXT,
                    domain TEXT,
                    server TEXT,
                    country TEXT,
                    city TEXT,
                    lastupdatetime TEXT,
                    raw_data TEXT,
                    FOREIGN KEY (search_id) REFERENCES fofa_searches (id)
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fofa_results_ip ON fofa_results(ip)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fofa_results_domain ON fofa_results(domain)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fofa_searches_query ON fofa_searches(query)
            """
            )

    def store_search(
        self, query: str, results: List[FOFAResult], search_params: Dict[str, Any]
    ) -> int:
        """Store search results in database

        Args:
            query: The FOFA search query
            results: List of FOFA search results
            search_params: Additional search parameters

        Returns:
            Database ID of the stored search

        Raises:
            sqlite3.Error: If database operation fails
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Insert search record
            cursor.execute(
                """
                INSERT INTO fofa_searches (query, timestamp, total_results, search_params)
                VALUES (?, ?, ?, ?)
            """,
                (
                    query,
                    datetime.now().isoformat(),
                    len(results),
                    json.dumps(search_params),
                ),
            )

            search_id = cursor.lastrowid
            if search_id is None:
                raise sqlite3.Error("Failed to get search ID from database")

            # Insert results
            for result in results:
                cursor.execute(
                    """
                    INSERT INTO fofa_results (
                        search_id, protocol, ip, port, host, title, domain,
                        server, country, city, lastupdatetime, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        search_id,
                        result.protocol,
                        result.ip,
                        result.port,
                        result.host,
                        result.title,
                        result.domain,
                        result.server,
                        result.country,
                        result.city,
                        result.lastupdatetime,
                        json.dumps(asdict(result)),
                    ),
                )

            return search_id

    def get_searches(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent searches"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, query, timestamp, total_results, search_params
                FROM fofa_searches
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (limit,),
            )

            return [
                {
                    "id": row[0],
                    "query": row[1],
                    "timestamp": row[2],
                    "total_results": row[3],
                    "search_params": json.loads(row[4]),
                }
                for row in cursor.fetchall()
            ]

    def get_results(self, search_id: int) -> List[FOFAResult]:
        """Get results for a specific search"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT protocol, ip, port, host, title, domain, server, country, city, lastupdatetime
                FROM fofa_results
                WHERE search_id = ?
            """,
                (search_id,),
            )

            return [
                FOFAResult(
                    protocol=row[0] or "",
                    ip=row[1] or "",
                    port=row[2] or "",
                    host=row[3] or "",
                    title=row[4] or "",
                    domain=row[5] or "",
                    server=row[6] or "",
                    country=row[7] or "",
                    city=row[8] or "",
                    lastupdatetime=row[9] or "",
                )
                for row in cursor.fetchall()
            ]

    def search_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Search stored results by IP"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT r.*, s.query, s.timestamp
                FROM fofa_results r
                JOIN fofa_searches s ON r.search_id = s.id
                WHERE r.ip = ?
                ORDER BY s.timestamp DESC
            """,
                (ip,),
            )

            return [
                dict(zip([d[0] for d in cursor.description], row))
                for row in cursor.fetchall()
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM fofa_searches")
            total_searches = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM fofa_results")
            total_results = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT ip) FROM fofa_results")
            unique_ips = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(DISTINCT domain) FROM fofa_results WHERE domain != ''"
            )
            unique_domains = cursor.fetchone()[0]

            file_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            return {
                "total_searches": total_searches,
                "total_results": total_results,
                "unique_ips": unique_ips,
                "unique_domains": unique_domains,
                "db_size_bytes": file_size,
                "db_path": str(self.db_path),
            }


class FOFAAIAssistant:
    """AI assistant for FOFA query optimization and result analysis

    Provides intelligent query enhancement and result analysis using OpenAI's API.
    Gracefully handles missing dependencies and provides fallback behavior.

    Attributes:
        model: The AI model to use (default: gpt-3.5-turbo)
        enabled: Whether AI features are available
        client: OpenAI client instance if available
    """

    def __init__(self, model: str = "gpt-3.5-turbo"):
        """Initialize AI assistant

        Args:
            model: OpenAI model to use for analysis
        """
        self.model = model
        self.enabled = False
        self.client = None

        try:
            import openai

            self.client = openai.OpenAI()
            self.enabled = True
        except ImportError:
            console.print(
                "[yellow]OpenAI library not available. AI features disabled.[/yellow]"
            )
            console.print("[dim]Install with: pip install openai[/dim]")
        except Exception as e:
            console.print(f"[yellow]Failed to initialize OpenAI client: {e}[/yellow]")

    def optimize_query(self, user_query: str) -> str:
        """Optimize user query for better FOFA results

        Args:
            user_query: Original FOFA query string

        Returns:
            Optimized query string (original if AI unavailable)
        """
        if not self.enabled or not self.client:
            return user_query

        prompt = f"""
        You are a FOFA search expert. Optimize the following query for better cybersecurity reconnaissance results.
        
        Original query: "{user_query}"
        
        Provide an optimized FOFA query using FOFA syntax. Consider:
        - Common ports and services
        - Country/region filters if relevant
        - Protocol specifications
        - Banner/title patterns
        - Certificate information
        
        Return only the optimized query, no explanation.
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150,
                temperature=0.1,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            console.print(f"[yellow]AI optimization failed: {e}[/yellow]")
            return user_query

    def analyze_results(self, results: List[FOFAResult]) -> Dict[str, Any]:
        """Analyze FOFA results and provide insights

        Args:
            results: List of FOFA search results

        Returns:
            Dictionary containing analysis summary and AI insights
        """
        if not self.enabled or not results or not self.client:
            return {}

        # Prepare summary data
        countries = [r.country for r in results if r.country]
        servers = [r.server for r in results if r.server]
        ports = [r.port for r in results if r.port]

        summary = {
            "total_results": len(results),
            "unique_countries": len(set(countries)),
            "top_countries": list(dict.fromkeys(countries))[:5],
            "unique_servers": len(set(servers)),
            "top_servers": list(dict.fromkeys(servers))[:5],
            "unique_ports": len(set(ports)),
            "top_ports": list(dict.fromkeys(ports))[:10],
        }

        prompt = f"""
        Analyze these FOFA search results and provide cybersecurity insights:
        
        Results Summary:
        - Total results: {summary['total_results']}
        - Countries: {summary['top_countries']}
        - Servers: {summary['top_servers']}
        - Ports: {summary['top_ports']}
        
        Provide insights about:
        1. Security implications
        2. Common vulnerabilities to check
        3. Geographic distribution analysis
        4. Service/technology risks
        
        Keep response concise and actionable.
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3,
            )

            return {
                "summary": summary,
                "ai_insights": response.choices[0].message.content.strip(),
            }
        except Exception as e:
            console.print(f"[yellow]AI analysis failed: {e}[/yellow]")
            return {"summary": summary}


class FOFAQueryEnhancer:
    """Enhanced query processor for fuzzy and smart searching"""

    def __init__(self):
        # Common technology variations and fuzzy keywords
        self.tech_mappings = {
            "jenkins": [
                "jenkins",
                "Hudson",
                "build",
                "ci/cd",
                "continuous integration",
            ],
            "jira": [
                "jira",
                "atlassian",
                "issue tracker",
                "bug tracker",
                "project management",
            ],
            "gitlab": ["gitlab", "git", "repository", "source code", "version control"],
            "grafana": [
                "grafana",
                "monitoring",
                "dashboard",
                "metrics",
                "observability",
            ],
            "kibana": [
                "kibana",
                "elastic",
                "elasticsearch",
                "log analysis",
                "ELK stack",
            ],
            "wordpress": ["wordpress", "wp-admin", "wp-content", "blog", "cms"],
            "drupal": ["drupal", "cms", "content management"],
            "phpmyadmin": ["phpmyadmin", "pma", "mysql admin", "database admin"],
            "tomcat": ["tomcat", "apache tomcat", "java servlet"],
            "apache": ["apache", "httpd", "web server"],
            "nginx": ["nginx", "web server", "reverse proxy"],
            "iis": ["iis", "microsoft-iis", "windows server"],
            "docker": ["docker", "container", "dockerd"],
            "kubernetes": ["kubernetes", "k8s", "container orchestration"],
            "redis": ["redis", "cache", "in-memory database"],
            "mongodb": ["mongodb", "mongo", "nosql", "document database"],
            "elasticsearch": ["elasticsearch", "elastic", "search engine"],
            "mysql": ["mysql", "mariadb", "database"],
            "postgresql": ["postgresql", "postgres", "database"],
            "oracle": ["oracle", "database"],
            "mssql": ["mssql", "microsoft sql", "sql server"],
            "ftp": ["ftp", "file transfer", "vsftpd"],
            "ssh": ["ssh", "openssh", "secure shell"],
            "vnc": ["vnc", "remote desktop", "tightvnc"],
            "rdp": ["rdp", "remote desktop", "terminal services"],
            "smtp": ["smtp", "mail server", "email"],
            "pop3": ["pop3", "mail", "email"],
            "imap": ["imap", "mail", "email"],
            "dns": ["dns", "bind", "domain name"],
            "snmp": ["snmp", "network management"],
            "telnet": ["telnet", "remote access"],
            "camera": ["camera", "webcam", "ip camera", "surveillance", "cctv"],
            "printer": ["printer", "print server", "cups"],
            "router": ["router", "gateway", "networking"],
            "switch": ["switch", "networking", "managed switch"],
            "firewall": ["firewall", "security appliance", "pfsense"],
        }

        # Common vulnerability patterns
        self.vuln_patterns = {
            "unauth": [
                'title="login"',
                'title="sign in"',
                'title="authentication"',
                'body="password"',
            ],
            "admin": [
                'title="admin"',
                'title="administrator"',
                'body="admin panel"',
                'path="/admin"',
            ],
            "default": [
                'title="welcome"',
                'title="default"',
                'body="default password"',
            ],
            "exposed": [
                'title="index of"',
                'title="directory listing"',
                'body="parent directory"',
            ],
            "config": ['title="configuration"', 'body="config"', 'path="/config"'],
            "debug": ['title="debug"', 'body="debug mode"', 'body="error"'],
            "test": ['title="test"', 'body="test page"', 'path="/test"'],
            "backup": ['title="backup"', 'body="backup"', 'path="/backup"'],
        }

        # Port mappings for services
        self.port_mappings = {
            "web": ["80", "443", "8080", "8443", "8000", "8888", "9000"],
            "ssh": ["22"],
            "ftp": ["21"],
            "telnet": ["23"],
            "smtp": ["25", "587"],
            "dns": ["53"],
            "pop3": ["110", "995"],
            "imap": ["143", "993"],
            "snmp": ["161"],
            "ldap": ["389", "636"],
            "mysql": ["3306"],
            "postgresql": ["5432"],
            "redis": ["6379"],
            "mongodb": ["27017"],
            "elasticsearch": ["9200"],
            "vnc": ["5900", "5901"],
            "rdp": ["3389"],
            "docker": ["2375", "2376"],
            "kubernetes": ["6443", "8080"],
        }

    def enhance_query_fuzzy(self, query: str) -> str:
        """Apply fuzzy keyword expansion to query"""
        enhanced_parts = []

        # Split query into parts and check each word
        words = query.lower().split()

        for word in words:
            # Remove FOFA operators to get clean keywords
            clean_word = word.strip('()&|!"=')

            # Check if word matches any technology
            fuzzy_terms = []
            for tech, variants in self.tech_mappings.items():
                if clean_word in tech or tech in clean_word:
                    fuzzy_terms.extend(variants[:3])  # Add top 3 variants
                    break

            if fuzzy_terms:
                # Create OR condition with fuzzy terms
                fuzzy_query = " || ".join(
                    [f'title="{term}"' for term in fuzzy_terms[:2]]
                )
                fuzzy_query += " || " + " || ".join(
                    [f'body="{term}"' for term in fuzzy_terms[:2]]
                )
                enhanced_parts.append(f"({fuzzy_query})")
            else:
                enhanced_parts.append(word)

        return " && ".join(enhanced_parts) if enhanced_parts else query

    def enhance_query_smart(self, query: str) -> str:
        """Apply smart query enhancement with context"""
        enhanced_query = query

        # Detect query type and add smart enhancements
        query_lower = query.lower()

        # Technology-specific enhancements
        for tech, variants in self.tech_mappings.items():
            if tech in query_lower:
                # Add common ports for the technology
                if tech in self.port_mappings:
                    ports = self.port_mappings.get(tech, [])
                    if ports:
                        port_filter = " || ".join(
                            [f'port="{port}"' for port in ports[:3]]
                        )
                        enhanced_query += f" && ({port_filter})"

                # Add vulnerability patterns
                if tech in ["jenkins", "jira", "gitlab", "grafana"]:
                    vuln_filter = " || ".join(self.vuln_patterns["unauth"][:2])
                    enhanced_query += f" && ({vuln_filter})"
                break

        # Add common exclusions for noise reduction
        exclusions = [
            'country!="CN"',  # Often requested
            "is_honeypot=false",  # Reduce false positives
        ]

        # Check if exclusions are not already in query
        for exclusion in exclusions:
            if exclusion not in enhanced_query:
                enhanced_query += f" && {exclusion}"

        return enhanced_query

    def suggest_related_queries(self, query: str) -> List[str]:
        """Suggest related queries based on the original"""
        suggestions = []
        query_lower = query.lower()

        # Technology-based suggestions
        for tech, variants in self.tech_mappings.items():
            if tech in query_lower:
                # Suggest vulnerability-focused variants
                suggestions.append(f'app="{tech.upper()}" && title="login"')
                suggestions.append(f'title="{tech}" && country="US"')
                suggestions.append(f'body="{tech}" && port="443"')

                # Suggest related technologies
                related_tech = {
                    "jenkins": ["gitlab", "jira"],
                    "jira": ["confluence", "bitbucket"],
                    "gitlab": ["jenkins", "github"],
                    "grafana": ["kibana", "prometheus"],
                    "kibana": ["elasticsearch", "grafana"],
                }.get(tech, [])

                for related in related_tech:
                    suggestions.append(f'title="{related}"')
                break

        return suggestions[:5]  # Return top 5 suggestions


class ToolChainManager:
    """Manager for chaining tools like httpx, nuclei, kscan"""

    def __init__(self, working_dir: Optional[str] = None):
        if working_dir is None:
            # Use secure temporary directory
            self.working_dir = Path(tempfile.mkdtemp(prefix="fofax_chain_"))
        else:
            self.working_dir = Path(working_dir)
        self.working_dir.mkdir(parents=True, exist_ok=True)
        self.results_file = self.working_dir / "fofa_results.txt"

    def _validate_command_args(self, cmd: List[str]) -> bool:
        """Validate command arguments for security"""
        if not cmd or not isinstance(cmd, list):
            return False

        # Check for dangerous patterns
        dangerous_patterns = [";", "&&", "||", "`", "$", ">", "<", "|"]
        for arg in cmd:
            if any(pattern in str(arg) for pattern in dangerous_patterns):
                console.print(
                    f"[red]⚠️  Dangerous pattern detected in command: {arg}[/red]"
                )
                return False

        return True

    def save_targets(self, results: List[FOFAResult], format_type: str = "url") -> str:
        """Save FOFA results as targets for other tools"""
        targets = []

        for result in results:
            if format_type == "url":
                # Create full URLs
                protocol = result.protocol if result.protocol else "http"
                host = result.host if result.host else result.ip
                port = result.port

                if port and port not in ["80", "443"]:
                    url = f"{protocol}://{host}:{port}"
                else:
                    url = f"{protocol}://{host}"
                targets.append(url)

            elif format_type == "ip":
                if result.ip:
                    targets.append(result.ip)

            elif format_type == "ip_port":
                if result.ip and result.port:
                    targets.append(f"{result.ip}:{result.port}")
                elif result.ip:
                    targets.append(result.ip)

        # Remove duplicates while preserving order
        unique_targets = list(dict.fromkeys(targets))

        with open(self.results_file, "w") as f:
            for target in unique_targets:
                f.write(f"{target}\n")

        return str(self.results_file)

    def run_httpx(self, targets_file: str, options: Optional[List[str]] = None) -> str:
        """Run httpx on targets"""
        if not options:
            options = ["-title", "-tech-detect", "-status-code", "-content-length"]

        output_file = self.working_dir / "httpx_results.json"
        cmd = ["httpx", "-l", targets_file, "-o", str(output_file), "-json"] + options

        # Validate command arguments for security
        if not self._validate_command_args(cmd):
            console.print("[red]❌ Invalid command arguments detected[/red]")
            return ""

        console.print(f"[cyan]Running httpx:[/cyan] {' '.join(cmd)}")

        try:
            # subprocess.run with validated arguments - safe from injection
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )  # nosec B603
            if result.returncode == 0:
                console.print(
                    f"[green]✅ httpx completed. Results saved to: {output_file}[/green]"
                )
                return str(output_file)
            else:
                console.print(f"[red]❌ httpx failed: {result.stderr}[/red]")
                return ""
        except subprocess.TimeoutExpired:
            console.print("[red]❌ httpx timed out[/red]")
            return ""
        except FileNotFoundError:
            console.print(
                "[red]❌ httpx not found. Please install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest[/red]"
            )
            return ""

    def run_nuclei(self, targets_file: str, options: Optional[List[str]] = None) -> str:
        """Run nuclei on targets"""
        if not options:
            options = ["-severity", "medium,high,critical", "-silent"]

        output_file = self.working_dir / "nuclei_results.jsonl"
        cmd = ["nuclei", "-l", targets_file, "-o", str(output_file), "-jsonl"] + options

        # Validate command arguments for security
        if not self._validate_command_args(cmd):
            console.print("[red]❌ Invalid command arguments detected[/red]")
            return ""

        console.print(f"[cyan]Running nuclei:[/cyan] {' '.join(cmd)}")

        try:
            # subprocess.run with validated arguments - safe from injection
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1200
            )  # nosec B603
            if result.returncode == 0:
                console.print(
                    f"[green]✅ nuclei completed. Results saved to: {output_file}[/green]"
                )
                return str(output_file)
            else:
                console.print(f"[red]❌ nuclei failed: {result.stderr}[/red]")
                return ""
        except subprocess.TimeoutExpired:
            console.print("[red]❌ nuclei timed out[/red]")
            return ""
        except FileNotFoundError:
            console.print(
                "[red]❌ nuclei not found. Please install nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/red]"
            )
            return ""

    def run_kscan(self, targets_file: str, options: Optional[List[str]] = None) -> str:
        """Run kscan on targets"""
        if not options:
            options = ["--check", "--hydra"]

        output_file = self.working_dir / "kscan_results.json"
        cmd = ["kscan", "-t", f"file:{targets_file}", "-oJ", str(output_file)] + options

        # Validate command arguments for security
        if not self._validate_command_args(cmd):
            console.print("[red]❌ Invalid command arguments detected[/red]")
            return ""

        console.print(f"[cyan]Running kscan:[/cyan] {' '.join(cmd)}")

        try:
            # subprocess.run with validated arguments - safe from injection
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )  # nosec B603
            if result.returncode == 0:
                console.print(
                    f"[green]✅ kscan completed. Results saved to: {output_file}[/green]"
                )
                return str(output_file)
            else:
                console.print(f"[red]❌ kscan failed: {result.stderr}[/red]")
                return ""
        except subprocess.TimeoutExpired:
            console.print("[red]❌ kscan timed out[/red]")
            return ""
        except FileNotFoundError:
            console.print(
                "[red]❌ kscan not found. Please install kscan from: https://github.com/lcvvvv/kscan[/red]"
            )
            return ""

    def run_uncover(self, query: str, options: Optional[List[str]] = None) -> str:
        """Run uncover for multi-engine search"""
        if not options:
            options = [
                "-e",
                "shodan,censys,fofa,quake,hunter,zoomeye,netlas,criminalip",
                "-limit",
                "200",
            ]

        output_file = self.working_dir / "uncover_results.txt"
        cmd = ["uncover", "-q", query, "-o", str(output_file)] + options

        # Validate command arguments for security
        if not self._validate_command_args(cmd):
            console.print("[red]❌ Invalid command arguments detected[/red]")
            return ""

        console.print(f"[cyan]Running uncover:[/cyan] {' '.join(cmd)}")

        try:
            # subprocess.run with validated arguments - safe from injection
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )  # nosec B603
            if result.returncode == 0:
                console.print(
                    f"[green]✅ uncover completed. Results saved to: {output_file}[/green]"
                )
                return str(output_file)
            else:
                console.print(f"[red]❌ uncover failed: {result.stderr}[/red]")
                return ""
        except subprocess.TimeoutExpired:
            console.print("[red]❌ uncover timed out[/red]")
            return ""
        except FileNotFoundError:
            console.print(
                "[red]❌ uncover not found. Please install uncover: go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest[/red]"
            )
            return ""

    def parse_httpx_results(self, results_file: str) -> List[Dict]:
        """Parse httpx JSON results"""
        results = []
        try:
            with open(results_file, "r") as f:
                for line in f:
                    if line.strip():
                        results.append(json.loads(line.strip()))
            return results
        except Exception as e:
            console.print(f"[red]❌ Error parsing httpx results: {e}[/red]")
            return []

    def parse_nuclei_results(self, results_file: str) -> List[Dict]:
        """Parse nuclei JSON results"""
        results = []
        try:
            with open(results_file, "r") as f:
                for line in f:
                    if line.strip():
                        results.append(json.loads(line.strip()))
            return results
        except Exception as e:
            console.print(f"[red]❌ Error parsing nuclei results: {e}[/red]")
            return []

    def parse_kscan_results(self, results_file: str) -> List[Dict]:
        """Parse kscan JSON results"""
        results = []
        try:
            with open(results_file, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    results = data
                elif isinstance(data, dict) and "results" in data:
                    results = data["results"]
            return results
        except Exception as e:
            console.print(f"[red]❌ Error parsing kscan results: {e}[/red]")
            return []

    def parse_uncover_results(self, results_file: str) -> List[Dict]:
        """Parse uncover results (ip:port format)"""
        results = []
        try:
            with open(results_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("["):  # Skip log lines
                        if ":" in line:
                            ip, port = line.split(":", 1)
                            results.append(
                                {
                                    "ip": ip.strip(),
                                    "port": port.strip(),
                                    "host": line.strip(),
                                    "source": "uncover",
                                }
                            )
                        else:
                            results.append(
                                {
                                    "ip": line.strip(),
                                    "port": "",
                                    "host": line.strip(),
                                    "source": "uncover",
                                }
                            )
            return results
        except Exception as e:
            console.print(f"[red]❌ Error parsing uncover results: {e}[/red]")
            return []


class FOFAClient:
    """FOFA API client with advanced features"""

    def __init__(self, config: FOFAConfig):
        self.config = config
        self.session = requests.Session()
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

        # Set user agent
        self.session.headers.update({"User-Agent": "fofaxcli/2.0.0 (Python)"})

        # Initialize advanced features
        self.cache_manager = FOFACacheManager() if config.cache_enabled else None
        self.db_manager = (
            FOFADatabaseManager(config.db_path) if config.db_enabled else None
        )
        self.ai_assistant = (
            FOFAAIAssistant(config.ai_model) if config.ai_enabled else None
        )

    def _debug_print(self, message: str):
        """Print debug message if debug mode is enabled"""
        if self.config.debug:
            console.print(f"[dim][DEBUG][/dim] {message}")

    def _encode_query(self, query: str) -> str:
        """Encode query to base64"""
        return base64.b64encode(query.encode()).decode()

    def search(
        self,
        query: str,
        size: int = 100,
        page: int = 1,
        fields: str = "protocol,ip,port,host,title,domain,server,country,city",
        use_cache: bool = True,
        store_db: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Execute FOFA search with caching and database storage

        Args:
            query: FOFA search query string
            size: Maximum number of results to fetch (1-10000)
            page: Page number for pagination (1-based)
            fields: Comma-separated list of fields to fetch
            use_cache: Whether to use cached results if available
            store_db: Whether to store results in database (None = use config)

        Returns:
            Dictionary containing search results and metadata

        Raises:
            ValueError: If credentials are missing or invalid parameters
            Exception: If FOFA API request fails
        """

        # Validate inputs
        if not self.config.email or not self.config.key:
            raise ValueError(
                "FOFA email and key are required. Please configure them first."
            )

        if not query or not query.strip():
            raise ValueError("Query cannot be empty")

        if not (1 <= size <= 10000):
            raise ValueError("Size must be between 1 and 10000")

        if page < 1:
            raise ValueError("Page must be >= 1")

        # AI query optimization
        original_query = query
        if self.ai_assistant:
            optimized_query = self.ai_assistant.optimize_query(query)
            if optimized_query != query:
                console.print(f"[cyan]AI optimized query:[/cyan] {optimized_query}")
                query = optimized_query

        # Check cache first
        cache_key = f"search:{hashlib.md5(f'{query}:{size}:{page}:{fields}'.encode(), usedforsecurity=False).hexdigest()}"
        if use_cache and self.cache_manager:
            cached_result = self.cache_manager.get(cache_key)
            if cached_result:
                console.print("[green]✓[/green] Using cached results")
                return cached_result

        encoded_query = self._encode_query(query)

        # Build API URL
        api_url = f"{self.config.fofa_url}/api/v1/search/all"

        params = {
            "email": self.config.email,
            "key": self.config.key,
            "qbase64": encoded_query,
            "size": size,
            "page": page,
            "fields": fields,
        }

        self._debug_print(f"FOFA Query: {query}")
        self._debug_print(f"API URL: {api_url}")
        self._debug_print(f"Encoded Query: {encoded_query}")

        start_time = time.time()

        try:
            response = self.session.get(api_url, params=params, timeout=30)
            response.raise_for_status()

            end_time = time.time()
            self._debug_print(
                f"Response Time: {int((end_time - start_time) * 1000)}/millis"
            )

            result = response.json()

            # Check for API errors
            if result.get("error"):
                raise Exception(
                    f"FOFA API Error: {result.get('errmsg', 'Unknown error')}"
                )

            # Store in cache
            if use_cache and self.cache_manager:
                self.cache_manager.set(cache_key, result, self.config.cache_ttl)

            # Store in database
            if (
                store_db or (store_db is None and self.config.db_enabled)
            ) and self.db_manager:
                if "results" in result and result["results"]:
                    # Convert results to FOFAResult objects
                    fofa_results = []
                    for item in result["results"]:
                        fofa_result = FOFAResult()
                        if len(item) > 0:
                            fofa_result.protocol = str(item[0]) if item[0] else ""
                        if len(item) > 1:
                            fofa_result.ip = str(item[1]) if item[1] else ""
                        if len(item) > 2:
                            fofa_result.port = str(item[2]) if item[2] else ""
                        if len(item) > 3:
                            fofa_result.host = str(item[3]) if item[3] else ""
                        if len(item) > 4:
                            fofa_result.title = str(item[4]) if item[4] else ""
                        if len(item) > 5:
                            fofa_result.domain = str(item[5]) if item[5] else ""
                        if len(item) > 6:
                            fofa_result.server = str(item[6]) if item[6] else ""
                        if len(item) > 7:
                            fofa_result.country = str(item[7]) if item[7] else ""
                        if len(item) > 8:
                            fofa_result.city = str(item[8]) if item[8] else ""
                        fofa_results.append(fofa_result)

                    search_params = {
                        "size": size,
                        "page": page,
                        "fields": fields,
                        "original_query": original_query,
                    }
                    self.db_manager.store_search(query, fofa_results, search_params)
                    console.print(
                        f"[green]✓[/green] Stored {len(fofa_results)} results in database"
                    )

            # AI analysis
            if self.ai_assistant and "results" in result and result["results"]:
                fofa_results = []
                for item in result["results"]:
                    fofa_result = FOFAResult()
                    if len(item) > 0:
                        fofa_result.protocol = str(item[0]) if item[0] else ""
                    if len(item) > 1:
                        fofa_result.ip = str(item[1]) if item[1] else ""
                    if len(item) > 2:
                        fofa_result.port = str(item[2]) if item[2] else ""
                    if len(item) > 3:
                        fofa_result.host = str(item[3]) if item[3] else ""
                    if len(item) > 4:
                        fofa_result.title = str(item[4]) if item[4] else ""
                    if len(item) > 5:
                        fofa_result.domain = str(item[5]) if item[5] else ""
                    if len(item) > 6:
                        fofa_result.server = str(item[6]) if item[6] else ""
                    if len(item) > 7:
                        fofa_result.country = str(item[7]) if item[7] else ""
                    if len(item) > 8:
                        fofa_result.city = str(item[8]) if item[8] else ""
                    fofa_results.append(fofa_result)

                ai_analysis = self.ai_assistant.analyze_results(fofa_results)
                if ai_analysis:
                    result["ai_analysis"] = ai_analysis

            return result

        except requests.exceptions.Timeout:
            raise Exception("FOFA API request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Failed to connect to FOFA API. Check your internet connection."
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise Exception(
                    "FOFA API authentication failed. Check your credentials."
                )
            elif e.response.status_code == 403:
                raise Exception(
                    "FOFA API access forbidden. Check your account permissions."
                )
            elif e.response.status_code == 429:
                raise Exception(
                    "FOFA API rate limit exceeded. Please wait and try again."
                )
            else:
                raise Exception(f"FOFA API HTTP error {e.response.status_code}: {e}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"FOFA API request failed: {str(e)}")

    def get_userinfo(self) -> Dict[str, Any]:
        """Get FOFA user information and account details

        Returns:
            Dictionary containing user account information including:
            - Username and email
            - Remaining query quota
            - Account type and permissions
            - Avatar and other profile data

        Raises:
            ValueError: If credentials are not configured
            Exception: If FOFA API request fails
        """
        if not self.config.email or not self.config.key:
            raise ValueError(
                "FOFA email and key are required. Please configure them first."
            )

        api_url = f"{self.config.fofa_url}/api/v1/info/my"

        params = {"email": self.config.email, "key": self.config.key}

        try:
            response = self.session.get(api_url, params=params, timeout=30)
            response.raise_for_status()

            result = response.json()

            # Check for API errors
            if result.get("error"):
                raise Exception(
                    f"FOFA API Error: {result.get('errmsg', 'Unknown error')}"
                )

            return result

        except requests.exceptions.Timeout:
            raise Exception("FOFA API request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Failed to connect to FOFA API. Check your internet connection."
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise Exception(
                    "FOFA API authentication failed. Check your credentials."
                )
            elif e.response.status_code == 403:
                raise Exception(
                    "FOFA API access forbidden. Check your account permissions."
                )
            else:
                raise Exception(f"FOFA API HTTP error {e.response.status_code}: {e}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get user info: {str(e)}")


class IconHashCalculator:
    """Calculate icon hash for FOFA queries

    Provides methods to calculate FOFA-compatible icon hashes from various sources.
    Icon hashes are used in FOFA queries to find websites with matching favicons.

    The hash algorithm uses MD5 of base64-encoded icon content, which is compatible
    with FOFA's icon_hash search syntax.
    """

    @staticmethod
    def calculate_from_url(url: str) -> str:
        """Calculate icon hash from URL

        Downloads favicon from URL and calculates FOFA-compatible hash.

        Args:
            url: URL to download favicon from

        Returns:
            MD5 hash of base64-encoded icon content

        Raises:
            Exception: If URL fetch fails or invalid content
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            if not response.content:
                raise Exception("Empty response from URL")

            return IconHashCalculator.calculate_from_content(response.content)
        except requests.exceptions.Timeout:
            raise Exception("Request timed out while fetching icon")
        except requests.exceptions.ConnectionError:
            raise Exception("Failed to connect to URL")
        except requests.exceptions.HTTPError as e:
            raise Exception(f"HTTP error {e.response.status_code} while fetching icon")
        except Exception as e:
            raise Exception(f"Failed to fetch icon from URL: {str(e)}")

    @staticmethod
    def calculate_from_file(file_path: str) -> str:
        """Calculate icon hash from local file

        Reads local icon file and calculates FOFA-compatible hash.

        Args:
            file_path: Path to local icon file

        Returns:
            MD5 hash of base64-encoded icon content

        Raises:
            Exception: If file read fails or invalid content
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()

            if not content:
                raise Exception("File is empty")

            return IconHashCalculator.calculate_from_content(content)
        except FileNotFoundError:
            raise Exception(f"Icon file not found: {file_path}")
        except PermissionError:
            raise Exception(f"Permission denied reading file: {file_path}")
        except Exception as e:
            raise Exception(f"Failed to read icon file: {str(e)}")

    @staticmethod
    def calculate_from_content(content: bytes) -> str:
        """Calculate icon hash from content

        Calculates FOFA-compatible icon hash from raw icon bytes.

        Args:
            content: Raw icon file bytes

        Returns:
            MD5 hash of base64-encoded content

        Raises:
            Exception: If content is invalid
        """
        if not content:
            raise Exception("Content cannot be empty")

        # FOFA icon hash algorithm - MD5 used for compatibility with FOFA API, not for security
        try:
            icon_hash = hashlib.md5(
                base64.encodebytes(content), usedforsecurity=False
            ).hexdigest()
            return icon_hash
        except Exception as e:
            raise Exception(f"Failed to calculate hash: {str(e)}")


class CertificateCalculator:
    """Calculate certificate hash for FOFA queries"""

    @staticmethod
    def get_cert_from_url(url: str) -> str:
        """Get certificate from HTTPS URL"""
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(True)
                    if cert_der:
                        # SHA1 used for compatibility with FOFA API, not for security
                        cert_hash = hashlib.sha1(
                            cert_der, usedforsecurity=False
                        ).hexdigest()
                        return cert_hash
                    else:
                        raise Exception("Failed to get certificate")

        except Exception as e:
            raise Exception(f"Failed to get certificate: {str(e)}")


class FOFAConfigManager:
    """Manage FOFA configuration"""

    CONFIG_PATHS = [
        "fofax.yaml",
        os.path.expanduser("~/.config/fofax/fofax.yaml"),
        "/etc/fofax.yaml",
    ]

    @staticmethod
    def get_config_path() -> str:
        """Get configuration file path"""
        for path in FOFAConfigManager.CONFIG_PATHS:
            if os.path.exists(path):
                return path

        # Return default path if none exists
        default_path = os.path.expanduser("~/.config/fofax/fofax.yaml")
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        return default_path

    @staticmethod
    def load_config(config_path: Optional[str] = None) -> FOFAConfig:
        """Load configuration from file"""
        if config_path is None:
            config_path = FOFAConfigManager.get_config_path()

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}

                return FOFAConfig(
                    email=data.get("fofa-email", ""),
                    key=data.get("fofakey", ""),
                    fofa_url=data.get("fofa-url", "https://fofa.info"),
                    proxy=data.get("proxy"),
                    debug=data.get("debug", False),
                    cache_enabled=data.get("cache-enabled", True),
                    cache_ttl=data.get("cache-ttl", 3600),
                    ai_enabled=data.get("ai-enabled", False),
                    ai_model=data.get("ai-model", "gpt-3.5-turbo"),
                    db_enabled=data.get("db-enabled", False),
                    db_path=data.get("db-path", "~/.config/fofax/fofax.db"),
                )
            except yaml.YAMLError as e:
                console.print(f"[red]YAML Error in config file: {str(e)}[/red]")
                console.print(f"[yellow]Creating new config file...[/yellow]")
                FOFAConfigManager.create_default_config(config_path)
                return FOFAConfig()
            except Exception as e:
                console.print(f"[red]Error loading config: {str(e)}[/red]")
                return FOFAConfig()
        else:
            # Create default config file
            FOFAConfigManager.create_default_config(config_path)
            return FOFAConfig()

    @staticmethod
    def create_default_config(config_path: str):
        """Create default configuration file"""
        default_config = {
            "fofa-email": "your-email@example.com",
            "fofakey": "your-fofa-api-key",
            "fofa-url": "https://fofa.info",
            "proxy": None,
            "debug": False,
        }

        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(default_config, f, default_flow_style=False)

        console.print(f"[green]Created default config file: {config_path}[/green]")
        console.print(
            "[yellow]Please edit the config file and add your FOFA email and API key[/yellow]"
        )

    @staticmethod
    def save_config(config: FOFAConfig, config_path: Optional[str] = None):
        """Save configuration to file"""
        if config_path is None:
            config_path = FOFAConfigManager.get_config_path()

        config_data = {
            "fofa-email": config.email,
            "fofakey": config.key,
            "fofa-url": config.fofa_url,
            "proxy": config.proxy,
            "debug": config.debug,
            "cache-enabled": config.cache_enabled,
            "cache-ttl": config.cache_ttl,
            "ai-enabled": config.ai_enabled,
            "ai-model": config.ai_model,
            "db-enabled": config.db_enabled,
            "db-path": config.db_path,
        }

        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, default_flow_style=False)


# FX Rules Manager (simplified version)
class FXRulesManager:
    """Manage FX syntax rules with extended rule set"""

    def __init__(self, rules_dir: Optional[str] = None):
        if rules_dir is None:
            self.rules_dir = os.path.expanduser("~/.config/fofax/fxrules")
        else:
            self.rules_dir = rules_dir

        os.makedirs(self.rules_dir, exist_ok=True)
        self.rules = self._load_builtin_rules()

    def _load_builtin_rules(self) -> Dict[str, Dict]:
        """Load built-in FX rules with extensive collection"""
        builtin_rules = {
            # Original rules
            "google-reverse": {
                "id": "fx-2021-1001",
                "query": "google-reverse",
                "rule_name": "Google反代服务器",
                "rule_english": "Google Reverse proxy",
                "author": "fofa",
                "fofa_query": 'body="var c = Array.prototype.slice.call(arguments, 1);return function() {var d=c.slice();"',
                "tag": ["google"],
                "type": "内置",
                "description": "不用挂代理就可以访问的Google搜索，但搜索记录可能会被记录。",
            },
            "jupyter-unauth": {
                "id": "fx-2021-1012",
                "query": "jupyter-unauth",
                "rule_name": "Jupyter 未授权",
                "rule_english": "Jupyter Unauthorized",
                "author": "xiecat",
                "fofa_query": 'body="ipython-main-app" && title="Home Page - Select or create a notebook"',
                "tag": ["unauth"],
                "type": "内置",
                "description": "Jupyter Notebook未授权访问",
            },
            "python-simplehttp": {
                "id": "fx-2021-1002",
                "query": "python-simplehttp",
                "rule_name": "Python SimpleHTTP",
                "rule_english": "Python SimpleHTTP Server",
                "author": "fofa",
                "fofa_query": 'server="SimpleHTTP" && title="Directory listing"',
                "tag": ["python"],
                "type": "内置",
                "description": "Python SimpleHTTP服务器",
            },
            # Extended cybersecurity rules
            "elastic-unauth": {
                "id": "fx-2025-2001",
                "query": "elastic-unauth",
                "rule_name": "Elasticsearch 未授权访问",
                "rule_english": "Elasticsearch Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'port="9200" && body="cluster_name" && body="elasticsearch"',
                "tag": ["unauth", "database"],
                "type": "内置",
                "description": "Elasticsearch数据库未授权访问漏洞",
            },
            "kibana-unauth": {
                "id": "fx-2025-2002",
                "query": "kibana-unauth",
                "rule_name": "Kibana 未授权访问",
                "rule_english": "Kibana Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'title="Kibana" && body="kibana" && (body="dashboards" || body="dev_tools")',
                "tag": ["unauth", "monitoring"],
                "type": "内置",
                "description": "Kibana仪表板未授权访问",
            },
            "mongodb-unauth": {
                "id": "fx-2025-2003",
                "query": "mongodb-unauth",
                "rule_name": "MongoDB 未授权访问",
                "rule_english": "MongoDB Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'port="27017" && banner="MongoDB"',
                "tag": ["unauth", "database"],
                "type": "内置",
                "description": "MongoDB数据库未授权访问",
            },
            "redis-unauth": {
                "id": "fx-2025-2004",
                "query": "redis-unauth",
                "rule_name": "Redis 未授权访问",
                "rule_english": "Redis Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'port="6379" && banner="redis_version"',
                "tag": ["unauth", "database", "cache"],
                "type": "内置",
                "description": "Redis缓存数据库未授权访问",
            },
            "docker-api": {
                "id": "fx-2025-2005",
                "query": "docker-api",
                "rule_name": "Docker API 未授权",
                "rule_english": "Docker API Exposed",
                "author": "reconCLI",
                "fofa_query": 'port="2375" || port="2376" && body="ApiVersion"',
                "tag": ["unauth", "docker", "api"],
                "type": "内置",
                "description": "Docker API端口暴露，可能存在未授权访问",
            },
            "grafana-unauth": {
                "id": "fx-2025-2006",
                "query": "grafana-unauth",
                "rule_name": "Grafana 未授权访问",
                "rule_english": "Grafana Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'title="Grafana" && body="grafana" && (body="dashboard" || body="login")',
                "tag": ["unauth", "monitoring"],
                "type": "内置",
                "description": "Grafana监控面板未授权访问",
            },
            "jenkins-unauth": {
                "id": "fx-2025-2007",
                "query": "jenkins-unauth",
                "rule_name": "Jenkins 未授权访问",
                "rule_english": "Jenkins Unauthorized Access",
                "author": "reconCLI",
                "fofa_query": 'title="Jenkins" && body="jenkins" && body="build"',
                "tag": ["unauth", "ci/cd"],
                "type": "内置",
                "description": "Jenkins CI/CD系统未授权访问",
            },
            "gitlab-exposed": {
                "id": "fx-2025-2008",
                "query": "gitlab-exposed",
                "rule_name": "GitLab 暴露实例",
                "rule_english": "GitLab Exposed Instance",
                "author": "reconCLI",
                "fofa_query": 'title="GitLab" && body="gitlab" && (body="sign in" || body="register")',
                "tag": ["git", "source-code"],
                "type": "内置",
                "description": "GitLab代码仓库暴露实例",
            },
            "wordpress-default": {
                "id": "fx-2025-2009",
                "query": "wordpress-default",
                "rule_name": "WordPress 默认页面",
                "rule_english": "WordPress Default Installation",
                "author": "reconCLI",
                "fofa_query": 'body="wp-content" && body="wordpress" && title="WordPress"',
                "tag": ["cms", "wordpress"],
                "type": "内置",
                "description": "WordPress CMS默认安装页面",
            },
            "phpmyadmin-exposed": {
                "id": "fx-2025-2010",
                "query": "phpmyadmin-exposed",
                "rule_name": "phpMyAdmin 暴露",
                "rule_english": "phpMyAdmin Exposed",
                "author": "reconCLI",
                "fofa_query": 'title="phpMyAdmin" && body="phpmyadmin"',
                "tag": ["database", "mysql", "admin"],
                "type": "内置",
                "description": "phpMyAdmin数据库管理工具暴露",
            },
            "webcam-exposed": {
                "id": "fx-2025-2011",
                "query": "webcam-exposed",
                "rule_name": "网络摄像头暴露",
                "rule_english": "Webcam/IP Camera Exposed",
                "author": "reconCLI",
                "fofa_query": 'body="webcam" || body="IP Camera" || title="IPCamera" || title="Network Camera"',
                "tag": ["iot", "camera", "surveillance"],
                "type": "内置",
                "description": "暴露的网络摄像头和IP摄像机",
            },
            "printer-exposed": {
                "id": "fx-2025-2012",
                "query": "printer-exposed",
                "rule_name": "网络打印机暴露",
                "rule_english": "Network Printer Exposed",
                "author": "reconCLI",
                "fofa_query": 'port="631" || port="9100" || body="printer" && (body="status" || body="jobs")',
                "tag": ["iot", "printer"],
                "type": "内置",
                "description": "暴露的网络打印机",
            },
            "vnc-exposed": {
                "id": "fx-2025-2013",
                "query": "vnc-exposed",
                "rule_name": "VNC 远程桌面暴露",
                "rule_english": "VNC Remote Desktop Exposed",
                "author": "reconCLI",
                "fofa_query": 'port="5900" || port="5901" || banner="RFB" || title="VNC"',
                "tag": ["remote", "vnc"],
                "type": "内置",
                "description": "暴露的VNC远程桌面服务",
            },
            "rdp-exposed": {
                "id": "fx-2025-2014",
                "query": "rdp-exposed",
                "rule_name": "RDP 远程桌面暴露",
                "rule_english": "RDP Remote Desktop Exposed",
                "author": "reconCLI",
                "fofa_query": 'port="3389" && banner="Remote Desktop"',
                "tag": ["remote", "rdp", "windows"],
                "type": "内置",
                "description": "暴露的Windows RDP远程桌面",
            },
            "ftp-anonymous": {
                "id": "fx-2025-2015",
                "query": "ftp-anonymous",
                "rule_name": "FTP 匿名访问",
                "rule_english": "FTP Anonymous Access",
                "author": "reconCLI",
                "fofa_query": 'port="21" && banner="220" && banner="anonymous"',
                "tag": ["ftp", "anonymous"],
                "type": "内置",
                "description": "允许匿名访问的FTP服务器",
            },
            "smtp-open-relay": {
                "id": "fx-2025-2016",
                "query": "smtp-open-relay",
                "rule_name": "SMTP 开放中继",
                "rule_english": "SMTP Open Relay",
                "author": "reconCLI",
                "fofa_query": 'port="25" && banner="220" && banner="SMTP"',
                "tag": ["smtp", "mail", "relay"],
                "type": "内置",
                "description": "可能存在开放中继的SMTP邮件服务器",
            },
            "solr-admin": {
                "id": "fx-2025-2017",
                "query": "solr-admin",
                "rule_name": "Apache Solr 管理界面",
                "rule_english": "Apache Solr Admin Interface",
                "author": "reconCLI",
                "fofa_query": 'title="Solr Admin" && body="solr" && body="dashboard"',
                "tag": ["search-engine", "apache", "admin"],
                "type": "内置",
                "description": "Apache Solr搜索引擎管理界面",
            },
            "zabbix-login": {
                "id": "fx-2025-2018",
                "query": "zabbix-login",
                "rule_name": "Zabbix 监控系统",
                "rule_english": "Zabbix Monitoring System",
                "author": "reconCLI",
                "fofa_query": 'title="Zabbix" && body="zabbix" && body="sign in"',
                "tag": ["monitoring", "zabbix"],
                "type": "内置",
                "description": "Zabbix网络监控系统登录页面",
            },
            "nagios-exposed": {
                "id": "fx-2025-2019",
                "query": "nagios-exposed",
                "rule_name": "Nagios 监控系统",
                "rule_english": "Nagios Monitoring System",
                "author": "reconCLI",
                "fofa_query": 'title="Nagios" && body="nagios" && body="monitoring"',
                "tag": ["monitoring", "nagios"],
                "type": "内置",
                "description": "Nagios网络监控系统",
            },
        }
        return builtin_rules

    def get_rule(self, query_id: str) -> Optional[Dict]:
        """Get FX rule by query ID"""
        return self.rules.get(query_id)

    def list_rules(self) -> List[Dict]:
        """List all FX rules"""
        return list(self.rules.values())

    def search_rules(self, keyword: str) -> List[Dict]:
        """Search rules by keyword"""
        results = []
        keyword_lower = keyword.lower()
        for rule in self.rules.values():
            if (
                keyword_lower in rule["rule_name"].lower()
                or keyword_lower in rule["rule_english"].lower()
                or keyword_lower in rule["description"].lower()
                or any(keyword_lower in tag.lower() for tag in rule["tag"])
            ):
                results.append(rule)
        return results

    def get_rules_by_tag(self, tag: str) -> List[Dict]:
        """Get rules by tag"""
        return [
            rule
            for rule in self.rules.values()
            if tag.lower() in [t.lower() for t in rule["tag"]]
        ]


# CLI Implementation
@click.group(invoke_without_command=True)
@click.option("--config", "-c", help="Configuration file path")
@click.option("--email", "--fofa-email", help="FOFA API Email")
@click.option("--key", "--fofakey", help="FOFA API Key")
@click.option(
    "--proxy", "-p", help="Proxy for HTTP requests (e.g., http://127.0.0.1:8080)"
)
@click.option("--fofa-url", default="https://fofa.info", help="FOFA URL")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def cli(ctx, config, email, key, proxy, fofa_url, debug, version):
    """
    FOFAX CLI - Python implementation of FOFA search tool

    A comprehensive command-line interface for querying FOFA search engine with advanced features:

    🔍 SEARCH CAPABILITIES:
    • Basic and advanced search with fuzzy matching
    • AI-powered query optimization and enhancement
    • Multi-engine search integration (Shodan, Censys, etc.)
    • FX rules for cybersecurity pattern discovery

    🚀 PERFORMANCE FEATURES:
    • Intelligent caching system with TTL management
    • Database storage for persistent results
    • Resume functionality for long-running scans
    • Parallel processing and rate limiting

    🔧 TOOL INTEGRATION:
    • httpx for HTTP probing and technology detection
    • nuclei for vulnerability scanning
    • uncover for multi-platform reconnaissance
    • kscan for port scanning and fingerprinting

    📊 OUTPUT FORMATS:
    • JSON, CSV, and TXT export formats
    • Rich terminal output with progress tracking
    • Database storage with search history
    • Professional reporting capabilities

    QUICK START:
        # Configure credentials
        reconcli fofacli config

        # Basic search
        reconcli fofacli search --query "apache" --fetch-size 100

        # Advanced search with AI and caching
        reconcli fofacli advanced-search --query "jenkins" --ai --cache --store-db

        # Multi-tool workflow
        reconcli fofacli chain --query "gitlab" --httpx --nuclei --fuzzy
    """

    if version:
        console.print("[bold green]FOFAX CLI v1.0.0[/bold green]")
        console.print("Python implementation of FOFA search tool")
        return

    if ctx.invoked_subcommand is None:
        # Show ASCII art and tips
        ascii_art = r"""
      ____        ____       _  __
     / __/____   / __/____ _| |/ /
    / /_ / __ \ / /_ / __ `/|   /
   / __// /_/ // __// /_/ //   |
  /_/   \____//_/   \__,_//_/|_|
                                    
                         fofaxcli (Python)
"""
        console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
        console.print(
            "\n[bold]FOFAX CLI is a command line FOFA query tool, simple is the best![/bold]"
        )
        console.print("\n[yellow]💡 Tips:[/yellow]")
        console.print("• Use 'fofaxcli search --help' to see search options")
        console.print("• Use 'fofaxcli config' to setup your FOFA credentials")
        console.print("• Use 'fofaxcli fx list' to see available FX rules")
        return

    # Load configuration
    if config:
        fofa_config = FOFAConfigManager.load_config(config)
    else:
        fofa_config = FOFAConfigManager.load_config()

    # Override config with command line arguments
    if email:
        fofa_config.email = email
    if key:
        fofa_config.key = key
    if proxy:
        fofa_config.proxy = proxy
    if fofa_url:
        fofa_config.fofa_url = fofa_url
    if debug:
        fofa_config.debug = debug

    ctx.obj = fofa_config


@cli.command()
@click.option("--query", "-q", help="FOFA query statement")
@click.option(
    "--fetch-size", "-fs", default=100, help="Maximum number of results to fetch"
)
@click.option("--exclude", "-e", is_flag=True, help="Exclude honeypots")
@click.option("--exclude-country-cn", "-ec", is_flag=True, help="Exclude China")
@click.option(
    "--fetch-fullhost-info",
    "-ffi",
    is_flag=True,
    help="Fetch full host info with scheme",
)
@click.option(
    "--fetch-titles-ofdomain", "-fto", is_flag=True, help="Fetch website titles"
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "txt"]),
    default="txt",
    help="Output format",
)
@click.option("--open-browser", "--open", is_flag=True, help="Open results in browser")
@click.option(
    "--fuzzy", is_flag=True, help="Enable fuzzy keyword expansion for better matching"
)
@click.option(
    "--smart-query", is_flag=True, help="Apply smart query enhancement with context"
)
@click.option("--show-suggestions", is_flag=True, help="Show related query suggestions")
@click.pass_obj
def search(
    fofa_config,
    query,
    fetch_size,
    exclude,
    exclude_country_cn,
    fetch_fullhost_info,
    fetch_titles_ofdomain,
    output,
    format,
    open_browser,
    fuzzy,
    smart_query,
    show_suggestions,
):
    """Execute FOFA search query with advanced options

    This command performs FOFA searches with intelligent enhancement capabilities:

    🔍 QUERY ENHANCEMENT:
    • --fuzzy: Expands keywords with related terms and variations
    • --smart-query: Adds contextual filters and noise reduction
    • --show-suggestions: Displays related query recommendations

    📊 OUTPUT OPTIONS:
    • --format: Choose between JSON, CSV, or TXT output
    • --output: Save results to file instead of displaying
    • --open-browser: Open results directly in web browser

    🎯 FILTERING:
    • --exclude: Filter out known honeypots
    • --exclude-country-cn: Exclude results from China
    • --fetch-size: Limit number of results (1-10000)

    📈 ENHANCED DATA:
    • --fetch-fullhost-info: Include complete host information
    • --fetch-titles-ofdomain: Extract website titles

    EXAMPLES:
        # Basic search
        reconcli fofacli search -q "apache" --fetch-size 50

        # Enhanced search with fuzzy matching
        reconcli fofacli search -q "jenkins" --fuzzy --smart-query

        # Export results with full information
        reconcli fofacli search -q "gitlab" --fetch-fullhost-info --format json -o results.json

        # Quick browser preview
        reconcli fofacli search -q "grafana" --open-browser
    """

    if not query:
        # Try to read from stdin
        if not sys.stdin.isatty():
            query = sys.stdin.read().strip()
        else:
            console.print(
                "[red]Error: Query is required. Use -q option or pipe query to stdin[/red]"
            )
            return

    if not fofa_config.email or not fofa_config.key:
        console.print(
            "[red]Error: FOFA email and key are required. Please run 'fofaxcli config' first[/red]"
        )
        return

    try:
        # Initialize query enhancer
        query_enhancer = FOFAQueryEnhancer()

        # Apply query enhancements
        original_query = query
        enhanced_query = query

        if fuzzy:
            console.print(f"[cyan]🔍 Applying fuzzy keyword expansion...[/cyan]")
            enhanced_query = query_enhancer.enhance_query_fuzzy(enhanced_query)
            console.print(f"[yellow]Fuzzy enhanced query:[/yellow] {enhanced_query}")

        if smart_query:
            console.print(f"[cyan]🧠 Applying smart query enhancement...[/cyan]")
            enhanced_query = query_enhancer.enhance_query_smart(enhanced_query)
            console.print(f"[yellow]Smart enhanced query:[/yellow] {enhanced_query}")

        # Show query suggestions if requested
        if show_suggestions:
            suggestions = query_enhancer.suggest_related_queries(original_query)
            if suggestions:
                console.print(f"\n[cyan]💡 Related query suggestions:[/cyan]")
                for i, suggestion in enumerate(suggestions, 1):
                    console.print(f"[dim]{i}.[/dim] {suggestion}")
                console.print()

        # Build query with filters
        final_query = enhanced_query
        if exclude:
            final_query += " && is_honeypot=false"
        if exclude_country_cn:
            final_query += ' && country!="CN"'

        # Determine fields to fetch
        fields = "protocol,ip,port,host"
        if fetch_titles_ofdomain:
            fields += ",title"
        if fetch_fullhost_info:
            fields += ",domain,server,country,city"

        client = FOFAClient(fofa_config)

        # Debug credentials if debug mode
        if fofa_config.debug:
            console.print(f"[dim]Email: {fofa_config.email}[/dim]")
            console.print(
                f"[dim]Key: {fofa_config.key[:10]}...{fofa_config.key[-4:] if len(fofa_config.key) > 14 else fofa_config.key}[/dim]"
            )
            console.print(f"[dim]FOFA URL: {fofa_config.fofa_url}[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching FOFA...", total=None)
            result = client.search(final_query, size=fetch_size, fields=fields)

        if not result.get("error"):
            total_count = result.get("size", 0)
            results = result.get("results", [])
            actual_count = len(results)

            console.print(
                f"[green]✅ Fetch Data From FOFA: [{actual_count}/{total_count}][/green]"
            )

            if open_browser:
                # Open in browser
                query_encoded = base64.b64encode(final_query.encode()).decode()
                browser_url = f"{fofa_config.fofa_url}/result?qbase64={query_encoded}"
                console.print(f"[yellow]🌐 Opening in browser: {final_query}[/yellow]")
                webbrowser.open(browser_url)
                return

            # Process and display results
            processed_results = []
            field_names = fields.split(",")

            for result_row in results:
                if len(result_row) >= len(field_names):
                    result_dict = dict(zip(field_names, result_row))
                    processed_results.append(result_dict)

            # Output results
            if output:
                save_results(
                    processed_results,
                    output,
                    format,
                    fetch_fullhost_info,
                    fetch_titles_ofdomain,
                )
            else:
                display_results(
                    processed_results, fetch_fullhost_info, fetch_titles_ofdomain
                )

        else:
            console.print(
                f"[red]❌ FOFA API Error: {result.get('errmsg', 'Unknown error')}[/red]"
            )

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.command()
@click.option("--url-cert", "-uc", help="Get certificate hash from HTTPS URL")
@click.option("--url-to-icon-hash", "-iu", help="Calculate icon hash from URL")
@click.option("--icon-file-path", "-if", help="Calculate icon hash from local file")
@click.option(
    "--fetch-size", "-fs", default=100, help="Maximum number of results to fetch"
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "txt"]),
    default="txt",
    help="Output format",
)
@click.pass_obj
def hash_search(
    fofa_config, url_cert, url_to_icon_hash, icon_file_path, fetch_size, output, format
):
    """Search using certificate or icon hash"""

    if not fofa_config.email or not fofa_config.key:
        console.print(
            "[red]Error: FOFA email and key are required. Please run 'fofaxcli config' first[/red]"
        )
        return

    query = None

    try:
        if url_cert:
            console.print(
                f"[yellow]🔐 Calculating certificate hash for: {url_cert}[/yellow]"
            )
            cert_hash = CertificateCalculator.get_cert_from_url(url_cert)
            query = f'cert.sha1="{cert_hash}"'
            console.print(f"[green]Certificate hash: {cert_hash}[/green]")

        elif url_to_icon_hash:
            console.print(
                f"[yellow]🎨 Calculating icon hash for: {url_to_icon_hash}[/yellow]"
            )
            icon_hash = IconHashCalculator.calculate_from_url(url_to_icon_hash)
            query = f'icon_hash="{icon_hash}"'
            console.print(f"[green]Icon hash: {icon_hash}[/green]")

        elif icon_file_path:
            console.print(
                f"[yellow]🎨 Calculating icon hash for file: {icon_file_path}[/yellow]"
            )
            icon_hash = IconHashCalculator.calculate_from_file(icon_file_path)
            query = f'icon_hash="{icon_hash}"'
            console.print(f"[green]Icon hash: {icon_hash}[/green]")

        if query:
            client = FOFAClient(fofa_config)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Searching FOFA...", total=None)
                result = client.search(query, size=fetch_size)

            if not result.get("error"):
                total_count = result.get("size", 0)
                results = result.get("results", [])
                actual_count = len(results)

                console.print(
                    f"[green]✅ Fetch Data From FOFA: [{actual_count}/{total_count}][/green]"
                )

                # Process results
                processed_results = []
                for result_row in results:
                    if len(result_row) >= 4:
                        result_dict = {
                            "protocol": result_row[0],
                            "ip": result_row[1],
                            "port": result_row[2],
                            "host": result_row[3],
                        }
                        processed_results.append(result_dict)

                # Output results
                if output:
                    save_results(processed_results, output, format, False, False)
                else:
                    display_results(processed_results, False, False)
            else:
                console.print(
                    f"[red]❌ FOFA API Error: {result.get('errmsg', 'Unknown error')}[/red]"
                )
        else:
            console.print(
                "[red]Error: Please specify one of: --url-cert, --url-to-icon-hash, --icon-file-path[/red]"
            )

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.group()
def fx():
    """FX syntax query commands"""
    pass


@fx.command("list")
@click.pass_obj
def fx_list(fofa_config):
    """List available FX rules"""
    fx_manager = FXRulesManager()
    rules = fx_manager.list_rules()

    table = Table(title="FX Query Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Query", style="green")
    table.add_column("Rule Name", style="yellow")
    table.add_column("Author", style="blue")
    table.add_column("Tags", style="magenta")
    table.add_column("Type", style="white")

    for rule in rules:
        tags = ", ".join(rule.get("tag", []))
        table.add_row(
            rule.get("id", ""),
            rule.get("query", ""),
            rule.get("rule_name", ""),
            rule.get("author", ""),
            tags,
            rule.get("type", ""),
        )

    console.print(table)


@fx.command("search")
@click.argument("fx_query")
@click.option(
    "--fetch-size", "-fs", default=100, help="Maximum number of results to fetch"
)
@click.option("--exclude", "-e", is_flag=True, help="Exclude honeypots")
@click.option("--exclude-country-cn", "-ec", is_flag=True, help="Exclude China")
@click.option(
    "--fetch-fullhost-info",
    "-ffi",
    is_flag=True,
    help="Fetch full host info with scheme",
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "txt"]),
    default="txt",
    help="Output format",
)
@click.option("--open-browser", "--open", is_flag=True, help="Open results in browser")
@click.pass_obj
def fx_search(
    fofa_config,
    fx_query,
    fetch_size,
    exclude,
    exclude_country_cn,
    fetch_fullhost_info,
    output,
    format,
    open_browser,
):
    """Search using FX syntax"""

    if not fofa_config.email or not fofa_config.key:
        console.print(
            "[red]Error: FOFA email and key are required. Please run 'fofaxcli config' first[/red]"
        )
        return

    fx_manager = FXRulesManager()
    rule = fx_manager.get_rule(fx_query)

    if not rule:
        console.print(f"[red]❌ FX rule '{fx_query}' not found[/red]")
        return

    console.print(f"[green]✅ Using FX rule: {fx_query}[/green]")
    fofa_query = rule["fofa_query"]

    # Build query with filters
    final_query = fofa_query
    if exclude:
        final_query += " && is_honeypot=false"
    if exclude_country_cn:
        final_query += ' && country!="CN"'

    try:
        client = FOFAClient(fofa_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching FOFA...", total=None)
            result = client.search(final_query, size=fetch_size)

        if not result.get("error"):
            total_count = result.get("size", 0)
            results = result.get("results", [])
            actual_count = len(results)

            console.print(
                f"[green]✅ Fetch Data From FOFA: [{actual_count}/{total_count}][/green]"
            )

            if open_browser:
                # Open in browser
                query_encoded = base64.b64encode(final_query.encode()).decode()
                browser_url = f"{fofa_config.fofa_url}/result?qbase64={query_encoded}"
                console.print(f"[yellow]🌐 Opening in browser: {final_query}[/yellow]")
                webbrowser.open(browser_url)
                return

            # Process results
            processed_results = []
            for result_row in results:
                if len(result_row) >= 4:
                    result_dict = {
                        "protocol": result_row[0],
                        "ip": result_row[1],
                        "port": result_row[2],
                        "host": result_row[3],
                    }
                    processed_results.append(result_dict)

            # Output results
            if output:
                save_results(
                    processed_results, output, format, fetch_fullhost_info, False
                )
            else:
                display_results(processed_results, fetch_fullhost_info, False)
        else:
            console.print(
                f"[red]❌ FOFA API Error: {result.get('errmsg', 'Unknown error')}[/red]"
            )

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@fx.command("show")
@click.argument("fx_id")
@click.pass_obj
def fx_show(fofa_config, fx_id):
    """Show details of an FX rule"""
    fx_manager = FXRulesManager()
    rule = fx_manager.get_rule(fx_id)

    if not rule:
        console.print(f"[red]❌ FX rule '{fx_id}' not found[/red]")
        return

    table = Table(title=f"FX Rule Details: {fx_id}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    for key, value in rule.items():
        if isinstance(value, list):
            value = ", ".join(value)
        table.add_row(key.title(), str(value))

    console.print(table)


@cli.command()
@click.pass_obj
def config(fofa_config):
    """Configure FOFA credentials and settings

    This command helps you set up FOFA API credentials and configuration:

    📋 CONFIGURATION STEPS:
    1. Creates default config file if none exists
    2. Shows current configuration status
    3. Provides instructions for credential setup
    4. Validates configuration format

    🔑 REQUIRED CREDENTIALS:
    • FOFA email address (account identifier)
    • FOFA API key (get from https://fofa.info/userCenter)

    📁 CONFIG FILE LOCATIONS:
    • ./fofax.yaml (current directory)
    • ~/.config/fofax/fofax.yaml (user config)
    • /etc/fofax.yaml (system-wide)

    ⚙️ CONFIGURATION OPTIONS:
    • fofa-email: Your FOFA account email
    • fofakey: Your FOFA API key
    • fofa-url: FOFA server URL (default: https://fofa.info)
    • proxy: HTTP/HTTPS proxy settings
    • debug: Enable debug logging
    • cache-enabled: Enable result caching
    • cache-ttl: Cache expiration time
    • ai-enabled: Enable AI features
    • db-enabled: Enable database storage

    AFTER CONFIGURATION:
        # Test your setup
        reconcli fofacli userinfo

        # Run your first search
        reconcli fofacli search -q "apache" --fetch-size 10
    """
    config_path = FOFAConfigManager.get_config_path()

    if os.path.exists(config_path):
        console.print(f"[green]📝 Current config file: {config_path}[/green]")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                current_config = yaml.safe_load(f) or {}

            email = current_config.get("fofa-email", "Not set")
            key = current_config.get("fofakey", "")

            console.print(f"[blue]Current email: {email}[/blue]")
            if key and key != "your-fofa-api-key":
                console.print(
                    f"[blue]Current key: {key[:10]}...{key[-4:] if len(key) > 14 else key}[/blue]"
                )
            else:
                console.print(f"[red]Current key: Not configured (using example)[/red]")
            console.print(
                f"[blue]Current URL: {current_config.get('fofa-url', 'https://fofa.info')}[/blue]"
            )

            # Check if using example credentials
            if email == "your-email@example.com" or key == "your-fofa-api-key":
                console.print(
                    "\n[red]⚠️  WARNING: You are using example credentials![/red]"
                )
                console.print(
                    "[yellow]Please edit the config file with your real FOFA API credentials.[/yellow]"
                )
                console.print(
                    "[dim]Get your API key from: https://fofa.info/userCenter[/dim]"
                )
        except yaml.YAMLError as e:
            console.print(f"[red]❌ YAML Error in config file: {str(e)}[/red]")
            console.print(f"[yellow]⚠️  Creating new config file...[/yellow]")
            FOFAConfigManager.create_default_config(config_path)
        except Exception as e:
            console.print(f"[red]❌ Error reading config: {str(e)}[/red]")
            console.print(f"[yellow]⚠️  Creating new config file...[/yellow]")
            FOFAConfigManager.create_default_config(config_path)
    else:
        console.print(
            f"[yellow]⚠️  Config file not found, creating: {config_path}[/yellow]"
        )
        FOFAConfigManager.create_default_config(config_path)

    console.print(f"\n[yellow]💡 Steps to configure FOFA CLI:[/yellow]")
    console.print(
        f"1. Get FOFA API credentials from: [link]https://fofa.info/userCenter[/link]"
    )
    console.print(f"2. Edit config file: [dim]vim {config_path}[/dim]")
    console.print(f"3. Replace 'your-email@example.com' with your real email")
    console.print(f"4. Replace 'your-fofa-api-key' with your real API key")
    console.print(f"5. Test with: [dim]reconcli fofacli userinfo[/dim]")


@cli.command()
@click.pass_obj
def userinfo(fofa_config):
    """Get FOFA user information"""
    if not fofa_config.email or not fofa_config.key:
        console.print(
            "[red]Error: FOFA email and key are required. Please run 'fofaxcli config' first[/red]"
        )
        return

    try:
        client = FOFAClient(fofa_config)
        user_info = client.get_userinfo()

        if not user_info.get("error"):
            table = Table(title="FOFA User Information")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            for key, value in user_info.items():
                if key != "error":
                    table.add_row(key.title(), str(value))

            console.print(table)
        else:
            console.print(
                f"[red]❌ Error: {user_info.get('errmsg', 'Unknown error')}[/red]"
            )

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.command()
@click.option("--enable-ai", is_flag=True, help="Enable AI features")
@click.option("--ai-model", default="gpt-3.5-turbo", help="AI model to use")
@click.option("--query", "-q", help="Query to analyze with AI")
@click.pass_context
def ai(ctx, enable_ai, ai_model, query):
    """AI-powered query optimization and result analysis"""
    config = ctx.obj

    if enable_ai:
        config.ai_enabled = True
        config.ai_model = ai_model
        FOFAConfigManager.save_config(config)
        console.print(f"[green]✅ AI features enabled with model: {ai_model}[/green]")
        return

    if not query:
        console.print("[red]❌ Please provide a query to analyze with --query[/red]")
        return

    try:
        ai_assistant = FOFAAIAssistant(ai_model)
        if not ai_assistant.enabled:
            console.print(
                "[red]❌ AI features not available. Install openai package: pip install openai[/red]"
            )
            return

        console.print(f"[cyan]Original query:[/cyan] {query}")
        optimized = ai_assistant.optimize_query(query)
        console.print(f"[green]Optimized query:[/green] {optimized}")

    except Exception as e:
        console.print(f"[red]❌ AI Error: {str(e)}[/red]")


@cli.group()
def cache():
    """Cache management commands"""
    pass


@cache.command("config")
@click.option("--enable", is_flag=True, help="Enable caching")
@click.option("--disable", is_flag=True, help="Disable caching")
@click.option("--ttl", type=int, help="Cache TTL in seconds")
@click.pass_context
def cache_config(ctx, enable, disable, ttl):
    """Configure cache settings"""
    config = ctx.obj

    if enable:
        config.cache_enabled = True
        console.print("[green]✅ Cache enabled[/green]")
    elif disable:
        config.cache_enabled = False
        console.print("[yellow]⚠️  Cache disabled[/yellow]")

    if ttl:
        config.cache_ttl = ttl
        console.print(f"[green]✅ Cache TTL set to {ttl} seconds[/green]")

    if enable or disable or ttl:
        FOFAConfigManager.save_config(config)


@cache.command("stats")
@click.pass_context
def cache_stats(ctx):
    """Show cache statistics"""
    config = ctx.obj

    if not config.cache_enabled:
        console.print("[yellow]⚠️  Cache is disabled[/yellow]")
        return

    try:
        cache_manager = FOFACacheManager()
        stats_data = cache_manager.stats()

        table = Table(title="Cache Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Entries", str(stats_data["total_entries"]))
        table.add_row("Valid Entries", str(stats_data["valid_entries"]))
        table.add_row("Expired Entries", str(stats_data["expired_entries"]))
        table.add_row("Cache Size", f"{stats_data['cache_size_bytes']} bytes")
        table.add_row("Cache File", stats_data["cache_file"])

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cache.command()
@click.option("--confirm", is_flag=True, help="Confirm cache clearing")
@click.pass_context
def clear(ctx, confirm):
    """Clear all cached data"""
    if not confirm:
        console.print("[yellow]⚠️  Use --confirm to clear cache[/yellow]")
        return

    try:
        cache_manager = FOFACacheManager()
        cache_manager.clear()
        console.print("[green]✅ Cache cleared successfully[/green]")

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cache.command()
@click.pass_context
def cleanup(ctx):
    """Remove expired cache entries"""
    try:
        cache_manager = FOFACacheManager()
        cache_manager.cleanup()
        console.print("[green]✅ Expired cache entries removed[/green]")

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.group()
def db():
    """Database management commands"""
    pass


@db.command("config")
@click.option("--enable", is_flag=True, help="Enable database storage")
@click.option("--disable", is_flag=True, help="Disable database storage")
@click.option("--path", help="Database file path")
@click.pass_context
def db_config(ctx, enable, disable, path):
    """Configure database settings"""
    config = ctx.obj

    if enable:
        config.db_enabled = True
        console.print("[green]✅ Database storage enabled[/green]")
    elif disable:
        config.db_enabled = False
        console.print("[yellow]⚠️  Database storage disabled[/yellow]")

    if path:
        config.db_path = path
        console.print(f"[green]✅ Database path set to {path}[/green]")

    if enable or disable or path:
        FOFAConfigManager.save_config(config)


@db.command("stats")
@click.pass_context
def db_stats(ctx):
    """Show database statistics"""
    config = ctx.obj

    try:
        db_manager = FOFADatabaseManager(config.db_path)
        stats_data = db_manager.get_stats()

        table = Table(title="Database Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Searches", str(stats_data["total_searches"]))
        table.add_row("Total Results", str(stats_data["total_results"]))
        table.add_row("Unique IPs", str(stats_data["unique_ips"]))
        table.add_row("Unique Domains", str(stats_data["unique_domains"]))
        table.add_row("Database Size", f"{stats_data['db_size_bytes']} bytes")
        table.add_row("Database Path", stats_data["db_path"])

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@db.command()
@click.option("--limit", default=10, help="Number of recent searches to show")
@click.pass_context
def history(ctx, limit):
    """Show search history"""
    config = ctx.obj

    try:
        db_manager = FOFADatabaseManager(config.db_path)
        searches = db_manager.get_searches(limit)

        if not searches:
            console.print("[yellow]No search history found[/yellow]")
            return

        table = Table(title="Search History")
        table.add_column("ID", style="cyan")
        table.add_column("Query", style="green")
        table.add_column("Results", style="yellow")
        table.add_column("Timestamp", style="blue")

        for search in searches:
            table.add_row(
                str(search["id"]),
                (
                    search["query"][:50] + "..."
                    if len(search["query"]) > 50
                    else search["query"]
                ),
                str(search["total_results"]),
                search["timestamp"][:19],
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@db.command()
@click.argument("search_id", type=int)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format", "format_type", default="txt", type=click.Choice(["txt", "json", "csv"])
)
@click.pass_context
def export(ctx, search_id, output, format_type):
    """Export results from a specific search"""
    config = ctx.obj

    try:
        db_manager = FOFADatabaseManager(config.db_path)
        results = db_manager.get_results(search_id)

        if not results:
            console.print(
                f"[yellow]No results found for search ID {search_id}[/yellow]"
            )
            return

        # Convert to dict format for saving
        results_dict = [asdict(result) for result in results]

        if output:
            save_results(results_dict, output, format_type)
        else:
            console.print(
                f"[green]Found {len(results)} results for search ID {search_id}[/green]"
            )
            for result in results[:10]:  # Show first 10
                console.print(f"{result.ip}:{result.port} - {result.title}")
            if len(results) > 10:
                console.print(f"... and {len(results) - 10} more results")

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@db.command()
@click.argument("ip")
@click.pass_context
def search_ip(ctx, ip):
    """Search stored results by IP address"""
    config = ctx.obj

    try:
        db_manager = FOFADatabaseManager(config.db_path)
        results = db_manager.search_by_ip(ip)

        if not results:
            console.print(f"[yellow]No results found for IP {ip}[/yellow]")
            return

        table = Table(title=f"Results for IP {ip}")
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Title", style="yellow")
        table.add_column("Query", style="blue")
        table.add_column("Date", style="magenta")

        for result in results:
            table.add_row(
                result.get("host", ""),
                result.get("port", ""),
                (
                    result.get("title", "")[:30] + "..."
                    if result.get("title", "") and len(result.get("title", "")) > 30
                    else result.get("title", "")
                ),
                (
                    result.get("query", "")[:20] + "..."
                    if len(result.get("query", "")) > 20
                    else result.get("query", "")
                ),
                result.get("timestamp", "")[:10],
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.command()
@click.option("--query", "-q", help="FOFA query statement")
@click.option(
    "--fetch-size", "-fs", default=100, help="Maximum number of results to fetch"
)
@click.option("--ai", is_flag=True, help="Use AI query optimization")
@click.option("--cache", is_flag=True, help="Use caching")
@click.option("--store-db", is_flag=True, help="Store results in database")
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format", "format_type", default="txt", type=click.Choice(["txt", "json", "csv"])
)
@click.option("--full-host", is_flag=True, help="Show full URLs with protocol")
@click.option("--title", is_flag=True, help="Include titles in output")
@click.pass_context
def advanced_search(
    ctx, query, fetch_size, ai, cache, store_db, output, format_type, full_host, title
):
    """Advanced search with AI, caching, and database features

    This command provides comprehensive FOFA search with enterprise features:

    🤖 AI-POWERED FEATURES:
    • --ai: Intelligent query optimization using machine learning
    • Automatic result analysis with security insights
    • Context-aware query enhancement suggestions

    ⚡ PERFORMANCE OPTIMIZATION:
    • --cache: High-speed result caching (100x+ faster repeat searches)
    • Intelligent cache invalidation and management
    • Configurable TTL and cache statistics

    💾 DATABASE INTEGRATION:
    • --store-db: Persistent storage in SQLite database
    • Search history tracking and management
    • Result correlation and analytics
    • Export capabilities from stored data

    📊 ENHANCED OUTPUT:
    • --full-host: Complete URL construction with protocols
    • --title: Website title extraction and display
    • Multiple format support (JSON, CSV, TXT)
    • Rich terminal output with progress tracking

    🔍 ANALYSIS FEATURES:
    • Geographic distribution analysis
    • Technology stack identification
    • Security risk assessment
    • Vulnerability correlation insights

    EXAMPLES:
        # AI-optimized search with caching
        reconcli fofacli advanced-search -q "jenkins" --ai --cache

        # Enterprise workflow with database storage
        reconcli fofacli advanced-search -q "elasticsearch" --ai --cache --store-db --format json

        # Quick analysis with full host information
        reconcli fofacli advanced-search -q "grafana" --full-host --title --ai

        # Large-scale reconnaissance with all features
        reconcli fofacli advanced-search -q "mongodb" --ai --cache --store-db --full-host --format json -o results.json
    """
    config = ctx.obj

    if not query:
        console.print("[red]❌ Query is required[/red]")
        return

    # Update config based on flags
    if ai:
        config.ai_enabled = True
    if cache:
        config.cache_enabled = True
    if store_db:
        config.db_enabled = True

    try:
        client = FOFAClient(config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching FOFA...", total=None)

            result = client.search(
                query=query, size=fetch_size, use_cache=cache, store_db=store_db
            )

            progress.update(task, completed=True)

        if result.get("error"):
            console.print(f"[red]❌ FOFA Error: {result['errmsg']}[/red]")
            return

        results = result.get("results", [])
        if not results:
            console.print("[yellow]⚠️  No results found[/yellow]")
            return

        console.print(f"[green]✅ Found {len(results)} results[/green]")

        # Show AI insights if available
        if "ai_analysis" in result and result["ai_analysis"].get("ai_insights"):
            console.print("\n[bold cyan]🤖 AI Insights:[/bold cyan]")
            console.print(result["ai_analysis"]["ai_insights"])

        # Convert results to proper format
        formatted_results = []
        for item in results:
            result_dict = {}
            fields = [
                "protocol",
                "ip",
                "port",
                "host",
                "title",
                "domain",
                "server",
                "country",
                "city",
            ]
            for i, field in enumerate(fields):
                if i < len(item):
                    result_dict[field] = str(item[i]) if item[i] else ""
                else:
                    result_dict[field] = ""
            formatted_results.append(result_dict)

        # Save or display results
        if output:
            save_results(formatted_results, output, format_type, full_host, title)
        else:
            console.print("\n[bold]Results:[/bold]")
            display_results(formatted_results[:20], full_host, title)  # Show first 20
            if len(formatted_results) > 20:
                console.print(f"\n... and {len(formatted_results) - 20} more results")
                console.print("Use --output to save all results to file")

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@cli.command()
@click.option("--query", "-q", required=True, help="FOFA query statement")
@click.option(
    "--fetch-size", "-fs", default=100, help="Maximum number of results to fetch"
)
@click.option("--httpx", is_flag=True, help="Chain with httpx for HTTP probing")
@click.option(
    "--nuclei", is_flag=True, help="Chain with nuclei for vulnerability scanning"
)
@click.option("--kscan", is_flag=True, help="Chain with kscan for port scanning")
@click.option(
    "--uncover", is_flag=True, help="Chain with uncover for multi-engine search"
)
@click.option("--httpx-opts", help="Additional httpx options (space-separated)")
@click.option("--nuclei-opts", help="Additional nuclei options (space-separated)")
@click.option("--kscan-opts", help="Additional kscan options (space-separated)")
@click.option("--uncover-opts", help="Additional uncover options (space-separated)")
@click.option("--output", "-o", help="Output directory for results")
@click.option("--ai", is_flag=True, help="Use AI query optimization")
@click.option("--cache", is_flag=True, help="Use caching")
@click.option("--store-db", is_flag=True, help="Store results in database")
@click.option("--fuzzy", is_flag=True, help="Enable fuzzy keyword expansion")
@click.option("--smart-query", is_flag=True, help="Apply smart query enhancement")
@click.pass_context
def chain(
    ctx,
    query,
    fetch_size,
    httpx,
    nuclei,
    kscan,
    uncover,
    httpx_opts,
    nuclei_opts,
    kscan_opts,
    uncover_opts,
    output,
    ai,
    cache,
    store_db,
    fuzzy,
    smart_query,
):
    """Chain FOFA search with other security tools (httpx, nuclei, kscan, uncover)"""
    config = ctx.obj

    if not any([httpx, nuclei, kscan, uncover]):
        console.print(
            "[red]❌ Please specify at least one tool to chain: --httpx, --nuclei, --kscan, or --uncover[/red]"
        )
        return

    # Update config based on flags
    if ai:
        config.ai_enabled = True
    if cache:
        config.cache_enabled = True
    if store_db:
        config.db_enabled = True

    try:
        # Initialize tool chain manager with secure temp directory
        if output:
            chain_manager = ToolChainManager(output)
        else:
            chain_manager = ToolChainManager()  # Uses secure tempdir

        # Apply query enhancements
        enhanced_query = query
        if fuzzy or smart_query:
            query_enhancer = FOFAQueryEnhancer()

            if fuzzy:
                console.print(f"[cyan]🔍 Applying fuzzy keyword expansion...[/cyan]")
                enhanced_query = query_enhancer.enhance_query_fuzzy(enhanced_query)
                console.print(
                    f"[yellow]Fuzzy enhanced query:[/yellow] {enhanced_query}"
                )

            if smart_query:
                console.print(f"[cyan]🧠 Applying smart query enhancement...[/cyan]")
                enhanced_query = query_enhancer.enhance_query_smart(enhanced_query)
                console.print(
                    f"[yellow]Smart enhanced query:[/yellow] {enhanced_query}"
                )

        # Step 1: Execute FOFA search
        console.print(f"[bold cyan]🔍 Step 1: FOFA Search[/bold cyan]")
        client = FOFAClient(config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching FOFA...", total=None)

            result = client.search(
                query=enhanced_query,
                size=fetch_size,
                use_cache=cache,
                store_db=store_db,
            )

            progress.update(task, completed=True)

        if result.get("error"):
            console.print(f"[red]❌ FOFA Error: {result['errmsg']}[/red]")
            return

        results = result.get("results", [])
        if not results:
            console.print("[yellow]⚠️  No results found from FOFA[/yellow]")
            return

        console.print(f"[green]✅ Found {len(results)} results from FOFA[/green]")

        # Convert results to FOFAResult objects
        fofa_results = []
        for item in results:
            fofa_result = FOFAResult()
            if len(item) > 0:
                fofa_result.protocol = str(item[0]) if item[0] else ""
            if len(item) > 1:
                fofa_result.ip = str(item[1]) if item[1] else ""
            if len(item) > 2:
                fofa_result.port = str(item[2]) if item[2] else ""
            if len(item) > 3:
                fofa_result.host = str(item[3]) if item[3] else ""
            if len(item) > 4:
                fofa_result.title = str(item[4]) if item[4] else ""
            if len(item) > 5:
                fofa_result.domain = str(item[5]) if item[5] else ""
            if len(item) > 6:
                fofa_result.server = str(item[6]) if item[6] else ""
            if len(item) > 7:
                fofa_result.country = str(item[7]) if item[7] else ""
            if len(item) > 8:
                fofa_result.city = str(item[8]) if item[8] else ""
            fofa_results.append(fofa_result)

        # Step 2: Chain with other tools
        if httpx:
            console.print(f"\n[bold cyan]🌐 Step 2: httpx HTTP Probing[/bold cyan]")
            targets_file = chain_manager.save_targets(fofa_results, "url")
            console.print(
                f"[cyan]Saved {len(fofa_results)} targets to: {targets_file}[/cyan]"
            )

            httpx_options = httpx_opts.split() if httpx_opts else []
            httpx_results_file = chain_manager.run_httpx(targets_file, httpx_options)

            if httpx_results_file:
                httpx_results = chain_manager.parse_httpx_results(httpx_results_file)
                console.print(
                    f"[green]✅ httpx found {len(httpx_results)} live targets[/green]"
                )

                # Show httpx summary
                if httpx_results:
                    table = Table(title="httpx Results Summary")
                    table.add_column("URL", style="cyan")
                    table.add_column("Status", style="green")
                    table.add_column("Title", style="yellow")
                    table.add_column("Tech", style="blue")

                    for result in httpx_results[:10]:  # Show first 10
                        table.add_row(
                            result.get("url", ""),
                            str(result.get("status_code", "")),
                            (
                                result.get("title", "")[:50] + "..."
                                if len(result.get("title", "")) > 50
                                else result.get("title", "")
                            ),
                            (
                                ", ".join(result.get("tech", []))[:30] + "..."
                                if len(", ".join(result.get("tech", []))) > 30
                                else ", ".join(result.get("tech", []))
                            ),
                        )

                    console.print(table)
                    if len(httpx_results) > 10:
                        console.print(f"... and {len(httpx_results) - 10} more results")

        if nuclei:
            console.print(
                f"\n[bold cyan]🔍 Step 3: nuclei Vulnerability Scanning[/bold cyan]"
            )

            # Use httpx results if available, otherwise use FOFA results
            if httpx and "httpx_results" in locals() and httpx_results:
                # Create targets from httpx results
                temp_targets = []
                for res in httpx_results:
                    if res.get("url"):
                        temp_targets.append(res["url"])

                nuclei_targets_file = chain_manager.working_dir / "nuclei_targets.txt"
                with open(nuclei_targets_file, "w") as f:
                    for target in temp_targets:
                        f.write(f"{target}\n")
                nuclei_targets_file = str(nuclei_targets_file)
            else:
                nuclei_targets_file = chain_manager.save_targets(fofa_results, "url")

            console.print(
                f"[cyan]Running nuclei on targets from: {nuclei_targets_file}[/cyan]"
            )

            nuclei_options = nuclei_opts.split() if nuclei_opts else []
            nuclei_results_file = chain_manager.run_nuclei(
                nuclei_targets_file, nuclei_options
            )

            if nuclei_results_file:
                nuclei_results = chain_manager.parse_nuclei_results(nuclei_results_file)
                console.print(
                    f"[green]✅ nuclei found {len(nuclei_results)} vulnerabilities[/green]"
                )

                # Show nuclei summary
                if nuclei_results:
                    table = Table(title="nuclei Vulnerabilities Found")
                    table.add_column("Target", style="cyan")
                    table.add_column("Template", style="green")
                    table.add_column("Severity", style="red")
                    table.add_column("Info", style="yellow")

                    for result in nuclei_results[:10]:  # Show first 10
                        info = result.get("info", {})
                        table.add_row(
                            result.get("matched-at", ""),
                            result.get("template-id", ""),
                            info.get("severity", ""),
                            (
                                info.get("name", "")[:50] + "..."
                                if len(info.get("name", "")) > 50
                                else info.get("name", "")
                            ),
                        )

                    console.print(table)
                    if len(nuclei_results) > 10:
                        console.print(
                            f"... and {len(nuclei_results) - 10} more vulnerabilities"
                        )

        if kscan:
            console.print(
                f"\n[bold cyan]🛡️  Step 4: kscan Port Scanning & Fingerprinting[/bold cyan]"
            )
            targets_file = chain_manager.save_targets(fofa_results, "ip")
            console.print(
                f"[cyan]Saved {len(fofa_results)} IP targets to: {targets_file}[/cyan]"
            )

            kscan_options = kscan_opts.split() if kscan_opts else []
            kscan_results_file = chain_manager.run_kscan(targets_file, kscan_options)

            if kscan_results_file:
                kscan_results = chain_manager.parse_kscan_results(kscan_results_file)
                console.print(
                    f"[green]✅ kscan completed scanning {len(kscan_results)} targets[/green]"
                )

                # Show kscan summary
                if kscan_results:
                    table = Table(title="kscan Results Summary")
                    table.add_column("Target", style="cyan")
                    table.add_column("Port", style="green")
                    table.add_column("Service", style="yellow")
                    table.add_column("Banner", style="blue")

                    for result in kscan_results[:10]:  # Show first 10
                        table.add_row(
                            result.get("target", ""),
                            str(result.get("port", "")),
                            result.get("service", ""),
                            (
                                result.get("banner", "")[:50] + "..."
                                if len(result.get("banner", "")) > 50
                                else result.get("banner", "")
                            ),
                        )

                    console.print(table)
                    if len(kscan_results) > 10:
                        console.print(f"... and {len(kscan_results) - 10} more results")

        if uncover:
            console.print(
                f"\n[bold cyan]🔍 Step 5: uncover Multi-Engine Search[/bold cyan]"
            )

            uncover_options = uncover_opts.split() if uncover_opts else []
            uncover_results_file = chain_manager.run_uncover(
                enhanced_query, uncover_options
            )

            if uncover_results_file:
                uncover_results = chain_manager.parse_uncover_results(
                    uncover_results_file
                )
                console.print(
                    f"[green]✅ uncover found {len(uncover_results)} additional hosts from multiple engines[/green]"
                )

                # Show uncover summary
                if uncover_results:
                    table = Table(title="uncover Multi-Engine Results")
                    table.add_column("Host", style="cyan")
                    table.add_column("IP", style="green")
                    table.add_column("Port", style="yellow")
                    table.add_column("Source", style="blue")

                    for result in uncover_results[:15]:  # Show first 15
                        table.add_row(
                            result.get("host", ""),
                            result.get("ip", ""),
                            result.get("port", ""),
                            result.get("source", ""),
                        )

                    console.print(table)
                    if len(uncover_results) > 15:
                        console.print(
                            f"... and {len(uncover_results) - 15} more hosts from multi-engine search"
                        )

        # Summary
        console.print(f"\n[bold green]🎯 Chain Execution Complete![/bold green]")
        console.print(
            f"[cyan]📁 All results saved in: {chain_manager.working_dir}[/cyan]"
        )
        console.print(f"[cyan]📊 FOFA Results: {len(fofa_results)}[/cyan]")
        if httpx and "httpx_results" in locals():
            console.print(f"[cyan]🌐 httpx Live Targets: {len(httpx_results)}[/cyan]")
        if nuclei and "nuclei_results" in locals():
            console.print(
                f"[cyan]🔍 nuclei Vulnerabilities: {len(nuclei_results)}[/cyan]"
            )
        if kscan and "kscan_results" in locals():
            console.print(f"[cyan]🛡️  kscan Scan Results: {len(kscan_results)}[/cyan]")

    except Exception as e:
        console.print(f"[red]❌ Chain Error: {str(e)}[/red]")


@cli.command()
@click.option("--targets", "--target-file", help="File containing targets (URLs/IPs)")
@click.option("--fofa-query", "-q", help="FOFA query to get targets")
@click.option("--fetch-size", "-fs", default=100, help="Maximum FOFA results")
@click.option("--title", is_flag=True, help="Extract page titles")
@click.option("--tech-detect", is_flag=True, help="Detect technologies")
@click.option("--status-code", is_flag=True, help="Show HTTP status codes")
@click.option("--content-length", is_flag=True, help="Show content length")
@click.option("--custom-opts", help="Custom httpx options (space-separated)")
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def httpx(
    ctx,
    targets,
    fofa_query,
    fetch_size,
    title,
    tech_detect,
    status_code,
    content_length,
    custom_opts,
    output,
):
    """Run httpx HTTP probing tool"""
    config = ctx.obj

    if not targets and not fofa_query:
        console.print(
            "[red]❌ Please provide targets file (--targets) or FOFA query (--fofa-query)[/red]"
        )
        return

    try:
        chain_manager = ToolChainManager()

        # Get targets
        if fofa_query:
            console.print(f"[cyan]Getting targets from FOFA: {fofa_query}[/cyan]")
            client = FOFAClient(config)
            result = client.search(query=fofa_query, size=fetch_size)

            if result.get("error"):
                console.print(f"[red]❌ FOFA Error: {result['errmsg']}[/red]")
                return

            results = result.get("results", [])
            if not results:
                console.print("[yellow]⚠️  No results found from FOFA[/yellow]")
                return

            # Convert to FOFAResult objects
            fofa_results = []
            for item in results:
                fofa_result = FOFAResult()
                if len(item) > 0:
                    fofa_result.protocol = str(item[0]) if item[0] else ""
                if len(item) > 1:
                    fofa_result.ip = str(item[1]) if item[1] else ""
                if len(item) > 2:
                    fofa_result.port = str(item[2]) if item[2] else ""
                if len(item) > 3:
                    fofa_result.host = str(item[3]) if item[3] else ""
                if len(item) > 4:
                    fofa_result.title = str(item[4]) if item[4] else ""
                if len(item) > 5:
                    fofa_result.domain = str(item[5]) if item[5] else ""
                if len(item) > 6:
                    fofa_result.server = str(item[6]) if item[6] else ""
                if len(item) > 7:
                    fofa_result.country = str(item[7]) if item[7] else ""
                if len(item) > 8:
                    fofa_result.city = str(item[8]) if item[8] else ""
                fofa_results.append(fofa_result)

            targets_file = chain_manager.save_targets(fofa_results, "url")
            console.print(
                f"[green]✅ Got {len(fofa_results)} targets from FOFA[/green]"
            )
        else:
            targets_file = targets

        # Build httpx options
        options = []
        if title:
            options.append("-title")
        if tech_detect:
            options.append("-tech-detect")
        if status_code:
            options.append("-status-code")
        if content_length:
            options.append("-content-length")
        if custom_opts:
            options.extend(custom_opts.split())

        # Run httpx
        console.print(f"[cyan]Running httpx on targets...[/cyan]")
        results_file = chain_manager.run_httpx(targets_file, options)

        if results_file:
            results = chain_manager.parse_httpx_results(results_file)
            console.print(f"[green]✅ httpx found {len(results)} live targets[/green]")

            if output:
                with open(output, "w") as f:
                    json.dump(results, f, indent=2)
                console.print(f"[green]✅ Results saved to: {output}[/green]")

            # Display results
            if results:
                table = Table(title="httpx Results")
                table.add_column("URL", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Title", style="yellow")
                table.add_column("Technologies", style="blue")

                for result in results[:20]:  # Show first 20
                    table.add_row(
                        result.get("url", ""),
                        str(result.get("status_code", "")),
                        (
                            result.get("title", "")[:50] + "..."
                            if len(result.get("title", "")) > 50
                            else result.get("title", "")
                        ),
                        (
                            ", ".join(result.get("tech", []))[:40] + "..."
                            if len(", ".join(result.get("tech", []))) > 40
                            else ", ".join(result.get("tech", []))
                        ),
                    )

                console.print(table)
                if len(results) > 20:
                    console.print(f"... and {len(results) - 20} more results")

    except Exception as e:
        console.print(f"[red]❌ httpx Error: {str(e)}[/red]")


@cli.command()
@click.option("--targets", "--target-file", help="File containing targets (URLs)")
@click.option("--fofa-query", "-q", help="FOFA query to get targets")
@click.option("--fetch-size", "-fs", default=100, help="Maximum FOFA results")
@click.option("--templates", "-t", help="Nuclei templates directory/file")
@click.option(
    "--severity", default="medium,high,critical", help="Severity levels to scan"
)
@click.option("--tags", help="Template tags to run")
@click.option("--exclude-tags", help="Template tags to exclude")
@click.option("--custom-opts", help="Custom nuclei options (space-separated)")
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def nuclei(
    ctx,
    targets,
    fofa_query,
    fetch_size,
    templates,
    severity,
    tags,
    exclude_tags,
    custom_opts,
    output,
):
    """Run nuclei vulnerability scanner"""
    config = ctx.obj

    if not targets and not fofa_query:
        console.print(
            "[red]❌ Please provide targets file (--targets) or FOFA query (--fofa-query)[/red]"
        )
        return

    try:
        chain_manager = ToolChainManager()

        # Get targets
        if fofa_query:
            console.print(f"[cyan]Getting targets from FOFA: {fofa_query}[/cyan]")
            client = FOFAClient(config)
            result = client.search(query=fofa_query, size=fetch_size)

            if result.get("error"):
                console.print(f"[red]❌ FOFA Error: {result['errmsg']}[/red]")
                return

            results = result.get("results", [])
            if not results:
                console.print("[yellow]⚠️  No results found from FOFA[/yellow]")
                return

            # Convert to FOFAResult objects
            fofa_results = []
            for item in results:
                fofa_result = FOFAResult()
                if len(item) > 0:
                    fofa_result.protocol = str(item[0]) if item[0] else ""
                if len(item) > 1:
                    fofa_result.ip = str(item[1]) if item[1] else ""
                if len(item) > 2:
                    fofa_result.port = str(item[2]) if item[2] else ""
                if len(item) > 3:
                    fofa_result.host = str(item[3]) if item[3] else ""
                if len(item) > 4:
                    fofa_result.title = str(item[4]) if item[4] else ""
                if len(item) > 5:
                    fofa_result.domain = str(item[5]) if item[5] else ""
                if len(item) > 6:
                    fofa_result.server = str(item[6]) if item[6] else ""
                if len(item) > 7:
                    fofa_result.country = str(item[7]) if item[7] else ""
                if len(item) > 8:
                    fofa_result.city = str(item[8]) if item[8] else ""
                fofa_results.append(fofa_result)

            targets_file = chain_manager.save_targets(fofa_results, "url")
            console.print(
                f"[green]✅ Got {len(fofa_results)} targets from FOFA[/green]"
            )
        else:
            targets_file = targets

        # Build nuclei options
        options = ["-severity", severity, "-silent"]
        if templates:
            options.extend(["-t", templates])
        if tags:
            options.extend(["-tags", tags])
        if exclude_tags:
            options.extend(["-exclude-tags", exclude_tags])
        if custom_opts:
            options.extend(custom_opts.split())

        # Run nuclei
        console.print(f"[cyan]Running nuclei vulnerability scan...[/cyan]")
        results_file = chain_manager.run_nuclei(targets_file, options)

        if results_file:
            results = chain_manager.parse_nuclei_results(results_file)
            console.print(
                f"[green]✅ nuclei found {len(results)} vulnerabilities[/green]"
            )

            if output:
                with open(output, "w") as f:
                    json.dump(results, f, indent=2)
                console.print(f"[green]✅ Results saved to: {output}[/green]")

            # Display results
            if results:
                table = Table(title="nuclei Vulnerabilities")
                table.add_column("Target", style="cyan")
                table.add_column("Template", style="green")
                table.add_column("Severity", style="red")
                table.add_column("Name", style="yellow")

                for result in results:
                    info = result.get("info", {})
                    table.add_row(
                        result.get("matched-at", ""),
                        result.get("template-id", ""),
                        info.get("severity", ""),
                        (
                            info.get("name", "")[:60] + "..."
                            if len(info.get("name", "")) > 60
                            else info.get("name", "")
                        ),
                    )

                console.print(table)

    except Exception as e:
        console.print(f"[red]❌ nuclei Error: {str(e)}[/red]")


@cli.command()
@click.option("--query", "-q", required=True, help="Search query for uncover")
@click.option(
    "--engines",
    "-e",
    default="shodan,censys,fofa,quake,hunter,zoomeye,netlas,criminalip",
    help="Search engines to use (comma-separated)",
)
@click.option("--limit", "-l", default=200, help="Maximum number of results")
@click.option("--field", "-f", default="ip:port", help="Output field format")
@click.option("--json", "-j", is_flag=True, help="Output in JSON format")
@click.option("--timeout", default=30, help="Timeout in seconds")
@click.option("--custom-opts", help="Custom uncover options (space-separated)")
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def uncover(ctx, query, engines, limit, field, json, timeout, custom_opts, output):
    """Run uncover multi-engine search across multiple platforms"""
    config = ctx.obj

    try:
        chain_manager = ToolChainManager()

        # Build uncover options
        options = [
            "-e",
            engines,
            "-limit",
            str(limit),
            "-field",
            field,
            "-timeout",
            str(timeout),
        ]
        if json:
            options.append("-json")
        if custom_opts:
            options.extend(custom_opts.split())

        # Run uncover
        console.print(f"[cyan]Running uncover multi-engine search...[/cyan]")
        console.print(f"[dim]Query: {query}[/dim]")
        console.print(f"[dim]Engines: {engines}[/dim]")

        results_file = chain_manager.run_uncover(query, options)

        if results_file:
            results = chain_manager.parse_uncover_results(results_file)
            console.print(f"[green]✅ uncover found {len(results)} hosts[/green]")

            if output:
                if json:
                    with open(output, "w") as f:
                        json.dump(results, f, indent=2)
                else:
                    with open(output, "w") as f:
                        for result in results:
                            f.write(f"{result['host']}\n")
                console.print(f"[green]✅ Results saved to: {output}[/green]")

            # Display results
            if results:
                table = Table(title="Uncover Multi-Engine Results")
                table.add_column("Host", style="cyan")
                table.add_column("IP", style="green")
                table.add_column("Port", style="yellow")
                table.add_column("Source", style="blue")

                for result in results[:20]:  # Show first 20 results
                    table.add_row(
                        result.get("host", ""),
                        result.get("ip", ""),
                        result.get("port", ""),
                        result.get("source", ""),
                    )

                console.print(table)

                if len(results) > 20:
                    console.print(
                        f"[dim]... and {len(results) - 20} more results[/dim]"
                    )

    except Exception as e:
        console.print(f"[red]❌ uncover Error: {str(e)}[/red]")


@cli.command()
@click.option("--query", "-q", required=True, help="Original query to enhance")
@click.option("--fuzzy", is_flag=True, help="Apply fuzzy keyword expansion")
@click.option("--smart", is_flag=True, help="Apply smart query enhancement")
@click.option(
    "--suggestions", "-s", is_flag=True, help="Show related query suggestions"
)
@click.option("--explain", is_flag=True, help="Explain the enhancements applied")
@click.pass_context
def query_enhance(ctx, query, fuzzy, smart, suggestions, explain):
    """Enhance FOFA queries with fuzzy keywords and smart context"""

    query_enhancer = FOFAQueryEnhancer()

    console.print(f"[cyan]🔍 Original Query:[/cyan] {query}")
    console.print()

    enhanced_query = query

    if fuzzy:
        console.print(f"[bold yellow]🔍 Fuzzy Enhancement:[/bold yellow]")
        enhanced_query = query_enhancer.enhance_query_fuzzy(enhanced_query)
        console.print(f"[green]Result:[/green] {enhanced_query}")

        if explain:
            console.print(
                f"[dim]Explanation: Expanded keywords with related terms and variations[/dim]"
            )
        console.print()

    if smart:
        console.print(f"[bold yellow]🧠 Smart Enhancement:[/bold yellow]")
        enhanced_query = query_enhancer.enhance_query_smart(enhanced_query)
        console.print(f"[green]Result:[/green] {enhanced_query}")

        if explain:
            console.print(
                f"[dim]Explanation: Added contextual filters, ports, and noise reduction[/dim]"
            )
        console.print()

    if suggestions:
        console.print(f"[bold yellow]💡 Related Query Suggestions:[/bold yellow]")
        related_queries = query_enhancer.suggest_related_queries(query)

        if related_queries:
            table = Table(title="Query Suggestions")
            table.add_column("#", style="cyan", width=3)
            table.add_column("Suggested Query", style="green")
            table.add_column("Focus", style="yellow")

            focus_descriptions = [
                "Login pages",
                "Geographic filter",
                "HTTPS services",
                "Related technology",
                "Vulnerability focus",
            ]

            for i, suggestion in enumerate(related_queries, 1):
                focus = (
                    focus_descriptions[i - 1]
                    if i <= len(focus_descriptions)
                    else "Related"
                )
                table.add_row(str(i), suggestion, focus)

            console.print(table)
        else:
            console.print("[yellow]No suggestions available for this query[/yellow]")
        console.print()

    if not fuzzy and not smart and not suggestions:
        console.print(
            "[yellow]💡 Tip: Use --fuzzy, --smart, or --suggestions to enhance your query[/yellow]"
        )
        console.print("Examples:")
        console.print(
            "  • [dim]reconcli fofacli query-enhance -q 'jenkins' --fuzzy --smart[/dim]"
        )
        console.print(
            "  • [dim]reconcli fofacli query-enhance -q 'gitlab' --suggestions[/dim]"
        )


# Helper functions
@fx.command("search-rules")
@click.argument("keyword")
@click.pass_context
def fx_search_rules(ctx, keyword):
    """Search FX rules by keyword"""
    try:
        fx_manager = FXRulesManager()
        rules = fx_manager.search_rules(keyword)

        if not rules:
            console.print(f"[yellow]No rules found for keyword: {keyword}[/yellow]")
            return

        table = Table(title=f"FX Rules matching '{keyword}'")
        table.add_column("Query", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("English", style="blue")
        table.add_column("Tags", style="yellow")

        for rule in rules:
            tags = ", ".join(rule["tag"])
            table.add_row(rule["query"], rule["rule_name"], rule["rule_english"], tags)

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


@fx.command()
@click.argument("tag")
@click.pass_context
def tag(ctx, tag):
    """List FX rules by tag"""
    try:
        fx_manager = FXRulesManager()
        rules = fx_manager.get_rules_by_tag(tag)

        if not rules:
            console.print(f"[yellow]No rules found for tag: {tag}[/yellow]")
            return

        table = Table(title=f"FX Rules with tag '{tag}'")
        table.add_column("Query", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="blue")

        for rule in rules:
            table.add_row(
                rule["query"],
                rule["rule_name"],
                (
                    rule["description"][:50] + "..."
                    if len(rule["description"]) > 50
                    else rule["description"]
                ),
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")


# Helper functions
def display_results(
    results: List[Dict], with_fullhost: bool = False, with_titles: bool = False
):
    """Display search results in formatted output

    Args:
        results: List of search result dictionaries
        with_fullhost: Whether to show full URLs with protocols
        with_titles: Whether to include website titles
    """
    for result in results:
        if with_fullhost and "protocol" in result:
            url = f"{result.get('protocol', 'http')}://{result.get('host', result.get('ip', ''))}"
            if result.get("port") and result["port"] not in ["80", "443"]:
                url += f":{result['port']}"
        else:
            ip = result.get("ip", "")
            port = result.get("port", "")
            if port and port not in ["80", "443"]:
                url = f"{ip}:{port}"
            else:
                url = ip

        if with_titles and "title" in result and result["title"]:
            console.print(f"{url} [{result['title']}]")
        else:
            console.print(url)


def save_results(
    results: List[Dict],
    output_path: str,
    format_type: str,
    with_fullhost: bool = False,
    with_titles: bool = False,
):
    """Save results to file in specified format

    Args:
        results: List of search result dictionaries
        output_path: File path to save results
        format_type: Output format (json, csv, txt)
        with_fullhost: Whether to include full URLs with protocols
        with_titles: Whether to include website titles

    Raises:
        Exception: If file write operation fails
    """
    try:
        if format_type == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        elif format_type == "csv":
            import csv

            if results:
                with open(output_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)

        else:  # txt format
            with open(output_path, "w", encoding="utf-8") as f:
                for result in results:
                    if with_fullhost and "protocol" in result:
                        url = f"{result.get('protocol', 'http')}://{result.get('host', result.get('ip', ''))}"
                        if result.get("port") and result["port"] not in ["80", "443"]:
                            url += f":{result['port']}"
                    else:
                        ip = result.get("ip", "")
                        port = result.get("port", "")
                        if port and port not in ["80", "443"]:
                            url = f"{ip}:{port}"
                        else:
                            url = ip

                    if with_titles and "title" in result and result["title"]:
                        f.write(f"{url} [{result['title']}]\n")
                    else:
                        f.write(f"{url}\n")

        console.print(f"[green]✅ Results saved to: {output_path}[/green]")

    except Exception as e:
        console.print(f"[red]❌ Error saving results: {str(e)}[/red]")
        raise


if __name__ == "__main__":
    cli()

# Export for main reconcli module
__all__ = ["cli"]
