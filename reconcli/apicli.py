import base64
import hashlib
import json
import re
import shutil
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import click
import requests
import urllib3
import yaml

# Import AI Cache Manager from vulncli for AI-powered analysis
try:
    from .vulncli import AICacheManager
except ImportError:
    # Fallback if vulncli is not available
    AICacheManager = None


class APICacheManager:
    """Intelligent caching system for API reconnaissance results with performance optimization."""

    def __init__(self, cache_dir: str = "api_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
        self.cache_index_file = self.cache_dir / "api_cache_index.json"
        self.cache_index = self._load_cache_index()
        self.hits = 0
        self.misses = 0

    def _load_cache_index(self) -> dict:
        """Load cache index from disk."""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_cache_index(self):
        """Save cache index to disk."""
        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(self.cache_index, f, indent=2)
        except IOError:
            pass

    def _generate_cache_key(
        self,
        url: str,
        scan_type: str,
        endpoints: list = None,
        custom_headers: str = None,
        auth_bypass: bool = False,
        cors_test: bool = False,
        injection_test: bool = False,
    ) -> str:
        """Generate SHA256 cache key from API scan parameters."""
        endpoints_str = ",".join(sorted(endpoints)) if endpoints else ""
        key_data = f"{url}|{scan_type}|{endpoints_str}|{custom_headers or ''}|{auth_bypass}|{cors_test}|{injection_test}"
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()

    def _is_cache_valid(self, timestamp_str: str) -> bool:
        """Check if cache entry is still valid."""
        try:
            cache_time = datetime.fromisoformat(timestamp_str)
            return datetime.now() - cache_time < self.max_age
        except (ValueError, TypeError):
            return False

    def get(self, url: str, scan_type: str, **kwargs) -> dict:
        """Retrieve cached API scan results if available and valid."""
        cache_key = self._generate_cache_key(url, scan_type, **kwargs)

        if cache_key in self.cache_index:
            cache_entry = self.cache_index[cache_key]
            if self._is_cache_valid(cache_entry["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            self.hits += 1
                            return json.load(f)
                    except (json.JSONDecodeError, IOError):
                        pass

        self.misses += 1
        return {}

    def set(self, url: str, scan_type: str, results: dict, **kwargs):
        """Cache API scan results."""
        cache_key = self._generate_cache_key(url, scan_type, **kwargs)
        timestamp = datetime.now().isoformat()

        # Save results to cache file
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(results, f, indent=2)

            # Update cache index
            self.cache_index[cache_key] = {
                "timestamp": timestamp,
                "url": url,
                "scan_type": scan_type,
                "file": cache_file.name,
            }
            self._save_cache_index()
        except IOError:
            pass

    def clear_cache(self):
        """Clear all cached data."""
        try:
            if self.cache_dir.exists():
                for cache_file in self.cache_dir.glob("*.json"):
                    cache_file.unlink()
            self.cache_index = {}
            self._save_cache_index()
            return True
        except Exception:
            return False

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        cache_size = sum(
            f.stat().st_size for f in self.cache_dir.glob("*.json") if f.exists()
        )
        cache_files = len([f for f in self.cache_dir.glob("*.json") if f.exists()])

        return {
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "hit_rate": round(hit_rate, 2),
            "total_requests": total_requests,
            "cache_size_bytes": cache_size,
            "cache_files": cache_files,
            "cache_directory": str(self.cache_dir),
        }


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


def initialize_database(db_path):
    """Initialize SQLite database for storing results."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables for storing API scan results
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS api_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_url TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            endpoint TEXT,
            method TEXT,
            status_code INTEGER,
            response_size INTEGER,
            response_time REAL,
            vulnerabilities TEXT,
            risk_level TEXT,
            findings TEXT
        )
    """
    )

    # Create table for secret scanning results
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS secret_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_url TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            secret_value TEXT,
            confidence_level REAL,
            context TEXT,
            line_number INTEGER,
            file_path TEXT,
            risk_assessment TEXT
        )
    """
    )

    # Create table for JavaScript analysis
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS js_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_url TEXT NOT NULL,
            js_url TEXT NOT NULL,
            file_size INTEGER,
            secrets_found INTEGER,
            endpoints_found INTEGER,
            domains_found INTEGER,
            analysis_data TEXT
        )
    """
    )

    conn.commit()
    conn.close()
    return db_path


def store_scan_result(db_path, scan_data):
    """Store scan result in database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        scan_type = scan_data.get("scan_type", "api_scan")

        if scan_type == "secret_scan":
            cursor.execute(
                """
                INSERT INTO secret_scans
                (timestamp, target_url, endpoint, secret_type, secret_value,
                 confidence_level, context, line_number, file_path, risk_assessment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_data.get("timestamp"),
                    scan_data.get("target_url"),
                    scan_data.get("endpoint"),
                    scan_data.get("secret_type"),
                    scan_data.get("secret_value", "")[:500],  # Limit length
                    scan_data.get("confidence_level", 0.0),
                    scan_data.get("context", "")[:1000],
                    scan_data.get("line_number", 0),
                    scan_data.get("file_path", ""),
                    scan_data.get("risk_assessment", ""),
                ),
            )
        elif scan_type == "js_analysis":
            cursor.execute(
                """
                INSERT INTO js_analysis
                (timestamp, target_url, js_url, file_size, secrets_found,
                 endpoints_found, domains_found, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_data.get("timestamp"),
                    scan_data.get("target_url"),
                    scan_data.get("js_url"),
                    scan_data.get("file_size", 0),
                    scan_data.get("secrets_found", 0),
                    scan_data.get("endpoints_found", 0),
                    scan_data.get("domains_found", 0),
                    json.dumps(scan_data.get("analysis_data", {})),
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO api_scans
                (timestamp, target_url, scan_type, endpoint, method, status_code,
                 response_size, response_time, vulnerabilities, risk_level, findings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_data.get("timestamp"),
                    scan_data.get("target_url"),
                    scan_data.get("scan_type", "general"),
                    scan_data.get("endpoint"),
                    scan_data.get("method", "GET"),
                    scan_data.get("status_code", 0),
                    scan_data.get("response_size", 0),
                    scan_data.get("response_time", 0.0),
                    json.dumps(scan_data.get("vulnerabilities", [])),
                    scan_data.get("risk_level", "low"),
                    json.dumps(scan_data.get("findings", {})),
                ),
            )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ [DB ERROR] Failed to store scan result: {e}")
        return False


def check_api_accessibility(url, timeout=5):
    """Check if API endpoint is accessible."""
    try:
        response = requests.get(url, timeout=timeout, verify=True)
        return {
            "accessible": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_length": len(response.content),
            "response_time": response.elapsed.total_seconds(),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "api_version": response.headers.get("API-Version", "Unknown"),
        }
    except Exception as e:
        return {
            "accessible": False,
            "error": str(e),
            "status_code": 0,
            "server": "Unknown",
            "content_length": 0,
            "response_time": 0,
            "content_type": "Unknown",
            "api_version": "Unknown",
        }


def detect_api_technology(url, timeout=3):
    """Detect API technology stack and framework."""
    try:
        headers = {"User-Agent": "APICLI/1.0 ReconCLI API Scanner"}
        response = requests.get(url, headers=headers, timeout=timeout, verify=True)

        api_indicators = {
            "rest": [
                "application/json",
                "application/hal+json",
                "application/vnd.api+json",
            ],
            "graphql": [
                "application/graphql",
                "graphql",
                "__schema",
                "query",
                "mutation",
            ],
            "soap": ["application/soap+xml", "text/xml", "envelope", "wsdl"],
            "grpc": ["application/grpc", "grpc-status", "grpc-message"],
            "odata": ["application/json;odata", "odata.metadata", "$metadata"],
            "jsonrpc": ["application/json-rpc", "jsonrpc", "method", "params"],
            "fastapi": ["openapi", "docs", "redoc", "swagger"],
            "django": ["django", "csrftoken", "x-frame-options"],
            "flask": ["flask", "werkzeug", "x-ratelimit"],
            "express": ["express", "x-powered-by: express"],
            "spring": ["spring", "x-application-context", "spring-boot"],
            "aspnet": ["asp.net", "x-aspnet-version", "x-powered-by: asp.net"],
            "laravel": ["laravel", "laravel_session", "x-ratelimit-limit"],
            "rails": ["rails", "x-powered-by: rails", "x-csrf-token"],
        }

        detected_tech = []
        response_text = response.text.lower()
        headers_text = str(response.headers).lower()
        content_type = response.headers.get("Content-Type", "").lower()

        for tech, indicators in api_indicators.items():
            for indicator in indicators:
                if (
                    indicator in response_text
                    or indicator in headers_text
                    or indicator in content_type
                ):
                    detected_tech.append(tech)
                    break

        # Additional detection based on response structure
        try:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                json_data = response.json()
                if "data" in json_data and "errors" in json_data:
                    detected_tech.append("graphql")
                elif "swagger" in json_data or "openapi" in json_data:
                    detected_tech.append("openapi")
        except Exception:
            pass

        return {
            "technologies": list(set(detected_tech)),
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "api_version": response.headers.get("API-Version", "Unknown"),
            "cors_enabled": "access-control-allow-origin" in headers_text,
            "rate_limit": response.headers.get("X-RateLimit-Limit", "Unknown"),
        }
    except Exception:
        return {
            "technologies": [],
            "status_code": 0,
            "server": "Unknown",
            "content_type": "Unknown",
            "api_version": "Unknown",
            "cors_enabled": False,
            "rate_limit": "Unknown",
        }


def discover_api_endpoints(base_url, common_paths=None, timeout=3):
    """Discover common API endpoints."""
    if common_paths is None:
        common_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/v1",
            "/v2",
            "/v3",
            "/rest",
            "/graphql",
            "/swagger",
            "/openapi.json",
            "/api-docs",
            "/docs",
            "/redoc",
            "/health",
            "/status",
            "/ping",
            "/version",
            "/info",
            "/metrics",
            "/admin",
            "/users",
            "/auth",
            "/login",
            "/token",
            "/oauth",
            "/api/users",
            "/api/auth",
            "/api/login",
            "/api/admin",
            "/api/health",
            "/api/status",
            "/api/config",
            "/api/settings",
            "/api/data",
            "/api/search",
            "/api/upload",
            "/api/download",
            "/api/files",
            "/api/docs",
            "/api/test",
            "/api/debug",
            "/api/internal",
            "/api/public",
            "/api/private",
            "/api/beta",
            "/api/dev",
            "/api/staging",
            "/api/prod",
            "/api/production",
        ]

    discovered_endpoints = []
    base_url = base_url.rstrip("/")

    def check_endpoint(path):
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=timeout, verify=True)
            return {
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", "Unknown"),
                "response_time": response.elapsed.total_seconds(),
                "accessible": response.status_code < 400,
                "methods": [],
                "auth_required": response.status_code == 401,
                "rate_limited": response.status_code == 429,
            }
        except Exception as e:
            return {
                "url": urljoin(base_url, path),
                "path": path,
                "status_code": 0,
                "content_length": 0,
                "content_type": "Unknown",
                "response_time": 0,
                "accessible": False,
                "methods": [],
                "auth_required": False,
                "rate_limited": False,
                "error": str(e),
            }

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {
            executor.submit(check_endpoint, path): path for path in common_paths
        }
        for future in as_completed(future_to_path):
            result = future.result()
            if result["accessible"] or result["auth_required"]:
                discovered_endpoints.append(result)

    return discovered_endpoints


def test_http_methods(url, timeout=3):
    """Test different HTTP methods on an endpoint."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    results = {}

    for method in methods:
        try:
            response = requests.request(method, url, timeout=timeout, verify=True)
            results[method] = {
                "status_code": response.status_code,
                "allowed": response.status_code not in [404, 405],
                "content_length": len(response.content),
                "response_time": response.elapsed.total_seconds(),
                "headers": dict(response.headers),
            }
        except Exception as e:
            results[method] = {
                "status_code": 0,
                "allowed": False,
                "content_length": 0,
                "response_time": 0,
                "headers": {},
                "error": str(e),
            }

    return results


def test_authentication_bypass(url, timeout=3):
    """Test for authentication bypass vulnerabilities."""
    bypass_tests = []

    # Test different authentication bypass techniques
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Original-URL": "/admin"},
        {"X-Override-URL": "/admin"},
        {"Authorization": "Bearer invalid_token"},
        {"Authorization": "Basic " + base64.b64encode("admin:admin".encode()).decode()},
        {"Authorization": "Basic " + base64.b64encode("test:test".encode()).decode()},
        {"X-User-ID": "1"},
        {"X-User-ID": "admin"},
        {"X-Role": "admin"},
        {"X-Admin": "true"},
        {"X-Authenticated": "true"},
        {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        },
    ]

    for headers in bypass_headers:
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=True)
            test_name = f"Header: {list(headers.keys())[0]}"
            bypass_tests.append(
                {
                    "test": test_name,
                    "headers": headers,
                    "status_code": response.status_code,
                    "bypassed": response.status_code not in [401, 403],
                    "content_length": len(response.content),
                    "response_time": response.elapsed.total_seconds(),
                }
            )
        except Exception as e:
            bypass_tests.append(
                {
                    "test": test_name,
                    "headers": headers,
                    "status_code": 0,
                    "bypassed": False,
                    "content_length": 0,
                    "response_time": 0,
                    "error": str(e),
                }
            )

    return bypass_tests


def test_parameter_pollution(url, timeout=3):
    """Test for HTTP Parameter Pollution vulnerabilities."""
    test_params = [
        {"id": ["1", "2"]},  # HPP with same parameter
        {"user": ["admin", "guest"]},
        {"role": ["user", "admin"]},
        {"format": ["json", "xml"]},
        {"version": ["v1", "v2"]},
    ]

    pollution_tests = []

    for params in test_params:
        try:
            # Test with parameter pollution
            response = requests.get(url, params=params, timeout=timeout, verify=True)
            pollution_tests.append(
                {
                    "params": params,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "response_time": response.elapsed.total_seconds(),
                    "potentially_vulnerable": response.status_code == 200,
                }
            )
        except Exception as e:
            pollution_tests.append(
                {
                    "params": params,
                    "status_code": 0,
                    "content_length": 0,
                    "response_time": 0,
                    "potentially_vulnerable": False,
                    "error": str(e),
                }
            )

    return pollution_tests


def test_rate_limiting(url, requests_count=10, timeout=3):
    """Test rate limiting implementation."""
    rate_limit_results = []

    for i in range(requests_count):
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout, verify=True)
            end_time = time.time()

            rate_limit_results.append(
                {
                    "request_number": i + 1,
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "rate_limited": response.status_code == 429,
                    "rate_limit_remaining": response.headers.get(
                        "X-RateLimit-Remaining", "Unknown"
                    ),
                    "rate_limit_reset": response.headers.get(
                        "X-RateLimit-Reset", "Unknown"
                    ),
                    "retry_after": response.headers.get("Retry-After", "Unknown"),
                }
            )

            if response.status_code == 429:
                break

        except Exception as e:
            rate_limit_results.append(
                {
                    "request_number": i + 1,
                    "status_code": 0,
                    "response_time": 0,
                    "rate_limited": False,
                    "rate_limit_remaining": "Unknown",
                    "rate_limit_reset": "Unknown",
                    "retry_after": "Unknown",
                    "error": str(e),
                }
            )

    return rate_limit_results


def test_cors_configuration(url, timeout=3):
    """Test CORS configuration."""
    cors_tests = []

    # Test different origins
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "http://localhost:8080",
        "https://test.com",
        "null",
        "*",
    ]

    for origin in test_origins:
        try:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Custom-Header",
            }

            # Test preflight request
            response = requests.options(
                url, headers=headers, timeout=timeout, verify=True
            )

            cors_tests.append(
                {
                    "origin": origin,
                    "method": "OPTIONS",
                    "status_code": response.status_code,
                    "access_control_allow_origin": response.headers.get(
                        "Access-Control-Allow-Origin", "Not Set"
                    ),
                    "access_control_allow_methods": response.headers.get(
                        "Access-Control-Allow-Methods", "Not Set"
                    ),
                    "access_control_allow_headers": response.headers.get(
                        "Access-Control-Allow-Headers", "Not Set"
                    ),
                    "access_control_allow_credentials": response.headers.get(
                        "Access-Control-Allow-Credentials", "Not Set"
                    ),
                    "vulnerable": response.headers.get("Access-Control-Allow-Origin")
                    == "*"
                    and response.headers.get("Access-Control-Allow-Credentials")
                    == "true",
                }
            )

        except Exception as e:
            cors_tests.append(
                {
                    "origin": origin,
                    "method": "OPTIONS",
                    "status_code": 0,
                    "access_control_allow_origin": "Error",
                    "access_control_allow_methods": "Error",
                    "access_control_allow_headers": "Error",
                    "access_control_allow_credentials": "Error",
                    "vulnerable": False,
                    "error": str(e),
                }
            )

    return cors_tests


def test_injection_vulnerabilities(url, timeout=3):
    """Test for common injection vulnerabilities."""
    injection_payloads = {
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "admin'--",
            "admin' /*",
            "' OR 1=1#",
        ],
        "nosql_injection": [
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "this.username == this.password"}',
            '{"$gt": ""}',
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>",
        ],
        "command_injection": [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
        ],
        "ldap_injection": [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*))(|(objectClass=*",
        ],
        "xml_injection": [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<![CDATA[<script>alert('XSS')</script>]]>",
        ],
    }

    injection_results = {}

    for injection_type, payloads in injection_payloads.items():
        injection_results[injection_type] = []

        for payload in payloads:
            try:
                # Test in URL parameters
                test_url = f"{url}?test={quote(payload)}"

                response = requests.get(test_url, timeout=timeout, verify=True)

                # Check for error patterns that might indicate vulnerability
                error_patterns = [
                    "sql",
                    "mysql",
                    "oracle",
                    "postgresql",
                    "sqlite",
                    "syntax error",
                    "unexpected",
                    "warning",
                    "error",
                    "exception",
                    "stack trace",
                    "debug",
                ]

                response_text = response.text.lower()
                potential_vulnerability = any(
                    pattern in response_text for pattern in error_patterns
                )

                injection_results[injection_type].append(
                    {
                        "payload": payload,
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "potential_vulnerability": potential_vulnerability,
                        "error_indicators": [
                            pattern
                            for pattern in error_patterns
                            if pattern in response_text
                        ],
                    }
                )

            except Exception as e:
                injection_results[injection_type].append(
                    {
                        "payload": payload,
                        "url": f"{url}?test={quote(payload)}",
                        "status_code": 0,
                        "content_length": 0,
                        "response_time": 0,
                        "potential_vulnerability": False,
                        "error_indicators": [],
                        "error": str(e),
                    }
                )

    return injection_results


def analyze_api_security(url, timeout=3):
    """Comprehensive API security analysis."""
    security_analysis = {
        "endpoint": url,
        "timestamp": datetime.now().isoformat(),
        "accessibility": check_api_accessibility(url, timeout),
        "technology": detect_api_technology(url, timeout),
        "http_methods": test_http_methods(url, timeout),
        "authentication_bypass": test_authentication_bypass(url, timeout),
        "parameter_pollution": test_parameter_pollution(url, timeout),
        "rate_limiting": test_rate_limiting(url, timeout=timeout),
        "cors_configuration": test_cors_configuration(url, timeout),
        "injection_tests": test_injection_vulnerabilities(url, timeout),
    }

    return security_analysis


def ai_smart_api_analysis(api_results, cache_manager=None):
    """AI-powered smart analysis of API scanning results"""
    try:
        if not api_results:
            return []

        # Check cache first
        cache_key = "smart_api_analysis"
        data_hash = hashlib.sha256(str(api_results).encode()).hexdigest()

        if cache_manager:
            cached_result = cache_manager.get_cached_analysis(
                cache_key, [data_hash], ""
            )
            if cached_result and cached_result.get("cached"):
                return cached_result["result"]

        # Simulate AI analysis with improved pattern detection
        analyzed_endpoints = []

        for endpoint_data in api_results:
            if not isinstance(endpoint_data, dict):
                continue

            endpoint_url = endpoint_data.get("endpoint", "")
            accessibility = endpoint_data.get("accessibility", {})

            # AI-powered endpoint prioritization
            risk_score = 0
            risk_factors = []

            # Check for high-risk patterns
            high_risk_patterns = [
                "/admin",
                "/api/admin",
                "/internal",
                "/debug",
                "/test",
                "/dev",
                "/staging",
                "/backup",
                "/config",
                "/private",
            ]

            for pattern in high_risk_patterns:
                if pattern in endpoint_url.lower():
                    risk_score += 30
                    risk_factors.append(f"High-risk endpoint pattern: {pattern}")

            # Check authentication bypass results
            auth_bypass = endpoint_data.get("authentication_bypass", [])
            if auth_bypass:
                bypassed_count = sum(
                    1 for test in auth_bypass if test.get("bypassed", False)
                )
                if bypassed_count > 0:
                    risk_score += 40
                    risk_factors.append(
                        f"Authentication bypass: {bypassed_count} methods"
                    )

            # Check CORS misconfigurations
            cors_config = endpoint_data.get("cors_configuration", [])
            if cors_config:
                vulnerable_cors = sum(
                    1 for test in cors_config if test.get("vulnerable", False)
                )
                if vulnerable_cors > 0:
                    risk_score += 35
                    risk_factors.append(
                        f"CORS misconfiguration: {vulnerable_cors} issues"
                    )

            # Check injection vulnerabilities
            injection_tests = endpoint_data.get("injection_tests", {})
            if injection_tests:
                total_vulns = 0
                for test_type, tests in injection_tests.items():
                    if isinstance(tests, list):
                        vulns = sum(
                            1
                            for test in tests
                            if test.get("potential_vulnerability", False)
                        )
                        total_vulns += vulns

                if total_vulns > 0:
                    risk_score += 45
                    risk_factors.append(
                        f"Injection vulnerabilities: {total_vulns} potential issues"
                    )

            # Check for rate limiting
            rate_limiting = endpoint_data.get("rate_limiting", [])
            if rate_limiting:
                rate_limited = any(
                    test.get("rate_limited", False) for test in rate_limiting
                )
                if not rate_limited:
                    risk_score += 15
                    risk_factors.append("No rate limiting detected")

            # AI confidence and prioritization
            if risk_score >= 70:
                priority = "CRITICAL"
                ai_confidence = 0.95
            elif risk_score >= 40:
                priority = "HIGH"
                ai_confidence = 0.85
            elif risk_score >= 20:
                priority = "MEDIUM"
                ai_confidence = 0.75
            else:
                priority = "LOW"
                ai_confidence = 0.60

            analyzed_endpoint = {
                "endpoint": endpoint_url,
                "ai_risk_score": risk_score,
                "ai_priority": priority,
                "ai_confidence": ai_confidence,
                "risk_factors": risk_factors,
                "ai_recommendation": generate_ai_recommendation(risk_factors, priority),
                "original_data": endpoint_data,
            }

            analyzed_endpoints.append(analyzed_endpoint)

        # Sort by risk score (highest first)
        analyzed_endpoints.sort(key=lambda x: x["ai_risk_score"], reverse=True)

        # Cache the result
        if cache_manager:
            cache_manager.store_analysis(cache_key, [data_hash], analyzed_endpoints)

        return analyzed_endpoints

    except Exception as e:
        print(f"❌ [AI-ERROR] Smart API analysis failed: {e}")
        return []


def ai_reduce_false_positives(
    scan_results, confidence_threshold=0.7, cache_manager=None
):
    """AI-powered false positive reduction for API scan results"""
    try:
        if not scan_results:
            return scan_results

        # Check cache first
        cache_key = "reduce_false_positives"
        data_hash = hashlib.sha256(str(scan_results).encode()).hexdigest()

        if cache_manager:
            cached_result = cache_manager.get_cached_analysis(
                cache_key, [data_hash], str(confidence_threshold)
            )
            if cached_result and cached_result.get("cached"):
                return cached_result["result"]

        filtered_results = []

        for result in scan_results:
            if not isinstance(result, dict):
                filtered_results.append(result)
                continue

            # AI-powered false positive detection
            confidence_score = 1.0
            false_positive_indicators = []

            endpoint = result.get("endpoint", "")

            # Check for common false positive patterns
            fp_patterns = [
                ("/favicon.ico", 0.9),
                ("/robots.txt", 0.8),
                ("/sitemap.xml", 0.8),
                ("/.well-known/", 0.7),
                ("/manifest.json", 0.7),
                ("/sw.js", 0.6),
                ("/service-worker.js", 0.6),
            ]

            for pattern, fp_weight in fp_patterns:
                if pattern in endpoint.lower():
                    confidence_score -= fp_weight
                    false_positive_indicators.append(
                        f"Common static file pattern: {pattern}"
                    )

            # Check status codes
            accessibility = result.get("accessibility", {})
            status_code = accessibility.get("status_code", 0)

            if status_code in [404, 410]:
                confidence_score -= 0.8
                false_positive_indicators.append(
                    f"Resource not found (status: {status_code})"
                )
            elif status_code in [403, 401]:
                confidence_score += 0.2  # Actually more interesting
                false_positive_indicators.append(
                    f"Access restricted (status: {status_code}) - potentially valid finding"
                )

            # Check response content patterns
            if accessibility.get("content_length", 0) == 0:
                confidence_score -= 0.3
                false_positive_indicators.append("Empty response content")

            # Check for error pages
            content_type = accessibility.get("content_type", "")
            if "text/html" in content_type.lower():
                if accessibility.get("content_length", 0) > 1000:  # Likely error page
                    confidence_score -= 0.4
                    false_positive_indicators.append("Likely HTML error page")

            # AI confidence adjustment
            final_confidence = max(0.0, min(1.0, confidence_score))

            if final_confidence >= confidence_threshold:
                result["ai_confidence"] = final_confidence
                result["ai_false_positive_indicators"] = false_positive_indicators
                filtered_results.append(result)

        print(
            f"🤖 [AI-FP] Filtered {len(scan_results) - len(filtered_results)} potential false positives"
        )

        # Cache the result
        if cache_manager:
            cache_manager.store_analysis(
                cache_key,
                [data_hash],
                filtered_results,
                confidence_threshold=confidence_threshold,
            )

        return filtered_results

    except Exception as e:
        print(f"❌ [AI-ERROR] False positive reduction failed: {e}")
        return scan_results


def generate_ai_recommendation(risk_factors, priority):
    """Generate AI-powered recommendations based on risk factors"""
    recommendations = []

    if any("authentication bypass" in factor.lower() for factor in risk_factors):
        recommendations.append(
            "🔒 Implement proper authentication and authorization controls"
        )
        recommendations.append("🛡️ Review and strengthen authentication mechanisms")

    if any("cors misconfiguration" in factor.lower() for factor in risk_factors):
        recommendations.append("🌐 Configure CORS policies to restrict allowed origins")
        recommendations.append(
            "🔐 Avoid using wildcard (*) with credentials in CORS headers"
        )

    if any("injection" in factor.lower() for factor in risk_factors):
        recommendations.append("🧼 Implement input validation and sanitization")
        recommendations.append("🛡️ Use parameterized queries and prepared statements")
        recommendations.append("🔍 Deploy Web Application Firewall (WAF)")

    if any("rate limiting" in factor.lower() for factor in risk_factors):
        recommendations.append("⏱️ Implement rate limiting to prevent abuse")
        recommendations.append(
            "📊 Monitor API usage patterns and set appropriate limits"
        )

    if any("high-risk endpoint" in factor.lower() for factor in risk_factors):
        recommendations.append("🚨 Restrict access to administrative endpoints")
        recommendations.append(
            "🔒 Implement additional authentication for sensitive paths"
        )
        recommendations.append(
            "🏠 Consider moving admin interfaces to internal networks"
        )

    if priority in ["CRITICAL", "HIGH"]:
        recommendations.append("🚨 Address these issues immediately")
        recommendations.append("🔍 Conduct thorough security review")
        recommendations.append("📝 Document and track remediation efforts")

    return recommendations


def ai_executive_summary(analysis_results, confidence_threshold=0.7):
    """Generate AI-powered executive summary with risk assessment"""
    try:
        summary = {
            "executive_overview": "",
            "key_findings": [],
            "risk_assessment": {
                "overall_risk": "LOW",
                "critical_issues": 0,
                "high_risk_issues": 0,
                "medium_risk_issues": 0,
                "compliance_concerns": [],
            },
            "business_impact": [],
            "recommendations": [],
            "next_steps": [],
        }

        if not analysis_results:
            summary["executive_overview"] = "No API endpoints were analyzed."
            return summary

        # Analyze results
        total_endpoints = len(analysis_results)
        critical_count = sum(
            1 for r in analysis_results if r.get("ai_priority") == "CRITICAL"
        )
        high_count = sum(1 for r in analysis_results if r.get("ai_priority") == "HIGH")
        medium_count = sum(
            1 for r in analysis_results if r.get("ai_priority") == "MEDIUM"
        )

        summary["risk_assessment"]["critical_issues"] = critical_count
        summary["risk_assessment"]["high_risk_issues"] = high_count
        summary["risk_assessment"]["medium_risk_issues"] = medium_count

        # Determine overall risk
        if critical_count > 0:
            summary["risk_assessment"]["overall_risk"] = "CRITICAL"
        elif high_count > 2:
            summary["risk_assessment"]["overall_risk"] = "HIGH"
        elif high_count > 0 or medium_count > 3:
            summary["risk_assessment"]["overall_risk"] = "MEDIUM"
        else:
            summary["risk_assessment"]["overall_risk"] = "LOW"

        # Generate executive overview
        risk_level = summary["risk_assessment"]["overall_risk"]
        summary[
            "executive_overview"
        ] = f"""
API Security Assessment completed for {total_endpoints} endpoints with {risk_level} overall risk level.
Identified {critical_count} critical, {high_count} high-risk, and {medium_count} medium-risk security issues.
Immediate attention required for authentication, authorization, and input validation vulnerabilities.
"""

        # Key findings
        common_issues = {}
        for result in analysis_results:
            for factor in result.get("risk_factors", []):
                issue_type = factor.split(":")[0] if ":" in factor else factor
                common_issues[issue_type] = common_issues.get(issue_type, 0) + 1

        for issue, count in sorted(
            common_issues.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            summary["key_findings"].append(f"{issue} detected in {count} endpoints")

        # Business impact
        if critical_count > 0:
            summary["business_impact"].append(
                "🚨 Critical vulnerabilities pose immediate risk to data confidentiality and system integrity"
            )
            summary["business_impact"].append(
                "💰 Potential for data breaches leading to regulatory fines and reputation damage"
            )

        if high_count > 0:
            summary["business_impact"].append(
                "⚠️ High-risk vulnerabilities could lead to unauthorized access and data exposure"
            )
            summary["business_impact"].append(
                "📉 Service availability and performance may be impacted"
            )

        # Compliance concerns
        if any(
            "injection" in factor.lower()
            for result in analysis_results
            for factor in result.get("risk_factors", [])
        ):
            summary["risk_assessment"]["compliance_concerns"].append(
                "OWASP API Top 10 - Injection vulnerabilities"
            )

        if any(
            "authentication" in factor.lower()
            for result in analysis_results
            for factor in result.get("risk_factors", [])
        ):
            summary["risk_assessment"]["compliance_concerns"].append(
                "OWASP API Top 10 - Broken authentication"
            )

        # Strategic recommendations
        summary["recommendations"] = [
            "🔒 Implement comprehensive API security strategy",
            "🛡️ Deploy API gateway with security controls",
            "📋 Establish security testing in CI/CD pipeline",
            "📊 Implement continuous security monitoring",
            "🎓 Provide security training for development teams",
        ]

        # Next steps
        if critical_count > 0:
            summary["next_steps"].append(
                "🚨 Address critical vulnerabilities within 24-48 hours"
            )
        if high_count > 0:
            summary["next_steps"].append(
                "⚠️ Remediate high-risk issues within 1-2 weeks"
            )

        summary["next_steps"].extend(
            [
                "🔍 Conduct detailed penetration testing",
                "📝 Develop incident response procedures",
                "🔄 Establish regular security assessment schedule",
            ]
        )

        return summary

    except Exception as e:
        print(f"❌ [AI-ERROR] Executive summary generation failed: {e}")
        return {"error": str(e)}


def generate_security_report(analysis_results):
    """Generate a comprehensive security report."""
    report = {
        "summary": {
            "total_endpoints": len(analysis_results),
            "vulnerable_endpoints": 0,
            "high_risk_issues": [],
            "medium_risk_issues": [],
            "low_risk_issues": [],
        },
        "detailed_results": analysis_results,
        "recommendations": [],
        "timestamp": datetime.now().isoformat(),
    }

    for result in analysis_results:
        endpoint = result["endpoint"]

        # Check for high-risk vulnerabilities
        if result.get("cors_configuration"):
            for cors_test in result["cors_configuration"]:
                if cors_test.get("vulnerable"):
                    report["summary"]["high_risk_issues"].append(
                        {
                            "endpoint": endpoint,
                            "issue": "CORS Misconfiguration",
                            "description": f"CORS allows any origin with credentials for {cors_test['origin']}",
                            "severity": "HIGH",
                        }
                    )

        # Check for authentication bypass
        if result.get("authentication_bypass"):
            for bypass_test in result["authentication_bypass"]:
                if bypass_test.get("bypassed"):
                    report["summary"]["high_risk_issues"].append(
                        {
                            "endpoint": endpoint,
                            "issue": "Authentication Bypass",
                            "description": f"Authentication bypassed with {bypass_test['test']}",
                            "severity": "HIGH",
                        }
                    )

        # Check for injection vulnerabilities
        if result.get("injection_tests"):
            for injection_type, tests in result["injection_tests"].items():
                for test in tests:
                    if test.get("potential_vulnerability"):
                        report["summary"]["high_risk_issues"].append(
                            {
                                "endpoint": endpoint,
                                "issue": f"{injection_type.replace('_', ' ').title()} Vulnerability",
                                "description": f"Potential {injection_type} with payload: {test['payload']}",
                                "severity": "HIGH",
                            }
                        )

        # Check for rate limiting issues
        if result.get("rate_limiting"):
            rate_limited = any(
                test.get("rate_limited") for test in result["rate_limiting"]
            )
            if not rate_limited:
                report["summary"]["medium_risk_issues"].append(
                    {
                        "endpoint": endpoint,
                        "issue": "No Rate Limiting",
                        "description": "Endpoint does not implement rate limiting",
                        "severity": "MEDIUM",
                    }
                )

    report["summary"]["vulnerable_endpoints"] = len(
        set(
            issue["endpoint"]
            for issue in report["summary"]["high_risk_issues"]
            + report["summary"]["medium_risk_issues"]
            + report["summary"]["low_risk_issues"]
        )
    )

    # Generate recommendations
    if report["summary"]["high_risk_issues"]:
        report["recommendations"].append(
            "🚨 Immediately address high-risk vulnerabilities"
        )
        report["recommendations"].append(
            "🔒 Implement proper authentication and authorization"
        )
        report["recommendations"].append("🛡️ Configure CORS policies securely")
        report["recommendations"].append("🧼 Sanitize and validate all user inputs")

    if report["summary"]["medium_risk_issues"]:
        report["recommendations"].append("⚠️ Implement rate limiting on all endpoints")
        report["recommendations"].append("📊 Monitor API usage and set up alerting")

    report["recommendations"].extend(
        [
            "🔐 Use HTTPS for all API communications",
            "🎯 Implement proper error handling to avoid information disclosure",
            "📝 Log all API requests for monitoring and debugging",
            "🔄 Regular security testing and vulnerability assessments",
        ]
    )

    return report


def save_results(results, output_dir, format_type="json"):
    """Save scan results to files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_type == "json":
        output_file = output_path / f"apicli_results_{timestamp}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return output_file

    elif format_type == "yaml":
        output_file = output_path / f"apicli_results_{timestamp}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(results, f, default_flow_style=False, allow_unicode=True)
        return output_file

    elif format_type == "markdown":
        output_file = output_path / f"apicli_report_{timestamp}.md"
        with open(output_file, "w") as f:
            f.write("# API Security Analysis Report\n\n")
            f.write(
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            if "summary" in results:
                f.write("## Summary\n\n")
                f.write(
                    f"- **Total Endpoints:** {results['summary']['total_endpoints']}\n"
                )
                f.write(
                    f"- **Vulnerable Endpoints:** {results['summary']['vulnerable_endpoints']}\n"
                )
                f.write(
                    f"- **High Risk Issues:** {len(results['summary']['high_risk_issues'])}\n"
                )
                f.write(
                    f"- **Medium Risk Issues:** {len(results['summary']['medium_risk_issues'])}\n"
                )
                f.write(
                    f"- **Low Risk Issues:** {len(results['summary']['low_risk_issues'])}\n\n"
                )

                if results["summary"]["high_risk_issues"]:
                    f.write("## 🚨 High Risk Issues\n\n")
                    for issue in results["summary"]["high_risk_issues"]:
                        f.write(f"- **{issue['issue']}** at `{issue['endpoint']}`\n")
                        f.write(f"  - {issue['description']}\n\n")

                if results["summary"]["medium_risk_issues"]:
                    f.write("## ⚠️ Medium Risk Issues\n\n")
                    for issue in results["summary"]["medium_risk_issues"]:
                        f.write(f"- **{issue['issue']}** at `{issue['endpoint']}`\n")
                        f.write(f"  - {issue['description']}\n\n")

                if results.get("recommendations"):
                    f.write("## 📋 Recommendations\n\n")
                    for rec in results["recommendations"]:
                        f.write(f"- {rec}\n")
                    f.write("\n")

        return output_file


def scan_javascript_secrets(js_content, js_url="", confidence_threshold=0.7):
    """Enhanced JavaScript secret scanning with SJ-like patterns."""

    # Comprehensive secret patterns with confidence scoring
    secret_patterns = {
        "aws_access_key": {
            "pattern": r'(?i)(aws_access_key_id|accesskeyid)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?',
            "confidence": 0.95,
            "risk": "HIGH",
        },
        "aws_secret_key": {
            "pattern": r'(?i)(aws_secret_access_key|secretaccesskey)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            "confidence": 0.90,
            "risk": "HIGH",
        },
        "github_token": {
            "pattern": r"(?i)(github_token|gh[ps]_[a-zA-Z0-9]{36})",
            "confidence": 0.95,
            "risk": "HIGH",
        },
        "api_key_generic": {
            "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-z0-9]{20,})["\']?',
            "confidence": 0.75,
            "risk": "MEDIUM",
        },
        "private_key": {
            "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "confidence": 0.99,
            "risk": "CRITICAL",
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "confidence": 0.85,
            "risk": "HIGH",
        },
        "database_url": {
            "pattern": r'(?i)(database_url|db_url)\s*[:=]\s*["\']?(mongodb|mysql|postgresql|postgres)://[^\s"\']+["\']?',
            "confidence": 0.90,
            "risk": "HIGH",
        },
        "slack_token": {
            "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "confidence": 0.95,
            "risk": "HIGH",
        },
        "discord_webhook": {
            "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]{68}",
            "confidence": 0.95,
            "risk": "MEDIUM",
        },
        "stripe_key": {
            "pattern": r"(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24}",
            "confidence": 0.95,
            "risk": "HIGH",
        },
        "google_api": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "confidence": 0.90,
            "risk": "MEDIUM",
        },
        "facebook_token": {
            "pattern": r"EAA[0-9A-Za-z]{90,}",
            "confidence": 0.85,
            "risk": "MEDIUM",
        },
        "twitter_token": {
            "pattern": r'(?i)(twitter|oauth)[_-]?(token|key|secret)\s*[:=]\s*["\']?([a-zA-Z0-9]{50})["\']?',
            "confidence": 0.80,
            "risk": "MEDIUM",
        },
        "password_field": {
            "pattern": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
            "confidence": 0.60,
            "risk": "MEDIUM",
        },
        "mongodb_connection": {
            "pattern": r"mongodb://[^:\s]+:[^@\s]+@[^/\s]+",
            "confidence": 0.95,
            "risk": "HIGH",
        },
        "redis_url": {
            "pattern": r"redis://[^:\s]*:[^@\s]*@[^/\s]+",
            "confidence": 0.90,
            "risk": "HIGH",
        },
        "mailgun_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "confidence": 0.85,
            "risk": "MEDIUM",
        },
        "sendgrid_key": {
            "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
            "confidence": 0.95,
            "risk": "MEDIUM",
        },
        "twilio_key": {
            "pattern": r"SK[0-9a-fA-F]{32}",
            "confidence": 0.90,
            "risk": "MEDIUM",
        },
        "paypal_token": {
            "pattern": r'(?i)(paypal[_-]?(token|key|secret))\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?',
            "confidence": 0.80,
            "risk": "HIGH",
        },
    }

    secrets_found = []
    lines = js_content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for secret_type, pattern_info in secret_patterns.items():
            pattern = pattern_info["pattern"]
            confidence = pattern_info["confidence"]
            risk = pattern_info["risk"]

            if confidence >= confidence_threshold:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Extract the actual secret value
                    secret_value = (
                        match.group(2) if len(match.groups()) >= 2 else match.group(0)
                    )

                    # Skip if it's obviously a placeholder
                    if any(
                        placeholder in secret_value.lower()
                        for placeholder in [
                            "placeholder",
                            "your_key",
                            "your_token",
                            "example",
                            "test_key",
                            "sample",
                        ]
                    ):
                        continue

                    # Context around the finding
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    context = "\n".join(lines[start_line:end_line])

                    secret_info = {
                        "type": secret_type,
                        "value": (
                            secret_value[:50] + "..."
                            if len(secret_value) > 50
                            else secret_value
                        ),
                        "full_value": secret_value,
                        "line_number": line_num,
                        "confidence": confidence,
                        "risk_level": risk,
                        "context": context,
                        "js_url": js_url,
                        "pattern_matched": pattern,
                    }

                    secrets_found.append(secret_info)

    return secrets_found


def extract_js_urls_from_html(html_content, base_url):
    """Extract JavaScript URLs from HTML content."""
    js_urls = set()

    # Find script tags with src attributes
    script_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+)["\'][^>]*>'
    matches = re.finditer(script_pattern, html_content, re.IGNORECASE)

    for match in matches:
        js_url = match.group(1)

        # Convert relative URLs to absolute
        if js_url.startswith("//"):
            js_url = "https:" + js_url
        elif js_url.startswith("/"):
            parsed_base = urlparse(base_url)
            js_url = f"{parsed_base.scheme}://{parsed_base.netloc}{js_url}"
        elif not js_url.startswith(("http://", "https://")):
            parsed_base = urlparse(base_url)
            base_path = "/".join(parsed_base.path.split("/")[:-1])
            js_url = f"{parsed_base.scheme}://{parsed_base.netloc}{base_path}/{js_url}"

        js_urls.add(js_url)

    # Also look for inline script blocks
    inline_pattern = r"<script[^>]*>(.*?)</script>"
    inline_matches = re.finditer(
        inline_pattern, html_content, re.IGNORECASE | re.DOTALL
    )

    inline_count = 0
    for match in inline_matches:
        inline_count += 1
        js_urls.add(f"{base_url}#inline-{inline_count}")

    return list(js_urls)


def scan_javascript_files(url, session, ssl_verify=True, store_db=False, db_path=None):
    """Scan JavaScript files for secrets and sensitive information."""
    results = {
        "js_files_scanned": 0,
        "secrets_found": [],
        "total_secrets": 0,
        "risk_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }

    try:
        print("🔍 [JS-SCAN] Scanning JavaScript files for secrets...")

        # First, get the main page to extract JS URLs
        response = session.get(url, timeout=10, verify=ssl_verify)
        if response.status_code != 200:
            return results

        js_urls = extract_js_urls_from_html(response.text, url)

        # Add common JS file paths
        common_js_paths = [
            "/js/app.js",
            "/js/main.js",
            "/js/bundle.js",
            "/js/vendor.js",
            "/assets/js/app.js",
            "/static/js/main.js",
            "/dist/js/bundle.js",
            "/js/config.js",
            "/js/api.js",
            "/js/auth.js",
        ]

        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        for path in common_js_paths:
            js_urls.append(base_url + path)

        # Scan each JavaScript file
        for js_url in js_urls[:20]:  # Limit to prevent excessive requests
            try:
                if js_url.startswith(base_url + "#inline-"):
                    # Handle inline scripts
                    inline_num = js_url.split("#inline-")[1]
                    inline_pattern = r"<script[^>]*>(.*?)</script>"
                    inline_matches = list(
                        re.finditer(
                            inline_pattern, response.text, re.IGNORECASE | re.DOTALL
                        )
                    )

                    if int(inline_num) <= len(inline_matches):
                        js_content = inline_matches[int(inline_num) - 1].group(1)
                    else:
                        continue
                else:
                    js_response = session.get(js_url, timeout=5, verify=ssl_verify)
                    if js_response.status_code != 200:
                        continue
                    js_content = js_response.text

                # Scan for secrets
                secrets = scan_javascript_secrets(js_content, js_url)

                if secrets:
                    results["secrets_found"].extend(secrets)
                    results["total_secrets"] += len(secrets)

                    # Update risk summary
                    for secret in secrets:
                        risk_level = secret.get("risk_level", "LOW")
                        results["risk_summary"][risk_level] += 1

                    print(f"🚨 [SECRET] Found {len(secrets)} secrets in {js_url}")

                    # Store in database if enabled
                    if store_db and db_path:
                        timestamp = datetime.now().isoformat()
                        for secret in secrets:
                            scan_data = {
                                "scan_type": "secret_scan",
                                "timestamp": timestamp,
                                "target_url": url,
                                "endpoint": js_url,
                                "secret_type": secret.get("type"),
                                "secret_value": secret.get("full_value", ""),
                                "confidence_level": secret.get("confidence", 0.0),
                                "context": secret.get("context", ""),
                                "line_number": secret.get("line_number", 0),
                                "file_path": js_url,
                                "risk_assessment": secret.get("risk_level", "UNKNOWN"),
                            }
                            store_scan_result(db_path, scan_data)

                results["js_files_scanned"] += 1

            except Exception:
                continue

        if results["total_secrets"] > 0:
            print(
                f"📊 [JS-SUMMARY] Found {results['total_secrets']} total secrets across {results['js_files_scanned']} JS files"
            )
            print(
                f"🎯 [RISK-BREAKDOWN] Critical: {results['risk_summary']['CRITICAL']}, High: {results['risk_summary']['HIGH']}, Medium: {results['risk_summary']['MEDIUM']}, Low: {results['risk_summary']['LOW']}"
            )

    except Exception as e:
        print(f"❌ [JS-ERROR] JavaScript scanning failed: {e}")

    return results


def parse_swagger_openapi(swagger_content, base_url):
    """Parse Swagger/OpenAPI definition file and extract API endpoints."""
    try:
        import json

        import yaml

        # Try to parse as JSON first, then YAML
        try:
            spec = json.loads(swagger_content)
        except json.JSONDecodeError:
            try:
                spec = yaml.safe_load(swagger_content)
            except yaml.YAMLError:
                return {"error": "Invalid JSON/YAML format"}

        # Extract basic info
        api_info = {
            "title": spec.get("info", {}).get("title", "Unknown"),
            "description": spec.get("info", {}).get("description", ""),
            "version": spec.get("info", {}).get("version", ""),
            "base_path": spec.get("basePath", ""),
            "host": spec.get("host", ""),
            "schemes": spec.get("schemes", ["https"]),
            "endpoints": [],
            "security_schemes": [],
            "servers": spec.get("servers", []),
        }

        # Extract endpoints
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.upper() in [
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                ]:
                    endpoint_info = {
                        "path": path,
                        "method": method.upper(),
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", ""),
                        "parameters": operation.get("parameters", []),
                        "security": operation.get("security", []),
                        "responses": operation.get("responses", {}),
                        "tags": operation.get("tags", []),
                    }
                    api_info["endpoints"].append(endpoint_info)

        # Extract security definitions
        security_defs = spec.get("securityDefinitions", {}) or spec.get(
            "components", {}
        ).get("securitySchemes", {})
        for name, scheme in security_defs.items():
            api_info["security_schemes"].append(
                {
                    "name": name,
                    "type": scheme.get("type", ""),
                    "in": scheme.get("in", ""),
                    "name_param": scheme.get("name", ""),
                }
            )

        return api_info
    except Exception as e:
        return {"error": f"Failed to parse Swagger/OpenAPI: {str(e)}"}


def swagger_brute_force(base_url, session, rate_limit=15, ssl_verify=True):
    """Brute force discover Swagger/OpenAPI definition files."""
    import time

    # Common Swagger/OpenAPI paths (from SJ tool)
    common_paths = [
        "",
        "/index",
        "/swagger",
        "/swagger-ui",
        "/swagger-resources",
        "/swagger-config",
        "/openapi",
        "/api",
        "/api-docs",
        "/apidocs",
        "/v1",
        "/v2",
        "/v3",
        "/doc",
        "/docs",
        "/apispec",
        "/apispec_1",
        "/api-merged",
    ]

    # Common directory prefixes
    prefixes = [
        "",
        "/swagger",
        "/swagger/docs",
        "/swagger/latest",
        "/swagger/v1",
        "/swagger/v2",
        "/swagger/v3",
        "/swagger/static",
        "/swagger/ui",
        "/swagger-ui",
        "/api-docs",
        "/api-docs/v1",
        "/api-docs/v2",
        "/apidocs",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/v3",
        "/doc",
        "/docs",
        "/docs/swagger",
        "/docs/swagger/v1",
        "/docs/swagger/v2",
        "/docs/swagger-ui",
        "/docs/swagger-ui/v1",
        "/docs/swagger-ui/v2",
        "/docs/v1",
        "/docs/v2",
        "/docs/v3",
        "/public",
        "/redoc",
    ]

    extensions = ["", ".json", ".yaml", ".yml", "/"]

    found_files = []
    total_requests = 0

    print("🔍 [SWAGGER-BRUTE] Starting brute force discovery...")

    for prefix in prefixes:
        for path in common_paths:
            for ext in extensions:
                url = f"{base_url}{prefix}{path}{ext}"
                try:
                    response = session.get(url, timeout=5, verify=ssl_verify)
                    total_requests += 1

                    if response.status_code == 200:
                        content = response.text.lower()
                        # Check for Swagger/OpenAPI indicators
                        if any(
                            indicator in content
                            for indicator in [
                                "swagger",
                                "openapi",
                                "info",
                                "paths",
                                "definitions",
                                "components",
                                "securitydefinitions",
                                "host",
                                "basepath",
                            ]
                        ):
                            found_files.append(
                                {
                                    "url": url,
                                    "status_code": response.status_code,
                                    "content_length": len(response.content),
                                    "content_type": response.headers.get(
                                        "Content-Type", ""
                                    ),
                                    "content": response.text,
                                }
                            )
                            print(f"🎯 [SWAGGER-FOUND] Definition file found: {url}")

                    # Rate limiting
                    if rate_limit > 0:
                        time.sleep(1.0 / rate_limit)

                except Exception:
                    continue

    print(
        f"📊 [SWAGGER-BRUTE] Completed {total_requests} requests, found {len(found_files)} definition files"
    )
    return found_files


def generate_swagger_commands(endpoints, prepare_tool="curl", base_url=""):
    """Generate testing commands from Swagger endpoints (SJ prepare mode)."""
    commands = []

    for endpoint in endpoints:
        path = endpoint["path"]
        method = endpoint["method"]

        # Replace path parameters with test values
        test_path = path
        import re

        test_path = re.sub(r"\{[^}]+\}", "test", test_path)

        full_url = f"{base_url}{test_path}"

        if prepare_tool.lower() == "curl":
            cmd = f"curl -sk -X {method} '{full_url}'"

            # Add headers
            if method in ["POST", "PUT", "PATCH"]:
                cmd += " -H 'Content-Type: application/json'"
                # Add sample body for POST/PUT requests
                if method in ["POST", "PUT"]:
                    cmd += ' -d \'{"test": "data"}\''

        elif prepare_tool.lower() == "sqlmap":
            cmd = f"sqlmap --method={method} -u {full_url}"
            if method in ["POST", "PUT", "PATCH"]:
                cmd += " --data='test=data'"
        else:
            cmd = f"# {method} {full_url}"

        commands.append(
            {
                "endpoint": endpoint,
                "command": cmd,
                "method": method,
                "path": path,
                "full_url": full_url,
            }
        )

    return commands


def swagger_automate_test(
    endpoints, session, base_url="", rate_limit=15, ssl_verify=True
):
    """Automate testing of Swagger endpoints (SJ automate mode)."""
    import time

    results = []

    print(f"🚀 [SWAGGER-AUTO] Testing {len(endpoints)} API endpoints...")

    for endpoint in endpoints:
        path = endpoint["path"]
        method = endpoint["method"]

        # Replace path parameters with test values
        test_path = path
        import re

        test_path = re.sub(r"\{[^}]+\}", "test", test_path)

        full_url = f"{base_url}{test_path}"

        try:
            # Prepare request data
            data = None
            headers = {"User-Agent": "APICLI/1.0 SJ-Integration Scanner"}

            if method in ["POST", "PUT", "PATCH"]:
                headers["Content-Type"] = "application/json"
                data = '{"test": "data"}'

            response = session.request(
                method,
                full_url,
                data=data,
                headers=headers,
                timeout=5,
                verify=ssl_verify,
            )

            result = {
                "endpoint": endpoint,
                "url": full_url,
                "method": method,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", ""),
                "accessible": response.status_code < 400,
                "auth_required": response.status_code == 401,
                "forbidden": response.status_code == 403,
                "not_found": response.status_code == 404,
                "server_error": response.status_code >= 500,
            }

            results.append(result)

            # Log result
            if result["accessible"]:
                print(f"✅ [ACCESSIBLE] {method} {response.status_code} {full_url}")
            elif result["auth_required"]:
                print(f"🔐 [AUTH-REQ] {method} {response.status_code} {full_url}")
            elif result["forbidden"]:
                print(f"🚫 [FORBIDDEN] {method} {response.status_code} {full_url}")
            elif result["not_found"]:
                print(f"❌ [NOT-FOUND] {method} {response.status_code} {full_url}")
            elif result["server_error"]:
                print(f"💥 [ERROR] {method} {response.status_code} {full_url}")
            else:
                print(f"⚠️ [MANUAL] {method} {response.status_code} {full_url}")

            # Rate limiting
            if rate_limit > 0:
                time.sleep(1.0 / rate_limit)

        except Exception as e:
            result = {
                "endpoint": endpoint,
                "url": full_url,
                "method": method,
                "status_code": 0,
                "error": str(e),
                "accessible": False,
            }
            results.append(result)
            print(f"❌ [ERROR] {method} 0 {full_url} - {str(e)}")

    # Summary
    accessible = len([r for r in results if r.get("accessible", False)])
    auth_required = len([r for r in results if r.get("auth_required", False)])
    total = len(results)

    print(
        f"📊 [SWAGGER-SUMMARY] Tested {total} endpoints: {accessible} accessible, {auth_required} require auth"
    )

    return results


@click.command()
@click.option("--url", help="Target API URL or base URL")
@click.option(
    "--endpoints-file",
    type=click.Path(exists=True),
    help="File containing API endpoints (one per line)",
)
@click.option("--discover", is_flag=True, help="Auto-discover API endpoints")
@click.option(
    "--security-test", is_flag=True, help="Perform comprehensive security testing"
)
@click.option("--method-test", is_flag=True, help="Test HTTP methods on endpoints")
@click.option(
    "--auth-bypass", is_flag=True, help="Test authentication bypass techniques"
)
@click.option("--cors-test", is_flag=True, help="Test CORS configuration")
@click.option(
    "--injection-test", is_flag=True, help="Test for injection vulnerabilities"
)
@click.option(
    "--rate-limit-test", is_flag=True, help="Test rate limiting implementation"
)
@click.option(
    "--parameter-pollution", is_flag=True, help="Test HTTP Parameter Pollution"
)
@click.option("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option(
    "--user-agent", default="APICLI/1.0 ReconCLI API Scanner", help="Custom User-Agent"
)
@click.option("--custom-headers", help="Custom headers (key:value,key2:value2)")
@click.option("--timeout", default=5, type=int, help="Request timeout in seconds")
@click.option("--threads", default=10, type=int, help="Number of concurrent threads")
@click.option("--delay", default=0, type=float, help="Delay between requests (seconds)")
@click.option("--output-dir", default="output/apicli", help="Output directory")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--yaml-report", is_flag=True, help="Generate YAML report")
@click.option("--markdown-report", is_flag=True, help="Generate Markdown report")
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--tech-detect", is_flag=True, help="Detect API technologies")
@click.option("--verify-ssl", is_flag=True, help="Verify SSL certificates")
@click.option(
    "--max-requests",
    default=100,
    type=int,
    help="Maximum requests for rate limit testing",
)
@click.option(
    "--secret-scan",
    is_flag=True,
    help="Enable JavaScript secret scanning (SJ integration)",
)
@click.option("--store-db", help="Store results in SQLite database (provide DB path)")
@click.option(
    "--swagger-parse",
    is_flag=True,
    help="Parse Swagger/OpenAPI definition files (SJ automate mode)",
)
@click.option(
    "--swagger-brute",
    is_flag=True,
    help="Brute force discover Swagger/OpenAPI files (SJ brute mode)",
)
@click.option(
    "--swagger-endpoints",
    is_flag=True,
    help="Extract endpoints from Swagger/OpenAPI files (SJ endpoints mode)",
)
@click.option(
    "--swagger-prepare",
    help="Generate testing commands (curl/sqlmap) from Swagger files",
)
@click.option("--swagger-url", help="Swagger/OpenAPI definition URL to parse")
@click.option(
    "--swagger-file",
    type=click.Path(exists=True),
    help="Local Swagger/OpenAPI definition file",
)
@click.option(
    "--rate-limit",
    default=15,
    type=int,
    help="Requests per second rate limit for SJ operations",
)
@click.option(
    "--insecure",
    is_flag=True,
    help="Disable SSL certificate verification (security risk)",
)
@click.option("--resume", is_flag=True, help="Skip steps if output exists.")
@click.option(
    "--resume-stat", is_flag=True, help="Show detailed resume statistics and progress"
)
@click.option(
    "--resume-reset", is_flag=True, help="Reset and clear all resume data completely"
)
@click.option(
    "--cache", is_flag=True, help="Enable intelligent caching for API results"
)
@click.option("--cache-dir", default="api_cache", help="Cache directory path")
@click.option("--cache-max-age", default=24, type=int, help="Cache max age in hours")
@click.option("--cache-stats", is_flag=True, help="Show cache performance statistics")
@click.option("--clear-cache", is_flag=True, help="Clear all cached API data")
@click.option("--fuzz", is_flag=True, help="Enable endpoint fuzzing with wordlists")
@click.option(
    "--wordlist",
    type=click.Path(exists=True),
    help="Wordlist file for endpoint fuzzing (one path per line)",
)
@click.option(
    "--fuzz-extensions",
    default="php,asp,aspx,jsp,json,xml,txt,bak,old,log",
    help="File extensions to test during fuzzing (comma-separated)",
)
@click.option(
    "--fuzz-methods",
    default="GET,POST,PUT,DELETE,PATCH",
    help="HTTP methods to test during fuzzing (comma-separated)",
)
@click.option(
    "--fuzz-depth",
    default=2,
    type=int,
    help="Maximum directory depth for fuzzing (default: 2)",
)
@click.option(
    "--fuzz-threads",
    default=20,
    type=int,
    help="Number of threads for fuzzing (default: 20)",
)
@click.option(
    "--burp-export",
    type=click.Path(),
    help="Export findings to Burp Suite XML format",
)
@click.option(
    "--ffuf-output",
    type=click.Path(),
    help="Export fuzzing results in ffuf JSON format",
)
@click.option(
    "--filter-status",
    default="200,201,204,301,302,307,401,403,405,500",
    help="HTTP status codes to include in results (comma-separated)",
)
@click.option(
    "--ai-mode", is_flag=True, help="Enable AI-powered API analysis and assessment"
)
@click.option(
    "--ai-reduce-fp",
    is_flag=True,
    help="Use AI to reduce false positives in API scan results",
)
@click.option(
    "--ai-smart-analysis",
    is_flag=True,
    help="AI-powered smart API endpoint analysis and prioritization",
)
@click.option(
    "--ai-executive-summary",
    is_flag=True,
    help="Generate AI-powered executive summary with API risk assessment",
)
@click.option(
    "--ai-confidence-threshold",
    default=0.7,
    type=float,
    help="Minimum confidence threshold for AI findings (0.0-1.0)",
)
@click.option(
    "--ai-cache", is_flag=True, help="Enable caching for AI-powered analysis results"
)
@click.option("--ai-cache-dir", default="ai_cache", help="Directory for AI cache files")
@click.option(
    "--ai-cache-max-age",
    default=24,
    type=int,
    help="Cache expiration time in hours (default: 24h)",
)
@click.option("--ai-clear-cache", is_flag=True, help="Clear all AI cached results")
@click.option("--ai-cache-stats", is_flag=True, help="Show AI cache statistics")
def main(
    url,
    endpoints_file,
    discover,
    security_test,
    method_test,
    auth_bypass,
    cors_test,
    injection_test,
    rate_limit_test,
    parameter_pollution,
    proxy,
    user_agent,
    custom_headers,
    timeout,
    threads,
    delay,
    output_dir,
    json_report,
    yaml_report,
    markdown_report,
    slack_webhook,
    discord_webhook,
    verbose,
    tech_detect,
    verify_ssl,
    max_requests,
    secret_scan,
    store_db,
    swagger_parse,
    swagger_brute,
    swagger_endpoints,
    swagger_prepare,
    swagger_url,
    swagger_file,
    rate_limit,
    insecure,
    resume,
    resume_stat,
    resume_reset,
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
    ai_mode,
    ai_reduce_fp,
    ai_smart_analysis,
    ai_executive_summary,
    ai_confidence_threshold,
    ai_cache,
    ai_cache_dir,
    ai_cache_max_age,
    ai_clear_cache,
    ai_cache_stats,
    fuzz,
    wordlist,
    fuzz_extensions,
    fuzz_methods,
    fuzz_depth,
    fuzz_threads,
    burp_export,
    ffuf_output,
    filter_status,
):
    """API security testing and analysis tool."""

    # ========== Cache System ==========
    if cache or cache_stats or clear_cache:
        cache_manager = APICacheManager(
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
            print(f"📊 [CACHE] API Cache Statistics:")
            print(f"    Cache hits: {stats['cache_hits']}")
            print(f"    Cache misses: {stats['cache_misses']}")
            print(f"    Hit rate: {stats['hit_rate']}%")
            print(f"    Total requests: {stats['total_requests']}")
            print(f"    Cache files: {stats['cache_files']}")
            print(f"    Cache size: {stats['cache_size_bytes']} bytes")
            print(f"    Cache directory: {stats['cache_directory']}")
            return
    else:
        cache_manager = None

    # ========== AI Cache System ==========
    ai_cache_manager = None
    if ai_cache or ai_cache_stats or ai_clear_cache:
        if AICacheManager is None:
            print(
                "⚠️  [AI-CACHE] Warning: AI Cache Manager not available. Install vulncli module."
            )
        else:
            ai_cache_manager = AICacheManager(cache_dir=ai_cache_dir)

            if ai_clear_cache:
                if ai_cache_manager.clear_cache():
                    print(
                        f"✅ [AI-CACHE] All cached AI analysis results cleared successfully"
                    )
                else:
                    print(f"❌ [AI-CACHE] Failed to clear AI cache")
                return

            if ai_cache_stats:
                stats = ai_cache_manager.get_cache_stats()
                print(f"📊 [AI-CACHE] Cache Statistics:")
                print(f"  Total entries: {stats.get('total_entries', 0)}")
                print(f"  Cache size: {stats.get('cache_size_mb', 0.0)} MB")
                print(f"  Hit rate: {stats.get('hit_rate_percent', 0.0)}%")
                print(f"  Hits: {stats.get('hits', 0)}")
                print(f"  Misses: {stats.get('misses', 0)}")
                print(f"  Total requests: {stats.get('total_requests', 0)}")
                return

    # URL is required for actual scanning
    if not url:
        click.echo("Error: --url is required for API scanning")
        return

    # ========== Resume Functionality ==========
    def create_resume_state(output_dir, target_url):
        """Create resume state file for tracking progress."""
        resume_dir = Path(output_dir) / ".resume"
        resume_dir.mkdir(parents=True, exist_ok=True)
        resume_file = resume_dir / "apicli_state.json"

        state = {
            "start_time": datetime.now().isoformat(),
            "target_url": target_url,
            "scan_progress": {
                "endpoints_scanned": 0,
                "total_endpoints": 0,
                "completed_scans": [],
                "failed_scans": [],
                "security_tests": {},
                "swagger_operations": [],
            },
            "results_files": [],
            "last_update": datetime.now().isoformat(),
        }

        with open(resume_file, "w") as f:
            json.dump(state, f, indent=2)

        return resume_file

    def load_resume_state(output_dir):
        """Load resume state from file."""
        resume_file = Path(output_dir) / ".resume" / "apicli_state.json"
        if resume_file.exists():
            try:
                with open(resume_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return None
        return None

    def update_resume_state(output_dir, updates):
        """Update resume state with new progress."""
        resume_file = Path(output_dir) / ".resume" / "apicli_state.json"
        if resume_file.exists():
            try:
                with open(resume_file, "r") as f:
                    state = json.load(f)

                # Update fields
                for key, value in updates.items():
                    if key in state:
                        if isinstance(state[key], dict) and isinstance(value, dict):
                            state[key].update(value)
                        else:
                            state[key] = value

                state["last_update"] = datetime.now().isoformat()

                with open(resume_file, "w") as f:
                    json.dump(state, f, indent=2)

                return True
            except Exception:
                return False
        return False

    def show_detailed_resume_stats(output_dir):
        """Show detailed resume statistics and progress."""
        state = load_resume_state(output_dir)

        if not state:
            print("📋 [RESUME-STAT] No resume state found")
            return

        print("📊 [RESUME-STAT] APICLI Scan Progress Details")
        print("=" * 60)
        print(f"🎯 Target URL: {state.get('target_url', 'Unknown')}")
        print(f"⏰ Scan Started: {state.get('start_time', 'Unknown')}")
        print(f"🔄 Last Updated: {state.get('last_update', 'Unknown')}")
        print()

        progress = state.get("scan_progress", {})
        total_endpoints = progress.get("total_endpoints", 0)
        completed = progress.get("endpoints_scanned", 0)

        if total_endpoints > 0:
            completion_rate = (completed / total_endpoints) * 100
            print(
                f"📈 Endpoint Progress: {completed}/{total_endpoints} ({completion_rate:.1f}%)"
            )
        else:
            print(f"📈 Endpoint Progress: {completed} endpoints scanned")

        # Show completed scans
        completed_scans = progress.get("completed_scans", [])
        if completed_scans:
            print(f"✅ Completed Scans ({len(completed_scans)}):")
            recent_scans = (
                completed_scans[-5:] if len(completed_scans) > 5 else completed_scans
            )
            for scan in recent_scans:  # Show last 5
                print(f"   • {scan}")
            if len(completed_scans) > 5:
                print(f"   ... and {len(completed_scans) - 5} more")

        # Show failed scans
        failed_scans = progress.get("failed_scans", [])
        if failed_scans:
            print(f"❌ Failed Scans ({len(failed_scans)}):")
            recent_failed = failed_scans[-3:] if len(failed_scans) > 3 else failed_scans
            for scan in recent_failed:  # Show last 3
                print(f"   • {scan}")
            if len(failed_scans) > 3:
                print(f"   ... and {len(failed_scans) - 3} more")

        # Show security test progress
        security_tests = progress.get("security_tests", {})
        if security_tests:
            print("🛡️ Security Tests Progress:")
            for test_type, status in security_tests.items():
                status_icon = "✅" if status else "⏳"
                print(f"   {status_icon} {test_type.replace('_', ' ').title()}")

        # Show Swagger operations
        swagger_ops = progress.get("swagger_operations", [])
        if swagger_ops:
            print(f"📋 Swagger Operations ({len(swagger_ops)}):")
            recent_ops = swagger_ops[-3:] if len(swagger_ops) > 3 else swagger_ops
            for op in recent_ops:  # Show last 3
                print(f"   • {op}")

        # Show result files
        result_files = state.get("results_files", [])
        if result_files:
            print(f"📁 Generated Reports ({len(result_files)}):")
            for file in result_files:
                if Path(file).exists():
                    size = Path(file).stat().st_size
                    print(f"   • {file} ({size} bytes)")
                else:
                    print(f"   • {file} (missing)")

        print("=" * 60)

    def reset_all_resume_data(output_dir):
        """Reset and clear all resume data completely."""
        resume_dir = Path(output_dir) / ".resume"

        if not resume_dir.exists():
            print("📋 [RESUME-RESET] No resume data found to reset")
            return

        try:
            # Remove all resume files
            shutil.rmtree(resume_dir)
            print("🔄 [RESUME-RESET] All resume data cleared successfully")
            print(f"   📁 Removed directory: {resume_dir}")
        except Exception as e:
            print(f"❌ [RESUME-RESET] Error clearing resume data: {e}")

    # Handle resume-only operations
    if resume_stat:
        show_detailed_resume_stats(output_dir)
        return

    if resume_reset:
        reset_all_resume_data(output_dir)
        return

    # ========== End Resume Functionality ==========

    # SSL verification setting
    ssl_verify = not insecure
    if insecure:
        click.echo(
            "⚠️  WARNING: SSL certificate verification is disabled. This is a security risk!"
        )
        click.echo("    Use --insecure only for testing against trusted endpoints.")

    if verbose:
        print("🚀 [START] APICLI - Advanced API Security Scanner")
        print(f"🎯 [TARGET] {url}")

    # Parse custom headers
    headers = {}
    if custom_headers:
        for header in custom_headers.split(","):
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

    # Add User-Agent
    headers["User-Agent"] = user_agent

    # Configure requests session
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    if not verify_ssl:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ========== SJ (Swagger Jacker) Integration ==========

    # Handle Swagger/OpenAPI specific operations
    if swagger_brute:
        if verbose:
            print("🔍 [SJ-BRUTE] Starting Swagger/OpenAPI brute force discovery...")

        found_swagger_files = swagger_brute_force(url, session, rate_limit, ssl_verify)

        if found_swagger_files:
            print(
                f"🎯 [SJ-BRUTE] Found {len(found_swagger_files)} Swagger/OpenAPI definition files"
            )
            for swagger_file in found_swagger_files:
                print(
                    f"   📄 {swagger_file['url']} (Status: {swagger_file['status_code']}, Size: {swagger_file['content_length']})"
                )
        else:
            print("❌ [SJ-BRUTE] No Swagger/OpenAPI definition files found")

        if store_db:
            initialize_database(store_db)
            for swagger_file in found_swagger_files:
                scan_data = {
                    "scan_type": "swagger_discovery",
                    "timestamp": datetime.now().isoformat(),
                    "target_url": url,
                    "endpoint": swagger_file["url"],
                    "method": "GET",
                    "status_code": swagger_file["status_code"],
                    "response_size": swagger_file["content_length"],
                    "response_time": 0.0,
                    "vulnerabilities": [],
                    "risk_level": "info",
                    "findings": swagger_file,
                }
                store_scan_result(store_db, scan_data)

        return  # Exit after brute force

    if (
        swagger_url
        or swagger_file
        or swagger_parse
        or swagger_endpoints
        or swagger_prepare
    ):
        swagger_content = ""
        swagger_source = ""

        # Load Swagger content
        if swagger_file:
            if verbose:
                print(
                    f"📂 [SJ] Loading Swagger/OpenAPI from local file: {swagger_file}"
                )
            with open(swagger_file, "r") as f:
                swagger_content = f.read()
            swagger_source = swagger_file
        elif swagger_url:
            if verbose:
                print(f"🌐 [SJ] Loading Swagger/OpenAPI from URL: {swagger_url}")
            try:
                response = session.get(swagger_url, timeout=10, verify=ssl_verify)
                if response.status_code == 200:
                    swagger_content = response.text
                    swagger_source = swagger_url
                else:
                    print(
                        f"❌ [SJ] Failed to load Swagger file: HTTP {response.status_code}"
                    )
                    return
            except Exception as e:
                print(f"❌ [SJ] Error loading Swagger file: {e}")
                return
        else:
            # Try to auto-discover Swagger from current URL
            swagger_urls = [
                f"{url}/swagger.json",
                f"{url}/swagger.yaml",
                f"{url}/openapi.json",
                f"{url}/openapi.yaml",
                f"{url}/api-docs",
                f"{url}/v2/swagger.json",
                f"{url}/v3/swagger.json",
                f"{url}/docs/swagger.json",
            ]

            for test_url in swagger_urls:
                try:
                    response = session.get(test_url, timeout=5, verify=ssl_verify)
                    if response.status_code == 200:
                        content = response.text.lower()
                        if any(
                            indicator in content
                            for indicator in ["swagger", "openapi", "paths", "info"]
                        ):
                            swagger_content = response.text
                            swagger_source = test_url
                            if verbose:
                                print(
                                    f"🎯 [SJ] Auto-discovered Swagger/OpenAPI at: {test_url}"
                                )
                            break
                except Exception:
                    continue

        if not swagger_content:
            print("❌ [SJ] No Swagger/OpenAPI definition found")
            return

        # Parse Swagger content
        api_spec = parse_swagger_openapi(swagger_content, url)

        if "error" in api_spec:
            print(f"❌ [SJ] {api_spec['error']}")
            return

        if verbose:
            print(f"📊 [SJ] Parsed API: {api_spec['title']} v{api_spec['version']}")
            print(f"📊 [SJ] Found {len(api_spec['endpoints'])} endpoints")

        # Handle different SJ modes
        if swagger_endpoints:
            print(f"📋 [SJ-ENDPOINTS] API Endpoints from {swagger_source}:")
            print(f"🔗 API: {api_spec['title']} v{api_spec['version']}")
            if api_spec["description"]:
                print(f"📝 Description: {api_spec['description']}")
            print()

            for endpoint in api_spec["endpoints"]:
                print(f"  {endpoint['method']} {endpoint['path']}")
                if endpoint["summary"]:
                    print(f"    └─ {endpoint['summary']}")

            return  # Exit after listing endpoints

        if swagger_prepare:
            print(
                f"🛠️ [SJ-PREPARE] Generating {swagger_prepare} commands for API testing:"
            )
            print(f"🔗 API: {api_spec['title']} v{api_spec['version']}")
            print()

            # Determine base URL for requests
            base_url = url
            if api_spec["host"]:
                scheme = api_spec["schemes"][0] if api_spec["schemes"] else "https"
                base_url = f"{scheme}://{api_spec['host']}"
            if api_spec["base_path"] and api_spec["base_path"] != "/":
                base_url += api_spec["base_path"]

            commands = generate_swagger_commands(
                api_spec["endpoints"], swagger_prepare, base_url
            )

            for cmd_info in commands:
                print(cmd_info["command"])

            # Store commands in database
            if store_db:
                initialize_database(store_db)
                scan_data = {
                    "scan_type": "swagger_commands",
                    "timestamp": datetime.now().isoformat(),
                    "target_url": swagger_source,
                    "endpoint": base_url,
                    "method": "PREPARE",
                    "status_code": 200,
                    "response_size": len(swagger_content),
                    "response_time": 0.0,
                    "vulnerabilities": [],
                    "risk_level": "info",
                    "findings": {"commands": commands, "api_spec": api_spec},
                }
                store_scan_result(store_db, scan_data)

            return  # Exit after generating commands

        if swagger_parse:
            print("🚀 [SJ-AUTOMATE] Testing API endpoints automatically...")

            # Determine base URL for requests
            base_url = url
            if api_spec["host"]:
                scheme = api_spec["schemes"][0] if api_spec["schemes"] else "https"
                base_url = f"{scheme}://{api_spec['host']}"
            if api_spec["base_path"] and api_spec["base_path"] != "/":
                base_url += api_spec["base_path"]

            # Test all endpoints automatically
            test_results = swagger_automate_test(
                api_spec["endpoints"], session, base_url, rate_limit, ssl_verify
            )

            # Store results in database
            if store_db:
                initialize_database(store_db)
                for result in test_results:
                    scan_data = {
                        "scan_type": "swagger_automate",
                        "timestamp": datetime.now().isoformat(),
                        "target_url": swagger_source,
                        "endpoint": result["url"],
                        "method": result["method"],
                        "status_code": result.get("status_code", 0),
                        "response_size": result.get("content_length", 0),
                        "response_time": result.get("response_time", 0.0),
                        "vulnerabilities": [],
                        "risk_level": "info" if result.get("accessible") else "medium",
                        "findings": result,
                    }
                    store_scan_result(store_db, scan_data)

            # Generate summary report
            accessible = len([r for r in test_results if r.get("accessible", False)])
            auth_required = len(
                [r for r in test_results if r.get("auth_required", False)]
            )
            forbidden = len([r for r in test_results if r.get("forbidden", False)])
            not_found = len([r for r in test_results if r.get("not_found", False)])

            print(f"\n📊 [SJ-AUTOMATE] Test Summary for {api_spec['title']}:")
            print(f"   ✅ Accessible endpoints: {accessible}")
            print(f"   🔐 Authentication required: {auth_required}")
            print(f"   🚫 Forbidden: {forbidden}")
            print(f"   ❌ Not found: {not_found}")

            return  # Exit after automated testing

    # ========== End SJ Integration ==========

    # Prepare endpoints list
    endpoints = []

    # Add base URL
    endpoints.append(url)

    # Load endpoints from file
    if endpoints_file:
        if verbose:
            print(f"📂 [LOAD] Loading endpoints from {endpoints_file}")
        with open(endpoints_file, "r") as f:
            for line in f:
                endpoint = line.strip()
                if endpoint and not endpoint.startswith("#"):
                    if not endpoint.startswith("http"):
                        endpoint = urljoin(url, endpoint)
                    endpoints.append(endpoint)
        if verbose:
            print(f"📝 [LOAD] Loaded {len(endpoints) - 1} endpoints from file")

    # Discover endpoints
    if discover:
        if verbose:
            print("🔍 [DISCOVER] Auto-discovering API endpoints...")
        discovered = discover_api_endpoints(url, timeout=timeout)
        for endpoint in discovered:
            endpoints.append(endpoint["url"])
        if verbose:
            print(f"🔍 [DISCOVER] Found {len(discovered)} endpoints")

    # Remove duplicates
    endpoints = list(set(endpoints))

    if verbose:
        print(f"📊 [TOTAL] Testing {len(endpoints)} endpoints")

    # Test accessibility
    if verbose:
        print("🌐 [CHECK] Testing API accessibility...")
    accessibility = check_api_accessibility(url, timeout)
    if accessibility["accessible"]:
        if verbose:
            print(
                f"✅ [CHECK] API accessible (Status: {accessibility['status_code']}, Server: {accessibility['server']})"
            )
    else:
        print(
            f"❌ [ERROR] API not accessible: {accessibility.get('error', 'Unknown error')}"
        )
        return

    # Technology detection
    if tech_detect:
        if verbose:
            print("🔬 [TECH] Detecting API technologies...")
        tech_info = detect_api_technology(url, timeout)
        if tech_info["technologies"]:
            if verbose:
                print(f"🔬 [TECH] Detected: {', '.join(tech_info['technologies'])}")
        else:
            if verbose:
                print("🔬 [TECH] No specific technologies detected")

    # Initialize results
    all_results = []

    # ========== Resume State Management ==========
    resume_state = None
    if resume:
        resume_state = load_resume_state(output_dir)
        if resume_state:
            if verbose:
                print("🔄 [RESUME] Loading previous scan state...")
                print(
                    f"   📊 Previous progress: {resume_state['scan_progress']['endpoints_scanned']} endpoints"
                )
        else:
            if verbose:
                print("🔄 [RESUME] No previous state found, starting fresh...")
            resume_state = create_resume_state(output_dir, url)
    else:
        # Create fresh resume state for tracking
        resume_state = create_resume_state(output_dir, url)

    # Update total endpoints count
    if resume_state:
        update_resume_state(
            output_dir, {"scan_progress": {"total_endpoints": len(endpoints)}}
        )

    # Process each endpoint
    for i, endpoint in enumerate(endpoints):
        if verbose:
            print(f"🔍 [SCAN] Processing endpoint {i + 1}/{len(endpoints)}: {endpoint}")

        # Check if endpoint was already processed (resume logic)
        if resume and resume_state and isinstance(resume_state, dict):
            completed_scans = resume_state.get("scan_progress", {}).get(
                "completed_scans", []
            )
            if endpoint in completed_scans:
                if verbose:
                    print(f"⏭️ [RESUME] Skipping already processed endpoint: {endpoint}")
                continue

        # ========== Cache System ==========
        cache_key_params = {
            "endpoints": [endpoint],
            "custom_headers": custom_headers,
            "auth_bypass": auth_bypass or security_test,
            "cors_test": cors_test or security_test,
            "injection_test": injection_test or security_test,
        }

        if cache and cache_manager:
            cached_results = cache_manager.get(
                url=endpoint, scan_type="endpoint_scan", **cache_key_params
            )

            if cached_results:
                if verbose:
                    print(f"⚡ [CACHE] Using cached results for {endpoint}")
                all_results.append(cached_results)
                continue

        start_time = time.time()

        endpoint_results = {
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
        }

        # Always check accessibility
        endpoint_results["accessibility"] = check_api_accessibility(endpoint, timeout)

        # Technology detection for each endpoint
        if tech_detect:
            endpoint_results["technology"] = detect_api_technology(endpoint, timeout)

        # HTTP methods testing
        if method_test or security_test:
            if verbose:
                print(f"🔧 [METHODS] Testing HTTP methods on {endpoint}")
            endpoint_results["http_methods"] = test_http_methods(endpoint, timeout)

        # Authentication bypass testing
        if auth_bypass or security_test:
            if verbose:
                print(f"🔐 [AUTH] Testing authentication bypass on {endpoint}")
            endpoint_results["authentication_bypass"] = test_authentication_bypass(
                endpoint, timeout
            )

        # CORS testing
        if cors_test or security_test:
            if verbose:
                print(f"🌐 [CORS] Testing CORS configuration on {endpoint}")
            endpoint_results["cors_configuration"] = test_cors_configuration(
                endpoint, timeout
            )

        # Injection testing
        if injection_test or security_test:
            if verbose:
                print(f"💉 [INJECT] Testing injection vulnerabilities on {endpoint}")
            endpoint_results["injection_tests"] = test_injection_vulnerabilities(
                endpoint, timeout
            )

        # Rate limiting testing
        if rate_limit_test or security_test:
            if verbose:
                print(f"⏱️ [RATE] Testing rate limiting on {endpoint}")
            endpoint_results["rate_limiting"] = test_rate_limiting(
                endpoint, min(max_requests, 10), timeout
            )

        # Parameter pollution testing
        if parameter_pollution or security_test:
            if verbose:
                print(f"🔄 [PARAM] Testing parameter pollution on {endpoint}")
            endpoint_results["parameter_pollution"] = test_parameter_pollution(
                endpoint, timeout
            )

        # JavaScript secret scanning (SJ integration)
        if secret_scan:
            if verbose:
                print(
                    f"🔐 [SECRETS] Scanning JavaScript files for secrets on {endpoint}"
                )
            endpoint_results["javascript_secrets"] = scan_javascript_files(
                endpoint,
                session,
                ssl_verify,
                store_db=(store_db is not None),
                db_path=store_db if store_db else None,
            )

        # ========== Cache Results ==========
        if cache and cache_manager:
            endpoint_results["scan_time"] = time.time() - start_time
            cache_manager.set(
                url=endpoint,
                scan_type="endpoint_scan",
                results=endpoint_results,
                **cache_key_params,
            )
            if verbose:
                print(f"💾 [CACHE] Cached results for {endpoint}")

        all_results.append(endpoint_results)

        # Update resume state
        if resume_state and isinstance(resume_state, dict):
            current_state = load_resume_state(output_dir)
            if current_state:
                completed_scans = current_state.get("scan_progress", {}).get(
                    "completed_scans", []
                )
                completed_scans.append(endpoint)
                update_resume_state(
                    output_dir,
                    {
                        "scan_progress": {
                            "endpoints_scanned": i + 1,
                            "completed_scans": completed_scans,
                        }
                    },
                )

        # Store results in database if --store-db is specified
        if store_db:
            if verbose:
                print(f"💾 [DB] Storing results to database: {store_db}")
            initialize_database(store_db)

            # Store main scan result
            scan_data = {
                "scan_type": "api_scan",
                "timestamp": endpoint_results.get("timestamp"),
                "target_url": url,
                "endpoint": endpoint,
                "method": "GET",
                "status_code": endpoint_results.get("accessibility", {}).get(
                    "status_code", 0
                ),
                "response_size": 0,
                "response_time": 0.0,
                "vulnerabilities": [],
                "risk_level": "unknown",
                "findings": endpoint_results,
            }
            store_scan_result(store_db, scan_data)

        # Add delay between requests
        if delay > 0:
            time.sleep(delay)

    # Generate security report
    if security_test or any(
        [
            method_test,
            auth_bypass,
            cors_test,
            injection_test,
            rate_limit_test,
            parameter_pollution,
        ]
    ):
        if verbose:
            print("📊 [REPORT] Generating security report...")
        security_report = generate_security_report(all_results)

        # ========== AI-Powered Analysis ==========
        if ai_mode or ai_smart_analysis or ai_reduce_fp or ai_executive_summary:
            if verbose:
                print("🤖 [AI] Running AI-powered analysis...")

            # AI Smart Analysis
            if ai_smart_analysis or ai_mode:
                if verbose:
                    print("🎯 [AI] Smart API endpoint analysis...")
                ai_analyzed_results = ai_smart_api_analysis(
                    all_results, ai_cache_manager
                )
                security_report["ai_smart_analysis"] = ai_analyzed_results

                # Filter high-confidence results
                high_confidence_results = [
                    r
                    for r in ai_analyzed_results
                    if r.get("ai_confidence", 0) >= ai_confidence_threshold
                ]

                if high_confidence_results:
                    print(
                        f"🎯 [AI-SMART] Identified {len(high_confidence_results)} high-confidence security issues"
                    )
                    for result in high_confidence_results[:3]:  # Show top 3
                        print(
                            f"    • {result['endpoint']} - {result['ai_priority']} (confidence: {result['ai_confidence']:.2f})"
                        )

            # AI False Positive Reduction
            if ai_reduce_fp or ai_mode:
                if verbose:
                    print("🔍 [AI] Reducing false positives...")
                filtered_results = ai_reduce_false_positives(
                    security_report["detailed_results"],
                    ai_confidence_threshold,
                    ai_cache_manager,
                )
                security_report["ai_filtered_results"] = filtered_results

                reduction_count = len(security_report["detailed_results"]) - len(
                    filtered_results
                )
                if reduction_count > 0:
                    print(
                        f"🎯 [AI-FP] Filtered out {reduction_count} potential false positives"
                    )

            # AI Executive Summary
            if ai_executive_summary or ai_mode:
                if verbose:
                    print("📋 [AI] Generating executive summary...")
                ai_summary = ai_executive_summary(
                    security_report.get("ai_smart_analysis", all_results),
                    ai_confidence_threshold,
                )
                security_report["ai_executive_summary"] = ai_summary

                print(
                    f"📋 [AI-EXEC] Overall Risk: {ai_summary['risk_assessment']['overall_risk']}"
                )
                print(
                    f"    Critical: {ai_summary['risk_assessment']['critical_issues']}, High: {ai_summary['risk_assessment']['high_risk_issues']}"
                )

                if ai_summary.get("business_impact"):
                    print("💼 [AI-IMPACT] Key Business Impacts:")
                    for impact in ai_summary["business_impact"][:2]:
                        print(f"    • {impact}")
    else:
        security_report = {
            "summary": {
                "total_endpoints": len(all_results),
                "vulnerable_endpoints": 0,
                "high_risk_issues": [],
                "medium_risk_issues": [],
                "low_risk_issues": [],
            },
            "detailed_results": all_results,
            "recommendations": [],
            "timestamp": datetime.now().isoformat(),
        }

    # Save results
    output_files = []

    if json_report:
        json_file = save_results(security_report, output_dir, "json")
        output_files.append(json_file)
        if verbose:
            print(f"💾 [SAVE] JSON report saved to {json_file}")

    if yaml_report:
        yaml_file = save_results(security_report, output_dir, "yaml")
        output_files.append(yaml_file)
        if verbose:
            print(f"💾 [SAVE] YAML report saved to {yaml_file}")

    if markdown_report:
        markdown_file = save_results(security_report, output_dir, "markdown")
        output_files.append(markdown_file)
        if verbose:
            print(f"💾 [SAVE] Markdown report saved to {markdown_file}")

    # Update resume state with result files
    if resume_state and output_files:
        update_resume_state(output_dir, {"results_files": output_files})

    # Print summary
    if verbose:
        print("\n📊 [SUMMARY] Scan Results:")
        print(
            f"   🎯 Total endpoints tested: {security_report['summary']['total_endpoints']}"
        )
        print(
            f"   🚨 High risk issues: {len(security_report['summary']['high_risk_issues'])}"
        )
        print(
            f"   ⚠️  Medium risk issues: {len(security_report['summary']['medium_risk_issues'])}"
        )
        print(f"   📁 Reports saved: {len(output_files)}")

    # Send notifications
    if slack_webhook or discord_webhook:
        summary = f"APICLI scan completed for {url}. Found {len(security_report['summary']['high_risk_issues'])} high-risk issues."

        if slack_webhook:
            if send_notification(slack_webhook, summary, "slack"):
                if verbose:
                    print("📲 [NOTIFY] Slack notification sent")

        if discord_webhook:
            if send_notification(discord_webhook, summary, "discord"):
                if verbose:
                    print("📲 [NOTIFY] Discord notification sent")

    # ========== Cache Performance Summary ==========
    if cache and cache_manager:
        stats = cache_manager.get_cache_stats()
        if stats["total_requests"] > 0:
            print(f"\n⚡ [CACHE] Performance Summary:")
            print(f"    Cache hits: {stats['cache_hits']}")
            print(f"    Cache misses: {stats['cache_misses']}")
            print(f"    Hit rate: {stats['hit_rate']}%")
            print(f"    Cache files: {stats['cache_files']}")

            if stats["cache_hits"] > 0:
                time_saved = stats["cache_hits"] * 5  # Estimate 5s per cached request
                print(f"    Estimated time saved: ~{time_saved}s")

    # ========== AI Cache Performance Summary ==========
    if ai_cache and ai_cache_manager:
        try:
            stats = ai_cache_manager.get_cache_stats()
            if stats.get("total_requests", 0) > 0:
                print(f"\n🤖 [AI-CACHE] Performance Summary:")
                print(f"    Total entries: {stats.get('total_entries', 0)}")
                print(f"    Cache size: {stats.get('cache_size_mb', 0.0)} MB")
                print(f"    Hit rate: {stats.get('hit_rate_percent', 0.0)}%")
                print(f"    Hits: {stats.get('hits', 0)}")
                print(f"    Misses: {stats.get('misses', 0)}")

                if stats.get("hits", 0) > 0:
                    ai_time_saved = (
                        stats.get("hits", 0) * 2
                    )  # Estimate 2s per AI analysis
                    print(f"    Estimated AI time saved: ~{ai_time_saved}s")
        except Exception as e:
            if verbose:
                print(f"⚠️  [AI-CACHE] Could not get cache stats: {e}")

    if verbose:
        print("🎉 [COMPLETE] APICLI scan finished successfully!")


if __name__ == "__main__":
    main()
