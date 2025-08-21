#!/usr/bin/env python3
import re
import sys
import json
import click
import mimetypes
import requests
import time
import math
import subprocess
import tempfile
import os
import zipfile
import string
from collections import Counter
from pathlib import Path

# Import tagging functions from tagger module
try:
    from .tagger import (
        auto_tag as tagger_auto_tag,
        calculate_risk_score,
        load_custom_rules,
        apply_custom_rules,
    )
except ImportError:
    # Fallback if tagger module not available
    def auto_tag(entry):
        return []

    def calculate_risk_score(domain, tags):
        return 0

    def load_custom_rules(rules_file):
        return {}

    def apply_custom_rules(entry, custom_rules):
        return []


from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color codes removal
ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")


def clean_ansi_codes(text):
    """Remove ANSI color codes and escape sequences from text."""
    if not text:
        return text
    # Remove ANSI escape sequences
    text = ANSI_REGEX.sub("", text)
    # Remove specific patterns like [36m, [0m, [35m
    text = re.sub(r"\[[\d;]*m", "", text)
    return text


def shannon_entropy(string):
    """
    Calculate Shannon entropy of a string.

    Shannon entropy measures the randomness or information content in data.
    Higher entropy values indicate more randomness, which can be useful for
    detecting encoded data, encrypted content, or high-entropy secrets.

    Args:
        string (str): Input string to calculate entropy for

    Returns:
        float: Shannon entropy value (0.0 to ~8.0 for typical strings)

    Examples:
        >>> shannon_entropy("aaaa")
        0.0
        >>> shannon_entropy("abcd")
        2.0
        >>> shannon_entropy("random_string_123")
        # Returns higher entropy value
    """
    if not string:
        return 0.0

    # Count frequency of each character
    char_counts = Counter(string)
    string_length = len(string)

    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        # Calculate probability of each character
        probability = count / string_length
        # Add to entropy calculation
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def detect_entropy_strings(strings, threshold=4.0, min_length=20):
    """
    Detect high-entropy strings that might be secrets, keys, or encoded data.

    Args:
        strings (list): List of strings to analyze
        threshold (float): Minimum entropy threshold (default: 4.0)
        min_length (int): Minimum string length to consider (default: 20)

    Returns:
        list: List of dictionaries with structure:
              [{"value": str, "entropy": float, "source": str}, ...]

    Examples:
        >>> detect_entropy_strings(["aaaaaaaa", "AKIAEXAMPLE123"])
        # Returns strings with entropy >= threshold and length >= min_length
    """
    results = []

    for string in strings:
        # Skip strings that are too short
        if len(string) < min_length:
            continue

        # Calculate entropy
        string_entropy = shannon_entropy(string)

        # Check if entropy meets threshold
        if string_entropy >= threshold:
            results.append(
                {
                    "value": string,
                    "entropy": string_entropy,
                    "source": "entropy_detection",
                }
            )

    return results


def generate_hex_dump(file_path, max_bytes=1024):
    """
    Generate hex dump of a file using xxd command.

    Args:
        file_path (str): Path to the file to dump
        max_bytes (int): Maximum number of bytes to dump (default: 1024)

    Returns:
        dict: Dictionary containing hex dump data:
              {
                "file_path": str,
                "hex_dump": str,
                "file_size": int,
                "truncated": bool,
                "error": str (if any)
              }
    """
    result = {
        "file_path": file_path,
        "hex_dump": "",
        "file_size": 0,
        "truncated": False,
        "error": None,
    }

    try:
        # Check if file exists and get size
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        file_size = os.path.getsize(file_path)
        result["file_size"] = file_size

        # Check if we need to truncate
        if file_size > max_bytes:
            result["truncated"] = True

        # Use xxd to generate hex dump with limit
        cmd = ["xxd", "-l", str(max_bytes), file_path]

        try:
            process_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )

            if process_result.returncode == 0:
                result["hex_dump"] = process_result.stdout
            else:
                result["error"] = f"xxd failed: {process_result.stderr}"

        except subprocess.TimeoutExpired:
            result["error"] = "xxd command timed out"
        except FileNotFoundError:
            result["error"] = "xxd command not found - please install xxd utility"

    except Exception as e:
        result["error"] = f"Error generating hex dump: {str(e)}"

    return result


def generate_hex_dumps_for_files(file_paths, max_bytes=1024):
    """
    Generate hex dumps for multiple files.

    Args:
        file_paths (list): List of file paths to dump
        max_bytes (int): Maximum bytes per file dump

    Returns:
        list: List of hex dump results
    """
    dumps = []

    for file_path in file_paths:
        dump_result = generate_hex_dump(file_path, max_bytes)
        dumps.append(dump_result)

    return dumps


def extract_strings_from_file(file_path, min_length=4):
    """
    Extract ASCII/UTF-8 strings from binary files.

    Args:
        file_path (str): Path to the file to extract strings from
        min_length (int): Minimum string length to extract (default: 4)

    Returns:
        dict: Dictionary containing extracted strings:
              {
                "file_path": str,
                "strings": list,
                "count": int,
                "error": str (if any)
              }
    """
    result = {"file_path": file_path, "strings": [], "count": 0, "error": None}

    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        # Read file in binary mode
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract printable ASCII strings
        ascii_strings = []
        current_string = ""

        for byte in data:
            char = chr(byte) if byte < 128 else None
            if char and char in string.printable and char not in "\t\r\n\x0b\x0c":
                current_string += char
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append(current_string)
                current_string = ""

        # Don't forget the last string
        if len(current_string) >= min_length:
            ascii_strings.append(current_string)

        # Try to extract UTF-8 strings as well
        try:
            text = data.decode("utf-8", errors="ignore")
            # Find sequences of printable characters
            import re

            utf8_strings = re.findall(r"[^\x00-\x1f\x7f-\x9f]{4,}", text)

            # Combine and deduplicate
            all_strings = list(set(ascii_strings + utf8_strings))
            all_strings = [
                s.strip() for s in all_strings if len(s.strip()) >= min_length
            ]

            result["strings"] = sorted(all_strings)
            result["count"] = len(all_strings)

        except Exception as e:
            result["strings"] = ascii_strings
            result["count"] = len(ascii_strings)

    except Exception as e:
        result["error"] = f"Error extracting strings: {str(e)}"

    return result


def extract_and_scan_zip(zip_path, temp_dir=None):
    """
    Extract ZIP/JAR/APK archives and scan contents with ExtractorCLI.

    Args:
        zip_path (str): Path to the ZIP archive
        temp_dir (str): Temporary directory for extraction

    Returns:
        dict: Dictionary containing extraction results:
              {
                "archive_path": str,
                "extracted_files": list,
                "scan_results": dict,
                "error": str (if any)
              }
    """
    result = {
        "archive_path": zip_path,
        "extracted_files": [],
        "scan_results": {},
        "error": None,
    }

    try:
        if not os.path.exists(zip_path):
            result["error"] = f"Archive not found: {zip_path}"
            return result

        # Create temporary directory
        if temp_dir is None:
            temp_dir = tempfile.mkdtemp(prefix="extractorcli_zip_")

        # Extract archive
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)
            result["extracted_files"] = zip_ref.namelist()

        # Scan extracted files
        extracted_content = {}
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, temp_dir)

                try:
                    # Read file content for scanning
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if content.strip():
                            extracted_content[rel_path] = content
                except Exception:
                    # For binary files, just note their presence
                    extracted_content[rel_path] = f"[Binary file: {file_path}]"

        result["scan_results"] = extracted_content

    except zipfile.BadZipFile:
        result["error"] = f"Invalid ZIP archive: {zip_path}"
    except Exception as e:
        result["error"] = f"Error extracting archive: {str(e)}"

    return result


def check_cors_headers(headers_text):
    """
    Check for CORS vulnerabilities in HTTP headers.

    Args:
        headers_text (str): HTTP headers as text

    Returns:
        dict: CORS analysis results
    """
    result = {"cors_issues": [], "headers_found": [], "vulnerabilities": []}

    # Look for CORS headers
    cors_headers = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
    ]

    lines = headers_text.split("\n")
    for line in lines:
        line = line.strip()
        for header in cors_headers:
            if line.lower().startswith(header.lower() + ":"):
                value = line.split(":", 1)[1].strip()
                result["headers_found"].append(f"{header}: {value}")

                # Check for dangerous configurations
                if header == "Access-Control-Allow-Origin" and value == "*":
                    result["vulnerabilities"].append(
                        {
                            "type": "Wildcard CORS Origin",
                            "header": f"{header}: {value}",
                            "severity": "HIGH",
                            "description": "Allows any domain to make cross-origin requests",
                        }
                    )

                if (
                    header == "Access-Control-Allow-Credentials"
                    and value.lower() == "true"
                ):
                    # Check if also has wildcard origin
                    for other_line in lines:
                        if (
                            "access-control-allow-origin" in other_line.lower()
                            and "*" in other_line
                        ):
                            result["vulnerabilities"].append(
                                {
                                    "type": "CORS Credentials with Wildcard",
                                    "header": f"{header}: {value}",
                                    "severity": "CRITICAL",
                                    "description": "Allows credentials with wildcard origin",
                                }
                            )

    return result


def analyze_csp_header(csp_header):
    """
    Analyze Content-Security-Policy headers for security issues.

    Args:
        csp_header (str): CSP header value

    Returns:
        dict: CSP analysis results
    """
    result = {"directives": {}, "unsafe_items": [], "sources": [], "issues": []}

    if not csp_header:
        return result

    # Parse CSP directives
    directives = csp_header.split(";")

    for directive in directives:
        directive = directive.strip()
        if not directive:
            continue

        parts = directive.split()
        if not parts:
            continue

        directive_name = parts[0]
        sources = parts[1:] if len(parts) > 1 else []

        result["directives"][directive_name] = sources
        result["sources"].extend(sources)

        # Check for unsafe configurations
        for source in sources:
            if source == "*":
                result["unsafe_items"].append(
                    {
                        "directive": directive_name,
                        "value": source,
                        "type": "Wildcard source",
                        "severity": "HIGH",
                    }
                )
                result["issues"].append(f"⚠️  {directive_name} allows wildcard (*)")

            elif source in ["'unsafe-inline'", "'unsafe-eval'"]:
                result["unsafe_items"].append(
                    {
                        "directive": directive_name,
                        "value": source,
                        "type": "Unsafe directive",
                        "severity": "MEDIUM",
                    }
                )
                result["issues"].append(f"⚠️  {directive_name} allows {source}")

            elif source.startswith("data:"):
                result["unsafe_items"].append(
                    {
                        "directive": directive_name,
                        "value": source,
                        "type": "Data URI",
                        "severity": "LOW",
                    }
                )

    return result


# Enhanced regex patterns for better extraction
URL_REGEX = re.compile(r"https?://[^\s\"'<>\[\](){}]+")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
FORM_REGEX = re.compile(r"<form[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
INPUT_REGEX = re.compile(r"<input[^>]*>", re.IGNORECASE)
AUTH_REGEX = re.compile(
    r"/(auth|login|signin|jwt|token|oauth|sso|saml)[^\"'\s<>]*", re.IGNORECASE
)
API_REGEX = re.compile(r"/(api|v1|v2|v3|rest|graphql)[^\"'\s<>]*", re.IGNORECASE)
SWAGGER_REGEX = re.compile(r"/(swagger|openapi|docs|redoc)[^\"'\s<>]*", re.IGNORECASE)

# JWT pattern - three Base64 segments separated by dots
JWT_REGEX = re.compile(r"\b[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b")

# Base64 pattern - at least 20 characters
BASE64_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

# WebSocket endpoints
WS_REGEX = re.compile(r"\bwss?://[^\s\"'<>\[\](){}]+", re.IGNORECASE)

# Enhanced patterns for API documentation - more precise matching
# Enhanced GraphQL patterns - includes common variations and typos
GRAPHQL_REGEX = re.compile(
    r"\b(graphql|grahql|grafql|graphq|takgraphql|graphiql|graphql.*(?:playground|explorer|interface|endpoint|api|ui|ide))\b",
    re.IGNORECASE,
)
GRAPHQL_FULL_REGEX = re.compile(
    r"\b(GraphQL|GrahQL|GrafQL|GraphQ|takGraphQL|GraphiQL)\s+(playground|explorer|interface|endpoint|API|UI|IDE)\b",
    re.IGNORECASE,
)
API_DOCS_REGEX = re.compile(
    r"\b(Swagger\s+UI|OpenAPI|API\s+Docs|LiteLLM\s+API|uCrawler\s+Agent\s+API\s+Docs)\b",
    re.IGNORECASE,
)
API_TITLE_REGEX = re.compile(
    r"https?://[^\s]+\s+\[([^\]]+(?:API|OpenAPI|Swagger|GraphQL|GrahQL|GraphiQL)[^\]]*)\]",
    re.IGNORECASE,
)  # API-related titles only
TECH_STACK_REGEX = re.compile(
    r"\[([^\]]+,\s*[^\]]+[^\]]*)\]", re.IGNORECASE
)  # Brackets with comma-separated tech stack

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
SUBDOMAIN_REGEX = lambda domain: re.compile(
    rf"\b((?:[\w-]+\.)+{re.escape(domain)})\b", re.IGNORECASE
)
SECRET_REGEX = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|pwd)[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=_-]+)"
)
JS_VAR_REGEX = re.compile(r"(?:var|let|const)\s+(\w+)\s*=\s*[\"']([^\"']+)[\"']")
COMMENT_REGEX = re.compile(r"<!--.*?-->|//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
AWS_KEY_REGEX = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_TOKEN_REGEX = re.compile(r"gh[ps]_[A-Za-z0-9]{36}")
SLACK_TOKEN_REGEX = re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")
JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")

# Additional secret patterns
DISCORD_TOKEN_REGEX = re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}")
TELEGRAM_BOT_REGEX = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")
STRIPE_KEY_REGEX = re.compile(r"sk_live_[0-9a-zA-Z]{24}")
PAYPAL_CLIENT_REGEX = re.compile(r"A[0-9A-Za-z_-]{79}")
MAILGUN_KEY_REGEX = re.compile(r"key-[0-9a-z]{32}")
TWILIO_SID_REGEX = re.compile(r"AC[a-z0-9]{32}")
SENDGRID_KEY_REGEX = re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}")
OPENAI_KEY_REGEX = re.compile(r"sk-[a-zA-Z0-9]{48}")
ANTHROPIC_KEY_REGEX = re.compile(r"sk-ant-[a-zA-Z0-9-]{95,}")
GOOGLE_API_KEY_REGEX = re.compile(r"AIza[0-9A-Za-z-_]{35}")
AZURE_KEY_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
DOCKER_TOKEN_REGEX = re.compile(r"dckr_pat_[a-zA-Z0-9_-]{36}")
HEROKU_API_KEY_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
CLOUDFLARE_TOKEN_REGEX = re.compile(r"[a-zA-Z0-9_-]{40}")
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----")
SSH_KEY_REGEX = re.compile(r"ssh-rsa [A-Za-z0-9+/]+[=]{0,3}")
DATABASE_URL_REGEX = re.compile(r"(?:postgres|mysql|mongodb)://[^\s\"'<>]+")
CONNECTION_STRING_REGEX = re.compile(
    r"(?:Server|Data Source|mongodb|redis)=[^\s;\"'<>]+"
)
ENV_VAR_REGEX = re.compile(r"[A-Z_]+=[a-zA-Z0-9+/=_-]{20,}")
# Mobile and Social Media patterns
PHONE_REGEX = re.compile(r"(\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})")
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)
SOCIAL_SECURITY_REGEX = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
TWITTER_HANDLE_REGEX = re.compile(r"@[A-Za-z0-9_]{1,15}")
INSTAGRAM_HANDLE_REGEX = re.compile(r"instagram\.com/([A-Za-z0-9_.]+)")
YOUTUBE_CHANNEL_REGEX = re.compile(
    r"youtube\.com/(?:c/|channel/|user/)([A-Za-z0-9_-]+)"
)
LINKEDIN_PROFILE_REGEX = re.compile(r"linkedin\.com/in/([A-Za-z0-9_-]+)")
FACEBOOK_PROFILE_REGEX = re.compile(r"facebook\.com/([A-Za-z0-9_.]+)")
DISCORD_INVITE_REGEX = re.compile(r"discord\.gg/[A-Za-z0-9]+")
TELEGRAM_CHANNEL_REGEX = re.compile(r"t\.me/([A-Za-z0-9_]+)")

# Crypto and Blockchain patterns
BITCOIN_ADDRESS_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
ETHEREUM_ADDRESS_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
MONERO_ADDRESS_REGEX = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
CRYPTO_WALLET_REGEX = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"
)

# API and configuration patterns
API_ENDPOINT_SECRET_REGEX = re.compile(
    r"(?:secret|key|token|password|pwd|api_key)[\"\']?\s*:\s*[\"\']([a-zA-Z0-9+/=_-]{10,})[\"\']?"
)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔍 TRUFFLEHOG INTEGRATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def run_trufflehog_scan(
    content,
    config_file=None,
    rules_file=None,
    exclude_detectors=None,
    include_detectors=None,
    concurrency=8,
    depth=100,
    archive_scan=False,
    verified_only=False,
    no_verification=False,
    entropy_threshold=3.0,
    verbose=False,
):
    """
    Run TruffleHog scan on content and return found secrets.

    Args:
        content (str): Content to scan for secrets
        config_file (str): Path to TruffleHog config file
        rules_file (str): Path to custom rules file
        exclude_detectors (list): List of detectors to exclude
        include_detectors (list): List of detectors to include
        concurrency (int): Number of concurrent workers
        depth (int): Maximum scan depth
        archive_scan (bool): Enable archive scanning
        verified_only (bool): Only return verified secrets
        no_verification (bool): Skip verification
        entropy_threshold (float): Minimum entropy threshold
        verbose (bool): Verbose output

    Returns:
        list: List of found secrets with metadata
    """
    try:
        import tempfile
        import json

        # Create temporary file with content
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp_file:
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        # Build TruffleHog command
        cmd = ["trufflehog", "filesystem", tmp_file_path]

        # Add configuration options
        if config_file:
            cmd.extend(["--config", config_file])

        if rules_file:
            cmd.extend(["--rules", rules_file])

        if exclude_detectors:
            for detector in exclude_detectors:
                cmd.extend(["--exclude-detectors", detector])

        if include_detectors:
            for detector in include_detectors:
                cmd.extend(["--include-detectors", detector])

        cmd.extend(["--concurrency", str(concurrency)])

        if archive_scan:
            cmd.append("--archive")

        if verified_only:
            cmd.append("--only-verified")

        if no_verification:
            cmd.append("--no-verification")

        # Always use JSON output for parsing
        cmd.append("--json")

        if verbose:
            click.echo(f"🔍 [TRUFFLEHOG] Running: {' '.join(cmd)}")

        # Execute TruffleHog
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300  # 5 minute timeout
        )

        # Clean up temp file
        Path(tmp_file_path).unlink(missing_ok=True)

        if result.returncode != 0:
            if verbose:
                click.echo(f"⚠️ [TRUFFLEHOG] Warning: {result.stderr}")
            return []

        # Parse JSON results
        secrets = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    secret_data = json.loads(line)

                    # Apply entropy filtering - check if entropy field exists
                    entropy = 0
                    if "entropy" in secret_data:
                        entropy = secret_data.get("entropy", 0)
                    elif isinstance(secret_data.get("Raw"), str):
                        # Calculate basic entropy for the raw secret
                        raw_secret = secret_data.get("Raw", "")
                        if raw_secret and len(raw_secret) > 1:
                            # Simple entropy calculation without math import
                            char_counts = {}
                            for c in raw_secret:
                                char_counts[c] = char_counts.get(c, 0) + 1

                            entropy = 0
                            total_chars = len(raw_secret)
                            for count in char_counts.values():
                                p = count / total_chars
                                if p > 0:
                                    # Use natural log approximation
                                    entropy -= p * (p**0.5)  # Simple approximation

                    if entropy < entropy_threshold:
                        continue

                    # Extract relevant information
                    secret_info = {
                        "detector_name": secret_data.get("DetectorName", "unknown"),
                        "detector_type": secret_data.get("DetectorType", "unknown"),
                        "raw_secret": secret_data.get("Raw", ""),
                        "redacted": secret_data.get("Redacted", ""),
                        "entropy": entropy,
                        "verified": secret_data.get("Verified", False),
                        "source_metadata": secret_data.get("SourceMetadata", {}),
                        "extra_data": secret_data.get("ExtraData", {}),
                        "structured_data": secret_data.get("StructuredData", {}),
                    }

                    secrets.append(secret_info)

                except json.JSONDecodeError:
                    continue

        if verbose:
            click.echo(f"✅ [TRUFFLEHOG] Found {len(secrets)} secrets")

        return secrets

    except subprocess.TimeoutExpired:
        if verbose:
            click.echo("⏱️ [TRUFFLEHOG] Scan timeout reached")
        return []
    except subprocess.CalledProcessError as e:
        if verbose:
            click.echo(f"❌ [TRUFFLEHOG] Scan failed: {e}")
        return []
    except FileNotFoundError:
        if verbose:
            click.echo(
                "❌ [TRUFFLEHOG] TruffleHog not found in PATH. Install with: pip install trufflehog"
            )
        return []
    except Exception as e:
        if verbose:
            click.echo(f"❌ [TRUFFLEHOG] Unexpected error: {e}")
        return []


def process_trufflehog_results(
    secrets, auto_tag_enabled=False, risk_scoring_enabled=False
):
    """
    Process TruffleHog results and convert to ExtractorCLI format.

    Args:
        secrets (list): List of secrets from TruffleHog
        auto_tag_enabled (bool): Whether to apply auto-tagging
        risk_scoring_enabled (bool): Whether to apply risk scoring

    Returns:
        list: Processed secrets in ExtractorCLI format
    """
    processed_secrets = []

    detector_risk_map = {
        "aws": 9,
        "github": 8,
        "google": 8,
        "slack": 7,
        "stripe": 8,
        "twilio": 7,
        "mailgun": 6,
        "sendgrid": 6,
        "discord": 5,
        "telegram": 5,
        "private_key": 9,
        "ssh_key": 8,
        "jwt": 6,
        "database": 9,
        "openai": 8,
        "anthropic": 8,
        "azure": 8,
        "gcp": 8,
        "docker": 7,
        "heroku": 7,
        "cloudflare": 7,
    }

    for secret in secrets:
        detector = secret["detector_name"].lower()

        # Calculate risk score
        base_risk = detector_risk_map.get(detector, 5)
        entropy_bonus = (
            min(2, int(secret["entropy"] - 3)) if secret["entropy"] > 3 else 0
        )
        verification_bonus = 2 if secret["verified"] else 0

        risk_score = min(10, base_risk + entropy_bonus + verification_bonus)

        # Generate tags
        tags = ["secret", "trufflehog"]
        if secret["verified"]:
            tags.append("verified")
        if secret["entropy"] > 4.5:
            tags.append("high_entropy")
        if detector in ["aws", "github", "google", "azure", "gcp"]:
            tags.append("cloud_service")
        if detector in ["private_key", "ssh_key"]:
            tags.append("cryptographic_key")
        if detector in ["database", "mongodb", "mysql", "postgres"]:
            tags.append("database_credential")

        # Auto-tag if enabled
        if auto_tag_enabled:
            tags.extend(["sensitive", "credential"])

        processed_secret = {
            "content": secret["redacted"] or secret["raw_secret"][:50] + "...",
            "raw_content": secret["raw_secret"],
            "detector": secret["detector_name"],
            "detector_type": secret["detector_type"],
            "entropy": secret["entropy"],
            "verified": secret["verified"],
            "tags": tags,
            "risk_level": risk_score if risk_scoring_enabled else 0,
            "source_metadata": secret["source_metadata"],
            "extra_data": secret["extra_data"],
            "structured_data": secret["structured_data"],
        }

        processed_secrets.append(processed_secret)

    return processed_secrets


@click.command(name="extractorcli")
@click.argument("input", type=click.Path(exists=True), required=False)
@click.option(
    "--input-file",
    "-i",
    type=click.Path(exists=True),
    help="Input file path (alternative to positional argument)",
)
@click.option(
    "--input-url",
    "-u",
    help="Single URL to process directly",
)
@click.option(
    "--input-list",
    "-l",
    type=click.Path(exists=True),
    help="File containing list of URLs to process",
)
@click.option(
    "--types",
    "-t",
    default="url,email,form,auth,api,swagger,graphql,api_docs,tech_stack,ip,domain,subdomain,secret,js,comment",
    help="Types to extract: url,email,form,auth,api,swagger,graphql,api_docs,tech_stack,ip,domain,subdomain,secret,js,comment,hash,base64,phone,crypto,social,pii",
)
@click.option("--target-domain", "-d", help="Domain for subdomain extraction")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--output-dir", type=click.Path(), help="Output directory for multiple files"
)
@click.option(
    "--output-dir", type=click.Path(), help="Output directory for multiple files"
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON format")
@click.option(
    "--to-jsonl", is_flag=True, help="Export each entry as JSONL (JSON Lines)"
)
@click.option("--tagged", is_flag=True, help="Tag results by category with metadata")
@click.option("--csv", is_flag=True, help="Output results as CSV format")
@click.option("--xml", is_flag=True, help="Output results as XML format")
@click.option("--ai-score", is_flag=True, help="Score results based on AI heuristics")
@click.option(
    "--score-threshold", default=0, type=int, help="Minimum score threshold for results"
)
@click.option("--limit", "-n", type=int, help="Limit number of results per category")
@click.option(
    "--smart-detect", is_flag=True, help="Auto-detect file type for better extraction"
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--file-patterns", help="File patterns to match (e.g., '*.html,*.js')")
@click.option(
    "--exclude-patterns", help="File patterns to exclude (e.g., '*.min.js,*.gz')"
)
@click.option(
    "--fetch-urls",
    "-f",
    is_flag=True,
    help="Fetch content from URLs and extract from them",
)
@click.option(
    "--fetch-depth", default=1, type=int, help="Depth level for recursive URL fetching"
)
@click.option(
    "--threads",
    default=10,
    type=int,
    help="Number of threads for concurrent URL fetching",
)
@click.option(
    "--timeout", default=10, type=int, help="Timeout for URL requests (seconds)"
)
@click.option(
    "--retry-count", default=3, type=int, help="Number of retries for failed requests"
)
@click.option(
    "--retry-delay", default=1, type=int, help="Delay between retries (seconds)"
)
@click.option(
    "--user-agent",
    default="ExtractorCLI/2.0 (+https://github.com/reconcli)",
    help="Custom User-Agent for HTTP requests",
)
@click.option(
    "--follow-redirects", is_flag=True, help="Follow HTTP redirects automatically"
)
@click.option(
    "--max-redirects", default=5, type=int, help="Maximum number of redirects to follow"
)
@click.option(
    "--include-comments", is_flag=True, help="Include HTML/JS comments in extraction"
)
@click.option(
    "--deep-js",
    is_flag=True,
    help="Deep JavaScript analysis for variables and functions",
)
@click.option(
    "--extract-inline", is_flag=True, help="Extract inline JavaScript and CSS"
)
@click.option(
    "--extract-base64", is_flag=True, help="Decode and analyze base64 content"
)
@click.option(
    "--verify-ssl", is_flag=True, default=True, help="Verify SSL certificates"
)
@click.option(
    "--insecure", is_flag=True, help="Disable SSL verification (security risk)"
)
@click.option("--proxy", help="HTTP proxy (e.g., http://proxy:8080)")
@click.option("--headers", help="Custom headers as JSON string")
@click.option("--cookies", help="Custom cookies as string")
@click.option(
    "--max-size", default=5, type=int, help="Maximum file size to download (MB)"
)
@click.option(
    "--min-length", default=1, type=int, help="Minimum length for extracted items"
)
@click.option(
    "--max-length", default=2048, type=int, help="Maximum length for extracted items"
)
@click.option("--encoding", default="utf-8", help="File encoding for text processing")
@click.option(
    "--verbose", "-v", is_flag=True, help="Verbose output with detailed information"
)
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode - minimal output")
@click.option("--debug", is_flag=True, help="Debug mode with extra information")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--dedup", is_flag=True, help="Remove duplicates from results")
@click.option(
    "--merge-with",
    type=click.Path(exists=True),
    help="Merge with existing file and deduplicate",
)
@click.option(
    "--dedup-by", default="url", help="Deduplicate by type: url,domain,email,all"
)
@click.option(
    "--dedup-strategy", default="first", help="Dedup strategy: first,last,merge"
)
@click.option("--sort-results", is_flag=True, help="Sort results alphabetically")
@click.option("--sort-by", default="value", help="Sort by: value,length,score")
@click.option(
    "--unique-only",
    is_flag=True,
    help="Only show unique results (removes all seen before)",
)
@click.option("--filter-regex", help="Filter results with regex pattern")
@click.option("--exclude-regex", help="Exclude results matching regex pattern")
@click.option("--whitelist-domains", help="Comma-separated list of allowed domains")
@click.option("--blacklist-domains", help="Comma-separated list of blocked domains")
@click.option("--xss-scan", is_flag=True, help="Run XSS-Vibes scan on extracted URLs")
@click.option("--xss-discover", is_flag=True, help="Use XSS-Vibes endpoint discovery")
@click.option("--xss-threads", default=5, type=int, help="Threads for XSS scanning")
@click.option("--xss-timeout", default=5, type=int, help="Timeout for XSS requests")
@click.option(
    "--xss-depth", default=2, type=int, help="Depth for XSS endpoint discovery"
)
@click.option("--xss-payloads", help="Custom XSS payloads file")
@click.option("--report", is_flag=True, help="Generate comprehensive report")
@click.option("--report-format", default="html", help="Report format: html,pdf,txt")
@click.option("--store-db", is_flag=True, help="Store results in SQLite database")
@click.option("--db-path", default="extractorcli_results.db", help="Database file path")
@click.option("--config", type=click.Path(), help="Configuration file path")
@click.option(
    "--save-config", type=click.Path(), help="Save current options to config file"
)
@click.option("--stats", is_flag=True, help="Show processing statistics")
@click.option("--benchmark", is_flag=True, help="Enable benchmark mode with timing")
@click.option(
    "--custom-patterns",
    type=click.Path(exists=True),
    help="JSON file with custom regex patterns",
)
@click.option(
    "--export-patterns", type=click.Path(), help="Export built-in patterns to JSON file"
)
@click.option("--live-mode", is_flag=True, help="Live monitoring mode for file changes")
@click.option(
    "--watch-dir", type=click.Path(), help="Directory to watch for changes in live mode"
)
@click.option(
    "--scan-cloud", is_flag=True, help="Scan cloud storage URLs (S3, Azure, GCP)"
)
@click.option(
    "--sensitivity",
    default="medium",
    help="Detection sensitivity: low,medium,high,paranoid",
)
@click.option(
    "--entropy",
    is_flag=True,
    help="Calculate and display Shannon entropy for extracted values",
)
@click.option("--jwt", is_flag=True, help="Detect and decode JWT tokens")
@click.option("--base64", is_flag=True, help="Detect and decode Base64 encoded strings")
@click.option("--har", is_flag=True, help="Parse HAR files and extract HTTP requests")
@click.option("--postman", is_flag=True, help="Parse Postman collection files")
@click.option(
    "--ws", is_flag=True, help="Detect WebSocket endpoints (ws:// and wss://)"
)
@click.option(
    "--emails", is_flag=True, help="Enhanced email detection with source tracking"
)
@click.option(
    "--auto-tag",
    is_flag=True,
    help="Automatically tag findings using intelligent classification",
)
@click.option(
    "--tag-rules",
    type=click.Path(exists=True),
    help="JSON file with custom tagging rules",
)
@click.option(
    "--tag-output",
    type=click.Path(),
    help="Save tagged results to separate file (JSON format)",
)
@click.option("--risk-scoring", is_flag=True, help="Enable risk scoring for findings")
@click.option(
    "--hex-dump",
    is_flag=True,
    help="Generate hex dumps of input files using xxd and include in report",
)
@click.option(
    "--strings",
    is_flag=True,
    help="Extract ASCII/UTF-8 strings from binary files using Python",
)
@click.option(
    "--zip",
    is_flag=True,
    help="Extract and scan .zip/.jar/.apk archives with ExtractorCLI",
)
@click.option(
    "--cors",
    is_flag=True,
    help="Detect Access-Control-Allow-Origin: * vulnerabilities in headers",
)
@click.option(
    "--csp",
    is_flag=True,
    help="Analyze Content-Security-Policy headers and highlight unsafe directives",
)
# TruffleHog Integration Options
@click.option(
    "--trufflehog",
    is_flag=True,
    help="Enable TruffleHog secret scanning integration",
)
@click.option(
    "--trufflehog-config",
    type=click.Path(exists=True),
    help="Path to TruffleHog configuration file",
)
@click.option(
    "--trufflehog-rules",
    type=click.Path(exists=True),
    help="Path to custom TruffleHog rules file",
)
@click.option(
    "--trufflehog-exclude",
    multiple=True,
    help="Detectors to exclude from TruffleHog scan (can be used multiple times)",
)
@click.option(
    "--trufflehog-include",
    multiple=True,
    help="Only run specified detectors in TruffleHog scan (can be used multiple times)",
)
@click.option(
    "--trufflehog-concurrency",
    type=int,
    default=8,
    help="Number of concurrent TruffleHog workers (default: 8)",
)
@click.option(
    "--trufflehog-depth",
    type=int,
    default=100,
    help="Maximum depth for TruffleHog scanning (default: 100)",
)
@click.option(
    "--trufflehog-archive",
    is_flag=True,
    help="Enable TruffleHog scanning of archive files (zip, tar, etc.)",
)
@click.option(
    "--trufflehog-json",
    is_flag=True,
    help="Output TruffleHog results in JSON format",
)
@click.option(
    "--trufflehog-verified",
    is_flag=True,
    help="Only show verified secrets from TruffleHog",
)
@click.option(
    "--trufflehog-filter-entropy",
    type=float,
    default=3.0,
    help="Minimum entropy threshold for TruffleHog secrets (default: 3.0)",
)
@click.option(
    "--trufflehog-no-verification",
    is_flag=True,
    help="Skip verification of found secrets (faster but less accurate)",
)
def extractor(
    input,
    input_file,
    input_url,
    input_list,
    types,
    target_domain,
    output,
    output_dir,
    json_out,
    to_jsonl,
    tagged,
    csv,
    xml,
    ai_score,
    score_threshold,
    limit,
    smart_detect,
    recursive,
    file_patterns,
    exclude_patterns,
    fetch_urls,
    fetch_depth,
    threads,
    timeout,
    retry_count,
    retry_delay,
    user_agent,
    follow_redirects,
    max_redirects,
    include_comments,
    deep_js,
    extract_inline,
    extract_base64,
    verify_ssl,
    insecure,
    proxy,
    headers,
    cookies,
    max_size,
    min_length,
    max_length,
    encoding,
    verbose,
    quiet,
    debug,
    no_color,
    dedup,
    merge_with,
    dedup_by,
    dedup_strategy,
    sort_results,
    sort_by,
    unique_only,
    filter_regex,
    exclude_regex,
    whitelist_domains,
    blacklist_domains,
    xss_scan,
    xss_discover,
    xss_threads,
    xss_timeout,
    xss_depth,
    xss_payloads,
    report,
    report_format,
    store_db,
    db_path,
    config,
    save_config,
    stats,
    benchmark,
    custom_patterns,
    export_patterns,
    live_mode,
    watch_dir,
    scan_cloud,
    sensitivity,
    entropy,
    jwt,
    base64,
    har,
    postman,
    ws,
    emails,
    auto_tag,
    tag_rules,
    tag_output,
    risk_scoring,
    hex_dump,
    strings,
    zip,
    cors,
    csp,
    # TruffleHog parameters
    trufflehog,
    trufflehog_config,
    trufflehog_rules,
    trufflehog_exclude,
    trufflehog_include,
    trufflehog_concurrency,
    trufflehog_depth,
    trufflehog_archive,
    trufflehog_json,
    trufflehog_verified,
    trufflehog_filter_entropy,
    trufflehog_no_verification,
):
    """
    🧲 ExtractorCLI v2.0 - Advanced Data Extraction & Security Analysis Tool

    Extract URLs, emails, forms, authentication endpoints, API endpoints, secrets,
    cryptocurrency addresses, social media profiles, phone numbers, PII data and more
    from files, directories, or URLs. Includes XSS-Vibes integration for vulnerability
    scanning and advanced AI-powered result analysis.

    BASIC USAGE:
      reconcli extractorcli file.html                           # Extract from file
      reconcli extractorcli --input-file data.txt              # Alternative input syntax
      reconcli extractorcli --input-url https://example.com    # Process single URL
      reconcli extractorcli --input-list urls.txt              # Process URL list

    EXTRACTION TYPES (Enhanced Categories):
      --types url,email,api,secret,subdomain          # Basic web data extraction
      --types crypto,phone,social,pii                 # Personal & financial data
      --types api_docs,tech_stack                     # Technical documentation
      --types auth,swagger,form                       # Security-focused extraction
      --target-domain example.com                     # Target for subdomain extraction

    NEW CATEGORIES:
      crypto     - Bitcoin, Ethereum, Monero addresses and crypto wallets
      phone      - Phone numbers in various formats
      social     - Twitter, Instagram, YouTube, LinkedIn, Discord, Telegram
      pii        - Credit cards, SSN and other personally identifiable info
      graphql    - GraphQL endpoints, playgrounds, schemas, and introspection
      api_docs   - API documentation titles and interfaces
      tech_stack - Technology stacks from comma-separated lists

    ENHANCED SECRET DETECTION:
      secret     - AWS keys, GitHub tokens, OpenAI keys, Stripe keys, Discord tokens,
                   Telegram bots, PayPal clients, Mailgun keys, Twilio SIDs,
                   SendGrid keys, Anthropic keys, Google API keys, Azure keys,
                   Docker tokens, Heroku keys, Cloudflare tokens, private keys,
                   SSH keys, database URLs, connection strings, environment vars

    OUTPUT FORMATS:
      --json --output results.json                    # Structured JSON output
      --tagged --ai-score                             # Categorized with AI scoring
      --csv --output results.csv                      # CSV format for analysis
      --to-jsonl --output results.jsonl               # JSON Lines format

    ADVANCED FEATURES:
      --fetch-urls --deep-js --dedup                  # Fetch URLs, analyze JS, deduplicate
      --recursive --smart-detect                      # Recursive dir scan with auto-detection
      --merge-with old.txt --dedup-by url             # Merge with existing data
      --custom-patterns patterns.json                 # Load custom regex patterns
      --export-patterns patterns.json                 # Export built-in patterns
      --live-mode --watch-dir /path/to/monitor        # Live file monitoring mode
      --scan-cloud                                     # Scan cloud storage URLs

    XSS INTEGRATION:
      --xss-discover --target-domain example.com      # Discover XSS endpoints
      --xss-scan --xss-threads 10                     # Scan URLs for XSS vulnerabilities

    SECURITY FEATURES:
      --types secret,auth,api --ai-score              # Focus on security-relevant data
      --filter-regex "admin|api" --score-threshold 5  # Filter high-value results
      --sensitivity paranoid                          # Detection sensitivity: low,medium,high,paranoid

    REAL-WORLD EXAMPLES:

      # Extract API documentation and tech stacks from Swagger file
      reconcli extractorcli swagger_endpoints.txt --types "api_docs,tech_stack" --verbose

      # Find all secrets in a directory with high sensitivity
      reconcli extractorcli /path/to/code --recursive --types secret --sensitivity paranoid

      # Extract cryptocurrency addresses and social media from text
      reconcli extractorcli data.txt --types "crypto,social,phone" --json --output findings.json

      # Live monitoring for sensitive data in logs
      reconcli extractorcli --live-mode --watch-dir /var/log --types "secret,pii" --tagged

      # Pipeline processing with XSS scanning
      cat urls.txt | reconcli extractorcli --fetch-urls --types api --xss-scan --verbose

      # Comprehensive security scan with AI scoring
      reconcli extractorcli target.com --types "secret,auth,api,crypto,pii" --ai-score --tagged

      # Extract and merge with existing data
      reconcli extractorcli new_data.txt --merge-with old_findings.json --dedup --output merged.json

    PIPELINE USAGE:
      echo "https://example.com" | reconcli extractorcli --fetch-urls --types api
      cat urls.txt | reconcli extractorcli --xss-scan --verbose
      find . -name "*.js" | xargs reconcli extractorcli --types secret --json

    For comprehensive documentation: see EXTRACTORCLI_DOCUMENTATION.md
    """
    # Configure output verbosity
    if quiet:
        verbose = False
    elif debug:
        verbose = True

    # Handle input sources - priority: input_url > input_list > input_file > positional input
    input_source = None
    if input_url:
        input_source = ("url", input_url)
        if verbose:
            click.echo(f"🌐 [INPUT] Processing single URL: {input_url}")
    elif input_list:
        input_source = ("list", input_list)
        if verbose:
            click.echo(f"📄 [INPUT] Processing URL list: {input_list}")
    elif input_file:
        input_source = ("file", input_file)
        if verbose:
            click.echo(f"📁 [INPUT] Processing file: {input_file}")
    elif input:
        input_source = ("file", input)
        if verbose:
            click.echo(f"📁 [INPUT] Processing positional input: {input}")
    else:
        input_source = ("stdin", None)
        if verbose:
            click.echo("📥 [INPUT] Reading from stdin")

    if insecure:
        verify_ssl = False
        if verbose:
            click.echo("⚠️  [WARN] SSL verification disabled", err=True)

    selected = set(types.lower().split(","))
    results = {
        k: set()
        for k in [
            "url",
            "email",
            "form",
            "auth",
            "api",
            "swagger",
            "graphql",  # New: Dedicated GraphQL extraction
            "api_docs",  # New: API documentation titles
            "tech_stack",  # New: Technology stacks
            "ip",
            "domain",
            "subdomain",
            "secret",
            "js",
            "comment",
            "hash",
            "base64",
            "phone",  # New: Phone numbers
            "crypto",  # New: Cryptocurrency addresses
            "social",  # New: Social media handles/links
            "pii",  # New: Personally Identifiable Information
            "jwt",  # New: JWT tokens
            "base64_enhanced",  # New: Enhanced Base64 detection
            "websocket",  # New: WebSocket endpoints
            "email_enhanced",  # New: Enhanced email detection
            "har",  # New: HAR file requests
            "postman",  # New: Postman collection requests
        ]
    }

    processed_urls = set()

    def extract_from_text(text, source=""):
        """Enhanced text extraction with multiple patterns"""
        if verbose and source:
            click.echo(f"🔍 [EXTRACT] Processing: {source}")

        if "url" in selected:
            urls = URL_REGEX.findall(text)
            results["url"].update(urls)
            if verbose:
                click.echo(f"   📌 Found {len(urls)} URLs")

        if "email" in selected:
            email_list = EMAIL_REGEX.findall(text)
            results["email"].update(email_list)
            if verbose and email_list:
                click.echo(f"   📧 Found {len(email_list)} emails")

        if "form" in selected:
            forms = FORM_REGEX.findall(text)
            inputs = INPUT_REGEX.findall(text)
            results["form"].update(forms + inputs)
            if verbose and (forms or inputs):
                click.echo(f"   📝 Found {len(forms)} forms, {len(inputs)} inputs")

        if "auth" in selected:
            auth_paths = AUTH_REGEX.findall(text)
            results["auth"].update(auth_paths)
            if verbose and auth_paths:
                click.echo(f"   🔐 Found {len(auth_paths)} auth endpoints")

        if "api" in selected:
            api_paths = API_REGEX.findall(text)
            results["api"].update(api_paths)
            if verbose and api_paths:
                click.echo(f"   🚀 Found {len(api_paths)} API endpoints")

        if "swagger" in selected:
            swagger_paths = SWAGGER_REGEX.findall(text)
            results["swagger"].update(swagger_paths)
            if verbose and swagger_paths:
                click.echo(f"   📚 Found {len(swagger_paths)} documentation endpoints")

        # Dedicated GraphQL extraction
        if "graphql" in selected:
            clean_text = clean_ansi_codes(text)

            # Extract full lines containing GraphQL URLs (with variations and typos)
            graphql_lines = re.findall(
                r"https?://[^\s]+.*\[(.*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql).*)\].*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update([f"[{line}]" for line in graphql_lines])

            # Also get full lines for context
            full_graphql_lines = re.findall(
                r"https?://[^\s]+.*\[.*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql).*\].*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(full_graphql_lines)

            # Extract GraphQL endpoints from URLs (with variations)
            graphql_urls = re.findall(
                r"https?://[^\s]*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s]*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(graphql_urls)

            # Extract GraphQL mentions and interfaces (both patterns)
            graphql_mentions = GRAPHQL_REGEX.findall(clean_text)
            results["graphql"].update(graphql_mentions)

            graphql_full_mentions = GRAPHQL_FULL_REGEX.findall(clean_text)
            results["graphql"].update(
                [f"{match[0]} {match[1]}" for match in graphql_full_mentions]
            )

            # Look for common GraphQL patterns with variations
            graphql_patterns = re.findall(
                r'/(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s"\'<>]*',
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(graphql_patterns)

            # GraphQL introspection endpoints with variations
            introspection_patterns = re.findall(
                r"[^\s]*(?:graphql|grahql|grafql|graphq|takgraphql|graphiql)[^\s]*query[^\s]*",
                text,
                re.IGNORECASE,
            )
            results["graphql"].update(introspection_patterns)

            if verbose and (
                graphql_lines
                or full_graphql_lines
                or graphql_urls
                or graphql_mentions
                or graphql_full_mentions
                or graphql_patterns
            ):
                total = (
                    len(graphql_lines)
                    + len(full_graphql_lines)
                    + len(graphql_urls)
                    + len(graphql_mentions)
                    + len(graphql_full_mentions)
                    + len(graphql_patterns)
                    + len(introspection_patterns)
                )
                click.echo(f"   🔮 Found {total} GraphQL endpoints/references")

        # New: API Documentation titles and tech stacks
        if "api_docs" in selected:
            # Clean ANSI first, then extract
            clean_text = clean_ansi_codes(text)

            # Extract API-specific titles (only those containing API-related keywords)
            api_titles = API_TITLE_REGEX.findall(text)
            results["api_docs"].update(api_titles)

            # Extract GraphQL mentions (more precise) - only if graphql not selected separately
            if "graphql" not in selected:
                graphql_matches = GRAPHQL_REGEX.findall(clean_text)
                results["api_docs"].update(
                    [f"GraphQL {match}" for match in graphql_matches]
                )

            # Extract general API docs mentions (more specific)
            docs_matches = API_DOCS_REGEX.findall(clean_text)
            results["api_docs"].update(docs_matches)

            if verbose:
                graphql_count = (
                    len(GRAPHQL_REGEX.findall(clean_text))
                    if "graphql" not in selected
                    else 0
                )
                total = len(api_titles) + graphql_count + len(docs_matches)
                if total > 0:
                    click.echo(f"   📋 Found {total} API documentation references")

        if "tech_stack" in selected:
            # Extract tech stack from end of lines
            tech_stacks = TECH_STACK_REGEX.findall(text)
            for stack in tech_stacks:
                # Split comma-separated and filter out common non-tech words
                technologies = [
                    tech.strip() for tech in stack.split(",") if tech.strip()
                ]
                # Filter out common non-technical terms
                filtered_tech = [
                    tech
                    for tech in technologies
                    if len(tech) > 2
                    and not tech.lower()
                    in ["hsts", "ubuntu", "windows server", "windows"]
                ]
                results["tech_stack"].update(filtered_tech)

            if verbose and tech_stacks:
                click.echo(f"   🔧 Found {len(tech_stacks)} technology references")

        if "ip" in selected:
            ips = IP_REGEX.findall(text)
            results["ip"].update(ips)
            if verbose and ips:
                click.echo(f"   🌐 Found {len(ips)} IP addresses")

        if "domain" in selected:
            domains = DOMAIN_REGEX.findall(text)
            results["domain"].update(domains)
            if verbose and domains:
                click.echo(f"   🏠 Found {len(domains)} domains")

        if "subdomain" in selected and target_domain:
            subdomains = SUBDOMAIN_REGEX(target_domain).findall(text)
            results["subdomain"].update(subdomains)
            if verbose and subdomains:
                click.echo(
                    f"   🌿 Found {len(subdomains)} subdomains for {target_domain}"
                )

        if "secret" in selected:
            # Multiple secret detection patterns
            secrets = SECRET_REGEX.findall(text)
            aws_keys = AWS_KEY_REGEX.findall(text)
            github_tokens = GITHUB_TOKEN_REGEX.findall(text)
            slack_tokens = SLACK_TOKEN_REGEX.findall(text)
            jwt_tokens = JWT_REGEX.findall(text)

            # Enhanced secret detection
            discord_tokens = DISCORD_TOKEN_REGEX.findall(text)
            telegram_bots = TELEGRAM_BOT_REGEX.findall(text)
            stripe_keys = STRIPE_KEY_REGEX.findall(text)
            paypal_clients = PAYPAL_CLIENT_REGEX.findall(text)
            mailgun_keys = MAILGUN_KEY_REGEX.findall(text)
            twilio_sids = TWILIO_SID_REGEX.findall(text)
            sendgrid_keys = SENDGRID_KEY_REGEX.findall(text)
            openai_keys = OPENAI_KEY_REGEX.findall(text)
            anthropic_keys = ANTHROPIC_KEY_REGEX.findall(text)
            google_api_keys = GOOGLE_API_KEY_REGEX.findall(text)
            azure_keys = AZURE_KEY_REGEX.findall(text)
            docker_tokens = DOCKER_TOKEN_REGEX.findall(text)
            heroku_keys = HEROKU_API_KEY_REGEX.findall(text)
            cloudflare_tokens = CLOUDFLARE_TOKEN_REGEX.findall(text)
            private_keys = PRIVATE_KEY_REGEX.findall(text)
            ssh_keys = SSH_KEY_REGEX.findall(text)
            database_urls = DATABASE_URL_REGEX.findall(text)
            connection_strings = CONNECTION_STRING_REGEX.findall(text)
            env_vars = ENV_VAR_REGEX.findall(text)
            api_secrets = API_ENDPOINT_SECRET_REGEX.findall(text)

            all_secrets = (
                [f"{k}:{v}" for k, v in secrets]
                + [f"AWS_KEY:{k}" for k in aws_keys]
                + [f"GITHUB_TOKEN:{t}" for t in github_tokens]
                + [f"SLACK_TOKEN:{t}" for t in slack_tokens]
                + [f"JWT_TOKEN:{t}" for t in jwt_tokens]
                + [f"DISCORD_TOKEN:{t}" for t in discord_tokens]
                + [f"TELEGRAM_BOT:{t}" for t in telegram_bots]
                + [f"STRIPE_KEY:{k}" for k in stripe_keys]
                + [f"PAYPAL_CLIENT:{c}" for c in paypal_clients]
                + [f"MAILGUN_KEY:{k}" for k in mailgun_keys]
                + [f"TWILIO_SID:{s}" for s in twilio_sids]
                + [f"SENDGRID_KEY:{k}" for k in sendgrid_keys]
                + [f"OPENAI_KEY:{k}" for k in openai_keys]
                + [f"ANTHROPIC_KEY:{k}" for k in anthropic_keys]
                + [f"GOOGLE_API_KEY:{k}" for k in google_api_keys]
                + [f"AZURE_KEY:{k}" for k in azure_keys]
                + [f"DOCKER_TOKEN:{t}" for t in docker_tokens]
                + [f"HEROKU_KEY:{k}" for k in heroku_keys]
                + [f"CLOUDFLARE_TOKEN:{t}" for t in cloudflare_tokens]
                + [f"PRIVATE_KEY:{k}" for k in private_keys]
                + [f"SSH_KEY:{k}" for k in ssh_keys]
                + [f"DATABASE_URL:{u}" for u in database_urls]
                + [f"CONNECTION_STRING:{c}" for c in connection_strings]
                + [f"ENV_VAR:{v}" for v in env_vars]
                + [f"API_SECRET:{s}" for s in api_secrets]
            )
            results["secret"].update(all_secrets)
            if verbose and all_secrets:
                click.echo(f"   🔑 Found {len(all_secrets)} potential secrets")

            # ═══════════════════════════════════════════════════════════════════════════════
            # 🔍 TRUFFLEHOG INTEGRATION
            # ═══════════════════════════════════════════════════════════════════════════════

            if trufflehog:
                if verbose:
                    click.echo("🔍 [TRUFFLEHOG] Starting enhanced secret scanning...")

                # Run TruffleHog scan
                trufflehog_secrets = run_trufflehog_scan(
                    content=text,
                    config_file=trufflehog_config,
                    rules_file=trufflehog_rules,
                    exclude_detectors=trufflehog_exclude,
                    include_detectors=trufflehog_include,
                    concurrency=trufflehog_concurrency,
                    depth=trufflehog_depth,
                    archive_scan=trufflehog_archive,
                    verified_only=trufflehog_verified,
                    no_verification=trufflehog_no_verification,
                    entropy_threshold=trufflehog_filter_entropy,
                    verbose=verbose,
                )

                if trufflehog_secrets:
                    # Process TruffleHog results
                    processed_secrets = process_trufflehog_results(
                        trufflehog_secrets,
                        auto_tag_enabled=auto_tag,
                        risk_scoring_enabled=risk_scoring,
                    )

                    # Add to results with special formatting
                    if "trufflehog_secrets" not in results:
                        results["trufflehog_secrets"] = set()

                    for secret in processed_secrets:
                        # Create enhanced secret entry
                        secret_entry = {
                            "content": secret["content"],
                            "detector": secret["detector"],
                            "detector_type": secret["detector_type"],
                            "entropy": secret["entropy"],
                            "verified": secret["verified"],
                            "tags": secret["tags"],
                            "risk_level": secret["risk_level"],
                            "raw_content": (
                                secret["raw_content"]
                                if not trufflehog_verified
                                else None
                            ),
                            "source_metadata": secret["source_metadata"],
                            "extra_data": secret["extra_data"],
                        }

                        results["trufflehog_secrets"].add(
                            json.dumps(secret_entry, sort_keys=True)
                        )

                    if verbose:
                        verified_count = sum(
                            1 for s in processed_secrets if s["verified"]
                        )
                        high_risk_count = sum(
                            1 for s in processed_secrets if s["risk_level"] >= 7
                        )
                        click.echo(
                            f"✅ [TRUFFLEHOG] Found {len(processed_secrets)} secrets"
                        )
                        click.echo(
                            f"   📊 Verified: {verified_count}, High Risk: {high_risk_count}"
                        )

                        # Show top detectors
                        detector_counts = {}
                        for secret in processed_secrets:
                            detector = secret["detector"]
                            detector_counts[detector] = (
                                detector_counts.get(detector, 0) + 1
                            )

                        if detector_counts:
                            top_detectors = sorted(
                                detector_counts.items(),
                                key=lambda x: x[1],
                                reverse=True,
                            )[:5]
                            click.echo(
                                f"   🔍 Top Detectors: {', '.join([f'{d}({c})' for d, c in top_detectors])}"
                            )

                else:
                    if verbose:
                        click.echo("ℹ️ [TRUFFLEHOG] No secrets found")

        # New extraction categories
        if "phone" in selected:
            phones = PHONE_REGEX.findall(text)
            results["phone"].update(phones)
            if verbose and phones:
                click.echo(f"   📞 Found {len(phones)} phone numbers")

        if "crypto" in selected:
            bitcoin_addrs = BITCOIN_ADDRESS_REGEX.findall(text)
            ethereum_addrs = ETHEREUM_ADDRESS_REGEX.findall(text)
            monero_addrs = MONERO_ADDRESS_REGEX.findall(text)
            crypto_wallets = CRYPTO_WALLET_REGEX.findall(text)

            all_crypto = (
                [f"BTC:{addr}" for addr in bitcoin_addrs]
                + [f"ETH:{addr}" for addr in ethereum_addrs]
                + [f"XMR:{addr}" for addr in monero_addrs]
                + [f"WALLET:{addr}" for addr in crypto_wallets]
            )
            results["crypto"].update(all_crypto)
            if verbose and all_crypto:
                click.echo(f"   ₿ Found {len(all_crypto)} cryptocurrency addresses")

        if "social" in selected:
            twitter_handles = TWITTER_HANDLE_REGEX.findall(text)
            instagram_handles = INSTAGRAM_HANDLE_REGEX.findall(text)
            youtube_channels = YOUTUBE_CHANNEL_REGEX.findall(text)
            linkedin_profiles = LINKEDIN_PROFILE_REGEX.findall(text)
            facebook_profiles = FACEBOOK_PROFILE_REGEX.findall(text)
            discord_invites = DISCORD_INVITE_REGEX.findall(text)
            telegram_channels = TELEGRAM_CHANNEL_REGEX.findall(text)

            all_social = (
                [f"TWITTER:{h}" for h in twitter_handles]
                + [f"INSTAGRAM:{h}" for h in instagram_handles]
                + [f"YOUTUBE:{c}" for c in youtube_channels]
                + [f"LINKEDIN:{p}" for p in linkedin_profiles]
                + [f"FACEBOOK:{p}" for p in facebook_profiles]
                + [f"DISCORD:{i}" for i in discord_invites]
                + [f"TELEGRAM:{c}" for c in telegram_channels]
            )
            results["social"].update(all_social)
            if verbose and all_social:
                click.echo(f"   📱 Found {len(all_social)} social media references")

        if "pii" in selected:
            credit_cards = CREDIT_CARD_REGEX.findall(text)
            social_security = SOCIAL_SECURITY_REGEX.findall(text)

            all_pii = [f"CC:{cc}" for cc in credit_cards] + [
                f"SSN:{ssn}" for ssn in social_security
            ]
            results["pii"].update(all_pii)
            if verbose and all_pii:
                click.echo(f"   🆔 Found {len(all_pii)} PII items")

        if "js" in selected and deep_js:
            js_vars = JS_VAR_REGEX.findall(text)
            js_formatted = [f"{var}={value}" for var, value in js_vars]
            results["js"].update(js_formatted)
            if verbose and js_formatted:
                click.echo(f"   🔧 Found {len(js_formatted)} JS variables")

        if "comment" in selected and include_comments:
            comments = COMMENT_REGEX.findall(text)
            results["comment"].update(comments)
            if verbose and comments:
                click.echo(f"   💬 Found {len(comments)} comments")

        if "hash" in selected:
            hashes = HASH_REGEX.findall(text)
            results["hash"].update(hashes)
            if verbose and hashes:
                click.echo(f"   #️⃣  Found {len(hashes)} hashes")

        if "base64" in selected:
            base64_strings = BASE64_REGEX.findall(text)
            results["base64"].update(base64_strings)
            if verbose and base64_strings:
                click.echo(f"   📊 Found {len(base64_strings)} base64 strings")

        # New JWT detection
        if jwt or "jwt" in selected:
            jwt_tokens = JWT_REGEX.findall(text)
            results["jwt"] = results.get("jwt", set())
            results["jwt"].update(jwt_tokens)
            if verbose and jwt_tokens:
                click.echo(f"   🎫 Found {len(jwt_tokens)} JWT tokens")

        # Enhanced Base64 detection
        if base64 or "base64_enhanced" in selected:
            base64_strings = BASE64_REGEX.findall(text)
            results["base64_enhanced"] = results.get("base64_enhanced", set())
            results["base64_enhanced"].update(base64_strings)
            if verbose and base64_strings:
                click.echo(f"   🔓 Found {len(base64_strings)} Base64 strings")

        # WebSocket endpoints
        if ws or "websocket" in selected:
            ws_endpoints = WS_REGEX.findall(text)
            results["websocket"] = results.get("websocket", set())
            results["websocket"].update(ws_endpoints)
            if verbose and ws_endpoints:
                click.echo(f"   🔌 Found {len(ws_endpoints)} WebSocket endpoints")

        # Enhanced email detection
        if emails or "email_enhanced" in selected:
            email_addresses = EMAIL_REGEX.findall(text)
            results["email_enhanced"] = results.get("email_enhanced", set())
            results["email_enhanced"].update(email_addresses)
            if verbose and email_addresses:
                click.echo(f"   📬 Found {len(email_addresses)} email addresses")

    def decode_jwt_token(jwt_token):
        """Decode JWT token and return header and payload"""
        import base64
        import json

        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return None

            header_encoded, payload_encoded, signature = parts

            # Add padding if needed
            header_encoded += "=" * (4 - len(header_encoded) % 4)
            payload_encoded += "=" * (4 - len(payload_encoded) % 4)

            # Decode
            header = base64.urlsafe_b64decode(header_encoded)
            payload = base64.urlsafe_b64decode(payload_encoded)

            return {
                "header": json.loads(header.decode("utf-8")),
                "payload": json.loads(payload.decode("utf-8")),
                "signature": signature,
            }
        except Exception:
            return None

    def decode_base64_string(base64_string):
        """Decode Base64 string and try to parse as JSON"""
        import base64
        import json

        try:
            # Add padding if needed
            base64_string += "=" * (4 - len(base64_string) % 4)
            decoded = base64.b64decode(base64_string)
            decoded_str = decoded.decode("utf-8")

            # Try to parse as JSON
            try:
                json_data = json.loads(decoded_str)
                return {"decoded": decoded_str, "json": json_data, "is_json": True}
            except json.JSONDecodeError:
                return {"decoded": decoded_str, "is_json": False}
        except Exception:
            return None

    def parse_har_file(file_path):
        """Parse HAR file and extract HTTP requests"""
        import json

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                har_data = json.load(f)

            requests_data = []
            entries = har_data.get("log", {}).get("entries", [])

            for entry in entries:
                request = entry.get("request", {})
                requests_data.append(
                    {
                        "url": request.get("url", ""),
                        "method": request.get("method", ""),
                        "headers": {
                            h["name"]: h["value"] for h in request.get("headers", [])
                        },
                        "source": "har_file",
                    }
                )

            return requests_data
        except Exception:
            return []

    def parse_postman_collection(file_path):
        """Parse Postman collection and extract requests"""
        import json

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                collection = json.load(f)

            requests_data = []

            def extract_from_items(items):
                for item in items:
                    if "request" in item:
                        request = item["request"]
                        if isinstance(request, dict):
                            url = request.get("url", {})
                            if isinstance(url, dict):
                                url_str = url.get("raw", "")
                            else:
                                url_str = str(url)

                            requests_data.append(
                                {
                                    "name": item.get("name", ""),
                                    "url": url_str,
                                    "method": request.get("method", ""),
                                    "source": "postman_collection",
                                }
                            )

                    if "item" in item:
                        extract_from_items(item["item"])

            if "item" in collection:
                extract_from_items(collection["item"])

            return requests_data
        except Exception:
            return []

    def fetch_url_content(url):
        """Fetch content from URL with proper error handling"""
        if url in processed_urls:
            return None

        processed_urls.add(url)

        try:
            if verbose:
                click.echo(f"🌐 [FETCH] Getting: {url}")

            headers = {"User-Agent": user_agent}
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=follow_redirects,
                stream=True,
            )

            # Check content length
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > max_size * 1024 * 1024:
                if verbose:
                    click.echo(f"⚠️  [SKIP] File too large: {content_length} bytes")
                return None

            # Read content with size limit
            content = ""
            size = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if chunk:
                    content += chunk
                    size += len(chunk.encode("utf-8"))
                    if size > max_size * 1024 * 1024:
                        if verbose:
                            click.echo(
                                f"⚠️  [TRUNCATED] Content truncated at {max_size}MB"
                            )
                        break

            if verbose:
                click.echo(f"✅ [SUCCESS] Fetched {len(content)} chars from {url}")

            return content

        except requests.exceptions.SSLError as e:
            if verbose:
                click.echo(f"🔒 [SSL-ERROR] {url}: {e}")
        except requests.exceptions.Timeout:
            if verbose:
                click.echo(f"⏱️  [TIMEOUT] {url}")
        except requests.exceptions.RequestException as e:
            if verbose:
                click.echo(f"❌ [ERROR] {url}: {e}")
        except Exception as e:
            if verbose:
                click.echo(f"💥 [UNEXPECTED] {url}: {e}")

        return None

    def process_urls_concurrent(urls_list):
        """Process multiple URLs concurrently"""
        if not urls_list:
            return

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {
                executor.submit(fetch_url_content, url): url for url in urls_list
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        extract_from_text(content, f"URL: {url}")

                        # Extract new URLs and potentially fetch them too
                        if fetch_urls:
                            new_urls = URL_REGEX.findall(content)
                            new_urls = [u for u in new_urls if u not in processed_urls]
                            if new_urls and verbose:
                                click.echo(
                                    f"🔗 [DISCOVERED] {len(new_urls)} new URLs from {url}"
                                )

                except Exception as e:
                    if verbose:
                        click.echo(f"❌ [PROCESSING-ERROR] {url}: {e}")

    def smart_type_detect(path):
        """Enhanced file type detection"""
        mime, _ = mimetypes.guess_type(path.name)
        suffix = path.suffix.lower()

        if mime:
            if "json" in mime or suffix == ".json":
                return "json"
            elif "html" in mime or suffix in [".html", ".htm"]:
                return "html"
            elif "javascript" in mime or suffix in [".js", ".jsx"]:
                return "js"
            elif "xml" in mime or suffix == ".xml":
                return "xml"
            elif "css" in mime or suffix == ".css":
                return "css"

        # Check content for additional detection
        try:
            content_sample = path.read_text(encoding="utf-8", errors="ignore")[:500]
            if content_sample.strip().startswith(("<!DOCTYPE", "<html", "<HTML")):
                return "html"
            elif content_sample.strip().startswith(
                "{"
            ) or content_sample.strip().startswith("["):
                return "json"
            elif (
                "function" in content_sample
                or "var " in content_sample
                or "const " in content_sample
            ):
                return "js"
        except:
            pass

        return "text"

    def process_file(path):
        """Enhanced file processing with type detection"""
        try:
            # Special handling for HAR files
            if har and path.suffix.lower() == ".har":
                if verbose:
                    click.echo(f"🗂️  [HAR] Parsing HAR file: {path}")
                har_requests = parse_har_file(str(path))
                results["har"] = results.get("har", set())
                for req in har_requests:
                    results["har"].add(f"{req['method']} {req['url']}")
                    # Also extract URLs for further processing
                    results["url"].add(req["url"])
                if verbose and har_requests:
                    click.echo(f"   📊 Found {len(har_requests)} HAR requests")
                return

            # Special handling for Postman collections
            if postman and path.suffix.lower() == ".json":
                if verbose:
                    click.echo(f"📮 [POSTMAN] Parsing collection: {path}")
                postman_requests = parse_postman_collection(str(path))
                if postman_requests:  # Only if it's actually a Postman collection
                    results["postman"] = results.get("postman", set())
                    for req in postman_requests:
                        results["postman"].add(f"{req['method']} {req['url']}")
                        # Also extract URLs for further processing
                        results["url"].add(req["url"])
                    if verbose:
                        click.echo(
                            f"   📊 Found {len(postman_requests)} Postman requests"
                        )
                    return

            content = path.read_text(encoding="utf-8", errors="ignore")

            if smart_detect:
                ftype = smart_type_detect(path)
                if verbose:
                    click.echo(f"📄 [FILE-TYPE] {path.name}: {ftype}")

                if ftype == "json":
                    try:
                        json_content = json.loads(content)
                        content = json.dumps(
                            json_content, indent=2
                        )  # normalize spacing
                    except:
                        pass
                elif ftype == "html" and deep_js:
                    # Extract and process inline JavaScript
                    script_pattern = r"<script[^>]*>(.*?)</script>"
                    scripts = re.findall(
                        script_pattern, content, re.DOTALL | re.IGNORECASE
                    )
                    for script in scripts:
                        extract_from_text(script, f"Inline JS in {path.name}")

            extract_from_text(content, str(path))

        except Exception as e:
            if verbose:
                click.echo(f"❌ [FILE-ERROR] Failed to process {path}: {e}", err=True)

    # Main processing logic with enhanced input handling
    initial_urls = []

    if input_source[0] == "url":
        # Process single URL directly
        if fetch_urls:
            initial_urls = [input_source[1]]
        else:
            extract_from_text(input_source[1], "direct URL input")

    elif input_source[0] == "list":
        # Process URL list file
        try:
            with open(input_source[1], "r", encoding=encoding) as f:
                urls = [
                    clean_ansi_codes(line.strip())  # Clean ANSI codes
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            if fetch_urls:
                initial_urls = urls
                if verbose:
                    click.echo(f"📋 [URL-LIST] Loaded {len(urls)} URLs for fetching")
            else:
                # Extract from URL strings themselves
                for url in urls:
                    extract_from_text(clean_ansi_codes(url), f"URL from list: {url}")

        except Exception as e:
            if verbose:
                click.echo(f"❌ [ERROR] Failed to read URL list {input_source[1]}: {e}")
            return

    elif input_source[0] == "file":
        # Process file input (original logic)
        p = Path(input_source[1])
        if p.is_file():
            process_file(p)
        elif p.is_dir() and recursive:
            if verbose:
                click.echo(f"📁 [RECURSIVE] Scanning directory: {p}")
            for file in p.rglob("*"):
                if file.is_file():
                    # Apply file pattern filtering
                    if file_patterns:
                        patterns = file_patterns.split(",")
                        if not any(file.match(pattern.strip()) for pattern in patterns):
                            continue

                    if exclude_patterns:
                        patterns = exclude_patterns.split(",")
                        if any(file.match(pattern.strip()) for pattern in patterns):
                            continue

                    process_file(file)
        else:
            click.echo("[!] Use --recursive for directories", err=True)
            return

    else:
        # Process stdin (original logic)
        stdin_content = sys.stdin.read()
        extract_from_text(stdin_content, "stdin")

        # Check if stdin contains URLs to fetch
        if fetch_urls:
            potential_urls = URL_REGEX.findall(stdin_content)
            initial_urls.extend(potential_urls)

    # Process URLs if fetch_urls is enabled
    if fetch_urls and "url" in results:
        urls_to_fetch = list(results["url"]) + initial_urls
        if urls_to_fetch:
            if verbose:
                click.echo(
                    f"🚀 [FETCH-MODE] Processing {len(urls_to_fetch)} URLs with {threads} threads"
                )
            process_urls_concurrent(urls_to_fetch)

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔍 POST-PROCESSING: JWT DECODING, BASE64 ANALYSIS, ENTROPY DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════

    # JWT token decoding
    if jwt and "jwt" in results:
        jwt_decoded = []
        for token in results["jwt"]:
            decoded = decode_jwt_token(token)
            if decoded:
                jwt_decoded.append(
                    {
                        "token": token,
                        "header": decoded["header"],
                        "payload": decoded["payload"],
                    }
                )
                if verbose:
                    click.echo(f"🎫 [JWT-DECODED] {token[:20]}...")

        # Store decoded JWT data for output
        if jwt_decoded:
            results["jwt_decoded"] = set()
            for item in jwt_decoded:
                results["jwt_decoded"].add(
                    f"JWT: {item['token'][:30]}... | Header: {item['header']} | Payload: {item['payload']}"
                )

    # Enhanced Base64 decoding
    if base64 and "base64_enhanced" in results:
        base64_decoded = []
        for b64_string in results["base64_enhanced"]:
            if len(b64_string) >= 20:  # Only process longer strings
                decoded = decode_base64_string(b64_string)
                if decoded:
                    base64_decoded.append(
                        {
                            "original": b64_string,
                            "decoded": decoded["decoded"],
                            "is_json": decoded["is_json"],
                            "json_data": decoded.get("json"),
                        }
                    )
                    if verbose:
                        click.echo(f"🔓 [BASE64-DECODED] {b64_string[:20]}...")

        # Store decoded Base64 data for output
        if base64_decoded:
            results["base64_decoded"] = set()
            for item in base64_decoded:
                if item["is_json"]:
                    results["base64_decoded"].add(
                        f"Base64 JSON: {item['original'][:30]}... -> {item['json_data']}"
                    )
                else:
                    results["base64_decoded"].add(
                        f"Base64: {item['original'][:30]}... -> {item['decoded'][:50]}..."
                    )

    # High-entropy string detection
    if entropy:
        all_strings = []
        for category, items in results.items():
            all_strings.extend(list(items))

        high_entropy_strings = detect_entropy_strings(
            all_strings, threshold=4.0, min_length=20
        )
        if high_entropy_strings:
            results["high_entropy"] = set()
            for item in high_entropy_strings:
                results["high_entropy"].add(
                    f"High Entropy: {item['value']} (H={item['entropy']})"
                )
            if verbose:
                click.echo(
                    f"🔥 [ENTROPY] Found {len(high_entropy_strings)} high-entropy strings"
                )

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🏷️ INTELLIGENT TAGGING AND CLASSIFICATION
    # ═══════════════════════════════════════════════════════════════════════════════

    tagged_results = []
    custom_rules = {}

    if auto_tag or tag_rules or tag_output or risk_scoring:
        if verbose:
            click.echo("🏷️ [TAGGING] Starting intelligent classification...")

        # Load custom rules if provided
        if tag_rules:
            custom_rules = load_custom_rules(tag_rules)
            if verbose:
                click.echo(f"📜 [TAGGING] Loaded {len(custom_rules)} custom rules")

        # Create tagged entries for all findings
        for category, items in results.items():
            if not items:
                continue

            for item in items:
                # Create entry structure compatible with tagger
                if category in ["url", "email", "domain"]:
                    # Extract domain from URL/email
                    if category == "url":
                        try:
                            from urllib.parse import urlparse

                            domain = urlparse(item).netloc
                        except:
                            domain = item
                    elif category == "email":
                        domain = item.split("@")[-1] if "@" in item else item
                    else:
                        domain = item

                    entry = {
                        "domain": domain,
                        "original_value": item,
                        "category": category,
                        "source": "extractorcli",
                        "ip": "",  # No IP resolution in extractor
                        "tags": [],
                    }

                    # Apply auto-tagging
                    if auto_tag:
                        try:
                            auto_tags = tagger_auto_tag(entry)
                            entry["tags"].extend(auto_tags)
                        except Exception:
                            # Fallback if tagger module not available
                            pass

                    # Apply custom rules
                    if custom_rules:
                        additional_tags = apply_custom_rules(entry, custom_rules)
                        entry["tags"].extend(additional_tags)

                    # Add category-based tags
                    category_tags = {
                        "graphql": ["api", "graphql"],
                        "swagger": ["api", "documentation"],
                        "api": ["api"],
                        "auth": ["security", "authentication"],
                        "secret": ["security", "credentials"],
                        "jwt": ["security", "token"],
                        "websocket": ["api", "realtime"],
                        "admin": ["security", "admin"],
                        "database": ["database"],
                        "har": ["testing", "http"],
                        "postman": ["testing", "api"],
                    }

                    if category in category_tags:
                        entry["tags"].extend(category_tags[category])

                    # Remove duplicates
                    entry["tags"] = list(set(entry["tags"]))

                    # Calculate risk score
                    if risk_scoring:
                        entry["risk_score"] = calculate_risk_score(
                            domain, entry["tags"]
                        )

                    tagged_results.append(entry)
                else:
                    # For non-domain items, create simplified entries
                    entry = {
                        "value": item,
                        "category": category,
                        "source": "extractorcli",
                        "tags": category_tags.get(category, [category]),
                    }

                    if risk_scoring:
                        # Simple risk scoring for non-domain items
                        risk_map = {
                            "secret": 9,
                            "jwt": 8,
                            "auth": 7,
                            "api": 5,
                            "graphql": 6,
                            "swagger": 4,
                            "base64": 3,
                        }
                        entry["risk_score"] = risk_map.get(category, 1)

                    tagged_results.append(entry)

        if verbose:
            click.echo(f"🎯 [TAGGING] Tagged {len(tagged_results)} findings")

        # Save tagged results if requested
        if tag_output:
            with open(tag_output, "w", encoding="utf-8") as f:
                json.dump(tagged_results, f, indent=2, ensure_ascii=False)
            click.echo(f"🏷️ [TAGGING] Saved tagged results to {tag_output}")

    # Filter out empty results and prepare final output
    final = {k: sorted(list(v)) for k, v in results.items() if v}

    # ═══════════════════════════════════════════════════════════════════════════════
    # 📊 HEX DUMP GENERATION
    # ═══════════════════════════════════════════════════════════════════════════════

    hex_dumps = []
    if hex_dump:
        click.echo("🔍 [HEX] Generating hex dumps...")
        files_to_dump = []

        # Collect files to dump based on input source
        source_type, source_data = input_source

        if source_type == "file" and source_data:
            files_to_dump.append(source_data)
        elif source_type == "list" and source_data:
            # Read file list and add those files
            try:
                with open(source_data, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and os.path.exists(line):
                            files_to_dump.append(line)
            except Exception as e:
                click.echo(f"⚠️ [HEX] Error reading file list: {e}")

        # Also include any files found during directory scanning
        if recursive and watch_dir:
            for root, dirs, files in os.walk(watch_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        files_to_dump.append(file_path)

        # Generate hex dumps with size limit (1KB by default)
        if files_to_dump:
            hex_dumps = generate_hex_dumps_for_files(files_to_dump, max_bytes=1024)
            click.echo(f"🔍 [HEX] Generated {len(hex_dumps)} hex dumps")

            # Add hex dumps to final results
            if hex_dumps:
                final["hex_dumps"] = hex_dumps

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔤 STRING EXTRACTION FROM BINARIES
    # ═══════════════════════════════════════════════════════════════════════════════

    string_results = []
    if strings:
        click.echo("🔤 [STRINGS] Extracting strings from binary files...", err=True)
        files_to_scan = []

        # Collect files to scan based on input source
        source_type, source_data = input_source

        if source_type == "file" and source_data:
            files_to_scan.append(source_data)
        elif source_type == "list" and source_data:
            try:
                with open(source_data, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and os.path.exists(line):
                            files_to_scan.append(line)
            except Exception as e:
                click.echo(f"⚠️ [STRINGS] Error reading file list: {e}")

        # Extract strings from files
        if files_to_scan:
            for file_path in files_to_scan:
                string_result = extract_strings_from_file(file_path, min_length=4)
                if string_result["strings"]:
                    string_results.append(string_result)
                    click.echo(
                        f"🔤 [STRINGS] {file_path}: {string_result['count']} strings found",
                        err=True,
                    )
                elif string_result["error"]:
                    click.echo(f"⚠️ [STRINGS] {string_result['error']}", err=True)

            # Add extracted strings to final results
            if string_results:
                final["extracted_strings"] = string_results

    # ═══════════════════════════════════════════════════════════════════════════════
    # 📦 ZIP/JAR/APK EXTRACTION AND SCANNING
    # ═══════════════════════════════════════════════════════════════════════════════

    zip_results = []
    if zip:
        click.echo("📦 [ZIP] Extracting and scanning archives...")
        archives_to_scan = []

        # Collect archive files to scan
        source_type, source_data = input_source

        if source_type == "file" and source_data:
            if source_data.lower().endswith((".zip", ".jar", ".apk")):
                archives_to_scan.append(source_data)
        elif source_type == "list" and source_data:
            try:
                with open(source_data, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if (
                            line
                            and os.path.exists(line)
                            and line.lower().endswith((".zip", ".jar", ".apk"))
                        ):
                            archives_to_scan.append(line)
            except Exception as e:
                click.echo(f"⚠️ [ZIP] Error reading file list: {e}")

        # Extract and scan archives
        if archives_to_scan:
            for archive_path in archives_to_scan:
                zip_result = extract_and_scan_zip(archive_path)
                if zip_result["scan_results"]:
                    zip_results.append(zip_result)
                    click.echo(
                        f"📦 [ZIP] {archive_path}: {len(zip_result['extracted_files'])} files extracted"
                    )
                elif zip_result["error"]:
                    click.echo(f"⚠️ [ZIP] {zip_result['error']}")

            # Add ZIP results to final results
            if zip_results:
                final["zip_extractions"] = zip_results

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🌐 CORS VULNERABILITY DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════

    cors_issues = []
    if cors:
        click.echo("🌐 [CORS] Checking for CORS vulnerabilities...", err=True)

        # Check headers in file content and extracted results
        content_to_check = ""

        # Add file content if available
        source_type, source_data = input_source
        if source_type == "file" and source_data and os.path.exists(source_data):
            try:
                with open(source_data, "r", encoding="utf-8", errors="ignore") as f:
                    content_to_check += f.read() + "\n"
            except Exception:
                pass

        # Also check extracted results
        for category, items in final.items():
            for item in items:
                if isinstance(item, str):
                    content_to_check += item + "\n"

        cors_result = check_cors_headers(content_to_check)
        if cors_result["vulnerabilities"]:
            cors_issues = cors_result["vulnerabilities"]
            for vuln in cors_result["vulnerabilities"]:
                severity_color = (
                    "🔴"
                    if vuln["severity"] == "CRITICAL"
                    else "🟡" if vuln["severity"] == "HIGH" else "🟢"
                )
                click.echo(f"{severity_color} [CORS] {vuln['type']}: {vuln['header']}")
                click.echo(f"    └─ {vuln['description']}")

            # Add CORS issues to final results
            final["cors_vulnerabilities"] = cors_issues

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🛡️ CONTENT SECURITY POLICY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════════

    csp_analysis = []
    if csp:
        click.echo("🛡️ [CSP] Analyzing Content-Security-Policy headers...", err=True)

        # Check CSP headers in file content and extracted results
        content_to_check = ""

        # Add file content if available
        source_type, source_data = input_source
        if source_type == "file" and source_data and os.path.exists(source_data):
            try:
                with open(source_data, "r", encoding="utf-8", errors="ignore") as f:
                    content_to_check += f.read() + "\n"
            except Exception:
                pass

        # Also check extracted results
        for category, items in final.items():
            for item in items:
                if isinstance(item, str):
                    content_to_check += item + "\n"

        # Find CSP headers
        csp_headers = []
        lines = content_to_check.split("\n")
        for line in lines:
            if "content-security-policy" in line.lower():
                # Extract CSP value
                if ":" in line:
                    csp_value = line.split(":", 1)[1].strip()
                    csp_headers.append(csp_value)

        if csp_headers:
            for i, csp_header in enumerate(csp_headers):
                csp_result = analyze_csp_header(csp_header)
                csp_analysis.append(
                    {
                        "header_index": i + 1,
                        "header_value": csp_header,
                        "analysis": csp_result,
                    }
                )

                click.echo(
                    f"🛡️ [CSP] Found CSP header with {len(csp_result['directives'])} directives"
                )

                # Show sources
                if csp_result["sources"]:
                    unique_sources = list(set(csp_result["sources"]))
                    click.echo(
                        f"    📍 Sources: {', '.join(unique_sources[:10])}{'...' if len(unique_sources) > 10 else ''}"
                    )

                # Show issues
                for issue in csp_result["issues"]:
                    click.echo(f"    {issue}")

                # Highlight dangerous items
                for unsafe_item in csp_result["unsafe_items"]:
                    severity_color = "🔴" if unsafe_item["severity"] == "HIGH" else "🟡"
                    click.echo(
                        f"    {severity_color} {unsafe_item['directive']}: {unsafe_item['value']} ({unsafe_item['type']})"
                    )
        else:
            click.echo("🛡️ [CSP] No Content-Security-Policy headers found", err=True)

        # Add CSP analysis to final results
        if csp_analysis:
            final["csp_analysis"] = csp_analysis

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔄 DEDUPLICATION AND MERGING LOGIC
    # ═══════════════════════════════════════════════════════════════════════════════

    def load_existing_data(file_path):
        """Load existing data from various file formats"""
        existing_data = {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = clean_ansi_codes(f.read().strip())  # Clean ANSI codes

            # Try to detect format
            if content.startswith("{"):
                # JSON format
                try:
                    data = json.loads(content)
                    for category, items in data.items():
                        if isinstance(items, list):
                            existing_data[category] = set(items)
                        elif isinstance(items, dict):
                            # Handle scored format
                            existing_data[category] = set(
                                item.get("value", item)
                                for item in items
                                if isinstance(item, dict)
                            )
                except json.JSONDecodeError:
                    pass
            else:
                # Plain text format - try to guess content type
                lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Auto-detect content type
                    if line.startswith("http"):
                        if "url" not in existing_data:
                            existing_data["url"] = set()
                        existing_data["url"].add(line)
                    elif "@" in line and "." in line:
                        if "email" not in existing_data:
                            existing_data["email"] = set()
                        existing_data["email"].add(line)
                    elif re.match(r"\d+\.\d+\.\d+\.\d+", line):
                        if "ip" not in existing_data:
                            existing_data["ip"] = set()
                        existing_data["ip"].add(line)
                    elif "." in line and not "/" in line:
                        if "domain" not in existing_data:
                            existing_data["domain"] = set()
                        existing_data["domain"].add(line)
                    else:
                        # Default to URL category
                        if "url" not in existing_data:
                            existing_data["url"] = set()
                        existing_data["url"].add(line)

        except Exception as e:
            if verbose:
                click.echo(f"⚠️  [MERGE-WARNING] Could not load {file_path}: {e}")

        return existing_data

    # Handle merging with existing file
    if merge_with:
        if verbose:
            click.echo(f"🔗 [MERGE] Loading existing data from {merge_with}")
        existing_data = load_existing_data(merge_with)

        # Merge data
        for category in final.keys():
            if category in existing_data:
                combined = final[category] + list(existing_data[category])
                final[category] = combined

    # Apply deduplication
    if dedup or merge_with or unique_only:
        if verbose:
            pre_dedup_count = sum(len(v) for v in final.values())

        dedup_categories = dedup_by.split(",") if dedup_by != "all" else final.keys()

        for category in dedup_categories:
            if category in final:
                if sort_results:
                    final[category] = sorted(list(set(final[category])))
                else:
                    final[category] = list(set(final[category]))

        if verbose:
            post_dedup_count = sum(len(v) for v in final.values())
            removed = pre_dedup_count - post_dedup_count
            click.echo(
                f"🧹 [DEDUP] Removed {removed} duplicates ({post_dedup_count} unique items remain)"
            )

    # Sort results if requested
    elif sort_results:
        final = {k: sorted(v) for k, v in final.items()}

    if verbose:
        total_items = sum(len(v) for v in final.values())
        click.echo(
            f"🎯 [SUMMARY] Final output: {total_items} total items across {len(final)} categories"
        )

    if ai_score:

        def calculate_score(entry, category):
            """Enhanced scoring algorithm"""
            score = 0
            entry_lower = entry.lower()

            # Category-specific scoring
            if category == "url":
                high_value_keywords = [
                    "admin",
                    "api",
                    "swagger",
                    "graphql",
                    "auth",
                    "login",
                    "internal",
                    "dev",
                    "test",
                    "debug",
                ]
                score += sum(
                    3 for keyword in high_value_keywords if keyword in entry_lower
                )

                # File extension scoring
                valuable_extensions = [
                    ".json",
                    ".xml",
                    ".config",
                    ".env",
                    ".properties",
                ]
                score += sum(2 for ext in valuable_extensions if ext in entry_lower)

            elif category == "secret":
                # Higher scores for potential secrets
                secret_indicators = [
                    "key",
                    "token",
                    "secret",
                    "password",
                    "api",
                    "auth",
                ]
                score += sum(
                    5 for indicator in secret_indicators if indicator in entry_lower
                )

            elif category == "api":
                api_indicators = ["v1", "v2", "v3", "rest", "graphql", "swagger"]
                score += sum(
                    2 for indicator in api_indicators if indicator in entry_lower
                )

            elif category == "api_docs":
                # High-value API documentation indicators
                high_value_api_terms = [
                    "management",
                    "admin",
                    "internal",
                    "private",
                    "enterprise",
                    "control",
                    "dashboard",
                ]
                score += sum(3 for term in high_value_api_terms if term in entry_lower)

                # API technology stack scoring
                api_tech_terms = [
                    "graphql",
                    "swagger",
                    "openapi",
                    "rest api",
                    "web api",
                    "api explorer",
                    "api gateway",
                ]
                score += sum(2 for term in api_tech_terms if term in entry_lower)

                # Specific API service indicators
                service_indicators = [
                    "trading",
                    "payment",
                    "banking",
                    "crypto",
                    "financial",
                    "security",
                    "auth",
                ]
                score += sum(
                    1 for indicator in service_indicators if indicator in entry_lower
                )

            # Universal high-value indicators
            high_value_general = [
                "private",
                "internal",
                "admin",
                "management",
                "control",
            ]
            score += sum(1 for keyword in high_value_general if keyword in entry_lower)

            return score

        if verbose:
            click.echo("🧠 [AI-SCORING] Applying intelligent scoring...")

        final = {
            k: sorted(v, key=lambda x: -calculate_score(x, k)) for k, v in final.items()
        }

    def find_tags_for_item(value, category):
        """Find tags for a specific item from tagged results"""
        if not tagged_results:
            return []

        for tagged_item in tagged_results:
            if (
                tagged_item.get("original_value") == value
                or tagged_item.get("value") == value
                or tagged_item.get("domain") == value
            ):
                return tagged_item.get("tags", [])
        return []

    def get_risk_score_for_item(value, category):
        """Get risk score for a specific item from tagged results"""
        if not tagged_results:
            return 0

        for tagged_item in tagged_results:
            if (
                tagged_item.get("original_value") == value
                or tagged_item.get("value") == value
                or tagged_item.get("domain") == value
            ):
                return tagged_item.get("risk_score", 0)
        return 0

    # Output formatting
    if to_jsonl:
        import json

        lines = []
        for category, values in final.items():
            for value in values:
                entry = {"type": category, "value": value}
                if ai_score:
                    entry["score"] = (
                        calculate_score(value, category)
                        if "calculate_score" in locals()
                        else 0
                    )
                if entropy:
                    entry["entropy"] = shannon_entropy(str(value))
                if auto_tag:
                    entry["tags"] = find_tags_for_item(value, category)
                if risk_scoring:
                    entry["risk_score"] = get_risk_score_for_item(value, category)
                lines.append(json.dumps(entry))
        output_data = "\n".join(lines)

    elif json_out:
        import json

        if ai_score and "calculate_score" in locals():
            # Add scores to JSON output
            scored_final = {}
            for category, values in final.items():
                scored_final[category] = []
                for value in values:
                    item_dict = {
                        "value": value,
                        "score": calculate_score(value, category),
                    }
                    if entropy:
                        item_dict["entropy"] = shannon_entropy(str(value))
                    if auto_tag:
                        item_dict["tags"] = find_tags_for_item(value, category)
                    if risk_scoring:
                        item_dict["risk_score"] = get_risk_score_for_item(
                            value, category
                        )
                    scored_final[category].append(item_dict)
            output_data = json.dumps(scored_final, indent=2)
        else:
            if entropy or auto_tag or risk_scoring:
                # Add entropy/tags to regular JSON output
                enhanced_final = {}
                for category, values in final.items():
                    enhanced_final[category] = []
                    for value in values:
                        item_dict = {"value": value}
                        if entropy:
                            item_dict["entropy"] = shannon_entropy(str(value))
                        if auto_tag:
                            item_dict["tags"] = find_tags_for_item(value, category)
                        if risk_scoring:
                            item_dict["risk_score"] = get_risk_score_for_item(
                                value, category
                            )
                        enhanced_final[category].append(item_dict)
                output_data = json.dumps(enhanced_final, indent=2)
            else:
                output_data = json.dumps(final, indent=2)

    elif tagged:
        output_data = f"# ExtractorCLI Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        output_data += f"# Processed: {input if input else 'stdin'}\n"
        output_data += f"# Types: {types}\n\n"

        for category, items in final.items():
            if items:
                output_data += f"\n## {category.upper()} ({len(items)} found):\n"
                for item in items:
                    if entropy:
                        item_entropy = shannon_entropy(str(item))
                        if ai_score and "calculate_score" in locals():
                            score = calculate_score(item, category)
                            output_data += f"[Score: {score:2d}] [ENTROPY] {item} (H={item_entropy}) [{category}]\n"
                        else:
                            output_data += (
                                f"[ENTROPY] {item} (H={item_entropy}) [{category}]\n"
                            )
                    else:
                        if ai_score and "calculate_score" in locals():
                            score = calculate_score(item, category)
                            output_data += f"[Score: {score:2d}] {item}\n"
                        else:
                            output_data += f"{item}\n"

    else:
        # Simple flat output
        if entropy:
            all_items = []
            for category, items in final.items():
                for item in items:
                    item_entropy = shannon_entropy(str(item))
                    all_items.append(
                        f"[ENTROPY] {item} (H={item_entropy}) [{category}]"
                    )
            output_data = "\n".join(all_items)
        else:
            all_items = []
            for category, items in final.items():
                for item in items:
                    # Handle dictionary items (like hex dumps, strings, zip results, etc.)
                    if isinstance(item, dict):
                        if category == "hex_dumps":
                            file_path = item.get("file_path", "unknown")
                            file_size = item.get("file_size", 0)
                            error = item.get("error")
                            if error:
                                all_items.append(f"[HEX] {file_path} - Error: {error}")
                            else:
                                all_items.append(
                                    f"[HEX] {file_path} ({file_size} bytes)"
                                )
                        elif category == "extracted_strings":
                            file_path = item.get("file_path", "unknown")
                            count = item.get("count", 0)
                            error = item.get("error")
                            if error:
                                all_items.append(
                                    f"[STRINGS] {file_path} - Error: {error}"
                                )
                            else:
                                all_items.append(
                                    f"[STRINGS] {file_path} ({count} strings)"
                                )
                        elif category == "zip_extractions":
                            archive_path = item.get("archive_path", "unknown")
                            extracted_count = len(item.get("extracted_files", []))
                            error = item.get("error")
                            if error:
                                all_items.append(
                                    f"[ZIP] {archive_path} - Error: {error}"
                                )
                            else:
                                all_items.append(
                                    f"[ZIP] {archive_path} ({extracted_count} files)"
                                )
                        elif category == "cors_vulnerabilities":
                            vuln_type = item.get("type", "Unknown")
                            severity = item.get("severity", "UNKNOWN")
                            all_items.append(f"[CORS] {severity}: {vuln_type}")
                        elif category == "csp_analysis":
                            header_index = item.get("header_index", 1)
                            analysis = item.get("analysis", {})
                            directive_count = len(analysis.get("directives", {}))
                            all_items.append(
                                f"[CSP] Header {header_index} ({directive_count} directives)"
                            )
                        else:
                            # For other dictionary items, convert to string
                            all_items.append(str(item))
                    else:
                        all_items.append(str(item))
            output_data = "\n".join(all_items)

    # ═══════════════════════════════════════════════════════════════════════════════
    # 🔥 XSS-VIBES INTEGRATION
    # ═══════════════════════════════════════════════════════════════════════════════

    if xss_scan or xss_discover:
        import subprocess
        import tempfile

        if verbose:
            click.echo("🔥 [XSS-VIBES] Starting XSS analysis...")

    # XSS Endpoint Discovery
    if xss_discover and target_domain:
        if verbose:
            click.echo(f"🔍 [XSS-DISCOVER] Discovering endpoints for {target_domain}")

        try:
            discover_output = f"{target_domain}_xss_endpoints.txt"
            subprocess.run(
                [
                    "xss-vibes",
                    "endpoints",
                    target_domain,
                    "--depth",
                    "2",
                    "--output",
                    discover_output,
                ],
                check=True,
                timeout=120,
            )

            if verbose:
                click.echo(f"✅ [XSS-DISCOVER] Results saved to {discover_output}")

            # Merge discovered endpoints back into results
            if Path(discover_output).exists():
                # XSS-vibes creates a directory, look for URL files
                if Path(discover_output).is_dir():
                    url_files = list(Path(discover_output).glob("*urls*.txt"))
                    all_discovered = []

                    for url_file in url_files:
                        with open(url_file, "r") as f:
                            urls = [line.strip() for line in f if line.strip()]
                            all_discovered.extend(urls)

                    if all_discovered:
                        if "url" not in final:
                            final["url"] = []
                        final["url"].extend(all_discovered)
                        final["url"] = list(set(final["url"]))  # Dedup

                        if verbose:
                            click.echo(
                                f"🔗 [MERGE] Added {len(all_discovered)} discovered endpoints"
                            )
                else:
                    # Single file case
                    with open(discover_output, "r") as f:
                        discovered_urls = [line.strip() for line in f if line.strip()]

                    if "url" not in final:
                        final["url"] = []
                    final["url"].extend(discovered_urls)
                    final["url"] = list(set(final["url"]))  # Dedup

                    if verbose:
                        click.echo(
                            f"🔗 [MERGE] Added {len(discovered_urls)} discovered endpoints"
                        )

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo("⏱️  [XSS-DISCOVER] Timeout reached")
        except subprocess.CalledProcessError:
            if verbose:
                click.echo("❌ [XSS-DISCOVER] Failed to run xss-vibes endpoints")
        except FileNotFoundError:
            if verbose:
                click.echo("❌ [XSS-DISCOVER] xss-vibes not found in PATH")

    # XSS Vulnerability Scanning
    if xss_scan and "url" in final and final["url"]:
        if verbose:
            click.echo(f"🎯 [XSS-SCAN] Testing {len(final['url'])} URLs for XSS")

        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp_file:
                for url in final["url"][:100]:  # Limit to first 100 URLs
                    tmp_file.write(f"{url}\n")
                tmp_file_path = tmp_file.name

            # Use first URL as positional argument (required by xss-vibes)
            first_url = final["url"][0] if final["url"] else "https://httpbin.org"
            xss_output = f"xss_scan_results_{int(time.time())}.txt"

            subprocess.run(
                [
                    "xss-vibes",
                    "scan",
                    first_url,
                    "--list",
                    tmp_file_path,
                    "--threads",
                    str(xss_threads),
                    "--timeout",
                    str(xss_timeout),
                    "--output",
                    xss_output,
                ],
                check=True,
                timeout=600,
            )

            if verbose:
                click.echo(f"✅ [XSS-SCAN] Results saved to {xss_output}")

            # Clean up temp file
            Path(tmp_file_path).unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            if verbose:
                click.echo("⏱️  [XSS-SCAN] Timeout reached")
        except subprocess.CalledProcessError:
            if verbose:
                click.echo("❌ [XSS-SCAN] Failed to run xss-vibes scan")
        except FileNotFoundError:
            if verbose:
                click.echo("❌ [XSS-SCAN] xss-vibes not found in PATH")

    # ═══════════════════════════════════════════════════════════════════════════════
    # 💾 FINAL OUTPUT GENERATION
    # ═══════════════════════════════════════════════════════════════════════════════

    # Regenerate output with merged data
    if xss_discover and "url" in final:
        # Regenerate final output data
        if to_jsonl:
            import json

            lines = []
            for category, values in final.items():
                for value in values:
                    entry = {"type": category, "value": value}
                    if ai_score:
                        entry["score"] = (
                            calculate_score(value, category)
                            if "calculate_score" in locals()
                            else 0
                        )
                    if entropy:
                        entry["entropy"] = shannon_entropy(str(value))
                    lines.append(json.dumps(entry))
            output_data = "\n".join(lines)

        elif json_out:
            import json

            if ai_score and "calculate_score" in locals():
                # Add scores to JSON output
                scored_final = {}
                for category, values in final.items():
                    scored_final[category] = []
                    for value in values:
                        item_dict = {
                            "value": value,
                            "score": calculate_score(value, category),
                        }
                        if entropy:
                            item_dict["entropy"] = shannon_entropy(str(value))
                        scored_final[category].append(item_dict)
                output_data = json.dumps(scored_final, indent=2)
            else:
                if entropy:
                    # Add entropy to regular JSON output
                    entropy_final = {}
                    for category, values in final.items():
                        entropy_final[category] = []
                        for value in values:
                            entropy_final[category].append(
                                {"value": value, "entropy": shannon_entropy(str(value))}
                            )
                    output_data = json.dumps(entropy_final, indent=2)
                else:
                    output_data = json.dumps(final, indent=2)

        elif tagged:
            output_data = (
                f"# ExtractorCLI Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            output_data += f"# Processed: {input if input else 'stdin'}\n"
            output_data += f"# Types: {types}\n"
            if xss_discover:
                output_data += f"# XSS-Vibes Integration: Enabled\n"
            output_data += "\n"

            for category, items in final.items():
                if items:
                    output_data += f"\n## {category.upper()} ({len(items)} found):\n"
                    for item in items:
                        item_line = ""
                        if entropy:
                            item_entropy = shannon_entropy(str(item))
                            if ai_score and "calculate_score" in locals():
                                score = calculate_score(item, category)
                                item_line = f"[Score: {score:2d}] [ENTROPY] {item} (H={item_entropy})"
                            else:
                                item_line = f"[ENTROPY] {item} (H={item_entropy})"
                        else:
                            if ai_score and "calculate_score" in locals():
                                score = calculate_score(item, category)
                                item_line = f"[Score: {score:2d}] {item}"
                            else:
                                item_line = f"{item}"

                        # Add tags if enabled
                        if auto_tag:
                            tags = find_tags_for_item(item, category)
                            if tags:
                                item_line += f" [tags: {', '.join(tags)}]"

                        # Add risk score if enabled
                        if risk_scoring:
                            risk_score = get_risk_score_for_item(item, category)
                            item_line += f" (risk: {risk_score})"

                        item_line += f" [{category}]\n"
                        output_data += item_line

        else:
            # Simple flat output
            if entropy or auto_tag or risk_scoring:
                all_items = []
                for category, items in final.items():
                    for item in items:
                        # Handle dictionary items (like hex dumps, strings, zip results, etc.)
                        if isinstance(item, dict):
                            if category == "hex_dumps":
                                file_path = item.get("file_path", "unknown")
                                file_size = item.get("file_size", 0)
                                error = item.get("error")
                                if error:
                                    item_line = f"[HEX] {file_path} - Error: {error}"
                                else:
                                    item_line = f"[HEX] {file_path} ({file_size} bytes)"
                            elif category == "extracted_strings":
                                file_path = item.get("file_path", "unknown")
                                count = item.get("count", 0)
                                error = item.get("error")
                                if error:
                                    item_line = (
                                        f"[STRINGS] {file_path} - Error: {error}"
                                    )
                                else:
                                    item_line = (
                                        f"[STRINGS] {file_path} ({count} strings)"
                                    )
                            elif category == "zip_extractions":
                                archive_path = item.get("archive_path", "unknown")
                                extracted_count = len(item.get("extracted_files", []))
                                error = item.get("error")
                                if error:
                                    item_line = f"[ZIP] {archive_path} - Error: {error}"
                                else:
                                    item_line = f"[ZIP] {archive_path} ({extracted_count} files)"
                            elif category == "cors_vulnerabilities":
                                vuln_type = item.get("type", "Unknown")
                                severity = item.get("severity", "UNKNOWN")
                                item_line = f"[CORS] {severity}: {vuln_type}"
                            elif category == "csp_analysis":
                                header_index = item.get("header_index", 1)
                                analysis = item.get("analysis", {})
                                directive_count = len(analysis.get("directives", {}))
                                item_line = f"[CSP] Header {header_index} ({directive_count} directives)"
                            else:
                                item_line = str(item)
                        else:
                            item_line = f"{item}"
                            if entropy:
                                item_entropy = shannon_entropy(str(item))
                                item_line = f"[ENTROPY] {item} (H={item_entropy})"

                            # Add tags if enabled
                            if auto_tag:
                                tags = find_tags_for_item(item, category)
                                if tags:
                                    item_line += f" [tags: {', '.join(tags)}]"

                            # Add risk score if enabled
                            if risk_scoring:
                                risk_score = get_risk_score_for_item(item, category)
                                item_line += f" (risk: {risk_score})"

                        item_line += f" [{category}]"
                        all_items.append(item_line)
                output_data = "\n".join(all_items)
            else:
                all_items = []
                for items in final.values():
                    all_items.extend(items)
                output_data = "\n".join(all_items)

    # Output results
    if output:
        output_path = Path(output)
        output_path.write_text(output_data, encoding="utf-8")
        click.echo(f"✅ [SAVED] Results saved to {output}")

        if verbose:
            total_items = sum(len(v) for v in final.values())
            click.echo(
                f"📊 [STATS] {total_items} items saved across {len(final)} categories"
            )
    elif not report and report_format.lower() == "txt":
        # Only output to stdout when not generating reports
        click.echo(output_data)

    # ═══════════════════════════════════════════════════════════════════════════════
    # 💾 DATABASE STORAGE
    # ═══════════════════════════════════════════════════════════════════════════════

    if store_db:
        import sqlite3
        from datetime import datetime

        if verbose:
            click.echo(f"💾 [DATABASE] Storing results to {db_path}")

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create tables if they don't exist
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS extraction_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    input_source TEXT,
                    types TEXT,
                    total_items INTEGER,
                    ai_score_enabled BOOLEAN,
                    score_threshold INTEGER
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS extracted_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER,
                    category TEXT,
                    value TEXT,
                    score INTEGER,
                    timestamp TEXT,
                    FOREIGN KEY (run_id) REFERENCES extraction_runs (id)
                )
            """
            )

            # Insert run record
            timestamp = datetime.now().isoformat()
            total_items = sum(len(v) for v in final.values())

            cursor.execute(
                """
                INSERT INTO extraction_runs 
                (timestamp, input_source, types, total_items, ai_score_enabled, score_threshold)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    timestamp,
                    input if input else "stdin",
                    types,
                    total_items,
                    ai_score,
                    score_threshold,
                ),
            )

            run_id = cursor.lastrowid

            # Insert individual items
            for category, items in final.items():
                for item in items:
                    score = 0
                    if ai_score and "calculate_score" in locals():
                        score = calculate_score(item, category)

                    cursor.execute(
                        """
                        INSERT INTO extracted_items 
                        (run_id, category, value, score, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """,
                        (run_id, category, item, score, timestamp),
                    )

            conn.commit()
            conn.close()

            if verbose:
                click.echo(
                    f"✅ [DATABASE] Stored {total_items} items in run ID {run_id}"
                )

        except Exception as e:
            if verbose:
                click.echo(f"❌ [DATABASE] Error storing to database: {e}")

    # ═══════════════════════════════════════════════════════════════════════════════
    # 📊 REPORT GENERATION LOGIC
    # ═══════════════════════════════════════════════════════════════════════════════

    if (
        report or report_format.lower() != "txt"
    ):  # Generate report if --report flag or non-default format
        from datetime import datetime

        def generate_html_report(
            final_results,
            entropy_enabled=False,
            tagging_enabled=False,
            risk_scoring_enabled=False,
        ):
            """Generate HTML report with results and entropy data"""
            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ExtractorCLI Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <!-- DataTables CSS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/responsive/2.5.0/css/responsive.bootstrap5.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        .section {{ background: white; margin: 30px 0; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        .category-title {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 12px; margin-bottom: 20px; font-weight: 600; }}
        .item {{ margin: 8px 0; padding: 12px; background-color: #f8f9fa; border-left: 4px solid #007bff; border-radius: 6px; transition: all 0.2s ease; }}
        .item:hover {{ background-color: #e9ecef; transform: translateX(3px); }}
        .entropy {{ color: #28a745; font-weight: bold; }}
        .high-entropy {{ color: #dc3545; font-weight: bold; background: #fff5f5; padding: 2px 6px; border-radius: 4px; }}
        .stats {{ display: flex; justify-content: space-between; flex-wrap: wrap; gap: 15px; }}
        .stat-box {{ background: linear-gradient(135deg, #e9ecef 0%, #f8f9fa 100%); padding: 20px; border-radius: 10px; margin: 5px; min-width: 200px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
        .stat-number {{ font-size: 2.2em; font-weight: 700; color: #495057; margin-bottom: 5px; }}
        .jwt-decode {{ background: #fff3cd; padding: 12px; margin: 8px 0; border-radius: 6px; border-left: 4px solid #ffc107; }}
        .base64-decode {{ background: #d1ecf1; padding: 12px; margin: 8px 0; border-radius: 6px; border-left: 4px solid #17a2b8; }}
        .tags {{ display: inline-block; margin-left: 10px; }}
        .tag {{ background: #007bff; color: white; padding: 3px 8px; border-radius: 15px; font-size: 0.8em; margin: 0 3px; display: inline-block; }}
        .risk-low {{ color: #28a745; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-high {{ color: #dc3545; font-weight: bold; }}
        .risk-critical {{ color: #6f42c1; font-weight: bold; }}
        .hex-dump {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #6c757d; }}
        .hex-dump strong {{ color: #495057; }}
        .hex-dump pre {{ margin: 10px 0 0 0; max-height: 300px; overflow-y: auto; }}
        
        /* Enhanced DataTable styling */
        .dataTables_wrapper {{ margin-top: 20px; }}
        .dt-buttons {{ margin-bottom: 15px; }}
        .dt-button {{ margin-right: 5px !important; }}
        .table-responsive {{ border-radius: 8px; overflow: hidden; }}
        .findings-table {{ font-size: 0.9em; }}
        .findings-table th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: 600; }}
        .collapsible-row {{ cursor: pointer; transition: background-color 0.2s ease; }}
        .collapsible-row:hover {{ background-color: #f8f9fa; }}
        .details-row {{ background-color: #f8f9fa; }}
        .badge-risk-low {{ background-color: #28a745; }}
        .badge-risk-medium {{ background-color: #ffc107; color: #000; }}
        .badge-risk-high {{ background-color: #dc3545; }}
        .badge-risk-critical {{ background-color: #6f42c1; }}
        .export-section {{ background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .filter-section {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #dee2e6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🧲 ExtractorCLI Analysis Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Input Source: {input_file or input_url or 'stdin'}</p>
        <p>Types Processed: {types}</p>
        {'<p>✅ Entropy Analysis: Enabled</p>' if entropy_enabled else ''}
        {'<p>🏷️ Auto-Tagging: Enabled</p>' if tagging_enabled else ''}
        {'<p>⚠️ Risk Scoring: Enabled</p>' if risk_scoring_enabled else ''}
    </div>

    <!-- Export and Filter Controls -->
    <div class="export-section">
        <div class="row">
            <div class="col-md-6">
                <h5><i class="bi bi-download"></i> Export Options</h5>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="exportTableData('csv')">
                        <i class="bi bi-filetype-csv"></i> CSV
                    </button>
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="exportTableData('json')">
                        <i class="bi bi-filetype-json"></i> JSON
                    </button>
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="exportTableData('excel')">
                        <i class="bi bi-file-earmark-excel"></i> Excel
                    </button>
                </div>
            </div>
            <div class="col-md-6">
                <h5><i class="bi bi-funnel"></i> Quick Filters</h5>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-success btn-sm" onclick="filterByRisk('all')">All</button>
                    <button type="button" class="btn btn-outline-warning btn-sm" onclick="filterByRisk('medium')">Medium+</button>
                    <button type="button" class="btn btn-outline-danger btn-sm" onclick="filterByRisk('high')">High+</button>
                    <button type="button" class="btn btn-outline-info btn-sm" onclick="toggleHighEntropy()">High Entropy</button>
                </div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>📊 Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{sum(len(v) for v in final_results.values())}</div>
                <div>Total Items Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(final_results)}</div>
                <div>Categories</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len([v for v in final_results.values() if 'high_entropy' in str(v)])}</div>
                <div>High Entropy Items</div>
            </div>
        </div>
    </div>
"""

            # Add DataTable with all findings
            html_template += """
    <div class="section">
        <h2 class="category-title"><i class="bi bi-table"></i> All Findings</h2>
        <div class="table-responsive">
            <table id="findingsTable" class="table table-striped table-hover findings-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Value</th>
                        <th>Entropy</th>
                        <th>Tags</th>
                        <th>Risk</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
"""

            # Generate table rows for all findings
            all_findings = []
            for category, items in final_results.items():
                if not items:
                    continue

                emoji_map = {
                    "url": "🔗",
                    "email": "📧",
                    "form": "📝",
                    "auth": "🔐",
                    "api": "🚀",
                    "secret": "🔑",
                    "trufflehog_secrets": "🔍",
                    "jwt": "🎫",
                    "websocket": "🔌",
                    "har": "🗂️",
                    "postman": "📮",
                    "base64_enhanced": "🔓",
                    "high_entropy": "🔥",
                    "jwt_decoded": "🎯",
                    "base64_decoded": "📋",
                    "hex_dumps": "🔍",
                    "extracted_strings": "🔤",
                    "zip_extractions": "📦",
                    "cors_vulnerabilities": "🌐",
                    "csp_analysis": "🛡️",
                    "ip": "📍",
                    "domain": "🌐",
                    "subdomain": "🌍",
                    "phone": "📞",
                    "crypto": "₿",
                    "social": "📱",
                    "pii": "🆔",
                    "graphql": "🔗",
                    "api_docs": "📚",
                    "tech_stack": "🔧",
                }

                emoji = emoji_map.get(category, "📄")

                for item in items:
                    # Handle different item types
                    if isinstance(item, dict):
                        if category == "hex_dumps":
                            value = f"{item.get('file_path', 'unknown')} ({item.get('file_size', 0)} bytes)"
                            entropy_val = "N/A"
                            tags = ""
                            risk_level = 0
                        elif category == "trufflehog_secrets":
                            # Special handling for TruffleHog secrets
                            value = item.get("content", str(item))
                            entropy_val = f"{item.get('entropy', 0):.2f}"
                            tags = ",".join(item.get("tags", []))
                            risk_level = item.get("risk_level", 0)
                            # Add detector info to display
                            detector = item.get("detector", "unknown")
                            verified = item.get("verified", False)
                            value = f"[{detector}{'✓' if verified else ''}] {value}"
                        elif category in [
                            "extracted_strings",
                            "zip_extractions",
                            "cors_vulnerabilities",
                            "csp_analysis",
                        ]:
                            value = str(
                                item.get("file_path", item.get("url", str(item)))
                            )[:100]
                            entropy_val = "N/A"
                            tags = ""
                            risk_level = 0
                        else:
                            # Handle tagged items
                            value = str(
                                item.get("content", item.get("value", str(item)))
                            )
                            entropy_val = (
                                f"{item.get('entropy', 0):.2f}"
                                if "entropy" in item
                                else "N/A"
                            )
                            tags = ",".join(item.get("tags", []))
                            risk_level = item.get("risk_level", 0)
                    else:
                        # Handle TruffleHog JSON strings
                        if category == "trufflehog_secrets":
                            try:
                                import json

                                secret_data = json.loads(item)
                                value = secret_data.get("content", str(item))
                                entropy_val = f"{secret_data.get('entropy', 0):.2f}"
                                tags = ",".join(secret_data.get("tags", []))
                                risk_level = secret_data.get("risk_level", 0)
                                detector = secret_data.get("detector", "unknown")
                                verified = secret_data.get("verified", False)
                                value = f"[{detector}{'✓' if verified else ''}] {value}"
                            except:
                                value = str(item)
                                entropy_val = "N/A"
                                tags = ""
                                risk_level = 0
                        else:
                            # Simple string item
                            value = str(item)
                            entropy_val = (
                                f"{shannon_entropy(value):.2f}"
                                if entropy_enabled
                                else "N/A"
                            )
                            tags = ""
                            risk_level = 0

                    # Determine risk class
                    if risk_level >= 8:
                        risk_class = "critical"
                        risk_badge = "badge-risk-critical"
                    elif risk_level >= 6:
                        risk_class = "high"
                        risk_badge = "badge-risk-high"
                    elif risk_level >= 3:
                        risk_class = "medium"
                        risk_badge = "badge-risk-medium"
                    else:
                        risk_class = "low"
                        risk_badge = "badge-risk-low"

                    # Escape HTML
                    safe_value = (
                        value.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace('"', "&quot;")
                    )
                    safe_tags = (
                        tags.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                    )

                    # Truncate long values for table display
                    display_value = (
                        safe_value[:80] + "..." if len(safe_value) > 80 else safe_value
                    )

                    html_template += f"""
                    <tr class="collapsible-row" data-category="{category}" data-risk="{risk_class}" data-entropy="{entropy_val}">
                        <td><span title="{category}">{emoji} {category.replace('_', ' ').title()}</span></td>
                        <td>
                            <span class="value-cell" title="{safe_value}">{display_value}</span>
                        </td>
                        <td class="{'high-entropy' if float(entropy_val.replace('N/A', '0')) > 4.0 else 'entropy'}">{entropy_val}</td>
                        <td>
                            {f'<span class="badge bg-primary">{safe_tags}</span>' if tags else '<span class="text-muted">-</span>'}
                        </td>
                        <td>
                            <span class="badge {risk_badge}">{risk_class.title()} ({risk_level})</span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary" onclick="copyToClipboard('{safe_value}')" title="Copy">
                                <i class="bi bi-clipboard"></i>
                            </button>
                        </td>
                    </tr>
"""

            html_template += """
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Legacy sections for special formatting -->
"""

            # Add detailed results for each category (legacy sections for special items)
            for category, items in final_results.items():
                if not items:
                    continue

                # Only show special formatting sections for complex items
                if category in [
                    "hex_dumps",
                    "extracted_strings",
                    "zip_extractions",
                    "cors_vulnerabilities",
                    "csp_analysis",
                ]:
                    emoji_map = {
                        "hex_dumps": "🔍",
                        "extracted_strings": "🔤",
                        "zip_extractions": "📦",
                        "cors_vulnerabilities": "🌐",
                        "csp_analysis": "🛡️",
                    }

                    emoji = emoji_map.get(category, "📄")
                    html_template += f"""
    <div class="section">
        <h2 class="category-title">{emoji} {category.upper().replace('_', ' ')} ({len(items)} found)</h2>
"""

                for item in sorted(items):
                    item_html = ""
                    item_class = "item"

                    # Special handling for different item types
                    if category == "hex_dumps" and isinstance(item, dict):
                        # Special formatting for hex dumps
                        item_class = "hex-dump"
                        file_path = item.get("file_path", "unknown")
                        file_size = item.get("file_size", 0)
                        truncated = item.get("truncated", False)
                        error = item.get("error")
                        hex_data = item.get("hex_dump", "")

                        if error:
                            item_html = f'<strong>{file_path}</strong> <span class="risk-high">(Error: {error})</span>'
                        else:
                            status = " (truncated)" if truncated else ""
                            item_html = f'<strong>{file_path}</strong> ({file_size} bytes{status})<br><pre style="background:#f8f9fa;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;overflow-x:auto;">{hex_data}</pre>'
                    elif category == "extracted_strings" and isinstance(item, dict):
                        # Special formatting for string extraction results
                        item_class = "item"
                        file_path = item.get("file_path", "unknown")
                        count = item.get("count", 0)
                        error = item.get("error")

                        if error:
                            item_html = f'<strong>{file_path}</strong> <span class="risk-high">(Error: {error})</span>'
                        else:
                            strings = item.get("strings", [])
                            preview = strings[:5] if strings else []
                            preview_text = "<br>".join(
                                [
                                    f"• {s[:50]}{'...' if len(s) > 50 else ''}"
                                    for s in preview
                                ]
                            )
                            more_text = (
                                f"<br><em>... and {len(strings) - 5} more strings</em>"
                                if len(strings) > 5
                                else ""
                            )
                            item_html = f'<strong>{file_path}</strong> ({count} strings found)<br><div style="margin:10px 0;padding:10px;background:#f8f9fa;border-radius:4px;font-family:monospace;font-size:12px;">{preview_text}{more_text}</div>'
                    elif category == "zip_extractions" and isinstance(item, dict):
                        # Special formatting for ZIP extraction results
                        item_class = "item"
                        archive_path = item.get("archive_path", "unknown")
                        extracted_files = item.get("extracted_files", [])
                        error = item.get("error")

                        if error:
                            item_html = f'<strong>{archive_path}</strong> <span class="risk-high">(Error: {error})</span>'
                        else:
                            file_list = extracted_files[:10] if extracted_files else []
                            file_text = "<br>".join([f"• {f}" for f in file_list])
                            more_text = (
                                f"<br><em>... and {len(extracted_files) - 10} more files</em>"
                                if len(extracted_files) > 10
                                else ""
                            )
                            item_html = f'<strong>{archive_path}</strong> ({len(extracted_files)} files extracted)<br><div style="margin:10px 0;padding:10px;background:#f8f9fa;border-radius:4px;font-size:12px;">{file_text}{more_text}</div>'
                    elif category == "cors_vulnerabilities" and isinstance(item, dict):
                        # Special formatting for CORS vulnerabilities
                        vuln_type = item.get("type", "Unknown")
                        severity = item.get("severity", "UNKNOWN")
                        header = item.get("header", "")
                        description = item.get("description", "")

                        severity_class = (
                            "risk-critical"
                            if severity == "CRITICAL"
                            else "risk-high" if severity == "HIGH" else "risk-medium"
                        )
                        item_class = "item"
                        item_html = f'<span class="{severity_class}">[{severity}]</span> <strong>{vuln_type}</strong><br><code>{header}</code><br><em>{description}</em>'
                    elif category == "csp_analysis" and isinstance(item, dict):
                        # Special formatting for CSP analysis
                        item_class = "item"
                        header_index = item.get("header_index", 1)
                        analysis = item.get("analysis", {})
                        directives = analysis.get("directives", {})
                        unsafe_items = analysis.get("unsafe_items", [])

                        directive_text = "<br>".join(
                            [
                                f"• <strong>{k}:</strong> {' '.join(v)}"
                                for k, v in directives.items()
                            ]
                        )
                        unsafe_text = ""
                        if unsafe_items:
                            unsafe_text = (
                                "<br><br><strong>⚠️ Security Issues:</strong><br>"
                            )
                            unsafe_text += "<br>".join(
                                [
                                    f"• <span class=\"risk-high\">{u['directive']}: {u['value']}</span> ({u['type']})"
                                    for u in unsafe_items
                                ]
                            )

                        item_html = f'<strong>CSP Header {header_index}</strong><br><div style="margin:10px 0;padding:10px;background:#f8f9fa;border-radius:4px;font-size:12px;">{directive_text}{unsafe_text}</div>'
                    elif "entropy" in category.lower() and "H=" in str(item):
                        item_class = "item high-entropy"
                        item_html = str(item)
                    elif "JWT:" in str(item) and "|" in str(item):
                        item_class = "jwt-decode"
                        item_html = str(item)
                    elif "Base64" in str(item) and "->" in str(item):
                        item_class = "base64-decode"
                        item_html = str(item)
                    elif entropy_enabled and len(str(item)) > 15:
                        item_entropy = shannon_entropy(str(item))
                        if item_entropy >= 4.0:
                            item_html = f'<span class="high-entropy">{item}</span> <span class="entropy">(H={item_entropy})</span>'
                        else:
                            item_html = f'{item} <span class="entropy">(H={item_entropy})</span>'
                    else:
                        item_html = str(item)

                    # Add tags if enabled
                    if tagging_enabled:
                        tags = find_tags_for_item(item, category)
                        if tags:
                            tags_html = (
                                '<span class="tags">'
                                + "".join(
                                    [f'<span class="tag">{tag}</span>' for tag in tags]
                                )
                                + "</span>"
                            )
                            item_html += tags_html

                    # Add risk score if enabled
                    if risk_scoring_enabled:
                        risk_score = get_risk_score_for_item(item, category)
                        risk_class = "risk-low"
                        if risk_score >= 7:
                            risk_class = "risk-critical"
                        elif risk_score >= 5:
                            risk_class = "risk-high"
                        elif risk_score >= 3:
                            risk_class = "risk-medium"
                        item_html += (
                            f' <span class="{risk_class}">(Risk: {risk_score})</span>'
                        )

                    html_template += (
                        f'        <div class="{item_class}">{item_html}</div>\n'
                    )

                html_template += "    </div>\n"

            html_template += """
    
    <!-- JavaScript Libraries -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    
    <script>
        $(document).ready(function() {
            // Initialize DataTable
            const table = $('#findingsTable').DataTable({
                responsive: true,
                pageLength: 25,
                dom: 'Bfrtip',
                buttons: [
                    'copy',
                    'csv', 
                    'excel',
                    'print',
                    {
                        extend: 'colvis',
                        text: 'Columns'
                    }
                ],
                order: [[4, 'desc']], // Sort by risk level desc
                columnDefs: [
                    {
                        targets: [2], // Entropy column
                        type: 'num'
                    },
                    {
                        targets: [4], // Risk column  
                        render: function(data, type, row) {
                            if (type === 'sort') {
                                // Extract risk number for sorting
                                const match = data.match(/\\((\\d+)\\)/);
                                return match ? parseInt(match[1]) : 0;
                            }
                            return data;
                        }
                    }
                ],
                language: {
                    search: "Search findings:",
                    lengthMenu: "Show _MENU_ findings per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ findings",
                    infoEmpty: "No findings available",
                    infoFiltered: "(filtered from _MAX_ total findings)"
                }
            });
            
            // Risk level filtering
            window.filterByRisk = function(level) {
                if (level === 'all') {
                    table.column(4).search('').draw();
                } else if (level === 'high') {
                    table.column(4).search('(High|Critical)', true, false).draw();
                } else if (level === 'medium') {
                    table.column(4).search('(Medium|High|Critical)', true, false).draw();
                }
            };
            
            // High entropy filtering
            window.toggleHighEntropy = function() {
                const currentSearch = table.column(2).search();
                if (currentSearch) {
                    table.column(2).search('').draw();
                } else {
                    table.column(2).search('[4-9]\\\\.[0-9]', true, false).draw();
                }
            };
            
            // Export functions
            window.exportTableData = function(format) {
                const data = table.data().toArray();
                const headers = ['Category', 'Value', 'Entropy', 'Tags', 'Risk'];
                
                if (format === 'csv') {
                    exportToCSV(data, headers);
                } else if (format === 'json') {
                    exportToJSON(data, headers);
                } else if (format === 'excel') {
                    // Use DataTables built-in Excel export
                    table.button('.buttons-excel').trigger();
                }
            };
            
            function exportToCSV(data, headers) {
                let csv = headers.join(',') + '\\n';
                data.forEach(row => {
                    const cleanRow = row.map(cell => {
                        // Remove HTML tags and escape quotes
                        const clean = cell.replace(/<[^>]*>/g, '').replace(/"/g, '""');
                        return '"' + clean + '"';
                    });
                    csv += cleanRow.join(',') + '\\n';
                });
                
                const blob = new Blob([csv], { type: 'text/csv' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'extractorcli_findings.csv';
                a.click();
                window.URL.revokeObjectURL(url);
            }
            
            function exportToJSON(data, headers) {
                const jsonData = data.map(row => {
                    const obj = {};
                    headers.forEach((header, index) => {
                        obj[header.toLowerCase()] = row[index].replace(/<[^>]*>/g, '');
                    });
                    return obj;
                });
                
                const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'extractorcli_findings.json';
                a.click();
                window.URL.revokeObjectURL(url);
            }
            
            // Copy to clipboard function
            window.copyToClipboard = function(text) {
                navigator.clipboard.writeText(text).then(function() {
                    // Show success feedback
                    const toast = document.createElement('div');
                    toast.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                    toast.innerHTML = `
                        <div class="toast show" role="alert">
                            <div class="toast-header">
                                <i class="bi bi-check-circle-fill text-success me-2"></i>
                                <strong class="me-auto">Copied!</strong>
                            </div>
                            <div class="toast-body">
                                Text copied to clipboard
                            </div>
                        </div>
                    `;
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 3000);
                }).catch(function(err) {
                    console.error('Could not copy text: ', err);
                });
            };
            
            // Row click for expansion (placeholder for future enhancement)
            $('#findingsTable tbody').on('click', 'tr', function() {
                $(this).toggleClass('table-active');
            });
            
            // Initialize tooltips
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
            var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl)
            });
        });
    </script>
</body>
</html>
"""
            return html_template

        # Check if we need to generate reports at all
        need_html_for_stdout = (
            not report
            and report_format.lower() == "html"
            and not json_out
            and not to_jsonl
        )
        need_html_for_file = report and report_format.lower() == "html"

        # Only generate HTML if we actually need it
        if need_html_for_stdout or need_html_for_file:
            # Generate and save report
            report_content = generate_html_report(
                final,
                entropy_enabled=entropy,
                tagging_enabled=auto_tag,
                risk_scoring_enabled=risk_scoring,
            )

        if report:  # Only generate report files if --report flag was used
            if report_format.lower() == "html":
                report_filename = f"extractorcli_report_{int(time.time())}.html"
                with open(report_filename, "w", encoding="utf-8") as f:
                    f.write(report_content)
                click.echo(f"📊 [REPORT] HTML report saved to {report_filename}")
            elif report_format.lower() == "txt":
                report_filename = f"extractorcli_report_{int(time.time())}.txt"
                with open(report_filename, "w", encoding="utf-8") as f:
                    f.write(
                        f"ExtractorCLI Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    )
                    f.write("=" * 60 + "\n\n")
                    for category, items in final.items():
                        if items:
                            f.write(f"{category.upper()} ({len(items)} found):\n")
                            for item in sorted(items):
                                f.write(f"  - {item}\n")
                            f.write("\n")
                click.echo(f"📊 [REPORT] Text report saved to {report_filename}")

        if not report:  # Only output to stdout if --report flag was not used
            if to_jsonl:
                # JSONL output already handled above, just return
                return
            elif json_out:
                # JSON output already handled above, just return
                return
            elif report_format.lower() == "html":
                # Generate HTML report and output to stdout
                report_content = generate_html_report(
                    final,
                    entropy_enabled=entropy,
                    tagging_enabled=auto_tag,
                    risk_scoring_enabled=risk_scoring,
                )
                print(report_content)
                return  # Exit after printing HTML
            elif report_format.lower() == "json":
                # Output JSON to stdout
                import json

                print(json.dumps(final, indent=2, default=str))
            else:
                # Default text format to stdout
                print(
                    f"# ExtractorCLI Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                print(f"# Processed: {input_file or input_url or 'stdin'}")
                print(f"# Types: {types}")
                print()

                for category, items in final.items():
                    if items:
                        print(f"## {category.upper()} ({len(items)} found):")
                        for item in sorted(items):
                            print(f"[ENTROPY] {item}")
                        print()


if __name__ == "__main__":
    extractor()
