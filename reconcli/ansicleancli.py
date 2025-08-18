#!/usr/bin/env python3
"""
ANSICLEANCLI - Advanced ANSI Code Cleaning and Text Processing Tool

This tool provides comprehensive text cleaning capabilities including:
- ANSI escape code removal
- Bracket and parentheses cleaning
- AI-powered text analysis and cleanup
- Database storage for results
- Multiple output formats
- Statistical analysis of cleaned data

Part of the ReconCLI toolkit for security and text processing.
"""

import re
import sys
import json
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import click

# Configuration Constants
DEFAULT_BRACKETS = ["[]", "()", "{}", "<>"]
ANSI_PATTERNS = {
    "escape_sequences": r"\x1b\[[0-9;]*[mGKHfJ]",
    "color_codes": r"\x1b\[[0-9;]*m",
    "cursor_movement": r"\x1b\[[0-9;]*[ABCDEFGHIJKLMNOPQRSTUVWXYZ]",
    "clear_sequences": r"\x1b\[[0-9;]*[JK]",
    "all_escapes": r"\x1b\[[0-9;]*[a-zA-Z]",
    "extended_ansi": r"\x1b\].*?\x07",
    "vt100": r"\x1b[()][AB012]",
}

BRACKET_PATTERNS = {
    "square": r"\[([^\[\]]*)\]",
    "round": r"\(([^\(\)]*)\)",
    "curly": r"\{([^\{\}]*)\}",
    "angle": r"<([^<>]*)>",
    "nested_square": r"\[(?:[^\[\]]++|(?R))*\]",
    "nested_round": r"\((?:[^\(\)]++|(?R))*\)",
}

DATABASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS text_cleaning_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_file TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    original_size INTEGER NOT NULL,
    cleaned_size INTEGER NOT NULL,
    ansi_codes_removed INTEGER NOT NULL,
    brackets_removed INTEGER NOT NULL,
    cleaning_options TEXT NOT NULL,
    processing_time_ms INTEGER NOT NULL,
    ai_analysis TEXT,
    output_file TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ansi_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL,
    ansi_type TEXT NOT NULL,
    pattern_matched TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL,
    first_position INTEGER NOT NULL,
    last_position INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bracket_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL,
    bracket_type TEXT NOT NULL,
    content TEXT NOT NULL,
    position INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


class ANSICleanDatabase:
    """Database manager for ANSI cleaning results and statistics"""

    def __init__(self, db_path: str):
        """
        Initialize database connection and create tables.

        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()

    def _create_tables(self):
        """Create database tables if they don't exist"""
        try:
            self.conn.executescript(DATABASE_SCHEMA)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"❌ [DB-ERROR] Failed to create tables: {e}")

    def store_cleaning_result(self, result_data: Dict) -> bool:
        """Store text cleaning results in database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO text_cleaning_results 
                (timestamp, source_file, file_hash, original_size, cleaned_size, 
                 ansi_codes_removed, brackets_removed, cleaning_options, 
                 processing_time_ms, ai_analysis, output_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    result_data.get("timestamp"),
                    result_data.get("source_file"),
                    result_data.get("file_hash"),
                    result_data.get("original_size"),
                    result_data.get("cleaned_size"),
                    result_data.get("ansi_codes_removed"),
                    result_data.get("brackets_removed"),
                    json.dumps(result_data.get("cleaning_options", {})),
                    result_data.get("processing_time_ms"),
                    (
                        json.dumps(result_data.get("ai_analysis"))
                        if result_data.get("ai_analysis")
                        else None
                    ),
                    result_data.get("output_file"),
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"❌ [DB-ERROR] Failed to store result: {e}")
            return False

    def store_ansi_statistics(self, file_hash: str, ansi_stats: List[Dict]) -> bool:
        """Store ANSI code statistics"""
        try:
            cursor = self.conn.cursor()
            for stat in ansi_stats:
                cursor.execute(
                    """
                    INSERT INTO ansi_statistics 
                    (file_hash, ansi_type, pattern_matched, occurrence_count, 
                     first_position, last_position)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        file_hash,
                        stat.get("ansi_type"),
                        stat.get("pattern_matched"),
                        stat.get("occurrence_count"),
                        stat.get("first_position"),
                        stat.get("last_position"),
                    ),
                )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"❌ [DB-ERROR] Failed to store ANSI stats: {e}")
            return False

    def store_bracket_statistics(
        self, file_hash: str, bracket_stats: List[Dict]
    ) -> bool:
        """Store bracket removal statistics"""
        try:
            cursor = self.conn.cursor()
            for stat in bracket_stats:
                cursor.execute(
                    """
                    INSERT INTO bracket_statistics 
                    (file_hash, bracket_type, content, position)
                    VALUES (?, ?, ?, ?)
                """,
                    (
                        file_hash,
                        stat.get("bracket_type"),
                        stat.get("content"),
                        stat.get("position"),
                    ),
                )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"❌ [DB-ERROR] Failed to store bracket stats: {e}")
            return False

    def get_cleaning_history(self, limit: int = 10) -> List[Dict]:
        """Get recent cleaning history"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM text_cleaning_results 
                ORDER BY created_at DESC LIMIT ?
            """,
                (limit,),
            )
            rows = cursor.fetchall()

            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        except sqlite3.Error as e:
            print(f"❌ [DB-ERROR] Failed to get history: {e}")
            return []

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class ANSICleanAI:
    """AI-powered text analysis and cleaning recommendations"""

    @staticmethod
    def analyze_text_content(text: str, ansi_stats: Dict, bracket_stats: Dict) -> Dict:
        """
        Analyze text content and provide AI-powered insights.

        Args:
            text (str): Cleaned text content
            ansi_stats (dict): ANSI code statistics
            bracket_stats (dict): Bracket removal statistics

        Returns:
            dict: AI analysis results with insights and recommendations
        """
        analysis = {
            "content_type": "unknown",
            "probable_source": "unknown",
            "quality_score": 0.0,
            "recommendations": [],
            "patterns_detected": [],
            "security_indicators": [],
            "data_insights": {},
        }

        # Detect content type based on patterns
        url_pattern = r"https?://[^\s]+"
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        domain_pattern = (
            r"\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b"
        )
        hash_pattern = r"\b[a-fA-F0-9]{32,}\b"

        url_matches = len(re.findall(url_pattern, text))
        ip_matches = len(re.findall(ip_pattern, text))
        domain_matches = len(re.findall(domain_pattern, text))
        hash_matches = len(re.findall(hash_pattern, text))

        # Content type detection
        if url_matches > 10:
            analysis["content_type"] = "web_crawl_results"
            analysis["probable_source"] = "web crawler or URL enumeration tool"
        elif ip_matches > 5:
            analysis["content_type"] = "network_scan"
            analysis["probable_source"] = "network scanner or reconnaissance tool"
        elif hash_matches > 5:
            analysis["content_type"] = "hash_data"
            analysis["probable_source"] = "hash cracking or cryptographic tool"
        elif "GraphQL" in text or "swagger" in text.lower():
            analysis["content_type"] = "api_discovery"
            analysis["probable_source"] = "API discovery or documentation tool"

        # Quality assessment
        ansi_density = ansi_stats.get("total_ansi_codes", 0) / max(len(text), 1)
        bracket_density = bracket_stats.get("total_brackets", 0) / max(len(text), 1)

        quality_score = 1.0 - min(ansi_density * 10 + bracket_density * 5, 1.0)
        analysis["quality_score"] = round(quality_score, 3)

        # Pattern detection
        if ansi_stats.get("color_codes", 0) > 0:
            analysis["patterns_detected"].append("Terminal color output")
        if bracket_stats.get("square_brackets", 0) > 10:
            analysis["patterns_detected"].append("Structured data with labels")
        if url_matches > 0:
            analysis["patterns_detected"].append(f"{url_matches} URLs detected")
        if ip_matches > 0:
            analysis["patterns_detected"].append(f"{ip_matches} IP addresses detected")

        # Security indicators
        security_keywords = [
            "exploit",
            "vulnerability",
            "CVE-",
            "payload",
            "injection",
            "xss",
            "sql",
        ]
        for keyword in security_keywords:
            if keyword.lower() in text.lower():
                analysis["security_indicators"].append(f"Security keyword: {keyword}")

        # Recommendations
        if ansi_density > 0.1:
            analysis["recommendations"].append(
                "High ANSI code density - consider additional cleaning"
            )
        if bracket_density > 0.05:
            analysis["recommendations"].append(
                "Many brackets detected - verify data structure"
            )
        if quality_score < 0.5:
            analysis["recommendations"].append(
                "Low quality score - manual review recommended"
            )
        if len(analysis["security_indicators"]) > 0:
            analysis["recommendations"].append(
                "Security-related content detected - handle with care"
            )

        # Data insights
        analysis["data_insights"] = {
            "total_lines": len(text.split("\n")),
            "total_words": len(text.split()),
            "total_characters": len(text),
            "unique_urls": len(set(re.findall(url_pattern, text))),
            "unique_ips": len(set(re.findall(ip_pattern, text))),
            "unique_domains": len(set(re.findall(domain_pattern, text))),
        }

        return analysis


class ANSICleaner:
    """Advanced ANSI code and text cleaning processor"""

    def __init__(self, verbose: bool = False):
        """
        Initialize ANSI cleaner.

        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
        self.stats = {
            "ansi_codes_removed": 0,
            "brackets_removed": 0,
            "processing_time_ms": 0,
            "ansi_details": {},
            "bracket_details": {},
        }

    def clean_ansi_codes(
        self, text: str, pattern_types: List[str] = None
    ) -> Tuple[str, Dict]:
        """
        Remove ANSI escape codes from text.

        Args:
            text (str): Input text with ANSI codes
            pattern_types (list): List of ANSI pattern types to remove

        Returns:
            tuple: (cleaned_text, ansi_statistics)
        """
        if pattern_types is None:
            pattern_types = list(ANSI_PATTERNS.keys())

        ansi_stats = {}
        cleaned_text = text

        for pattern_name in pattern_types:
            if pattern_name in ANSI_PATTERNS:
                pattern = ANSI_PATTERNS[pattern_name]
                matches = list(re.finditer(pattern, cleaned_text))

                if matches:
                    ansi_stats[pattern_name] = {
                        "count": len(matches),
                        "first_position": matches[0].start(),
                        "last_position": matches[-1].end(),
                        "pattern": pattern,
                    }
                    cleaned_text = re.sub(pattern, "", cleaned_text)

                    if self.verbose:
                        print(f"🧹 [ANSI] Removed {len(matches)} {pattern_name} codes")

        total_removed = sum(stat["count"] for stat in ansi_stats.values())
        self.stats["ansi_codes_removed"] = total_removed
        self.stats["ansi_details"] = ansi_stats

        return cleaned_text, ansi_stats

    def clean_brackets(
        self,
        text: str,
        bracket_types: List[str] = None,
        keep_content: bool = True,
        custom_brackets: List[str] = None,
    ) -> Tuple[str, Dict]:
        """
        Remove or clean bracket content from text.

        Args:
            text (str): Input text with brackets
            bracket_types (list): Types of brackets to clean
            keep_content (bool): Whether to keep content inside brackets
            custom_brackets (list): Custom bracket pairs to remove

        Returns:
            tuple: (cleaned_text, bracket_statistics)
        """
        if bracket_types is None:
            bracket_types = list(BRACKET_PATTERNS.keys())

        bracket_stats = {}
        cleaned_text = text

        for bracket_type in bracket_types:
            if bracket_type in BRACKET_PATTERNS:
                pattern = BRACKET_PATTERNS[bracket_type]
                matches = list(re.finditer(pattern, cleaned_text))

                if matches:
                    bracket_stats[bracket_type] = {
                        "count": len(matches),
                        "contents": [match.group(1) for match in matches],
                        "positions": [match.start() for match in matches],
                    }

                    if keep_content:
                        # Replace brackets but keep content
                        cleaned_text = re.sub(pattern, r"\1", cleaned_text)
                    else:
                        # Remove brackets and content
                        cleaned_text = re.sub(pattern, "", cleaned_text)

                    if self.verbose:
                        action = "cleaned" if keep_content else "removed"
                        print(
                            f"🧹 [BRACKET] {action.title()} {len(matches)} {bracket_type} brackets"
                        )

        # Handle custom brackets
        if custom_brackets:
            for bracket_pair in custom_brackets:
                if len(bracket_pair) == 2:
                    open_br, close_br = bracket_pair
                    pattern = f"\\{open_br}([^\\{open_br}\\{close_br}]*)\\{close_br}"
                    matches = list(re.finditer(pattern, cleaned_text))

                    if matches:
                        bracket_stats[f"custom_{bracket_pair}"] = {
                            "count": len(matches),
                            "contents": [match.group(1) for match in matches],
                            "positions": [match.start() for match in matches],
                        }

                        if keep_content:
                            cleaned_text = re.sub(pattern, r"\1", cleaned_text)
                        else:
                            cleaned_text = re.sub(pattern, "", cleaned_text)

        total_removed = sum(stat["count"] for stat in bracket_stats.values())
        self.stats["brackets_removed"] = total_removed
        self.stats["bracket_details"] = bracket_stats

        return cleaned_text, bracket_stats

    def normalize_whitespace(self, text: str, preserve_structure: bool = True) -> str:
        """
        Normalize whitespace in text.

        Args:
            text (str): Input text
            preserve_structure (bool): Whether to preserve line structure

        Returns:
            str: Text with normalized whitespace
        """
        if preserve_structure:
            # Normalize spaces but preserve line breaks
            lines = text.split("\n")
            normalized_lines = []
            for line in lines:
                # Remove multiple spaces but preserve single spaces
                normalized_line = re.sub(r" +", " ", line.strip())
                normalized_lines.append(normalized_line)
            return "\n".join(normalized_lines)
        else:
            # Aggressive whitespace normalization
            return re.sub(r"\s+", " ", text).strip()

    def remove_empty_lines(self, text: str, consecutive_only: bool = True) -> str:
        """
        Remove empty lines from text.

        Args:
            text (str): Input text
            consecutive_only (bool): Only remove consecutive empty lines

        Returns:
            str: Text with empty lines removed
        """
        if consecutive_only:
            # Remove consecutive empty lines (keep single empty lines)
            return re.sub(r"\n\n+", "\n\n", text)
        else:
            # Remove all empty lines
            lines = [line for line in text.split("\n") if line.strip()]
            return "\n".join(lines)


def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of file content"""
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def save_results(results: Dict, output_file: str, format_type: str = "json") -> bool:
    """Save processing results to file"""
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format_type.lower() == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        elif format_type.lower() == "yaml":
            import yaml

            with open(output_path, "w", encoding="utf-8") as f:
                yaml.dump(results, f, default_flow_style=False, allow_unicode=True)
        else:
            # Text format
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(str(results))

        return True
    except Exception as e:
        print(f"❌ [SAVE-ERROR] Failed to save results: {e}")
        return False


@click.command()
@click.argument("input_file", type=click.Path(exists=True), required=False)
@click.option(
    "--input",
    "-i",
    "input_option",
    type=click.Path(exists=True),
    help="Input file path (alternative to positional argument)",
)
@click.option(
    "--output", "-o", help="Output file path (default: input_file_cleaned.txt)"
)
@click.option("--backup", is_flag=True, help="Create backup of original file")
@click.option(
    "--dry-run", is_flag=True, help="Show what would be cleaned without making changes"
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--store-db", help="Store results in SQLite database (provide DB path)")
@click.option("--ansi-only", is_flag=True, help="Only remove ANSI codes, keep brackets")
@click.option(
    "--brackets-only", is_flag=True, help="Only remove brackets, keep ANSI codes"
)
@click.option(
    "--keep-bracket-content",
    is_flag=True,
    default=True,
    help="Keep content inside brackets (default: True)",
)
@click.option(
    "--remove-bracket-content", is_flag=True, help="Remove content inside brackets"
)
@click.option(
    "--bracket-types",
    default="square,round",
    help="Bracket types to clean: square,round,curly,angle",
)
@click.option(
    "--ansi-types",
    default="all",
    help="ANSI types to remove: all,color,cursor,clear,escape",
)
@click.option(
    "--custom-brackets", help='Custom bracket pairs (e.g., "[],()" for multiple pairs)'
)
@click.option(
    "--normalize-whitespace", is_flag=True, help="Normalize whitespace in output"
)
@click.option(
    "--remove-empty-lines", is_flag=True, help="Remove empty lines from output"
)
@click.option(
    "--preserve-structure",
    is_flag=True,
    default=True,
    help="Preserve text structure (default: True)",
)
@click.option("--ai-analysis", is_flag=True, help="Enable AI-powered content analysis")
@click.option(
    "--ai-confidence-threshold",
    default=0.7,
    type=float,
    help="AI analysis confidence threshold",
)
@click.option("--export-stats", help="Export statistics to file (JSON/YAML)")
@click.option(
    "--export-format",
    default="json",
    type=click.Choice(["json", "yaml", "txt"]),
    help="Export format",
)
@click.option(
    "--show-history", is_flag=True, help="Show cleaning history from database"
)
@click.option("--benchmark", is_flag=True, help="Show performance benchmarks")
def main(
    input_file,
    input_option,
    output,
    backup,
    dry_run,
    verbose,
    store_db,
    ansi_only,
    brackets_only,
    keep_bracket_content,
    remove_bracket_content,
    bracket_types,
    ansi_types,
    custom_brackets,
    normalize_whitespace,
    remove_empty_lines,
    preserve_structure,
    ai_analysis,
    ai_confidence_threshold,
    export_stats,
    export_format,
    show_history,
    benchmark,
):
    """
    ANSICLEANCLI - Advanced ANSI Code Cleaning and Text Processing Tool

    Clean ANSI escape codes, brackets, and normalize text formatting from files.
    Includes AI-powered analysis, database storage, and comprehensive statistics.

    Examples:
        Basic ANSI cleaning (positional argument):
        $ reconcli ansicleancli input.txt

        Basic ANSI cleaning (secure input option):
        $ reconcli ansicleancli --input /absolute/path/to/input.txt

        Comprehensive cleaning with AI analysis:
        $ reconcli ansicleancli --input /path/to/input.txt --ai-analysis --store-db results.db
    """

    # Handle input file parameter - prioritize --input option over positional argument
    if input_option and input_file:
        click.echo(
            "Warning: Both --input option and positional argument provided. Using --input option.",
            err=True,
        )
        actual_input = input_option
    elif input_option:
        actual_input = input_option
    elif input_file:
        actual_input = input_file
    else:
        click.echo(
            "Error: No input file specified. Use either positional argument or --input option.",
            err=True,
        )
        return

    # Convert to Path object for validation
    input_path = Path(actual_input)

    # Validate that the input path is absolute (for security)
    if not input_path.is_absolute():
        click.echo(
            f"Error: Input path must be absolute. Provided: {actual_input}", err=True
        )
        return

    # Validate file exists
    if not input_path.exists():
        click.echo(f"Error: Input file does not exist: {actual_input}", err=True)
        return

    if not input_path.is_file():
        click.echo(f"Error: Input path is not a file: {actual_input}", err=True)
        return

    start_time = datetime.now()

    # Database setup
    db_manager = None
    if store_db or show_history:
        if not store_db:
            print("❌ [ERROR] --store-db required when using --show-history")
            return

        if verbose:
            print(f"💾 [DB] Initializing database: {store_db}")
        db_manager = ANSICleanDatabase(store_db)

        if show_history:
            history = db_manager.get_cleaning_history()
            print("\n📊 [HISTORY] Recent Cleaning Operations:")
            print("=" * 80)
            for record in history[:5]:
                print(f"🕒 {record['timestamp']}")
                print(f"📁 File: {record['source_file']}")
                print(
                    f"📏 Size: {record['original_size']} → {record['cleaned_size']} bytes"
                )
                print(
                    f"🧹 Cleaned: {record['ansi_codes_removed']} ANSI codes, {record['brackets_removed']} brackets"
                )
                print(f"⏱️  Time: {record['processing_time_ms']}ms")
                print("-" * 40)
            db_manager.close()
            return

    # Check if input file is provided for actual cleaning operations
    if not actual_input and not show_history:
        print("❌ [ERROR] Input file is required for cleaning operations")
        print("Use --help for usage information")
        return

    if verbose and actual_input:
        print("🚀 [START] ANSICLEANCLI - Advanced Text Cleaning Tool")
        print(f"📁 [INPUT] Processing file: {actual_input}")

    # Continue with existing database logic
    if not db_manager and (store_db or show_history):
        if verbose:
            print(f"💾 [DB] Initializing database: {store_db}")
        db_manager = ANSICleanDatabase(store_db)

        if show_history:
            history = db_manager.get_cleaning_history()
            print("\n📊 [HISTORY] Recent Cleaning Operations:")
            print("=" * 80)
            for record in history[:5]:
                print(f"🕒 {record['timestamp']}")
                print(f"📁 File: {record['source_file']}")
                print(
                    f"📏 Size: {record['original_size']} → {record['cleaned_size']} bytes"
                )
                print(
                    f"🧹 Cleaned: {record['ansi_codes_removed']} ANSI codes, {record['brackets_removed']} brackets"
                )
                print(f"⏱️  Time: {record['processing_time_ms']}ms")
                print("-" * 40)
            db_manager.close()
            return

    # Read input file
    try:
        with open(actual_input, "r", encoding="utf-8", errors="ignore") as f:
            original_text = f.read()
    except Exception as e:
        print(f"❌ [ERROR] Failed to read input file: {e}")
        return

    original_size = len(original_text)
    file_hash = calculate_file_hash(actual_input)

    if verbose:
        print(f"📊 [STATS] Original file size: {original_size:,} characters")
        print(f"🔍 [HASH] File hash: {file_hash[:16]}...")

    # Initialize cleaner
    cleaner = ANSICleaner(verbose=verbose)
    cleaned_text = original_text

    # Parse options
    if remove_bracket_content:
        keep_bracket_content = False

    # Parse bracket types
    bracket_type_list = []
    if bracket_types.lower() != "none":
        type_mapping = {
            "square": "square",
            "round": "round",
            "curly": "curly",
            "angle": "angle",
        }
        bracket_type_list = [
            type_mapping[bt.strip()]
            for bt in bracket_types.split(",")
            if bt.strip() in type_mapping
        ]

    # Parse ANSI types
    ansi_type_list = []
    if ansi_types.lower() == "all":
        ansi_type_list = list(ANSI_PATTERNS.keys())
    else:
        type_mapping = {
            "color": ["color_codes"],
            "cursor": ["cursor_movement"],
            "clear": ["clear_sequences"],
            "escape": ["escape_sequences", "all_escapes"],
        }
        for at in ansi_types.split(","):
            at = at.strip()
            if at in type_mapping:
                ansi_type_list.extend(type_mapping[at])

    # Parse custom brackets
    custom_bracket_list = []
    if custom_brackets:
        for bracket_pair in custom_brackets.split(","):
            bracket_pair = bracket_pair.strip()
            if len(bracket_pair) == 2:
                custom_bracket_list.append(bracket_pair)

    # Perform cleaning operations
    ansi_stats = {}
    bracket_stats = {}

    if not brackets_only:
        if verbose:
            print("🧹 [ANSI] Removing ANSI escape codes...")
        cleaned_text, ansi_stats = cleaner.clean_ansi_codes(
            cleaned_text, ansi_type_list
        )

    if not ansi_only:
        if verbose:
            print("🧹 [BRACKET] Processing brackets...")
        cleaned_text, bracket_stats = cleaner.clean_brackets(
            cleaned_text, bracket_type_list, keep_bracket_content, custom_bracket_list
        )

    # Additional text processing
    if normalize_whitespace:
        if verbose:
            print("🧹 [WHITESPACE] Normalizing whitespace...")
        cleaned_text = cleaner.normalize_whitespace(cleaned_text, preserve_structure)

    if remove_empty_lines:
        if verbose:
            print("🧹 [LINES] Removing empty lines...")
        cleaned_text = cleaner.remove_empty_lines(cleaned_text, preserve_structure)

    # Calculate results
    end_time = datetime.now()
    processing_time_ms = int((end_time - start_time).total_seconds() * 1000)
    cleaned_size = len(cleaned_text)
    size_reduction = original_size - cleaned_size
    reduction_percent = (
        (size_reduction / original_size * 100) if original_size > 0 else 0
    )

    # AI Analysis
    ai_analysis_result = None
    if ai_analysis:
        if verbose:
            print("🤖 [AI] Performing content analysis...")

        ai_analyzer = ANSICleanAI()
        ai_analysis_result = ai_analyzer.analyze_text_content(
            cleaned_text, ansi_stats, bracket_stats
        )

        if verbose:
            print(f"🤖 [AI] Content type: {ai_analysis_result['content_type']}")
            print(f"🤖 [AI] Probable source: {ai_analysis_result['probable_source']}")
            print(f"🤖 [AI] Quality score: {ai_analysis_result['quality_score']}")

            if ai_analysis_result["recommendations"]:
                print("🤖 [AI] Recommendations:")
                for rec in ai_analysis_result["recommendations"]:
                    print(f"    • {rec}")

    # Prepare results data
    results_data = {
        "timestamp": start_time.isoformat(),
        "source_file": str(actual_input),
        "file_hash": file_hash,
        "original_size": original_size,
        "cleaned_size": cleaned_size,
        "size_reduction": size_reduction,
        "reduction_percent": round(reduction_percent, 2),
        "ansi_codes_removed": cleaner.stats["ansi_codes_removed"],
        "brackets_removed": cleaner.stats["brackets_removed"],
        "processing_time_ms": processing_time_ms,
        "cleaning_options": {
            "ansi_only": ansi_only,
            "brackets_only": brackets_only,
            "keep_bracket_content": keep_bracket_content,
            "bracket_types": bracket_type_list,
            "ansi_types": ansi_type_list,
            "custom_brackets": custom_bracket_list,
            "normalize_whitespace": normalize_whitespace,
            "remove_empty_lines": remove_empty_lines,
            "preserve_structure": preserve_structure,
        },
        "ansi_statistics": ansi_stats,
        "bracket_statistics": bracket_stats,
        "ai_analysis": ai_analysis_result,
        "output_file": output,
    }

    # Show statistics
    print(f"\n📊 [RESULTS] Cleaning Summary:")
    print(
        f"   📏 Size: {original_size:,} → {cleaned_size:,} characters ({reduction_percent:.1f}% reduction)"
    )
    print(f"   🧹 ANSI codes removed: {cleaner.stats['ansi_codes_removed']:,}")
    print(f"   🧹 Brackets processed: {cleaner.stats['brackets_removed']:,}")
    print(f"   ⏱️  Processing time: {processing_time_ms}ms")

    if benchmark:
        chars_per_second = (
            (original_size / processing_time_ms * 1000) if processing_time_ms > 0 else 0
        )
        print(f"   ⚡ Performance: {chars_per_second:,.0f} chars/second")

    if ai_analysis_result:
        print(f"   🤖 AI Quality Score: {ai_analysis_result['quality_score']}")
        print(f"   🤖 Content Type: {ai_analysis_result['content_type']}")

    # Dry run check
    if dry_run:
        print("\n🔍 [DRY-RUN] No files were modified (dry run mode)")
        if db_manager:
            db_manager.close()
        return

    # Create backup if requested
    if backup:
        backup_path = f"{actual_input}.backup"
        try:
            import shutil

            shutil.copy2(actual_input, backup_path)
            if verbose:
                print(f"💾 [BACKUP] Created backup: {backup_path}")
        except Exception as e:
            print(f"⚠️ [BACKUP] Failed to create backup: {e}")

    # Determine output file
    if not output:
        input_path = Path(actual_input)
        output = input_path.parent / f"{input_path.stem}_cleaned{input_path.suffix}"

    # Save cleaned text
    try:
        with open(output, "w", encoding="utf-8") as f:
            f.write(cleaned_text)
        print(f"✅ [SAVED] Cleaned text saved to: {output}")
        results_data["output_file"] = str(output)
    except Exception as e:
        print(f"❌ [ERROR] Failed to save cleaned text: {e}")
        if db_manager:
            db_manager.close()
        return

    # Export statistics
    if export_stats:
        export_path = export_stats
        if not export_path.endswith((".json", ".yaml", ".yml", ".txt")):
            export_path += f".{export_format}"

        if save_results(results_data, export_path, export_format):
            if verbose:
                print(f"📊 [EXPORT] Statistics exported to: {export_path}")

    # Store in database
    if db_manager:
        if verbose:
            print("💾 [DB] Storing results in database...")

        # Store main result
        db_manager.store_cleaning_result(results_data)

        # Store detailed ANSI statistics
        ansi_detail_stats = []
        for ansi_type, stats in ansi_stats.items():
            ansi_detail_stats.append(
                {
                    "ansi_type": ansi_type,
                    "pattern_matched": stats["pattern"],
                    "occurrence_count": stats["count"],
                    "first_position": stats["first_position"],
                    "last_position": stats["last_position"],
                }
            )

        if ansi_detail_stats:
            db_manager.store_ansi_statistics(file_hash, ansi_detail_stats)

        # Store bracket statistics
        bracket_detail_stats = []
        for bracket_type, stats in bracket_stats.items():
            for i, content in enumerate(stats["contents"]):
                bracket_detail_stats.append(
                    {
                        "bracket_type": bracket_type,
                        "content": content[:500],  # Limit content length
                        "position": (
                            stats["positions"][i] if i < len(stats["positions"]) else 0
                        ),
                    }
                )

        if bracket_detail_stats:
            db_manager.store_bracket_statistics(file_hash, bracket_detail_stats)

        print("✅ [DB] Results stored successfully")
        db_manager.close()

    print("🎉 [COMPLETE] Text cleaning finished successfully!")


if __name__ == "__main__":
    main()
