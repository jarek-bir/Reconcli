"""
ReconCLI Database Module

Provides SQLite-based storage for reconnaissance data with support for:
- Target management
- Scan result persistence
- Historical tracking
- Basic analytics
"""

from .database import DatabaseManager, get_db_manager, init_database
from .operations import store_target, store_whois_findings

__all__ = [
    "DatabaseManager",
    "get_db_manager",
    "init_database",
    "store_target",
    "store_whois_findings",
]
