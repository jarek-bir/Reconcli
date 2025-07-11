"""
ReconCLI Database Module

Provides SQLite-based storage for reconnaissance data with support for:
- Target management
- Scan result persistence
- Historical tracking
- Basic analytics
"""

from .database import DatabaseManager, get_db_manager, init_database

__all__ = ["DatabaseManager", "get_db_manager", "init_database"]
