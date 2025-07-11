"""
Database Manager for ReconCLI

Handles SQLite database connections, initialization, and basic operations.
Provides a simple interface for storing and retrieving reconnaissance data.
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, Union
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine

from .models import Base


class DatabaseManager:
    """
    Manages SQLite database connection and operations for ReconCLI
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database manager

        Args:
            db_path: Path to SQLite database file. If None, uses default location.
        """
        if db_path is None:
            # Default database location in user's home directory
            home_dir = Path.home()
            reconcli_dir = home_dir / ".reconcli"
            reconcli_dir.mkdir(exist_ok=True)
            self.db_path = reconcli_dir / "reconcli.db"
        else:
            self.db_path = Path(db_path)

        self.engine = None
        self.Session = None
        self._initialize_database()

    def _initialize_database(self):
        """Initialize SQLite database with proper configuration"""
        # Create SQLite engine with proper settings
        database_url = f"sqlite:///{self.db_path}"
        self.engine = create_engine(
            database_url,
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            connect_args={
                "check_same_thread": False,  # Allow multiple threads
                "timeout": 30,  # 30 second timeout
            },
        )

        # Enable foreign key constraints for SQLite
        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            if "sqlite" in str(self.engine.url):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")  # Better concurrency
                cursor.execute("PRAGMA synchronous=NORMAL")  # Better performance
                cursor.close()

        # Create all tables
        Base.metadata.create_all(self.engine)

        # Create session factory
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        """Get a new database session"""
        return self.Session()

    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics"""
        with self.get_session() as session:
            try:
                # Get table counts
                from .models import Target, Subdomain, PortScan, Vulnerability

                info = {
                    "database_path": str(self.db_path),
                    "database_size_mb": (
                        self.db_path.stat().st_size / (1024 * 1024)
                        if self.db_path.exists()
                        else 0
                    ),
                    "tables": {
                        "targets": session.query(Target).count(),
                        "subdomains": session.query(Subdomain).count(),
                        "port_scans": session.query(PortScan).count(),
                        "vulnerabilities": session.query(Vulnerability).count(),
                    },
                }
                return info
            except Exception as e:
                return {"error": str(e), "database_path": str(self.db_path)}

    def backup_database(self, backup_path: Optional[str] = None) -> str:
        """
        Create a backup of the database

        Args:
            backup_path: Path for backup file. If None, creates timestamped backup.

        Returns:
            Path to the backup file
        """
        if backup_path is None:
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path_obj = self.db_path.parent / f"reconcli_backup_{timestamp}.db"
            backup_path = str(backup_path_obj)

        backup_path_obj = Path(backup_path)

        # Use SQLite backup API for consistent backup
        source = sqlite3.connect(str(self.db_path))
        backup = sqlite3.connect(str(backup_path_obj))

        source.backup(backup)
        backup.close()
        source.close()

        return str(backup_path_obj)

    def restore_database(self, backup_path: str):
        """
        Restore database from backup

        Args:
            backup_path: Path to backup file
        """
        backup_path_obj = Path(backup_path)
        if not backup_path_obj.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        # Close current connections
        if self.engine:
            self.engine.dispose()

        # Replace current database with backup
        import shutil

        shutil.copy2(backup_path_obj, self.db_path)

        # Reinitialize
        self._initialize_database()

    def optimize_database(self):
        """Optimize database performance (VACUUM, ANALYZE)"""
        with self.get_session() as session:
            # VACUUM reclaims space and defragments
            session.execute("VACUUM")
            # ANALYZE updates query planner statistics
            session.execute("ANALYZE")
            session.commit()

    def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager(db_path: Optional[str] = None) -> DatabaseManager:
    """
    Get global database manager instance

    Args:
        db_path: Path to database file (only used on first call)

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
    return _db_manager


def init_database(db_path: Optional[str] = None) -> DatabaseManager:
    """
    Initialize database (alias for get_db_manager)

    Args:
        db_path: Path to database file

    Returns:
        DatabaseManager instance
    """
    return get_db_manager(db_path)
