# database/migrations/__init__.py

"""
WOLFSTRIKE Database Migrations
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Database migration management for version control
of database schema changes.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


class MigrationManager:
    """
    Manages database schema migrations.
    
    Tracks applied migrations and applies new ones
    in sequential order based on version.
    """
    
    MIGRATIONS: List[Dict[str, Any]] = [
        {
            'version': '1.0.0',
            'description': 'Initial database schema',
            'sql_up': """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'initialized',
                    start_time REAL NOT NULL,
                    end_time REAL,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    total_errors INTEGER DEFAULT 0,
                    total_requests INTEGER DEFAULT 0,
                    total_modules INTEGER DEFAULT 0,
                    completed_modules INTEGER DEFAULT 0,
                    metadata_json TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    name TEXT,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    confidence REAL,
                    endpoint TEXT,
                    method TEXT,
                    payload TEXT,
                    description TEXT,
                    impact TEXT,
                    evidence_json TEXT,
                    remediation TEXT,
                    references_json TEXT,
                    owasp_category TEXT,
                    cwe_id TEXT,
                    is_false_positive INTEGER DEFAULT 0,
                    verified INTEGER DEFAULT 0,
                    verified_by TEXT,
                    verified_at TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS module_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    execution_time REAL,
                    start_time REAL,
                    end_time REAL,
                    metadata_json TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS scan_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    module_name TEXT,
                    error_type TEXT,
                    error_message TEXT NOT NULL,
                    traceback_text TEXT,
                    endpoint TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS session_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    data_type TEXT DEFAULT 'string',
                    expires_at TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                
                CREATE TABLE IF NOT EXISTS migrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT UNIQUE NOT NULL,
                    description TEXT,
                    applied_at TEXT DEFAULT (datetime('now')),
                    success INTEGER DEFAULT 1
                );
                
                CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON vulnerabilities(scan_id);
                CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(vulnerability_type);
                CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_module_scan_id ON module_results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_errors_scan_id ON scan_errors(scan_id);
                CREATE INDEX IF NOT EXISTS idx_session_key ON session_data(key);
            """,
            'sql_down': """
                DROP TABLE IF EXISTS vulnerabilities;
                DROP TABLE IF EXISTS module_results;
                DROP TABLE IF EXISTS scan_errors;
                DROP TABLE IF EXISTS session_data;
                DROP TABLE IF EXISTS scans;
                DROP TABLE IF EXISTS migrations;
            """
        },
    ]
    
    def __init__(self, db_path: str = 'database/wolfstrike.db'):
        """
        Initialize migration manager.
        
        Args:
            db_path: Path to database file
        """
        self.db_path = db_path
    
    def get_applied_migrations(self) -> List[str]:
        """
        Get list of applied migration versions.
        
        Returns:
            List of version strings
        """
        import sqlite3
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                "SELECT version FROM migrations WHERE success = 1 ORDER BY version"
            )
            versions = [row[0] for row in cursor.fetchall()]
            conn.close()
            return versions
        except sqlite3.Error:
            return []
    
    def apply_migration(self, version: str) -> bool:
        """
        Apply a specific migration.
        
        Args:
            version: Migration version to apply
            
        Returns:
            True if successful
        """
        import sqlite3
        
        migration = None
        for mig in self.MIGRATIONS:
            if mig['version'] == version:
                migration = mig
                break
        
        if migration is None:
            return False
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.executescript(migration['sql_up'])
            
            conn.execute(
                "INSERT OR REPLACE INTO migrations (version, description, success) VALUES (?, ?, 1)",
                (migration['version'], migration['description'])
            )
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error:
            return False
    
    def rollback_migration(self, version: str) -> bool:
        """
        Rollback a specific migration.
        
        Args:
            version: Migration version to rollback
            
        Returns:
            True if successful
        """
        import sqlite3
        
        migration = None
        for mig in self.MIGRATIONS:
            if mig['version'] == version:
                migration = mig
                break
        
        if migration is None:
            return False
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.executescript(migration['sql_down'])
            
            conn.execute(
                "DELETE FROM migrations WHERE version = ?",
                (version,)
            )
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error:
            return False
    
    def migrate(self) -> List[str]:
        """
        Apply all pending migrations.
        
        Returns:
            List of newly applied version strings
        """
        applied = self.get_applied_migrations()
        new_migrations = []
        
        for migration in self.MIGRATIONS:
            if migration['version'] not in applied:
                if self.apply_migration(migration['version']):
                    new_migrations.append(migration['version'])
        
        return new_migrations
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get migration status.
        
        Returns:
            Dictionary with migration status
        """
        applied = self.get_applied_migrations()
        pending = [
            m['version'] for m in self.MIGRATIONS
            if m['version'] not in applied
        ]
        
        return {
            'total_migrations': len(self.MIGRATIONS),
            'applied_count': len(applied),
            'pending_count': len(pending),
            'applied': applied,
            'pending': pending,
            'is_up_to_date': len(pending) == 0,
        }