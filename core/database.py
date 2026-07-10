# core/database.py

"""
Database Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

SQLite database manager for storing scan results,
vulnerability findings, and session data persistently.
"""

import os
import sqlite3
import json
import threading
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
from contextlib import contextmanager
from core.exceptions import DatabaseError


class DatabaseManager:
    """
    SQLite database manager for WOLFSTRIKE.
    
    Provides persistent storage for scan results,
    vulnerability findings, and configuration data.
    """
    
    SCHEMA_VERSION = 1
    
    SCHEMA = """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            start_time REAL NOT NULL,
            end_time REAL,
            total_vulnerabilities INTEGER DEFAULT 0,
            total_errors INTEGER DEFAULT 0,
            total_requests INTEGER DEFAULT 0,
            metadata TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            endpoint TEXT,
            payload TEXT,
            description TEXT,
            confidence REAL,
            cvss_score REAL,
            evidence TEXT,
            remediation TEXT,
            is_false_positive INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );
        
        CREATE TABLE IF NOT EXISTS module_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            module_name TEXT NOT NULL,
            success INTEGER NOT NULL,
            findings_count INTEGER DEFAULT 0,
            errors_count INTEGER DEFAULT 0,
            execution_time REAL,
            metadata TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );
        
        CREATE TABLE IF NOT EXISTS scan_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            module_name TEXT,
            error_message TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );
        
        CREATE TABLE IF NOT EXISTS session_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id 
            ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type 
            ON vulnerabilities(vulnerability_type);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity 
            ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_module_results_scan_id 
            ON module_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_errors_scan_id 
            ON scan_errors(scan_id);
    """
    
    def __init__(self, db_path: str = "database/wolfstrike.db"):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database schema."""
        try:
            with self._get_connection() as conn:
                conn.executescript(self.SCHEMA)
                conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize database: {str(e)}")
    
    @contextmanager
    def _get_connection(self) -> sqlite3.Connection:
        """
        Get a database connection with context management.
        
        Yields:
            SQLite connection object
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database connection error: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    def save_scan(self, scan_data: Dict[str, Any]) -> bool:
        """
        Save a scan record.
        
        Args:
            scan_data: Scan data dictionary
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO scans 
                           (scan_id, target, mode, status, start_time, end_time,
                            total_vulnerabilities, total_errors, total_requests, metadata)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_data.get('scan_id'),
                            scan_data.get('target'),
                            scan_data.get('mode'),
                            scan_data.get('status'),
                            scan_data.get('start_time'),
                            scan_data.get('end_time'),
                            scan_data.get('total_vulnerabilities', 0),
                            scan_data.get('total_errors', 0),
                            scan_data.get('total_requests', 0),
                            json.dumps(scan_data.get('metadata', {}))
                        )
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to save scan: {str(e)}")
    
    def save_vulnerability(
        self,
        scan_id: str,
        vuln_data: Dict[str, Any]
    ) -> bool:
        """
        Save a vulnerability finding.
        
        Args:
            scan_id: Associated scan ID
            vuln_data: Vulnerability data dictionary
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO vulnerabilities
                           (scan_id, vulnerability_type, severity, endpoint, payload,
                            description, confidence, cvss_score, evidence, remediation)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id,
                            vuln_data.get('type', 'unknown'),
                            vuln_data.get('severity', 'info'),
                            vuln_data.get('endpoint', ''),
                            vuln_data.get('payload', ''),
                            vuln_data.get('description', ''),
                            vuln_data.get('confidence', 0.0),
                            vuln_data.get('cvss_score', 0.0),
                            json.dumps(vuln_data.get('evidence', {})),
                            vuln_data.get('remediation', '')
                        )
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to save vulnerability: {str(e)}")
    
    def save_module_result(
        self,
        scan_id: str,
        module_data: Dict[str, Any]
    ) -> bool:
        """
        Save a module execution result.
        
        Args:
            scan_id: Associated scan ID
            module_data: Module result data
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO module_results
                           (scan_id, module_name, success, findings_count,
                            errors_count, execution_time, metadata)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id,
                            module_data.get('module_name', 'unknown'),
                            1 if module_data.get('success', False) else 0,
                            module_data.get('findings_count', 0),
                            module_data.get('errors_count', 0),
                            module_data.get('execution_time', 0.0),
                            json.dumps(module_data.get('metadata', {}))
                        )
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to save module result: {str(e)}")
    
    def save_error(
        self,
        scan_id: str,
        module_name: Optional[str],
        error_message: str
    ) -> bool:
        """
        Save a scan error.
        
        Args:
            scan_id: Associated scan ID
            module_name: Module that generated the error
            error_message: Error message text
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO scan_errors (scan_id, module_name, error_message)
                           VALUES (?, ?, ?)""",
                        (scan_id, module_name, error_message)
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to save error: {str(e)}")
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan record.
        
        Args:
            scan_id: Scan ID to retrieve
            
        Returns:
            Scan data dictionary or None
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM scans WHERE scan_id = ?",
                    (scan_id,)
                )
                row = cursor.fetchone()
                if row:
                    columns = [desc[0] for desc in cursor.description]
                    return dict(zip(columns, row))
                return None
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get scan: {str(e)}")
    
    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve vulnerability records with optional filters.
        
        Args:
            scan_id: Filter by scan ID
            severity: Filter by severity
            vuln_type: Filter by vulnerability type
            limit: Maximum records to return
            
        Returns:
            List of vulnerability dictionaries
        """
        try:
            with self._get_connection() as conn:
                query = "SELECT * FROM vulnerabilities WHERE 1=1"
                params = []
                
                if scan_id:
                    query += " AND scan_id = ?"
                    params.append(scan_id)
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                if vuln_type:
                    query += " AND vulnerability_type = ?"
                    params.append(vuln_type)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get vulnerabilities: {str(e)}")
    
    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve all scan records.
        
        Args:
            limit: Maximum records to return
            
        Returns:
            List of scan dictionaries
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                )
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get scans: {str(e)}")
    
    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and all related records.
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        "DELETE FROM vulnerabilities WHERE scan_id = ?",
                        (scan_id,)
                    )
                    conn.execute(
                        "DELETE FROM module_results WHERE scan_id = ?",
                        (scan_id,)
                    )
                    conn.execute(
                        "DELETE FROM scan_errors WHERE scan_id = ?",
                        (scan_id,)
                    )
                    conn.execute(
                        "DELETE FROM scans WHERE scan_id = ?",
                        (scan_id,)
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to delete scan: {str(e)}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            with self._get_connection() as conn:
                total_scans = conn.execute(
                    "SELECT COUNT(*) FROM scans"
                ).fetchone()[0]
                
                total_vulns = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities"
                ).fetchone()[0]
                
                critical_vulns = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'"
                ).fetchone()[0]
                
                return {
                    'total_scans': total_scans,
                    'total_vulnerabilities': total_vulns,
                    'critical_vulnerabilities': critical_vulns,
                }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get statistics: {str(e)}")
    
    def vacuum(self) -> None:
        """Optimize database storage."""
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to vacuum database: {str(e)}")
    
    def close(self) -> None:
        """Close all database connections."""
        pass