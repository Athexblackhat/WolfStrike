# database/models.py

"""
SQLAlchemy Database Models
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Defines all database models for storing scan results,
vulnerability findings, module execution data, and session
information using SQLAlchemy ORM.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
    Index,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import SQLAlchemyError

Base = declarative_base()

engine = None
SessionLocal = None


class Scan(Base):
    """
    Scan record model.
    
    Stores information about each scan execution including
    target, mode, status, timing, and result counts.
    """
    
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    target = Column(String(2048), nullable=False)
    mode = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default='initialized')
    start_time = Column(Float, nullable=False)
    end_time = Column(Float, nullable=True)
    total_vulnerabilities = Column(Integer, default=0)
    total_errors = Column(Integer, default=0)
    total_requests = Column(Integer, default=0)
    total_modules = Column(Integer, default=0)
    completed_modules = Column(Integer, default=0)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    vulnerabilities = relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan')
    module_results = relationship('ModuleResult', back_populates='scan', cascade='all, delete-orphan')
    scan_errors = relationship('ScanError', back_populates='scan', cascade='all, delete-orphan')
    
    def __repr__(self) -> str:
        return f"<Scan(id={self.scan_id}, target='{self.target}', status='{self.status}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan record to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target': self.target,
            'mode': self.mode,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'total_vulnerabilities': self.total_vulnerabilities,
            'total_errors': self.total_errors,
            'total_requests': self.total_requests,
            'total_modules': self.total_modules,
            'completed_modules': self.completed_modules,
            'metadata': json.loads(self.metadata_json) if self.metadata_json else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Vulnerability(Base):
    """
    Vulnerability finding model.
    
    Stores detailed information about each vulnerability
    discovered during scanning including type, severity,
    evidence, and remediation guidance.
    """
    
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey('scans.scan_id', ondelete='CASCADE'), nullable=False, index=True)
    vulnerability_type = Column(String(128), nullable=False, index=True)
    name = Column(String(256), nullable=True)
    severity = Column(String(32), nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    endpoint = Column(String(2048), nullable=True)
    method = Column(String(16), nullable=True)
    payload = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    references_json = Column(Text, nullable=True)
    owasp_category = Column(String(128), nullable=True)
    cwe_id = Column(String(32), nullable=True)
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    verified_by = Column(String(32), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan = relationship('Scan', back_populates='vulnerabilities')
    
    __table_args__ = (
        Index('idx_vuln_scan_severity', 'scan_id', 'severity'),
        Index('idx_vuln_type_severity', 'vulnerability_type', 'severity'),
    )
    
    def __repr__(self) -> str:
        return f"<Vulnerability(type='{self.vulnerability_type}', severity='{self.severity}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'vulnerability_type': self.vulnerability_type,
            'name': self.name,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'endpoint': self.endpoint,
            'method': self.method,
            'payload': self.payload,
            'description': self.description,
            'impact': self.impact,
            'evidence': json.loads(self.evidence_json) if self.evidence_json else {},
            'remediation': self.remediation,
            'references': json.loads(self.references_json) if self.references_json else [],
            'owasp_category': self.owasp_category,
            'cwe_id': self.cwe_id,
            'is_false_positive': self.is_false_positive,
            'verified': self.verified,
            'verified_by': self.verified_by,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ModuleResult(Base):
    """
    Module execution result model.
    
    Records the execution outcome of each module during
    a scan including success status and timing.
    """
    
    __tablename__ = 'module_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey('scans.scan_id', ondelete='CASCADE'), nullable=False, index=True)
    module_name = Column(String(128), nullable=False)
    success = Column(Boolean, default=False)
    findings_count = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)
    execution_time = Column(Float, nullable=True)
    start_time = Column(Float, nullable=True)
    end_time = Column(Float, nullable=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship('Scan', back_populates='module_results')
    
    __table_args__ = (
        Index('idx_module_scan_name', 'scan_id', 'module_name'),
    )
    
    def __repr__(self) -> str:
        return f"<ModuleResult(module='{self.module_name}', success={self.success})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert module result to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'module_name': self.module_name,
            'success': self.success,
            'findings_count': self.findings_count,
            'errors_count': self.errors_count,
            'execution_time': self.execution_time,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'metadata': json.loads(self.metadata_json) if self.metadata_json else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ScanError(Base):
    """
    Scan error record model.
    
    Stores errors encountered during scan execution
    with module attribution and timestamps.
    """
    
    __tablename__ = 'scan_errors'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey('scans.scan_id', ondelete='CASCADE'), nullable=False, index=True)
    module_name = Column(String(128), nullable=True)
    error_type = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=False)
    traceback_text = Column(Text, nullable=True)
    endpoint = Column(String(2048), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship('Scan', back_populates='scan_errors')
    
    def __repr__(self) -> str:
        return f"<ScanError(module='{self.module_name}', type='{self.error_type}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan error to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'module_name': self.module_name,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'traceback': self.traceback_text,
            'endpoint': self.endpoint,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SessionData(Base):
    """
    Session data storage model.
    
    Stores key-value pairs for maintaining session state
    across application restarts.
    """
    
    __tablename__ = 'session_data'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(256), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    data_type = Column(String(32), default='string')
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<SessionData(key='{self.key}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session data to dictionary."""
        value = self.value
        if self.data_type == 'json':
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass
        elif self.data_type == 'integer':
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        elif self.data_type == 'float':
            try:
                value = float(value)
            except (ValueError, TypeError):
                pass
        elif self.data_type == 'boolean':
            value = value.lower() in ('true', '1', 'yes')
        
        return {
            'id': self.id,
            'key': self.key,
            'value': value,
            'data_type': self.data_type,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Migration(Base):
    """
    Database migration tracking model.
    
    Tracks applied database migrations for schema versioning.
    """
    
    __tablename__ = 'migrations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(64), unique=True, nullable=False)
    description = Column(String(256), nullable=True)
    applied_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=True)
    
    def __repr__(self) -> str:
        return f"<Migration(version='{self.version}')>"


def init_database(
    db_path: str = 'database/wolfstrike.db',
    echo: bool = False
) -> None:
    """
    Initialize the database engine and create all tables.
    
    Args:
        db_path: Path to SQLite database file
        echo: Enable SQL query logging
    """
    global engine, SessionLocal
    
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    
    connection_string = f'sqlite:///{db_path}'
    
    engine = create_engine(
        connection_string,
        echo=echo,
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    
    Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )


def get_session() -> Session:
    """
    Get a new database session.
    
    Returns:
        SQLAlchemy Session object
        
    Raises:
        RuntimeError: If database not initialized
    """
    if SessionLocal is None:
        raise RuntimeError(
            "Database not initialized. Call init_database() first."
        )
    
    return SessionLocal()


def close_session(session: Session) -> None:
    """
    Close a database session safely.
    
    Args:
        session: SQLAlchemy Session to close
    """
    if session:
        try:
            session.close()
        except SQLAlchemyError:
            pass


class DatabaseOperations:
    """
    High-level database operations for common queries.
    
    Provides CRUD operations and common queries for all
    database models with proper session management.
    """
    
    @staticmethod
    def save_scan(session: Session, scan_data: Dict[str, Any]) -> Scan:
        """
        Save a scan record to database.
        
        Args:
            session: Database session
            scan_data: Scan data dictionary
            
        Returns:
            Saved Scan object
        """
        existing = session.query(Scan).filter_by(
            scan_id=scan_data.get('scan_id')
        ).first()
        
        if existing:
            for key, value in scan_data.items():
                if hasattr(existing, key) and key != 'id':
                    setattr(existing, key, value)
            scan = existing
        else:
            scan = Scan(**scan_data)
            session.add(scan)
        
        session.commit()
        return scan
    
    @staticmethod
    def save_vulnerability(
        session: Session,
        vuln_data: Dict[str, Any]
    ) -> Vulnerability:
        """
        Save a vulnerability finding to database.
        
        Args:
            session: Database session
            vuln_data: Vulnerability data dictionary
            
        Returns:
            Saved Vulnerability object
        """
        if 'evidence' in vuln_data and isinstance(vuln_data['evidence'], dict):
            vuln_data['evidence_json'] = json.dumps(vuln_data['evidence'])
            del vuln_data['evidence']
        
        if 'references' in vuln_data and isinstance(vuln_data['references'], list):
            vuln_data['references_json'] = json.dumps(vuln_data['references'])
            del vuln_data['references']
        
        vulnerability = Vulnerability(**vuln_data)
        session.add(vulnerability)
        session.commit()
        return vulnerability
    
    @staticmethod
    def save_module_result(
        session: Session,
        result_data: Dict[str, Any]
    ) -> ModuleResult:
        """
        Save a module execution result to database.
        
        Args:
            session: Database session
            result_data: Module result data dictionary
            
        Returns:
            Saved ModuleResult object
        """
        if 'metadata' in result_data and isinstance(result_data['metadata'], dict):
            result_data['metadata_json'] = json.dumps(result_data['metadata'])
            del result_data['metadata']
        
        module_result = ModuleResult(**result_data)
        session.add(module_result)
        session.commit()
        return module_result
    
    @staticmethod
    def save_error(
        session: Session,
        error_data: Dict[str, Any]
    ) -> ScanError:
        """
        Save a scan error to database.
        
        Args:
            session: Database session
            error_data: Error data dictionary
            
        Returns:
            Saved ScanError object
        """
        error = ScanError(**error_data)
        session.add(error)
        session.commit()
        return error
    
    @staticmethod
    def get_scan_by_id(
        session: Session,
        scan_id: str
    ) -> Optional[Scan]:
        """
        Get a scan record by scan ID.
        
        Args:
            session: Database session
            scan_id: Scan identifier
            
        Returns:
            Scan object or None
        """
        return session.query(Scan).filter_by(scan_id=scan_id).first()
    
    @staticmethod
    def get_vulnerabilities_by_scan(
        session: Session,
        scan_id: str,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Vulnerability]:
        """
        Get vulnerabilities for a scan with optional filtering.
        
        Args:
            session: Database session
            scan_id: Scan identifier
            severity: Filter by severity level
            limit: Maximum results
            
        Returns:
            List of Vulnerability objects
        """
        query = session.query(Vulnerability).filter_by(scan_id=scan_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        return query.order_by(
            Vulnerability.cvss_score.desc().nullslast()
        ).limit(limit).all()
    
    @staticmethod
    def get_vulnerability_statistics(
        session: Session,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get vulnerability statistics.
        
        Args:
            session: Database session
            scan_id: Optional scan ID filter
            
        Returns:
            Dictionary with statistics
        """
        query = session.query(Vulnerability)
        
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        
        total = query.count()
        critical = query.filter_by(severity='critical').count()
        high = query.filter_by(severity='high').count()
        medium = query.filter_by(severity='medium').count()
        low = query.filter_by(severity='low').count()
        info = query.filter_by(severity='info').count()
        false_positives = query.filter_by(is_false_positive=True).count()
        verified = query.filter_by(verified=True).count()
        
        return {
            'total': total,
            'by_severity': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': info,
            },
            'false_positives': false_positives,
            'verified': verified,
            'false_positive_rate': (false_positives / total * 100) if total > 0 else 0,
        }
    
    @staticmethod
    def get_all_scans(
        session: Session,
        limit: int = 50,
        offset: int = 0
    ) -> List[Scan]:
        """
        Get all scan records with pagination.
        
        Args:
            session: Database session
            limit: Maximum results
            offset: Result offset
            
        Returns:
            List of Scan objects
        """
        return session.query(Scan).order_by(
            Scan.created_at.desc()
        ).offset(offset).limit(limit).all()
    
    @staticmethod
    def delete_scan_cascade(
        session: Session,
        scan_id: str
    ) -> bool:
        """
        Delete a scan and all related records.
        
        Args:
            session: Database session
            scan_id: Scan identifier
            
        Returns:
            True if deleted
        """
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        
        if scan:
            session.delete(scan)
            session.commit()
            return True
        
        return False
    
    @staticmethod
    def save_session_data(
        session: Session,
        key: str,
        value: Any,
        data_type: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> SessionData:
        """
        Save session data key-value pair.
        
        Args:
            session: Database session
            key: Data key
            value: Data value
            data_type: Type of data
            expires_at: Expiration timestamp
            
        Returns:
            Saved SessionData object
        """
        if data_type is None:
            if isinstance(value, bool):
                data_type = 'boolean'
                value = str(value)
            elif isinstance(value, int):
                data_type = 'integer'
                value = str(value)
            elif isinstance(value, float):
                data_type = 'float'
                value = str(value)
            elif isinstance(value, (dict, list)):
                data_type = 'json'
                value = json.dumps(value)
            else:
                data_type = 'string'
                value = str(value)
        
        existing = session.query(SessionData).filter_by(key=key).first()
        
        if existing:
            existing.value = value
            existing.data_type = data_type
            existing.expires_at = expires_at
            existing.updated_at = datetime.utcnow()
            result = existing
        else:
            result = SessionData(
                key=key,
                value=value,
                data_type=data_type,
                expires_at=expires_at,
            )
            session.add(result)
        
        session.commit()
        return result
    
    @staticmethod
    def get_session_data(
        session: Session,
        key: str,
        default: Any = None
    ) -> Any:
        """
        Get session data by key.
        
        Args:
            session: Database session
            key: Data key
            default: Default value if not found
            
        Returns:
            Stored value or default
        """
        data = session.query(SessionData).filter_by(key=key).first()
        
        if data is None:
            return default
        
        if data.expires_at and data.expires_at < datetime.utcnow():
            session.delete(data)
            session.commit()
            return default
        
        return data.to_dict().get('value', default)
    
    @staticmethod
    def vacuum_database() -> None:
        """Optimize database storage."""
        if engine:
            with engine.connect() as conn:
                conn.execute(text('VACUUM'))
                conn.commit()