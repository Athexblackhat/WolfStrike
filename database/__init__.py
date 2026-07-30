# database/__init__.py

"""
WOLFSTRIKE Database Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Database models and migration management for persistent
storage of scan results, vulnerabilities, and session data.
"""

from database.models import (
    Scan,
    Vulnerability,
    ModuleResult,
    ScanError,
    SessionData,
    Migration,
    Base,
    init_database,
    get_session,
    close_session,
    DatabaseOperations,
)

__all__ = [
    'Scan',
    'Vulnerability',
    'ModuleResult',
    'ScanError',
    'SessionData',
    'Migration',
    'Base',
    'init_database',
    'get_session',
    'close_session',
    'DatabaseOperations',
    'create_all_tables',
    'drop_all_tables',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def create_all_tables(db_path: str = 'database/wolfstrike.db', echo: bool = False) -> None:
    """
    Create all database tables.
    
    Args:
        db_path: Path to SQLite database file
        echo: Enable SQL query logging
    """
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    
    engine = create_engine(
        f'sqlite:///{db_path}',
        echo=echo,
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    
    Base.metadata.create_all(engine)
    engine.dispose()


def drop_all_tables(db_path: str = 'database/wolfstrike.db', echo: bool = False) -> None:
    """
    Drop all database tables (WARNING: Destructive).
    
    Args:
        db_path: Path to SQLite database file
        echo: Enable SQL query logging
    """
    import warnings
    
    warnings.warn(
        "drop_all_tables() will delete ALL data in the database!",
        UserWarning,
        stacklevel=2
    )
    
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    
    engine = create_engine(
        f'sqlite:///{db_path}',
        echo=echo,
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    
    Base.metadata.drop_all(engine)
    engine.dispose()
