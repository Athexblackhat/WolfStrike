# core/logger.py

"""
Custom Logging System
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced logging system with multiple output handlers,
log rotation, severity levels, and colored console output.
"""

import os
import sys
import time
import logging
import logging.handlers
import re
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class Logger:
    """
    Advanced logging system for WOLFSTRIKE.
    
    Provides file and console logging with rotation,
    colored output, and multiple severity levels.
    """
    
    COLOR_MAP = {
        logging.DEBUG: '\033[90m',
        logging.INFO: '\033[94m',
        logging.WARNING: '\033[93m',
        logging.ERROR: '\033[91m',
        logging.CRITICAL: '\033[95m',
    }
    
    RESET_COLOR = '\033[0m'
    
    SENSITIVE_PATTERNS = [
        (r'(api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']?([A-Za-z0-9]{10,})["\']?', r'\1=***REDACTED***'),
        (r'(secret|SECRET)\s*[:=]\s*["\']?([A-Za-z0-9]{10,})["\']?', r'\1=***REDACTED***'),
        (r'(token|TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{10,})["\']?', r'\1=***REDACTED***'),
        (r'(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'&]{4,})["\']?', r'\1=***REDACTED***'),
        (r'(bearer|Bearer)\s+["\']?([A-Za-z0-9\-_\.]{20,})["\']?', r'Bearer ***REDACTED***'),
        (r'Authorization:\s*["\']?([A-Za-z0-9\-_\.]{20,})["\']?', r'Authorization: ***REDACTED***'),
    ]
    
    def __init__(
        self,
        name: str = "WolfStrike",
        debug_mode: bool = False,
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        max_file_size: int = 10 * 1024 * 1024,
        backup_count: int = 5,
        no_color: bool = False,
        max_log_files: int = 10,
        log_retention_days: int = 30,
        sanitize_sensitive_data: bool = True
    ):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            debug_mode: Enable debug mode
            log_file: Path to log file
            log_level: Logging level string
            max_file_size: Maximum log file size in bytes
            backup_count: Number of backup log files
            no_color: Disable colored output
            max_log_files: Maximum number of log files to keep
            log_retention_days: Days to keep log files
            sanitize_sensitive_data: Whether to sanitize sensitive data
        """
        self.name = name
        self.debug_mode = debug_mode
        self.no_color = no_color
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.max_log_files = max_log_files
        self.log_retention_days = log_retention_days
        self.sanitize_sensitive_data = sanitize_sensitive_data
        self.log_file = log_file
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug_mode else self._parse_level(log_level))
        self.logger.handlers.clear()
        self.logger.propagate = False
        
        self._setup_console_handler()
        
        if log_file:
            self._validate_log_file(log_file)
            self._setup_file_handler(log_file, max_file_size, backup_count)
            
            # Clean old logs on initialization
            self._clean_old_logs()
    
    def _parse_level(self, level_str: str) -> int:
        """
        Parse log level string to logging constant.
        
        Args:
            level_str: Log level string
            
        Returns:
            Logging level constant
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL,
        }
        return level_map.get(level_str.upper(), logging.INFO)
    
    def _validate_log_file(self, log_file: str) -> bool:
        """
        Validate log file path.
        
        Args:
            log_file: Path to log file
            
        Returns:
            True if valid
        """
        log_dir = os.path.dirname(log_file)
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError as e:
                print(f"Warning: Could not create log directory: {e}", file=sys.stderr)
                return False
        
        # Check if file is writable
        try:
            with open(log_file, 'a') as f:
                pass
        except (IOError, OSError) as e:
            print(f"Warning: Log file is not writable: {e}", file=sys.stderr)
            return False
        
        return True
    
    def _check_disk_space(self, log_file: str) -> bool:
        """
        Check if there is enough disk space for logging.
        
        Args:
            log_file: Path to log file
            
        Returns:
            True if enough space
        """
        try:
            stat = os.statvfs(log_file)
            free_space = stat.f_frsize * stat.f_bavail
            # Require at least 50MB free space
            return free_space > 50 * 1024 * 1024
        except Exception:
            return True  # Assume there is space if we can't check
    
    def _get_log_file_size(self, log_file: str) -> int:
        """
        Get current log file size.
        
        Args:
            log_file: Path to log file
            
        Returns:
            File size in bytes
        """
        try:
            return os.path.getsize(log_file)
        except (OSError, FileNotFoundError):
            return 0
    
    def _rotate_if_needed(self, log_file: str) -> None:
        """
        Manually trigger log rotation if needed.
        
        Args:
            log_file: Path to log file
        """
        if not os.path.exists(log_file):
            return
        
        current_size = self._get_log_file_size(log_file)
        if current_size >= self.max_file_size:
            # Close and reopen handler to force rotation
            for handler in self.logger.handlers:
                if isinstance(handler, logging.handlers.RotatingFileHandler):
                    handler.doRollback()
    
    def _sanitize_message(self, message: str) -> str:
        """
        Remove sensitive data from log message.
        
        Args:
            message: Original log message
            
        Returns:
            Sanitized log message
        """
        if not self.sanitize_sensitive_data:
            return message
        
        sanitized = message
        
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _clean_old_logs(self) -> None:
        """Clean old log files based on retention policy."""
        if not self.log_file:
            return
        
        log_dir = os.path.dirname(self.log_file)
        if not log_dir or not os.path.isdir(log_dir):
            return
        
        try:
            log_files = []
            base_name = os.path.basename(self.log_file)
            pattern = re.compile(rf'^{re.escape(base_name)}(\.[0-9]+)?$')
            
            for filename in os.listdir(log_dir):
                if pattern.match(filename):
                    file_path = os.path.join(log_dir, filename)
                    log_files.append((file_path, os.path.getmtime(file_path)))
            
            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: x[1])
            
            # Remove by count
            if len(log_files) > self.max_log_files:
                for file_path, _ in log_files[:len(log_files) - self.max_log_files]:
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
            
            # Remove by age
            cutoff_time = time.time() - (self.log_retention_days * 24 * 60 * 60)
            for file_path, mtime in log_files:
                if mtime < cutoff_time:
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                        
        except Exception:
            pass
    
    def _get_log_stats(self) -> Dict[str, Any]:
        """
        Get log file statistics.
        
        Returns:
            Dictionary with log statistics
        """
        if not self.log_file:
            return {}
        
        stats = {
            'log_file': self.log_file,
            'exists': os.path.exists(self.log_file),
        }
        
        if stats['exists']:
            size = self._get_log_file_size(self.log_file)
            stats['size_bytes'] = size
            stats['size_mb'] = round(size / (1024 * 1024), 2)
        
        return stats
    
    def _setup_console_handler(self) -> None:
        """Setup console output handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
        
        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(
        self,
        log_file: str,
        max_size: int,
        backup_count: int
    ) -> None:
        """
        Setup file output handler with rotation.
        
        Args:
            log_file: Path to log file
            max_size: Maximum file size before rotation
            backup_count: Number of backup files
        """
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def _format_message(self, level: int, message: str) -> str:
        """
        Format a log message with optional color.
        
        Args:
            level: Logging level
            message: Message text
            
        Returns:
            Formatted message string
        """
        # Sanitize sensitive data
        sanitized_message = self._sanitize_message(message)
        
        if self.no_color:
            return sanitized_message
        
        color = self.COLOR_MAP.get(level, '')
        if color:
            return f"{color}{sanitized_message}{self.RESET_COLOR}"
        
        return sanitized_message
    
    def debug(self, message: str) -> None:
        """Log a debug message."""
        self.logger.debug(self._format_message(logging.DEBUG, message))
    
    def info(self, message: str) -> None:
        """Log an info message."""
        self.logger.info(self._format_message(logging.INFO, message))
    
    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.logger.warning(self._format_message(logging.WARNING, message))
    
    def error(self, message: str) -> None:
        """Log an error message."""
        self.logger.error(self._format_message(logging.ERROR, message))
    
    def critical(self, message: str) -> None:
        """Log a critical message."""
        self.logger.critical(self._format_message(logging.CRITICAL, message))
    
    def exception(self, message: str) -> None:
        """Log an exception with traceback."""
        sanitized_message = self._sanitize_message(message)
        self.logger.exception(self._format_message(logging.ERROR, sanitized_message))
    
    def set_debug_mode(self, enabled: bool) -> None:
        """
        Enable or disable debug mode.
        
        Args:
            enabled: Whether to enable debug mode
        """
        self.debug_mode = enabled
        self.logger.setLevel(logging.DEBUG if enabled else logging.INFO)
        
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG if enabled else logging.INFO)
    
    def set_level(self, level: str) -> None:
        """
        Set the logging level.
        
        Args:
            level: Log level string
        """
        parsed_level = self._parse_level(level)
        self.logger.setLevel(parsed_level)
    
    def add_handler(self, handler: logging.Handler) -> None:
        """
        Add a custom log handler.
        
        Args:
            handler: Logging handler instance
        """
        self.logger.addHandler(handler)
    
    def remove_handlers(self) -> None:
        """Remove all handlers."""
        self.logger.handlers.clear()
    
    def flush(self) -> None:
        """Flush all log handlers."""
        for handler in self.logger.handlers:
            handler.flush()
    
    def get_logger(self) -> logging.Logger:
        """
        Get the underlying Python logger.
        
        Returns:
            Logger instance
        """
        return self.logger
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get logger statistics.
        
        Returns:
            Dictionary with logger statistics
        """
        stats = {
            'name': self.name,
            'debug_mode': self.debug_mode,
            'log_level': logging.getLevelName(self.logger.level),
            'no_color': self.no_color,
            'handlers': len(self.logger.handlers),
            'log_file': self.log_file,
            'max_file_size_mb': round(self.max_file_size / (1024 * 1024), 2),
            'backup_count': self.backup_count,
            'max_log_files': self.max_log_files,
            'log_retention_days': self.log_retention_days,
            'sanitize_sensitive_data': self.sanitize_sensitive_data,
        }
        
        # Add file stats if log file exists
        if self.log_file:
            file_stats = self._get_log_stats()
            stats.update(file_stats)
        
        return stats
