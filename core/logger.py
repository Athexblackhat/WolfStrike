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
from typing import Optional, Dict, Any
from datetime import datetime
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
    
    def __init__(
        self,
        name: str = "WolfStrike",
        debug_mode: bool = False,
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        max_file_size: int = 10 * 1024 * 1024,
        backup_count: int = 5,
        no_color: bool = False
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
        """
        self.name = name
        self.debug_mode = debug_mode
        self.no_color = no_color
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug_mode else self._parse_level(log_level))
        self.logger.handlers.clear()
        self.logger.propagate = False
        
        self._setup_console_handler()
        
        if log_file:
            self._setup_file_handler(log_file, max_file_size, backup_count)
    
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
        if self.no_color:
            return message
        
        color = self.COLOR_MAP.get(level, '')
        if color:
            return f"{color}{message}{self.RESET_COLOR}"
        
        return message
    
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
        self.logger.exception(self._format_message(logging.ERROR, message))
    
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
            handler: Logging handler instance        """
        self.logger.addHandler(handler)
    
    def remove_handlers(self) -> None:
        """Remove all handlers."""
        self.logger.handlers.clear()
    
    def get_logger(self) -> logging.Logger:
        """
        Get the underlying Python logger.
        
        Returns:
            Logger instance
        """
        return self.logger