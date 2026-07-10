# cli/prompts.py

"""
Interactive Prompt Handler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Handles all user input prompts with validation,
defaults, and type checking for interactive mode.
"""

import re
import os
import sys
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum


class PromptType(Enum):
    """Types of input prompts."""
    TEXT = "text"
    NUMBER = "number"
    CONFIRM = "confirm"
    CHOICE = "choice"
    PASSWORD = "password"
    URL = "url"
    IP = "ip"
    FILE_PATH = "file_path"
    DIRECTORY_PATH = "directory_path"
    EMAIL = "email"
    MULTI_CHOICE = "multi_choice"


@dataclass
class PromptConfig:
    """Configuration for a prompt."""
    prompt_type: PromptType = PromptType.TEXT
    message: str = ""
    default: Optional[Any] = None
    required: bool = True
    validator: Optional[Callable[[Any], bool]] = None
    error_message: str = "Invalid input"
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    choices: Optional[List[str]] = None
    allow_empty: bool = False
    trim: bool = True
    max_attempts: int = 3


class PromptHandler:
    """
    Interactive prompt handler for user input.
    
    Provides validated input collection with various
    types, defaults, and error handling.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the prompt handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.default_max_attempts = self.config.get('max_attempts', 3)
    
    def prompt(self, config: PromptConfig) -> Optional[Any]:
        """
        Display a prompt and collect validated input.
        
        Args:
            config: Prompt configuration
            
        Returns:
            Validated user input or None if cancelled
        """
        attempts = 0
        max_attempts = config.max_attempts or self.default_max_attempts
        
        while attempts < max_attempts:
            attempts += 1
            
            try:
                value = self._display_prompt(config)
                
                if value is None and not config.required:
                    return config.default
                
                if config.trim and isinstance(value, str):
                    value = value.strip()
                
                if not value and not config.allow_empty:
                    if config.default is not None:
                        return config.default
                    
                    if config.required:
                        print(f"  {config.error_message or 'Input required'}")
                        continue
                    return None
                
                if config.validator:
                    if not config.validator(value):
                        print(f"  {config.error_message}")
                        continue
                
                if not self._validate_by_type(value, config):
                    continue
                
                return value
                
            except KeyboardInterrupt:
                print("\n  Input cancelled")
                return None
            except EOFError:
                return config.default
        
        print(f"  Maximum attempts ({max_attempts}) reached")
        return config.default
    
    def _display_prompt(self, config: PromptConfig) -> Optional[str]:
        """
        Display the prompt and get raw input.
        
        Args:
            config: Prompt configuration
            
        Returns:
            Raw user input
        """
        if config.prompt_type == PromptType.PASSWORD:
            return self._get_password(config.message)
        
        if config.prompt_type == PromptType.CONFIRM:
            default_hint = " [Y/n]: " if config.default else " [y/N]: "
            sys.stdout.write(config.message + default_hint)
            sys.stdout.flush()
            return input().strip()
        
        if config.prompt_type == PromptType.CHOICE and config.choices:
            print(f"\n  {config.message}")
            for i, choice in enumerate(config.choices, 1):
                print(f"    [{i}] {choice}")
            
            if config.default is not None:
                sys.stdout.write(f"  Enter choice [1-{len(config.choices)}] (default: {config.default}): ")
            else:
                sys.stdout.write(f"  Enter choice [1-{len(config.choices)}]: ")
            
            sys.stdout.flush()
            return input().strip()
        
        if config.prompt_type == PromptType.MULTI_CHOICE and config.choices:
            print(f"\n  {config.message}")
            for i, choice in enumerate(config.choices, 1):
                print(f"    [{i}] {choice}")
            print(f"    [a] Select All")
            print(f"    [n] Select None")
            
            sys.stdout.write(f"  Enter choices (comma-separated): ")
            sys.stdout.flush()
            return input().strip()
        
        if config.default is not None:
            sys.stdout.write(f"{config.message} [{config.default}]: ")
        else:
            sys.stdout.write(f"{config.message}: ")
        
        sys.stdout.flush()
        return input()
    
    def _get_password(self, message: str) -> str:
        """
        Get password input without echo.
        
        Args:
            message: Prompt message
            
        Returns:
            Password string
        """
        import getpass
        try:
            return getpass.getpass(f"  {message}: ")
        except Exception:
            return input(f"  {message}: ")
    
    def _validate_by_type(self, value: Any, config: PromptConfig) -> bool:
        """
        Validate input by prompt type.
        
        Args:
            value: Input value
            config: Prompt configuration
            
        Returns:
            True if valid, False otherwise
        """
        if config.prompt_type == PromptType.NUMBER:
            try:
                num_value = float(value)
                if config.min_value is not None and num_value < config.min_value:
                    print(f"  Value must be >= {config.min_value}")
                    return False
                if config.max_value is not None and num_value > config.max_value:
                    print(f"  Value must be <= {config.max_value}")
                    return False
                return True
            except ValueError:
                print(f"  Please enter a valid number")
                return False
        
        if config.prompt_type == PromptType.CONFIRM:
            return True
        
        if config.prompt_type == PromptType.CHOICE:
            try:
                choice_num = int(value)
                if 1 <= choice_num <= len(config.choices):
                    return True
                print(f"  Choice must be between 1 and {len(config.choices)}")
                return False
            except ValueError:
                if value in config.choices:
                    return True
                print(f"  Invalid choice")
                return False
        
        if config.prompt_type == PromptType.URL:
            from urllib.parse import urlparse
            try:
                result = urlparse(value if '://' in value else f'https://{value}')
                if result.netloc:
                    return True
                print(f"  Please enter a valid URL")
                return False
            except Exception:
                print(f"  Invalid URL format")
                return False
        
        if config.prompt_type == PromptType.IP:
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, value):
                parts = value.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    return True
            print(f"  Please enter a valid IP address")
            return False
        
        if config.prompt_type == PromptType.FILE_PATH:
            if os.path.isfile(value):
                return True
            print(f"  File not found: {value}")
            return False
        
        if config.prompt_type == PromptType.DIRECTORY_PATH:
            if os.path.isdir(value):
                return True
            print(f"  Directory not found: {value}")
            return False
        
        if config.prompt_type == PromptType.EMAIL:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if re.match(email_pattern, value):
                return True
            print(f"  Please enter a valid email address")
            return False
        
        return True
    
    def ask_text(
        self,
        message: str,
        default: Optional[str] = None,
        required: bool = True,
        validator: Optional[Callable] = None
    ) -> Optional[str]:
        """
        Ask for text input.
        
        Args:
            message: Prompt message
            default: Default value
            required: Whether input is required
            validator: Custom validator function
            
        Returns:
            User input or default
        """
        config = PromptConfig(
            prompt_type=PromptType.TEXT,
            message=message,
            default=default,
            required=required,
            validator=validator
        )
        return self.prompt(config)
    
    def ask_number(
        self,
        message: str,
        default: Optional[float] = None,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None
    ) -> Optional[float]:
        """
        Ask for numeric input.
        
        Args:
            message: Prompt message
            default: Default value
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            
        Returns:
            Number or default
        """
        config = PromptConfig(
            prompt_type=PromptType.NUMBER,
            message=message,
            default=default,
            min_value=min_value,
            max_value=max_value
        )
        result = self.prompt(config)
        if result is not None:
            try:
                return float(result)
            except (ValueError, TypeError):
                return default
        return default
    
    def ask_confirm(
        self,
        message: str,
        default: bool = False
    ) -> bool:
        """
        Ask for confirmation.
        
        Args:
            message: Prompt message
            default: Default response
            
        Returns:
            True if confirmed, False otherwise
        """
        config = PromptConfig(
            prompt_type=PromptType.CONFIRM,
            message=message,
            default=default
        )
        result = self.prompt(config)
        if result is None:
            return default
        if isinstance(result, str):
            return result.lower() in ['y', 'yes', 'true', '1']
        return bool(result)
    
    def ask_choice(
        self,
        message: str,
        choices: List[str],
        default: Optional[int] = None
    ) -> Optional[str]:
        """
        Ask for a choice from a list.
        
        Args:
            message: Prompt message
            choices: List of choices
            default: Default choice index
            
        Returns:
            Selected choice or None
        """
        config = PromptConfig(
            prompt_type=PromptType.CHOICE,
            message=message,
            choices=choices,
            default=default
        )
        result = self.prompt(config)
        if result is None:
            return None
        
        try:
            index = int(result) - 1
            if 0 <= index < len(choices):
                return choices[index]
        except (ValueError, IndexError):
            if result in choices:
                return result
        
        if default is not None and 1 <= default <= len(choices):
            return choices[default - 1]
        
        return None
    
    def ask_password(self, message: str) -> Optional[str]:
        """
        Ask for password input.
        
        Args:
            message: Prompt message
            
        Returns:
            Password string
        """
        config = PromptConfig(
            prompt_type=PromptType.PASSWORD,
            message=message
        )
        return self.prompt(config)
    
    def ask_url(self, message: str) -> Optional[str]:
        """
        Ask for a URL.
        
        Args:
            message: Prompt message
            
        Returns:
            Validated URL
        """
        config = PromptConfig(
            prompt_type=PromptType.URL,
            message=message
        )
        return self.prompt(config)
    
    def ask_file(self, message: str) -> Optional[str]:
        """
        Ask for a file path.
        
        Args:
            message: Prompt message
            
        Returns:
            Valid file path
        """
        config = PromptConfig(
            prompt_type=PromptType.FILE_PATH,
            message=message
        )
        return self.prompt(config)