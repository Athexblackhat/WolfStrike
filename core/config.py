# core/config.py

"""
Configuration Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages all configuration operations including loading,
saving, merging, and validating configuration data from
files, environment variables, and command-line arguments.
"""

import os
import yaml
import json
import copy
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from core.exceptions import ConfigurationError


class ConfigManager:
    """
    Configuration management system.
    
    Handles loading, saving, merging, and validation of
    configuration from multiple sources with priority ordering.
    """
    
    DEFAULT_CONFIG = {
        'general': {
            'debug_mode': False,
            'verbose': True,
            'quiet': False,
            'no_color': False,
            'log_level': 'INFO',
        },
        'performance': {
            'threads': 50,
            'timeout': 30,
            'delay': 0,
            'retries': 3,
            'max_depth': 3,
        },
        'http': {
            'user_agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'follow_redirects': True,
            'verify_ssl': False,
            'custom_headers': {},
            'cookies': {},
        },
        'stealth': {
            'enabled': False,
            'random_user_agent': False,
            'tor_enabled': False,
            'proxy_enabled': False,
        },
        'ai_engine': {
            'enabled': True,
            'pattern_recognition': True,
            'smart_payload_generation': True,
            'false_positive_filter': True,
            'min_confidence_threshold': 0.7,
        },
        'modules': {},
        'reporting': {
            'auto_generate': True,
            'output_directory': './reports',
            'formats': ['json'],
        },
        'api_keys': {},
        'database': {
            'enabled': True,
            'type': 'sqlite',
            'path': 'database/wolfstrike.db',
        },
        'cache': {
            'enabled': True,
            'type': 'memory',
            'max_size_mb': 256,
        },
    }
    
    CONFIG_SEARCH_PATHS = [
        './config/settings.yaml',
        './settings.yaml',
        '~/.config/wolfstrike/settings.yaml',
        '/etc/wolfstrike/settings.yaml',
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self.DEFAULT_CONFIG.copy()
        self.loaded_files: List[str] = []
    
    def load_default_config(self) -> Dict[str, Any]:
        """
        Load default configuration merged with file config.
        
        Returns:
            Merged configuration dictionary
        """
        self.config = copy.deepcopy(self.DEFAULT_CONFIG)
        
        config_file = self._find_config_file()
        if config_file:
            try:
                file_config = self._load_yaml_file(config_file)
                self.config = self._deep_merge(self.config, file_config)
                self.loaded_files.append(config_file)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config file {config_file}: {str(e)}")
        
        if self.config_path and os.path.exists(self.config_path):
            try:
                file_config = self._load_yaml_file(self.config_path)
                self.config = self._deep_merge(self.config, file_config)
                self.loaded_files.append(self.config_path)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config file {self.config_path}: {str(e)}")
        
        return self.config
    
    def _find_config_file(self) -> Optional[str]:
        """
        Find configuration file in search paths.
        
        Returns:
            Path to config file or None
        """
        for path in self.CONFIG_SEARCH_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path
        return None
    
    def _load_yaml_file(self, filepath: str) -> Dict[str, Any]:
        """
        Load and parse a YAML configuration file.
        
        Args:
            filepath: Path to YAML file
            
        Returns:
            Parsed configuration dictionary
        """
        try:
            with open(filepath, 'r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {filepath}: {str(e)}")
    
    def _load_json_file(self, filepath: str) -> Dict[str, Any]:
        """
        Load and parse a JSON configuration file.
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            Parsed configuration dictionary
        """
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in {filepath}: {str(e)}")
    
    def _deep_merge(
        self,
        base: Dict[str, Any],
        override: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            override: Override dictionary
            
        Returns:
            Merged dictionary
        """
        result = copy.deepcopy(base)
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        
        return result
    
    def override_from_env(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Override configuration from environment variables.
        
        Args:
            config: Current configuration
            
        Returns:
            Updated configuration
        """
        env_mappings = {
            'WOLFSTRIKE_THREADS': ('performance', 'threads', int),
            'WOLFSTRIKE_TIMEOUT': ('performance', 'timeout', int),
            'WOLFSTRIKE_DELAY': ('performance', 'delay', float),
            'WOLFSTRIKE_VERBOSE': ('general', 'verbose', lambda x: x.lower() == 'true'),
            'WOLFSTRIKE_DEBUG': ('general', 'debug_mode', lambda x: x.lower() == 'true'),
            'WOLFSTRIKE_QUIET': ('general', 'quiet', lambda x: x.lower() == 'true'),
            'WOLFSTRIKE_STEALTH': ('stealth', 'enabled', lambda x: x.lower() == 'true'),
            'WOLFSTRIKE_TOR': ('stealth', 'tor_enabled', lambda x: x.lower() == 'true'),
            'WOLFSTRIKE_PROXY': ('stealth', 'proxy_url', str),
            'WOLFSTRIKE_OUTPUT_DIR': ('reporting', 'output_directory', str),
            'SHODAN_API_KEY': ('api_keys', 'shodan', str),
            'CENSYS_API_ID': ('api_keys', 'censys_id', str),
            'CENSYS_API_SECRET': ('api_keys', 'censys_secret', str),
            'SECURITYTRAILS_API_KEY': ('api_keys', 'securitytrails', str),
            'GITHUB_TOKEN': ('api_keys', 'github_token', str),
        }
        
        for env_var, (section, key, converter) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    if section not in config:
                        config[section] = {}
                    config[section][key] = converter(value)
                except (ValueError, TypeError):
                    pass
        
        return config
    
    def override_from_args(
        self,
        config: Dict[str, Any],
        args: Any
    ) -> Dict[str, Any]:
        """
        Override configuration from command-line arguments.
        
        Args:
            config: Current configuration
            args: Parsed command-line arguments
            
        Returns:
            Updated configuration
        """
        arg_mappings = {
            'threads': ('performance', 'threads'),
            'timeout': ('performance', 'timeout'),
            'delay': ('performance', 'delay'),
            'verbose': ('general', 'verbose'),
            'debug': ('general', 'debug_mode'),
            'quiet': ('general', 'quiet'),
            'stealth': ('stealth', 'enabled'),
            'tor': ('stealth', 'tor_enabled'),
            'no_color': ('general', 'no_color'),
        }
        
        for arg_name, (section, key) in arg_mappings.items():
            if hasattr(args, arg_name):
                value = getattr(args, arg_name)
                if value is not None and value is not False:
                    if section not in config:
                        config[section] = {}
                    config[section][key] = value
        
        if hasattr(args, 'output') and args.output:
            if 'reporting' not in config:
                config['reporting'] = {}
            config['reporting']['output_directory'] = args.output
        
        return config
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration values.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if valid, False otherwise
        """
        if 'performance' in config:
            perf = config['performance']
            
            if 'threads' in perf:
                if not isinstance(perf['threads'], int) or perf['threads'] < 1 or perf['threads'] > 500:
                    raise ConfigurationError("threads must be between 1 and 500")
            
            if 'timeout' in perf:
                if not isinstance(perf['timeout'], (int, float)) or perf['timeout'] < 1 or perf['timeout'] > 300:
                    raise ConfigurationError("timeout must be between 1 and 300")
            
            if 'delay' in perf:
                if not isinstance(perf['delay'], (int, float)) or perf['delay'] < 0 or perf['delay'] > 60:
                    raise ConfigurationError("delay must be between 0 and 60")
        
        if 'ai_engine' in config:
            ai = config['ai_engine']
            if 'min_confidence_threshold' in ai:
                threshold = ai['min_confidence_threshold']
                if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 1:
                    raise ConfigurationError("min_confidence_threshold must be between 0 and 1")
        
        return True
    
    def save_config(self, filepath: str, config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save configuration to file.
        
        Args:
            filepath: Path to save configuration
            config: Configuration to save (uses current if None)
            
        Returns:
            True if successful, False otherwise
        """
        if config is None:
            config = self.config
        
        try:
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            
            with open(filepath, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to save config to {filepath}: {str(e)}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key_path: Dot-separated key path (e.g., 'performance.threads')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.
        
        Args:
            key_path: Dot-separated key path (e.g., 'performance.threads')
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def reset(self) -> None:
        """Reset configuration to defaults."""
        self.config = copy.deepcopy(self.DEFAULT_CONFIG)
        self.loaded_files.clear()