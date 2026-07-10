#!/usr/bin/env python3
"""
WOLFSTRIKE - Ultimate Web Penetration Testing Toolkit
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
License: MIT
Version: 1.0.0

This is the main entry point for the WOLFSTRIKE toolkit.
It handles command-line argument parsing and dispatches to appropriate modules.
"""

import argparse
import sys
import os
import signal
import traceback
from typing import Optional, Dict, Any

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.platform_checker import PlatformChecker
from core.logger import Logger
from core.config import ConfigManager
from core.banner import Banner
from cli.arg_parser import ArgumentParser
from cli.help_system import HelpSystem
from core.exceptions import WolfStrikeException, ConfigurationError


class WolfStrike:
    """
    Main application class for WOLFSTRIKE toolkit.
    Handles initialization, configuration, and module dispatching.
    """
    
    VERSION = "1.0.0"
    CODENAME = "Shadowfang"
    AUTHOR = "ATHEX BLACK HAT"
    TEAM = "Wolf Intelligence PK"
    
    def __init__(self):
        """
        Initialize the WOLFSTRIKE application.
        Sets up platform checker, logger, and configuration manager.
        """
        self.platform_checker = PlatformChecker()
        self.logger = Logger(
            name="WolfStrike",
            debug_mode=False,
            log_file=os.path.join("logs", "wolfstrike.log")
        )
        self.config_manager = ConfigManager()
        self.banner = Banner()
        self.args = None
        self.target = None
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info("WOLFSTRIKE initialized successfully")
    
    def _signal_handler(self, signum: int, frame: Any) -> None:
        """
        Handle interrupt signals for graceful shutdown.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        self.logger.warning(f"Received signal {signum}. Shutting down gracefully...")
        print("\n[*] Scan interrupted by user. Saving progress...")
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self) -> None:
        """
        Perform cleanup operations before exit.
        Saves state, closes connections, and releases resources.
        """
        try:
            self.logger.info("Performing cleanup operations...")
            # Save scan state if needed
            # Close database connections
            # Release thread pools
            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")
    
    def parse_arguments(self) -> argparse.Namespace:
        """
        Parse command-line arguments.
        
        Returns:
            Parsed arguments namespace
        """
        parser = ArgumentParser(
            version=self.VERSION,
            codename=self.CODENAME,
            author=self.AUTHOR,
            team=self.TEAM
        )
        self.args = parser.parse_args()
        return self.args
    
    def validate_target(self, target: str) -> bool:
        """
        Validate the target URL or IP address.
        
        Args:
            target: Target URL or IP address
            
        Returns:
            True if valid, False otherwise
        """
        import re
        from urllib.parse import urlparse
        
        if not target:
            return False
        
        # Check if target is IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            return True
        
        # Check if target is valid URL
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except Exception:
            # Try adding https:// prefix
            try:
                result = urlparse(f"https://{target}")
                return all([result.scheme, result.netloc])
            except Exception:
                return False
    
    def normalize_target(self, target: str) -> str:
        """
        Normalize the target URL.
        
        Args:
            target: Raw target input
            
        Returns:
            Normalized URL string
        """
        from urllib.parse import urlparse
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def load_configuration(self) -> Dict[str, Any]:
        """
        Load and merge all configuration sources.
        
        Returns:
            Dictionary containing merged configuration
        """
        config = self.config_manager.load_default_config()
        
        # Override with environment variables if present
        config = self.config_manager.override_from_env(config)
        
        # Override with command-line arguments if provided
        if self.args:
            config = self.config_manager.override_from_args(config, self.args)
        
        # Validate configuration
        if not self.config_manager.validate_config(config):
            raise ConfigurationError("Invalid configuration detected")
        
        return config
    
    def check_platform_compatibility(self) -> None:
        """
        Check platform compatibility and warn about limitations.
        """
        platform_info = self.platform_checker.get_platform_info()
        
        if platform_info['is_termux']:
            print(self.banner.get_termux_warning())
            self.logger.warning("Running in Termux environment - Limited features")
        elif platform_info['platform'] == 'linux':
            if platform_info['is_root']:
                self.logger.info("Running on Linux with root privileges - Full power")
            else:
                self.logger.info("Running on Linux without root - Some features limited")
        elif platform_info['platform'] == 'windows':
            self.logger.warning("Running on Windows - Some features may be limited")
    
    def dispatch_module(self, module_name: str, config: Dict[str, Any]) -> None:
        """
        Dispatch to appropriate scanning module.
        
        Args:
            module_name: Name of the module to run
            config: Configuration dictionary
        """
        module_map = {
            'recon': 'modules.recon',
            'scan': 'modules.scanner',
            'vulnscan': 'modules.vuln_scanner',
            'attack': 'modules.attacks',
            'auth': 'modules.auth_tester',
            'crawl': 'modules.crawler',
            'api': 'modules.api_tester',
            'network': 'modules.network',
            'osint': 'modules.osint',
        }
        
        if module_name == 'all':
            self._run_all_modules(config)
        elif module_name in module_map:
            self._run_single_module(module_map[module_name], config)
        else:
            raise WolfStrikeException(f"Unknown module: {module_name}")
    
    def _run_all_modules(self, config: Dict[str, Any]) -> None:
        """
        Execute all available scanning modules sequentially.
        
        Args:
            config: Configuration dictionary
        """
        from core.engine import ScanEngine
        
        engine = ScanEngine(
            target=self.target,
            config=config,
            platform_checker=self.platform_checker,
            logger=self.logger
        )
        engine.run_full_scan()
    
    def _run_single_module(self, module_path: str, config: Dict[str, Any]) -> None:
        """
        Execute a single scanning module.
        
        Args:
            module_path: Import path of the module
            config: Configuration dictionary
        """
        import importlib
        
        try:
            module = importlib.import_module(module_path)
            if hasattr(module, 'run'):
                module.run(target=self.target, config=config)
            else:
                raise WolfStrikeException(f"Module {module_path} has no run() function")
        except ImportError as e:
            self.logger.error(f"Failed to import module {module_path}: {str(e)}")
            raise WolfStrikeException(f"Module {module_path} not found")
    
    def run(self) -> None:
        """
        Main execution method.
        Parses arguments, validates input, and dispatches to modules.
        """
        try:
            # Display banner
            print(self.banner.get_main_banner())
            
            # Parse command-line arguments
            self.parse_arguments()
            
            # Check if help is requested
            if self.args.help:
                HelpSystem.show_help()
                return
            
            # Check platform compatibility
            self.check_platform_compatibility()
            
            # Validate target
            if not self.args.target:
                self.logger.error("No target specified")
                print("Error: No target specified. Use --target <url> or -t <url>")
                print("Use --help for more information")
                sys.exit(1)
            
            if not self.validate_target(self.args.target):
                self.logger.error(f"Invalid target: {self.args.target}")
                print(f"Error: Invalid target '{self.args.target}'")
                print("Please provide a valid URL or IP address")
                sys.exit(1)
            
            # Normalize target
            self.target = self.normalize_target(self.args.target)
            self.logger.info(f"Target set to: {self.target}")
            
            # Load configuration
            config = self.load_configuration()
            self.logger.info("Configuration loaded successfully")
            
            # Set logging level
            if self.args.verbose:
                self.logger.set_debug_mode(True)
            
            # Dispatch to appropriate module
            module_name = self.args.module if hasattr(self.args, 'module') else 'all'
            self.dispatch_module(module_name, config)
            
        except ConfigurationError as e:
            self.logger.error(f"Configuration error: {str(e)}")
            print(f"Configuration Error: {str(e)}")
            sys.exit(1)
        except WolfStrikeException as e:
            self.logger.error(f"WolfStrike error: {str(e)}")
            print(f"Error: {str(e)}")
            sys.exit(1)
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
            print("\n[*] Scan interrupted by user")
            self._cleanup()
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            self.logger.debug(traceback.format_exc())
            print(f"Unexpected Error: {str(e)}")
            if hasattr(self.args, 'debug') and self.args.debug:
                traceback.print_exc()
            sys.exit(1)


def main():
    """
    Entry point for the WOLFSTRIKE application.
    """
    app = WolfStrike()
    app.run()


if __name__ == "__main__":
    main()