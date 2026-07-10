# cli/arg_parser.py

"""
Command Line Argument Parser
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced argument parser for WOLFSTRIKE with support
for all modules, modes, and configuration options.
"""

import argparse
import sys
import os
from typing import Optional, List, Dict, Any


class ArgumentParser:
    """
    Custom argument parser for WOLFSTRIKE.
    
    Handles all command-line argument definitions,
    validation, and parsing with detailed help messages.
    """
    
    def __init__(
        self,
        version: str = "1.0.0",
        codename: str = "Shadowfang",
        author: str = "ATHEX BLACK HAT",
        team: str = "Wolf Intelligence PK"
    ):
        """
        Initialize the argument parser.
        
        Args:
            version: Tool version
            codename: Version codename
            author: Author name
            team: Team name
        """
        self.version = version
        self.codename = codename
        self.author = author
        self.team = team
        
        self.parser = argparse.ArgumentParser(
            prog="wolfstrike",
            description=f"WOLFSTRIKE v{version} ({codename}) - Ultimate Web Penetration Testing Toolkit",
            epilog=f"Author: {author} | Team: {team}",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            add_help=False
        )
        
        self._build_arguments()
    
    def _build_arguments(self) -> None:
        """Build all argument groups and arguments."""
        
        self._add_help_argument()
        self._add_target_arguments()
        self._add_scan_mode_arguments()
        self._add_module_arguments()
        self._add_performance_arguments()
        self._add_stealth_arguments()
        self._add_output_arguments()
        self._add_advanced_arguments()
        self._add_miscellaneous_arguments()
    
    def _add_help_argument(self) -> None:
        """Add help argument."""
        self.parser.add_argument(
            '-h', '--help',
            action='store_true',
            help='Show this help message and exit'
        )
    
    def _add_target_arguments(self) -> None:
        """Add target specification arguments."""
        target_group = self.parser.add_argument_group('Target Specification')
        
        target_group.add_argument(
            '-t', '--target',
            type=str,
            metavar='URL',
            help='Target URL or IP address to scan'
        )
        
        target_group.add_argument(
            '-f', '--file',
            type=str,
            metavar='FILE',
            help='File containing list of targets (one per line)'
        )
        
        target_group.add_argument(
            '--exclude',
            type=str,
            metavar='PATTERN',
            help='Exclude targets matching pattern'
        )
    
    def _add_scan_mode_arguments(self) -> None:
        """Add scan mode arguments."""
        mode_group = self.parser.add_argument_group('Scan Modes')
        
        mode_group.add_argument(
            '--quick',
            action='store_true',
            help='Run quick scan with default settings'
        )
        
        mode_group.add_argument(
            '--full-power',
            action='store_true',
            dest='full_power',
            help='Run full power scan with all modules enabled'
        )
        
        mode_group.add_argument(
            '--interactive',
            action='store_true',
            help='Launch interactive menu mode'
        )
        
        mode_group.add_argument(
            '--resume',
            type=str,
            metavar='SESSION_ID',
            help='Resume a previous scan session'
        )
    
    def _add_module_arguments(self) -> None:
        """Add module selection arguments."""
        module_group = self.parser.add_argument_group('Module Selection')
        
        module_group.add_argument(
            '-m', '--module',
            type=str,
            metavar='MODULES',
            help='Comma-separated list of modules to run (recon,scanner,vuln_scanner,attacks,auth_tester,crawler,api_tester,osint)'
        )
        
        module_group.add_argument(
            '--exclude-module',
            type=str,
            metavar='MODULES',
            dest='exclude_module',
            help='Comma-separated list of modules to exclude'
        )
        
        module_group.add_argument(
            '--list-modules',
            action='store_true',
            help='List all available modules and exit'
        )
    
    def _add_performance_arguments(self) -> None:
        """Add performance tuning arguments."""
        perf_group = self.parser.add_argument_group('Performance Options')
        
        perf_group.add_argument(
            '--threads',
            type=int,
            metavar='N',
            default=50,
            help='Number of concurrent threads (default: 50)'
        )
        
        perf_group.add_argument(
            '--timeout',
            type=int,
            metavar='SECONDS',
            default=30,
            help='Request timeout in seconds (default: 30)'
        )
        
        perf_group.add_argument(
            '--delay',
            type=float,
            metavar='SECONDS',
            default=0,
            help='Delay between requests in seconds (default: 0)'
        )
        
        perf_group.add_argument(
            '--retries',
            type=int,
            metavar='N',
            default=3,
            help='Number of retries for failed requests (default: 3)'
        )
        
        perf_group.add_argument(
            '--max-depth',
            type=int,
            metavar='N',
            default=3,
            dest='max_depth',
            help='Maximum crawl depth (default: 3)'
        )
    
    def _add_stealth_arguments(self) -> None:
        """Add stealth and evasion arguments."""
        stealth_group = self.parser.add_argument_group('Stealth & Evasion')
        
        stealth_group.add_argument(
            '--stealth',
            action='store_true',
            help='Enable stealth mode with evasion techniques'
        )
        
        stealth_group.add_argument(
            '--tor',
            action='store_true',
            help='Route traffic through TOR network'
        )
        
        stealth_group.add_argument(
            '--proxy',
            type=str,
            metavar='PROXY_URL',
            help='Use proxy server (http://host:port or socks5://host:port)'
        )
        
        stealth_group.add_argument(
            '--proxy-file',
            type=str,
            metavar='FILE',
            dest='proxy_file',
            help='File containing proxy list for rotation'
        )
        
        stealth_group.add_argument(
            '--random-agent',
            action='store_true',
            dest='random_agent',
            help='Use random User-Agent for each request'
        )
        
        stealth_group.add_argument(
            '--user-agent',
            type=str,
            metavar='AGENT',
            dest='user_agent',
            help='Custom User-Agent string'
        )
    
    def _add_output_arguments(self) -> None:
        """Add output and reporting arguments."""
        output_group = self.parser.add_argument_group('Output & Reporting')
        
        output_group.add_argument(
            '-o', '--output',
            type=str,
            metavar='DIR',
            default='./reports',
            help='Output directory for reports (default: ./reports)'
        )
        
        output_group.add_argument(
            '--report',
            type=str,
            metavar='FORMAT',
            choices=['pdf', 'html', 'json', 'all'],
            help='Generate report in specified format'
        )
        
        output_group.add_argument(
            '--no-report',
            action='store_true',
            help='Disable report generation'
        )
        
        output_group.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        output_group.add_argument(
            '--debug',
            action='store_true',
            help='Enable debug mode with detailed logging'
        )
        
        output_group.add_argument(
            '-q', '--quiet',
            action='store_true',
            help='Suppress all output except errors'
        )
        
        output_group.add_argument(
            '--no-color',
            action='store_true',
            help='Disable colored output'
        )
    
    def _add_advanced_arguments(self) -> None:
        """Add advanced configuration arguments."""
        adv_group = self.parser.add_argument_group('Advanced Options')
        
        adv_group.add_argument(
            '--config',
            type=str,
            metavar='FILE',
            help='Load configuration from YAML file'
        )
        
        adv_group.add_argument(
            '--save-config',
            type=str,
            metavar='FILE',
            dest='save_config',
            help='Save current configuration to file'
        )
        
        adv_group.add_argument(
            '--cookie',
            type=str,
            metavar='COOKIE',
            action='append',
            dest='cookies',
            help='Add cookie (format: name=value)'
        )
        
        adv_group.add_argument(
            '--header',
            type=str,
            metavar='HEADER',
            action='append',
            dest='headers',
            help='Add custom header (format: Name: Value)'
        )
        
        adv_group.add_argument(
            '--auth',
            type=str,
            metavar='USER:PASS',
            help='Basic authentication credentials'
        )
        
        adv_group.add_argument(
            '--waf-bypass',
            action='store_true',
            dest='waf_bypass',
            help='Enable WAF bypass techniques'
        )
        
        adv_group.add_argument(
            '--ai-engine',
            action='store_true',
            dest='ai_engine',
            help='Enable AI-powered detection engine'
        )
        
        adv_group.add_argument(
            '--no-ai',
            action='store_true',
            dest='no_ai',
            help='Disable AI-powered detection engine'
        )
    
    def _add_miscellaneous_arguments(self) -> None:
        """Add miscellaneous arguments."""
        misc_group = self.parser.add_argument_group('Miscellaneous')
        
        misc_group.add_argument(
            '--version',
            action='version',
            version=f'WOLFSTRIKE v{self.version} ({self.codename}) - {self.author} | {self.team}'
        )
        
        misc_group.add_argument(
            '--update',
            action='store_true',
            help='Check for updates'
        )
        
        misc_group.add_argument(
            '--banner',
            action='store_true',
            help='Display the WOLFSTRIKE banner'
        )
    
    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """
        Parse command-line arguments.
        
        Args:
            args: List of arguments (uses sys.argv if None)
            
        Returns:
            Parsed arguments namespace
        """
        parsed_args = self.parser.parse_args(args)
        
        if parsed_args.help:
            self.print_help()
            sys.exit(0)
        
        if parsed_args.list_modules:
            self._list_modules()
            sys.exit(0)
        
        if parsed_args.banner:
            from core.banner import Banner
            banner = Banner()
            print(banner.get_main_banner())
            sys.exit(0)
        
        if parsed_args.interactive:
            return parsed_args
        
        if not parsed_args.target and not parsed_args.file and not parsed_args.resume:
            self.parser.error("No target specified. Use --target, --file, or --interactive")
        
        self._validate_args(parsed_args)
        
        return parsed_args
    
    def _validate_args(self, args: argparse.Namespace) -> None:
        """
        Validate parsed arguments for conflicts.
        
        Args:
            args: Parsed arguments to validate
        """
        if args.threads < 1 or args.threads > 500:
            self.parser.error("Threads must be between 1 and 500")
        
        if args.timeout < 1 or args.timeout > 300:
            self.parser.error("Timeout must be between 1 and 300 seconds")
        
        if args.delay < 0 or args.delay > 60:
            self.parser.error("Delay must be between 0 and 60 seconds")
        
        if args.retries < 0 or args.retries > 10:
            self.parser.error("Retries must be between 0 and 10")
        
        if args.max_depth < 1 or args.max_depth > 10:
            self.parser.error("Max depth must be between 1 and 10")
        
        if args.quiet and args.verbose:
            self.parser.error("Cannot use both --quiet and --verbose")
        
        if args.ai_engine and args.no_ai:
            self.parser.error("Cannot use both --ai-engine and --no-ai")
    
    def _list_modules(self) -> None:
        """List all available modules."""
        modules = {
            'recon': 'Reconnaissance - Subdomain, WHOIS, DNS, Technology detection',
            'scanner': 'Scanner - Port scanning, Service detection, OS fingerprinting',
            'vuln_scanner': 'Vulnerability Scanner - XSS, SQLi, LFI/RFI, CSRF, SSRF, SSTI',
            'attacks': 'Attack Modules - SQLi exploitation, XSS exploitation, JWT attacks',
            'auth_tester': 'Authentication Testing - Brute force, Session testing, JWT analysis',
            'crawler': 'Crawler - Web spider, AJAX crawler, Sitemap generation',
            'api_tester': 'API Testing - REST, GraphQL, SOAP endpoint testing',
            'osint': 'OSINT - Shodan, Censys, SecurityTrails, GitHub dorking',
        }
        
        print(f"\nAvailable Modules:")
        print(f"=" * 60)
        for name, description in modules.items():
            print(f"  {name:<15} - {description}")
        print(f"=" * 60)
        print(f"\nUsage: wolfstrike --target example.com --module recon,scanner")
    
    def print_help(self) -> None:
        """Print help message."""
        help_text = f"""
WOLFSTRIKE v{self.version} ({self.codename})
Ultimate Web Penetration Testing Toolkit
Author: {self.author} | Team: {self.team}

"""
        help_text += self.parser.format_help()
        help_text += f"""
Examples:
  # Quick scan of a single target
  wolfstrike --target example.com --quick

  # Full power scan with all modules
  wolfstrike --target example.com --full-power

  # Specific module scan
  wolfstrike --target example.com --module sqli,xss

  # Stealth scan through TOR
  wolfstrike --target example.com --stealth --tor

  # Scan with custom threads and timeout
  wolfstrike --target example.com --threads 100 --timeout 15

  # Generate PDF report after scan
  wolfstrike --target example.com --report pdf --output ./results

  # Interactive mode
  wolfstrike --interactive

  # Load targets from file
  wolfstrike --file targets.txt --quick

For more information: https://github.com/WolfIntelligencePK/WolfStrike
"""
        print(help_text)