# cli/help_system.py

"""
Built-in Help System
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Comprehensive help system with detailed documentation
for all commands, modules, and features.
"""

import sys
from typing import Dict, List, Optional, Any


class HelpSystem:
    """
    Built-in help system for WOLFSTRIKE.
    
    Provides detailed documentation for all commands,
    modules, and features accessible from the CLI.
    """
    
    HELP_TOPICS = {
        'overview': {
            'title': 'WOLFSTRIKE Overview',
            'content': """
WOLFSTRIKE is an all-in-one web application penetration testing toolkit
developed by Wolf Intelligence PK under ATHEX BLACK HAT.

Version: 1.0.0 (Shadowfang)
Features: 160+ scanning, reconnaissance, exploitation, and reporting modules

Key Capabilities:
  - Complete reconnaissance suite
  - Advanced vulnerability scanning
  - Intelligent attack modules
  - AI-powered detection engine
  - Professional reporting system
  - Cross-platform support (Linux, Windows, macOS, Termux)
  - Stealth and evasion techniques
"""
        },
        'quickstart': {
            'title': 'Quick Start Guide',
            'content': """
Quick Start:

  1. Basic Scan:
     wolfstrike --target example.com

  2. Full Power Scan (Linux):
     wolfstrike --target example.com --full-power

  3. Interactive Mode:
     wolfstrike --interactive

  4. Specific Module:
     wolfstrike --target example.com --module sqli,xss

  5. Stealth Scan:
     wolfstrike --target example.com --stealth --tor

  6. Generate Report:
     wolfstrike --target example.com --report pdf
"""
        },
        'modules': {
            'title': 'Available Modules',
            'content': """
Modules:

  recon          - Reconnaissance
    Subdomain enumeration, WHOIS lookup, DNS analysis,
    Technology detection, WAF detection, SSL analysis

  scanner        - Port & Service Scanner
    Port scanning, Service version detection,
    OS fingerprinting, HTTP method testing

  vuln_scanner   - Vulnerability Scanner
    XSS, SQLi, LFI/RFI, CSRF, SSRF, SSTI,
    Command injection, File upload testing

  attacks        - Attack Modules
    SQLi exploitation, XSS exploitation,
    JWT attacks, Deserialization attacks

  auth_tester    - Authentication Testing
    Brute force, Session analysis,
    JWT analysis, OAuth testing, MFA testing

  crawler        - Web Crawler
    Web spider, AJAX crawler,
    Sitemap generation, Link checker

  api_tester     - API Testing
    REST API, GraphQL, SOAP testing,
    Rate limiting, Mass assignment

  osint          - OSINT Integration
    Shodan, Censys, SecurityTrails,
    GitHub dorking, Certificate transparency
"""
        },
        'commands': {
            'title': 'Command Reference',
            'content': """
Commands:

  Target Specification:
    -t, --target URL       Target URL or IP address
    -f, --file FILE         File with target list
    --exclude PATTERN       Exclude matching targets

  Scan Modes:
    --quick                 Quick scan with defaults
    --full-power            All modules enabled
    --interactive           Interactive menu mode
    --resume SESSION_ID     Resume previous scan

  Module Selection:
    -m, --module MODULES    Modules to run (comma-separated)
    --exclude-module MODS   Modules to exclude

  Performance:
    --threads N             Concurrent threads (default: 50)
    --timeout SECONDS       Request timeout (default: 30)
    --delay SECONDS         Request delay (default: 0)
    --retries N             Request retries (default: 3)
    --max-depth N           Crawl depth (default: 3)

  Stealth & Evasion:
    --stealth               Enable stealth mode
    --tor                   Route through TOR
    --proxy URL             Use proxy server
    --proxy-file FILE       Proxy rotation list
    --random-agent          Random User-Agent
    --user-agent AGENT      Custom User-Agent

  Output & Reporting:
    -o, --output DIR        Output directory
    --report FORMAT         Generate report (pdf/html/json/all)
    -v, --verbose           Verbose output
    --debug                 Debug mode
    -q, --quiet             Quiet mode
    --no-color              Disable colored output

  Advanced:
    --config FILE           Load config file
    --save-config FILE      Save config to file
    --cookie COOKIE         Add cookie
    --header HEADER         Add custom header
    --auth USER:PASS        Basic authentication
    --waf-bypass            WAF bypass techniques
    --ai-engine             Enable AI detection
    --no-ai                 Disable AI detection

  Miscellaneous:
    --version               Show version
    --update                Check for updates
    --banner                Display banner
    --list-modules          List all modules
    -h, --help              Show this help
"""
        },
        'platforms': {
            'title': 'Platform Support',
            'content': """
Platform Support:

  Linux (Kali/Parrot/Ubuntu):
    Full support - All 160+ features available
    Recommended for penetration testing

  Windows:
    Full support with some limitations
    PowerShell or Command Prompt compatible

  macOS:
    Full support via Homebrew Python
    Native terminal compatible

  Termux (Android):
    Lite mode - 40+ core features
    Limited multi-threading and advanced attacks
    Warning: For full power, use Linux

  Docker:
    Containerized deployment
    All features available
    Cross-platform compatible
"""
        },
        'configuration': {
            'title': 'Configuration Guide',
            'content': """
Configuration:

  Environment Variables:
    SHODAN_API_KEY         Shodan API key
    CENSYS_API_ID          Censys API ID
    CENSYS_API_SECRET      Censys API secret
    SECURITYTRAILS_KEY     SecurityTrails API key
    GITHUB_TOKEN           GitHub personal access token

  Configuration File (YAML):
    threads: 50
    timeout: 30
    delay: 0
    stealth: false
    tor: false
    output_dir: ./reports
    ai_engine: true

  Default Locations:
    Linux:   ~/.config/wolfstrike/config.yaml
    Windows: %APPDATA%\\WolfStrike\\config.yaml
    macOS:   ~/Library/Application Support/WolfStrike/config.yaml
"""
        },
        'reporting': {
            'title': 'Reporting Guide',
            'content': """
Reporting:

  Formats:
    PDF     - Professional PDF report with charts
    HTML    - Interactive HTML dashboard
    JSON    - Machine-readable JSON export

  Report Contents:
    - Executive summary
    - Vulnerability findings
    - Risk assessment scores
    - MITRE ATT&CK mapping
    - Remediation recommendations
    - Evidence and screenshots
    - Technical details

  Customization:
    wolfstrike --target example.com --report pdf --output ./audit/
    wolfstrike --target example.com --report all --verbose
"""
        },
        'faq': {
            'title': 'Frequently Asked Questions',
            'content': """
FAQ:

  Q: Is WOLFSTRIKE free?
  A: Yes, open-source under MIT license.

  Q: Do I need root privileges?
  A: Some features require root. Most work without.

  Q: Is it safe to use?
  A: Only use on systems you own or have authorization to test.

  Q: How to update?
  A: git pull && pip install -r requirements.txt --upgrade

  Q: Where are reports saved?
  A: Default ./reports/ directory, configurable with --output.

  Q: Can I contribute?
  A: Yes! See CONTRIBUTING.md for guidelines.

  Q: What Python version?
  A: Python 3.10 or higher required.

  Q: How to report bugs?
  A: GitHub Issues or email wolfintelligencepk@protonmail.com
"""
        },
    }
    
    @classmethod
    def show_help(cls, topic: Optional[str] = None) -> None:
        """
        Display help information.
        
        Args:
            topic: Specific help topic to display
        """
        if topic and topic in cls.HELP_TOPICS:
            cls._print_topic(topic)
            return
        
        cls._print_main_help()
        
        if topic:
            print(f"\nUnknown topic: {topic}")
            print(f"Available topics: {', '.join(cls.HELP_TOPICS.keys())}")
    
    @classmethod
    def _print_main_help(cls) -> None:
        """Print main help overview."""
        print("""
    ==================================================================
                        WOLFSTRIKE HELP SYSTEM
              Wolf Intelligence PK | ATHEX BLACK HAT
    ==================================================================

    Usage: wolfstrike [OPTIONS] --target URL
           wolfstrike --interactive

    Help Topics:
      overview        - General overview
      quickstart      - Quick start guide
      modules         - Available modules
      commands        - Command reference
      platforms       - Platform support
      configuration   - Configuration guide
      reporting       - Reporting guide
      faq             - Frequently asked questions

    Examples:
      wolfstrike --help
      wolfstrike --help modules
      wolfstrike --help commands

    For detailed help on a topic:
      wolfstrike --help <topic>
    ==================================================================
    """)
    
    @classmethod
    def _print_topic(cls, topic: str) -> None:
        """
        Print a specific help topic.
        
        Args:
            topic: Topic key
        """
        topic_data = cls.HELP_TOPICS[topic]
        print(f"\n{'=' * 60}")
        print(f"  {topic_data['title']}")
        print(f"{'=' * 60}")
        print(topic_data['content'])
        print(f"{'=' * 60}\n")
    
    @classmethod
    def get_topic(cls, topic: str) -> Optional[Dict[str, str]]:
        """
        Get help topic data.
        
        Args:
            topic: Topic key
            
        Returns:
            Topic dictionary or None
        """
        return cls.HELP_TOPICS.get(topic)
    
    @classmethod
    def list_topics(cls) -> List[str]:
        """
        List all available help topics.
        
        Returns:
            List of topic keys
        """
        return list(cls.HELP_TOPICS.keys())
    
    @classmethod
    def search_help(cls, query: str) -> List[str]:
        """
        Search help topics for a query.
        
        Args:
            query: Search query
            
        Returns:
            List of matching topic keys
        """
        query_lower = query.lower()
        results = []
        
        for topic_key, topic_data in cls.HELP_TOPICS.items():
            if query_lower in topic_key.lower():
                results.append(topic_key)
                continue
            
            if query_lower in topic_data['title'].lower():
                results.append(topic_key)
                continue
            
            if query_lower in topic_data['content'].lower():
                results.append(topic_key)
        
        return results