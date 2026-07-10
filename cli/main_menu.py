# cli/main_menu.py

"""
Interactive Main Menu System
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides an interactive terminal menu for WOLFSTRIKE
with full navigation, submenus, and configuration options.
"""

import os
import sys
import time
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum


class MenuState(Enum):
    """States for menu navigation."""
    MAIN = "main"
    SCAN_OPTIONS = "scan_options"
    MODULE_SELECT = "module_select"
    CONFIGURATION = "configuration"
    REPORTING = "reporting"
    TARGET_SETUP = "target_setup"
    ADVANCED = "advanced"
    EXIT = "exit"


@dataclass
class MenuItem:
    """Represents a single menu item."""
    key: str
    label: str
    description: str
    action: Optional[Callable] = None
    next_state: Optional[MenuState] = None
    requires_target: bool = False
    requires_config: bool = False
    enabled: bool = True


class MainMenu:
    """
    Interactive main menu system for WOLFSTRIKE.
    
    Provides a full-featured terminal menu with navigation,
    submenus, and integration with all toolkit modules.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the main menu system.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.target: Optional[str] = None
        self.current_state = MenuState.MAIN
        self.previous_state: Optional[MenuState] = None
        self.running = True
        self.selected_modules: List[str] = []
        self.scan_in_progress = False
        
        self.menu_items: Dict[MenuState, List[MenuItem]] = {}
        self._build_menus()
    
    def _build_menus(self) -> None:
        """Build all menu structures."""
        
        self.menu_items[MenuState.MAIN] = [
            MenuItem(
                key="1",
                label="Target Setup",
                description="Configure target URL or IP address",
                next_state=MenuState.TARGET_SETUP
            ),
            MenuItem(
                key="2",
                label="Quick Scan",
                description="Run a fast scan with default settings",
                action=self._quick_scan,
                requires_target=True
            ),
            MenuItem(
                key="3",
                label="Full Power Scan",
                description="Run comprehensive scan with all modules",
                action=self._full_power_scan,
                requires_target=True
            ),
            MenuItem(
                key="4",
                label="Module Selection",
                description="Select specific modules to run",
                next_state=MenuState.MODULE_SELECT,
                requires_target=True
            ),
            MenuItem(
                key="5",
                label="Scan Options",
                description="Configure scan parameters",
                next_state=MenuState.SCAN_OPTIONS
            ),
            MenuItem(
                key="6",
                label="Configuration",
                description="Manage toolkit configuration",
                next_state=MenuState.CONFIGURATION
            ),
            MenuItem(
                key="7",
                label="Reporting",
                description="Generate and manage reports",
                next_state=MenuState.REPORTING
            ),
            MenuItem(
                key="8",
                label="Advanced Options",
                description="Advanced scanning and stealth options",
                next_state=MenuState.ADVANCED
            ),
            MenuItem(
                key="9",
                label="Help",
                description="Display help and documentation",
                action=self._show_help
            ),
            MenuItem(
                key="0",
                label="Exit",
                description="Exit WOLFSTRIKE",
                next_state=MenuState.EXIT
            ),
        ]
        
        self.menu_items[MenuState.TARGET_SETUP] = [
            MenuItem(
                key="1",
                label="Set Target URL",
                description="Enter target URL or IP address",
                action=self._set_target
            ),
            MenuItem(
                key="2",
                label="Load Targets from File",
                description="Load multiple targets from a file",
                action=self._load_targets_from_file
            ),
            MenuItem(
                key="3",
                label="View Current Target",
                description="Display current target information",
                action=self._view_target
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
        
        self.menu_items[MenuState.SCAN_OPTIONS] = [
            MenuItem(
                key="1",
                label="Set Thread Count",
                description="Configure number of concurrent threads",
                action=self._set_threads
            ),
            MenuItem(
                key="2",
                label="Set Timeout",
                description="Configure request timeout in seconds",
                action=self._set_timeout
            ),
            MenuItem(
                key="3",
                label="Set Delay",
                description="Configure delay between requests",
                action=self._set_delay
            ),
            MenuItem(
                key="4",
                label="Set User-Agent",
                description="Configure custom User-Agent string",
                action=self._set_user_agent
            ),
            MenuItem(
                key="5",
                label="Proxy Configuration",
                description="Configure proxy settings",
                action=self._set_proxy
            ),
            MenuItem(
                key="6",
                label="Set Output Directory",
                description="Configure output directory for reports",
                action=self._set_output_dir
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
        
        self.menu_items[MenuState.MODULE_SELECT] = [
            MenuItem(
                key="1",
                label="Reconnaissance",
                description="Subdomain, WHOIS, DNS, Technology detection",
                action=lambda: self._toggle_module("recon")
            ),
            MenuItem(
                key="2",
                label="Scanner",
                description="Port scanning, Service detection, OS fingerprinting",
                action=lambda: self._toggle_module("scanner")
            ),
            MenuItem(
                key="3",
                label="Vulnerability Scanner",
                description="XSS, SQLi, LFI/RFI, CSRF, SSRF, SSTI detection",
                action=lambda: self._toggle_module("vuln_scanner")
            ),
            MenuItem(
                key="4",
                label="Attack Modules",
                description="SQLi exploitation, XSS exploitation, JWT attacks",
                action=lambda: self._toggle_module("attacks")
            ),
            MenuItem(
                key="5",
                label="Authentication Testing",
                description="Brute force, Session testing, JWT analysis",
                action=lambda: self._toggle_module("auth_tester")
            ),
            MenuItem(
                key="6",
                label="Crawler",
                description="Web spider, AJAX crawler, Sitemap generation",
                action=lambda: self._toggle_module("crawler")
            ),
            MenuItem(
                key="7",
                label="API Testing",
                description="REST, GraphQL, SOAP endpoint testing",
                action=lambda: self._toggle_module("api_tester")
            ),
            MenuItem(
                key="8",
                label="OSINT",
                description="Shodan, Censys, SecurityTrails, GitHub dorking",
                action=lambda: self._toggle_module("osint")
            ),
            MenuItem(
                key="9",
                label="Select All Modules",
                description="Enable all scanning modules",
                action=self._select_all_modules
            ),
            MenuItem(
                key="r",
                label="Run Selected Modules",
                description="Execute scan with selected modules",
                action=self._run_selected_modules,
                requires_target=True
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
        
        self.menu_items[MenuState.CONFIGURATION] = [
            MenuItem(
                key="1",
                label="View Configuration",
                description="Display current configuration",
                action=self._view_config
            ),
            MenuItem(
                key="2",
                label="Load Configuration File",
                description="Load configuration from YAML file",
                action=self._load_config_file
            ),
            MenuItem(
                key="3",
                label="Save Configuration",
                description="Save current configuration to file",
                action=self._save_config
            ),
            MenuItem(
                key="4",
                label="Reset to Defaults",
                description="Reset all settings to default values",
                action=self._reset_config
            ),
            MenuItem(
                key="5",
                label="API Keys Setup",
                description="Configure API keys for external services",
                action=self._setup_api_keys
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
        
        self.menu_items[MenuState.REPORTING] = [
            MenuItem(
                key="1",
                label="Generate PDF Report",
                description="Generate detailed PDF report",
                action=lambda: self._generate_report("pdf")
            ),
            MenuItem(
                key="2",
                label="Generate HTML Report",
                description="Generate interactive HTML report",
                action=lambda: self._generate_report("html")
            ),
            MenuItem(
                key="3",
                label="Generate JSON Report",
                description="Generate machine-readable JSON report",
                action=lambda: self._generate_report("json")
            ),
            MenuItem(
                key="4",
                label="View Last Report",
                description="Display the most recent scan report",
                action=self._view_last_report
            ),
            MenuItem(
                key="5",
                label="List All Reports",
                description="List all generated reports",
                action=self._list_reports
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
        
        self.menu_items[MenuState.ADVANCED] = [
            MenuItem(
                key="1",
                label="Stealth Mode",
                description="Enable stealth scanning with evasion techniques",
                action=self._toggle_stealth
            ),
            MenuItem(
                key="2",
                label="TOR Routing",
                description="Route traffic through TOR network",
                action=self._toggle_tor
            ),
            MenuItem(
                key="3",
                label="Custom Headers",
                description="Set custom HTTP headers",
                action=self._set_custom_headers
            ),
            MenuItem(
                key="4",
                label="Cookie Injection",
                description="Inject custom cookies into requests",
                action=self._set_cookies
            ),
            MenuItem(
                key="5",
                label="Rate Limiting",
                description="Configure intelligent rate limiting",
                action=self._set_rate_limit
            ),
            MenuItem(
                key="6",
                label="WAF Bypass Mode",
                description="Enable WAF bypass techniques",
                action=self._toggle_waf_bypass
            ),
            MenuItem(
                key="7",
                label="AI Engine Settings",
                description="Configure AI/ML detection parameters",
                action=self._configure_ai_engine
            ),
            MenuItem(
                key="0",
                label="Back to Main Menu",
                description="Return to main menu",
                next_state=MenuState.MAIN
            ),
        ]
    
    def display(self) -> None:
        """Display the current menu."""
        self._clear_screen()
        self._print_header()
        self._print_target_status()
        self._print_menu_items()
        self._print_footer()
    
    def _clear_screen(self) -> None:
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def _print_header(self) -> None:
        """Print the menu header with banner."""
        header = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    WOLFSTRIKE v1.0.0                        ║
    ║              Wolf Intelligence PK | ATHEX BLACK HAT         ║
    ╚══════════════════════════════════════════════════════════════╝
        """
        print(header)
    
    def _print_target_status(self) -> None:
        """Print current target status."""
        if self.target:
            print(f"    Target: {self.target}")
        else:
            print("    Target: [NOT SET]")
        
        if self.selected_modules:
            modules_str = ", ".join(self.selected_modules)
            print(f"    Modules: {modules_str}")
        
        print("    " + "-" * 58)
    
    def _print_menu_items(self) -> None:
        """Print menu items for current state."""
        items = self.menu_items.get(self.current_state, [])
        
        state_titles = {
            MenuState.MAIN: "MAIN MENU",
            MenuState.TARGET_SETUP: "TARGET SETUP",
            MenuState.SCAN_OPTIONS: "SCAN OPTIONS",
            MenuState.MODULE_SELECT: "MODULE SELECTION",
            MenuState.CONFIGURATION: "CONFIGURATION",
            MenuState.REPORTING: "REPORTING",
            MenuState.ADVANCED: "ADVANCED OPTIONS",
        }
        
        title = state_titles.get(self.current_state, "MENU")
        print(f"    [{title}]")
        print()
        
        for item in items:
            if not item.enabled:
                continue
            
            disabled = ""
            if item.requires_target and not self.target:
                disabled = " [Requires Target]"
            
            print(f"    [{item.key}] {item.label}{disabled}")
            print(f"         {item.description}")
            print()
    
    def _print_footer(self) -> None:
        """Print menu footer."""
        print("    " + "-" * 58)
        print("    Enter your choice: ", end="")
    
    def handle_input(self) -> None:
        """Handle user input for menu navigation."""
        choice = input().strip().lower()
        
        items = self.menu_items.get(self.current_state, [])
        
        selected_item = None
        for item in items:
            if item.key.lower() == choice:
                selected_item = item
                break
        
        if selected_item is None:
            print(f"\n    Invalid choice: {choice}")
            time.sleep(1)
            return
        
        if selected_item.requires_target and not self.target:
            print(f"\n    Target not set. Please configure target first.")
            time.sleep(1.5)
            return
        
        if selected_item.action:
            try:
                selected_item.action()
            except Exception as e:
                print(f"\n    Error: {str(e)}")
                time.sleep(1.5)
        
        if selected_item.next_state == MenuState.EXIT:
            self.running = False
            self._exit_program()
        elif selected_item.next_state:
            self.previous_state = self.current_state
            self.current_state = selected_item.next_state
    
    def run(self) -> None:
        """Main menu loop."""
        while self.running:
            try:
                self.display()
                self.handle_input()
            except KeyboardInterrupt:
                self._exit_program()
                break
            except EOFError:
                self._exit_program()
                break
    
    def _set_target(self) -> None:
        """Set target URL."""
        print("\n    Enter target URL or IP address: ", end="")
        target = input().strip()
        
        if target:
            from urllib.parse import urlparse
            
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            try:
                parsed = urlparse(target)
                if parsed.netloc:
                    self.target = target
                    print(f"\n    Target set to: {self.target}")
                else:
                    print(f"\n    Invalid target format")
            except Exception:
                print(f"\n    Invalid URL format")
        else:
            print(f"\n    Target not changed")
        
        time.sleep(1)
    
    def _load_targets_from_file(self) -> None:
        """Load targets from a file."""
        print("\n    Enter file path: ", end="")
        filepath = input().strip()
        
        if not filepath:
            print("\n    No file specified")
            time.sleep(1)
            return
        
        try:
            with open(filepath, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            if targets:
                self.target = targets[0]
                print(f"\n    Loaded {len(targets)} targets. First target set to: {self.target}")
            else:
                print(f"\n    No targets found in file")
        except FileNotFoundError:
            print(f"\n    File not found: {filepath}")
        except PermissionError:
            print(f"\n    Permission denied: {filepath}")
        except Exception as e:
            print(f"\n    Error loading file: {str(e)}")
        
        time.sleep(1.5)
    
    def _view_target(self) -> None:
        """View current target information."""
        if self.target:
            print(f"\n    Current Target: {self.target}")
            print(f"    Modules Selected: {len(self.selected_modules)}")
            if self.selected_modules:
                for module in self.selected_modules:
                    print(f"      - {module}")
        else:
            print(f"\n    No target configured")
        
        print(f"\n    Press Enter to continue...", end="")
        input()
    
    def _quick_scan(self) -> None:
        """Execute a quick scan."""
        if not self.target:
            print(f"\n    No target configured")
            time.sleep(1)
            return
        
        print(f"\n    Starting Quick Scan on {self.target}...")
        print(f"    This may take a few minutes...")
        time.sleep(1)
        
        self._run_scan(full_power=False)
    
    def _full_power_scan(self) -> None:
        """Execute a full power scan."""
        if not self.target:
            print(f"\n    No target configured")
            time.sleep(1)
            return
        
        print(f"\n    WARNING: Full Power Scan will run ALL modules!")
        print(f"    This may take several hours depending on target size.")
        print(f"\n    Continue? [y/N]: ", end="")
        
        confirm = input().strip().lower()
        if confirm != 'y':
            print(f"\n    Scan cancelled")
            time.sleep(1)
            return
        
        print(f"\n    Starting Full Power Scan on {self.target}...")
        time.sleep(1)
        
        self._run_scan(full_power=True)
    
    def _run_scan(self, full_power: bool = False) -> None:
        """
        Execute scan with current configuration.
        
        Args:
            full_power: Whether to run full power scan
        """
        self.scan_in_progress = True
        
        try:
            from core.engine import ScanEngine
            
            engine = ScanEngine(
                target=self.target,
                config=self.config,
                platform_checker=None,
                logger=None
            )
            
            if full_power:
                engine.run_full_scan()
            else:
                engine.run_quick_scan(modules=self.selected_modules)
            
            print(f"\n    Scan completed successfully!")
            
        except Exception as e:
            print(f"\n    Scan failed: {str(e)}")
        finally:
            self.scan_in_progress = False
        
        print(f"\n    Press Enter to continue...", end="")
        input()
    
    def _toggle_module(self, module_name: str) -> None:
        """
        Toggle a module selection.
        
        Args:
            module_name: Name of module to toggle
        """
        if module_name in self.selected_modules:
            self.selected_modules.remove(module_name)
            print(f"\n    Module '{module_name}' deselected")
        else:
            self.selected_modules.append(module_name)
            print(f"\n    Module '{module_name}' selected")
        
        time.sleep(0.5)
    
    def _select_all_modules(self) -> None:
        """Select all available modules."""
        all_modules = [
            "recon", "scanner", "vuln_scanner", "attacks",
            "auth_tester", "crawler", "api_tester", "osint"
        ]
        self.selected_modules = all_modules.copy()
        print(f"\n    All {len(all_modules)} modules selected")
        time.sleep(0.5)
    
    def _run_selected_modules(self) -> None:
        """Run scan with selected modules."""
        if not self.selected_modules:
            print(f"\n    No modules selected")
            time.sleep(1)
            return
        
        print(f"\n    Running {len(self.selected_modules)} modules...")
        self._run_scan(full_power=False)
    
    def _set_threads(self) -> None:
        """Set thread count."""
        print(f"\n    Enter thread count [10-200] (current: {self.config.get('threads', 50)}): ", end="")
        try:
            threads = int(input().strip())
            if 10 <= threads <= 200:
                self.config['threads'] = threads
                print(f"\n    Thread count set to: {threads}")
            else:
                print(f"\n    Value must be between 10 and 200")
        except ValueError:
            print(f"\n    Invalid number")
        time.sleep(1)
    
    def _set_timeout(self) -> None:
        """Set request timeout."""
        print(f"\n    Enter timeout in seconds [1-60] (current: {self.config.get('timeout', 30)}): ", end="")
        try:
            timeout = int(input().strip())
            if 1 <= timeout <= 60:
                self.config['timeout'] = timeout
                print(f"\n    Timeout set to: {timeout}s")
            else:
                print(f"\n    Value must be between 1 and 60")
        except ValueError:
            print(f"\n    Invalid number")
        time.sleep(1)
    
    def _set_delay(self) -> None:
        """Set delay between requests."""
        print(f"\n    Enter delay in seconds [0-10] (current: {self.config.get('delay', 0)}): ", end="")
        try:
            delay = float(input().strip())
            if 0 <= delay <= 10:
                self.config['delay'] = delay
                print(f"\n    Delay set to: {delay}s")
            else:
                print(f"\n    Value must be between 0 and 10")
        except ValueError:
            print(f"\n    Invalid number")
        time.sleep(1)
    
    def _set_user_agent(self) -> None:
        """Set custom User-Agent."""
        print(f"\n    Enter User-Agent string (or 'default' for default): ", end="")
        ua = input().strip()
        if ua.lower() == 'default':
            self.config.pop('user_agent', None)
            print(f"\n    User-Agent reset to default")
        elif ua:
            self.config['user_agent'] = ua
            print(f"\n    User-Agent set")
        else:
            print(f"\n    No change made")
        time.sleep(1)
    
    def _set_proxy(self) -> None:
        """Set proxy configuration."""
        print(f"\n    Enter proxy URL (or 'none' to disable): ", end="")
        proxy = input().strip()
        if proxy.lower() == 'none':
            self.config.pop('proxy', None)
            print(f"\n    Proxy disabled")
        elif proxy:
            self.config['proxy'] = proxy
            print(f"\n    Proxy set to: {proxy}")
        else:
            print(f"\n    No change made")
        time.sleep(1)
    
    def _set_output_dir(self) -> None:
        """Set output directory."""
        print(f"\n    Enter output directory path: ", end="")
        outdir = input().strip()
        if outdir:
            self.config['output_dir'] = outdir
            print(f"\n    Output directory set to: {outdir}")
        else:
            print(f"\n    No change made")
        time.sleep(1)
    
    def _view_config(self) -> None:
        """View current configuration."""
        print(f"\n    Current Configuration:")
        print(f"    " + "-" * 40)
        for key, value in self.config.items():
            print(f"    {key}: {value}")
        print(f"\n    Press Enter to continue...", end="")
        input()
    
    def _load_config_file(self) -> None:
        """Load configuration from file."""
        print(f"\n    Enter config file path: ", end="")
        filepath = input().strip()
        if filepath:
            import yaml
            try:
                with open(filepath, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    self.config.update(loaded_config)
                    print(f"\n    Configuration loaded from: {filepath}")
            except FileNotFoundError:
                print(f"\n    File not found: {filepath}")
            except Exception as e:
                print(f"\n    Error loading config: {str(e)}")
        time.sleep(1)
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        print(f"\n    Enter file path to save: ", end="")
        filepath = input().strip()
        if filepath:
            import yaml
            try:
                with open(filepath, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
                    print(f"\n    Configuration saved to: {filepath}")
            except Exception as e:
                print(f"\n    Error saving config: {str(e)}")
        time.sleep(1)
    
    def _reset_config(self) -> None:
        """Reset configuration to defaults."""
        print(f"\n    Reset all settings to defaults? [y/N]: ", end="")
        confirm = input().strip().lower()
        if confirm == 'y':
            self.config = {
                'threads': 50,
                'timeout': 30,
                'delay': 0,
                'stealth': False,
                'tor': False,
                'verbose': True,
                'output_dir': './reports',
            }
            print(f"\n    Configuration reset to defaults")
        time.sleep(1)
    
    def _setup_api_keys(self) -> None:
        """Setup API keys."""
        print(f"\n    API Key Setup:")
        print(f"    Enter Shodan API key (or press Enter to skip): ", end="")
        shodan_key = input().strip()
        if shodan_key:
            self.config['shodan_api_key'] = shodan_key
        
        print(f"    Enter Censys API ID (or press Enter to skip): ", end="")
        censys_id = input().strip()
        if censys_id:
            self.config['censys_api_id'] = censys_id
        
        print(f"    Enter Censys API Secret (or press Enter to skip): ", end="")
        censys_secret = input().strip()
        if censys_secret:
            self.config['censys_api_secret'] = censys_secret
        
        print(f"\n    API keys updated")
        time.sleep(1)
    
    def _generate_report(self, format_type: str) -> None:
        """Generate a report."""
        print(f"\n    Generating {format_type.upper()} report...")
        time.sleep(1)
        print(f"    Report generation not yet implemented in this version")
        time.sleep(1)
    
    def _view_last_report(self) -> None:
        """View last generated report."""
        print(f"\n    No previous reports found")
        time.sleep(1)
    
    def _list_reports(self) -> None:
        """List all generated reports."""
        print(f"\n    No reports found in output directory")
        time.sleep(1)
    
    def _toggle_stealth(self) -> None:
        """Toggle stealth mode."""
        current = self.config.get('stealth', False)
        self.config['stealth'] = not current
        status = "enabled" if self.config['stealth'] else "disabled"
        print(f"\n    Stealth mode {status}")
        time.sleep(0.5)
    
    def _toggle_tor(self) -> None:
        """Toggle TOR routing."""
        current = self.config.get('tor', False)
        self.config['tor'] = not current
        status = "enabled" if self.config['tor'] else "disabled"
        print(f"\n    TOR routing {status}")
        time.sleep(0.5)
    
    def _set_custom_headers(self) -> None:
        """Set custom HTTP headers."""
        print(f"\n    Enter custom headers (format: Header: Value, one per line, blank to finish):")
        headers = {}
        while True:
            line = input("    ").strip()
            if not line:
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        if headers:
            self.config['custom_headers'] = headers
            print(f"\n    {len(headers)} custom headers set")
        time.sleep(1)
    
    def _set_cookies(self) -> None:
        """Set custom cookies."""
        print(f"\n    Enter cookies (format: name=value, one per line, blank to finish):")
        cookies = {}
        while True:
            line = input("    ").strip()
            if not line:
                break
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        if cookies:
            self.config['cookies'] = cookies
            print(f"\n    {len(cookies)} cookies set")
        time.sleep(1)
    
    def _set_rate_limit(self) -> None:
        """Set rate limiting."""
        print(f"\n    Enter requests per second [1-100] (0 to disable): ", end="")
        try:
            rate = int(input().strip())
            if rate == 0:
                self.config.pop('rate_limit', None)
                print(f"\n    Rate limiting disabled")
            elif 1 <= rate <= 100:
                self.config['rate_limit'] = rate
                print(f"\n    Rate limit set to: {rate} req/s")
            else:
                print(f"\n    Value must be between 1 and 100")
        except ValueError:
            print(f"\n    Invalid number")
        time.sleep(1)
    
    def _toggle_waf_bypass(self) -> None:
        """Toggle WAF bypass mode."""
        current = self.config.get('waf_bypass', False)
        self.config['waf_bypass'] = not current
        status = "enabled" if self.config['waf_bypass'] else "disabled"
        print(f"\n    WAF bypass mode {status}")
        time.sleep(0.5)
    
    def _configure_ai_engine(self) -> None:
        """Configure AI engine settings."""
        print(f"\n    AI Engine Settings:")
        print(f"    Enable AI detection? [Y/n]: ", end="")
        enable = input().strip().lower()
        if enable != 'n':
            self.config['ai_enabled'] = True
            print(f"    AI engine enabled")
        else:
            self.config['ai_enabled'] = False
            print(f"    AI engine disabled")
        
        print(f"    Strict mode (fewer false positives)? [y/N]: ", end="")
        strict = input().strip().lower()
        self.config['ai_strict'] = strict == 'y'
        
        time.sleep(1)
    
    def _show_help(self) -> None:
        """Show help information."""
        from cli.help_system import HelpSystem
        HelpSystem.show_help()
    
    def _exit_program(self) -> None:
        """Exit the program."""
        print("\n")
        print("    " + "=" * 58)
        print("    WOLFSTRIKE shutting down...")
        print("    Wolf Intelligence PK | ATHEX BLACK HAT")
        print("    " + "=" * 58)
        print()
        self.running = False