# termux/termux_banner.py

"""
Termux Banner Display
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Displays Termux-specific banner with limitation
warnings and recommendations.
"""

from typing import Optional


class TermuxBanner:
    """
    Termux banner display with warnings.
    
    Shows Termux-specific ASCII art and limitation
    notices when running on Android devices.
    """
    
    TERMUX_BANNER = r"""
    
    ██╗    ██╗ ██████╗ ██╗     ███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██║    ██║██╔═══██╗██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ██║ █╗ ██║██║   ██║██║     █████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██║███╗██║██║   ██║██║     ██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ╚███╔███╔╝╚██████╔╝███████╗██║     ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
     ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                                                                     
                 TERMUX EDITION | LITE MODE
         Wolf Intelligence PK | ATHEX BLACK HAT | v1.0.0
    """
    
    WARNING_BANNER = """
    +-------------------------------------------------------------+
      WARNING: TERMUX LIMITATION NOTICE                          
                                                                 
      You are running WOLFSTRIKE on Termux (Android).           
                                                                 
      LIMITED FEATURES ENABLED:                                  
        - Basic Scanning                                         
        - Reconnaissance                                         
        - Vulnerability Detection                                
        - Port Scanning (limited)                                
        - DNS Enumeration                                        
        - SSL/TLS Analysis                                       
                                                                 
      DISABLED FEATURES:                                         
        - Advanced Attack Modules                                
        - AI Engine (Full Power)                                 
        - Multi-threading (Limited)                             
        - Browser Automation                                     
        - Raw Socket Operations                                  
        - Advanced OS Fingerprinting                             
        - PDF Report Generation                                  
                                                                 
      TO UNLEASH THE REAL POWER OF WOLFSTRIKE:                   
        USE KALI LINUX / PARROT OS / ARCH LINUX                 
        OR DEPLOY VIA DOCKER ON A VPS                            
                                                                 
    +-------------------------------------------------------------+
    """
    
    MINIMAL_BANNER = """
    [WOLFSTRIKE] Termux Edition v1.0.0
    [WARNING] Limited features. Use Linux for full power.
    """
    
    def __init__(self, no_color: bool = False):
        """
        Initialize the Termux banner.
        
        Args:
            no_color: Disable colored output
        """
        self.no_color = no_color
    
    def get_banner(self) -> str:
        """
        Get the Termux ASCII art banner.
        
        Returns:
            Banner string
        """
        banner = self.TERMUX_BANNER
        
        if not self.no_color:
            banner = f"\033[91m{banner}\033[0m"
        
        return banner
    
    def get_warning(self) -> str:
        """
        Get the Termux limitation warning.
        
        Returns:
            Warning string
        """
        warning = self.WARNING_BANNER
        
        if not self.no_color:
            warning = f"\033[93m{warning}\033[0m"
        
        return warning
    
    def get_minimal(self) -> str:
        """
        Get minimal banner for quiet mode.
        
        Returns:
            Minimal banner string
        """
        return self.MINIMAL_BANNER
    
    def print_full_banner(self) -> None:
        """Print full banner with warning."""
        print(self.get_banner())
        print(self.get_warning())
    
    def print_minimal_banner(self) -> None:
        """Print minimal banner only."""
        print(self.get_minimal())
    
    def print_banner(self, minimal: bool = False) -> None:
        """
        Print appropriate banner.
        
        Args:
            minimal: Whether to print minimal banner
        """
        if minimal:
            self.print_minimal_banner()
        else:
            self.print_full_banner()