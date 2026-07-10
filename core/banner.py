# core/banner.py

"""
Banner Display Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates and displays ASCII art banners for different
platforms and modes with version and author information.
"""

import random
from typing import Optional


class Banner:
    """
    Banner generator for WOLFSTRIKE.
    
    Provides ASCII art banners for different platforms
    with dynamic version and status information.
    """
    
    MAIN_BANNER = r"""
    __        _____  _     ____  _____ ____  _____ _  ________ _____ 
    \ \      / / _ \| |   / ___||_   _|  _ \| ____| |/ /_   _| ____|
     \ \ /\ / / | | | |   \___ \  | | | |_) |  _| | ' /  | | |  _|  
      \ V  V /| |_| | |___ ___) | | | |  _ <| |___| . \  | | | |___ 
       \_/\_/  \___/|_____|____/  |_| |_| \_\_____|_|\_\ |_| |_____|
                                                                     
         Wolf Intelligence PK | ATHEX BLACK HAT | v1.0.0
    """

    SUB_BANNER = r"""
      ___       ___       ___       ___       ___       ___   
     /\  \     /\  \     /\  \     /\  \     /\  \     /\__\  
    /::\  \   /::\  \   /::\  \   /::\  \   /::\  \   /:/  /  
   /:/\:\__\ /:/\:\__\ /::\:\__\ /::\:\__\ /::\:\__\ /:/__/   
   \:\ \/__/ \:\ \/__/ \/\::/  / \;:::/  / \:\:\/  / \:\  \   
    \:\__\    \:\__\     /:/  /   |:\/__/   \:\/  /   \:\__\  
     \/__/     \/__/     \/__/     \|__|     \/__/     \/__/   
    """

    TERMUX_BANNER = r"""
    __        _____  _     ____  _____ ____  _____ _  ________ _____ 
    \ \      / / _ \| |   / ___||_   _|  _ \| ____| |/ /_   _| ____|
     \ \ /\ / / | | | |   \___ \  | | | |_) |  |_| | ' /  | | |  _|  
      \ V  V /| |_| | |___ ___) | | | |  _ <| |___| . \  | | | |___ 
       \_/\_/  \___/|_____|____/  |_| |_| \_\_____|_|\_\ |_| |_____|
                                                                     
                 TERMUX EDITION | LITE MODE
         Wolf Intelligence PK | ATHEX BLACK HAT | v1.0.0
    """

    TAGLINES = [
        "Unleash the Pack, Strike the Shadows",
        "The Wolf Pack Hunts Tonight",
        "Silent. Deadly. Precise.",
        "Where Wolves Hunt, Shadows Fall",
        "Precision Strikes, Zero Mercy",
        "In the Dark, We See All",
        "Pack Mentality, Lone Wolf Capability",
        "Hunt Smart, Strike Hard",
    ]

    def __init__(self, no_color: bool = False):
        """
        Initialize the banner generator.
        
        Args:
            no_color: Disable colored output
        """
        self.no_color = no_color

    def get_main_banner(self) -> str:
        """
        Get the main WOLFSTRIKE banner.
        
        Returns:
            Banner string
        """
        tagline = random.choice(self.TAGLINES)
        banner = self.MAIN_BANNER
        
        if not self.no_color:
            banner = f"\033[91m{banner}\033[0m"
            tagline = f"\033[93m        {tagline}\033[0m"
        
        return f"{banner}\n{tagline}\n"

    def get_termux_banner(self) -> str:
        """
        Get the Termux-specific banner.
        
        Returns:
            Termux banner string
        """
        return self.TERMUX_BANNER

    def get_sub_banner(self) -> str:
        """
        Get the secondary banner.
        
        Returns:
            Secondary banner string
        """
        return self.SUB_BANNER

    def get_tagline(self) -> str:
        """
        Get a random tagline.
        
        Returns:
            Random tagline string
        """
        return random.choice(self.TAGLINES)

    def get_termux_warning(self) -> str:
        """
        Get Termux limitation warning message.
        
        Returns:
            Warning message string
        """
        warning = """
    +-------------------------------------------------------------+
    |  WARNING: TERMUX LIMITATION NOTICE                          |
    |                                                             |
    |  You are running WOLFSTRIKE on Termux (Android).           |
    |                                                             |
    |  LIMITED FEATURES ENABLED:                                  |
    |    - Basic Scanning                                         |
    |    - Reconnaissance                                         |
    |    - Vulnerability Detection                                |
    |                                                             |
    |  DISABLED FEATURES:                                         |
    |    - Advanced Attacks                                       |
    |    - AI Engine                                              |
    |    - Multi-threading (Limited)                              |
    |    - Browser Automation                                     |
    |                                                             |
    |  TO UNLEASH THE REAL POWER OF WOLFSTRIKE:                   |
    |    USE KALI LINUX / PARROT OS / ARCH LINUX                  |
    |                                                             |
    +-------------------------------------------------------------+
        """
        if not self.no_color:
            warning = f"\033[93m{warning}\033[0m"
        
        return warning

    def get_version_info(self) -> str:
        """
        Get version information string.
        
        Returns:
            Version info string
        """
        return "WOLFSTRIKE v1.0.0 (Shadowfang) - Wolf Intelligence PK | ATHEX BLACK HAT"

    def print_banner(self) -> None:
        """Print the main banner to console."""
        print(self.get_main_banner())

    def print_termux_banner(self) -> None:
        """Print Termux banner with warning."""
        print(self.get_termux_banner())
        print(self.get_termux_warning())