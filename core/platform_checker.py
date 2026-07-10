# core/platform_checker.py

"""
Platform Detection Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects operating system, environment, and available
capabilities for cross-platform compatibility.
"""

import os
import sys
import platform
import subprocess
import shutil
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class PlatformType(Enum):
    """Operating system types."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    TERMUX = "termux"
    DOCKER = "docker"
    UNKNOWN = "unknown"


class EnvironmentType(Enum):
    """Runtime environment types."""
    NATIVE = "native"
    DOCKER = "docker"
    VIRTUAL_MACHINE = "virtual_machine"
    WSL = "wsl"
    CLOUD = "cloud"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Comprehensive platform information."""
    platform: PlatformType
    environment: EnvironmentType
    os_name: str
    os_version: str
    architecture: str
    python_version: str
    hostname: str
    is_root: bool
    is_termux: bool
    is_docker: bool
    available_tools: Dict[str, bool]
    limitations: list
    recommendations: list


class PlatformChecker:
    """
    Platform detection and compatibility checker.
    
    Determines the operating system, environment, and
    available capabilities for cross-platform operation.
    """
    
    def __init__(self):
        """Initialize the platform checker."""
        self.platform_info = self._detect_platform()
    
    def _detect_platform(self) -> PlatformInfo:
        """
        Detect the current platform and environment.
        
        Returns:
            PlatformInfo object with platform details
        """
        system = platform.system().lower()
        
        platform_type = PlatformType.UNKNOWN
        if os.path.exists('/data/data/com.termux'):
            platform_type = PlatformType.TERMUX
        elif system == 'linux':
            platform_type = PlatformType.LINUX
        elif system == 'windows':
            platform_type = PlatformType.WINDOWS
        elif system == 'darwin':
            platform_type = PlatformType.MACOS
        
        environment = EnvironmentType.UNKNOWN
        is_docker = self._check_docker()
        is_wsl = self._check_wsl()
        is_vm = self._check_virtual_machine()
        
        if is_docker:
            environment = EnvironmentType.DOCKER
        elif is_wsl:
            environment = EnvironmentType.WSL
        elif is_vm:
            environment = EnvironmentType.VIRTUAL_MACHINE
        else:
            environment = EnvironmentType.NATIVE
        
        is_root = self._check_root()
        is_termux = platform_type == PlatformType.TERMUX
        available_tools = self._check_available_tools()
        limitations = self._get_limitations(platform_type, is_termux, is_root)
        recommendations = self._get_recommendations(platform_type)
        
        return PlatformInfo(
            platform=platform_type,
            environment=environment,
            os_name=platform.system(),
            os_version=platform.version(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            hostname=platform.node(),
            is_root=is_root,
            is_termux=is_termux,
            is_docker=is_docker,
            available_tools=available_tools,
            limitations=limitations,
            recommendations=recommendations
        )
    
    def _check_root(self) -> bool:
        """
        Check if running with root/administrator privileges.
        
        Returns:
            True if running as root
        """
        try:
            if hasattr(os, 'geteuid'):
                return os.geteuid() == 0
            elif sys.platform == 'win32':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return False
        except Exception:
            return False
    
    def _check_docker(self) -> bool:
        """
        Check if running inside a Docker container.
        
        Returns:
            True if in Docker container
        """
        docker_indicators = [
            '/.dockerenv',
            '/proc/1/cgroup',
        ]
        
        for indicator in docker_indicators:
            if os.path.exists(indicator):
                try:
                    with open(indicator, 'r') as f:
                        content = f.read()
                        if 'docker' in content.lower():
                            return True
                except Exception:
                    pass
        
        return os.path.exists('/.dockerenv')
    
    def _check_wsl(self) -> bool:
        """
        Check if running in Windows Subsystem for Linux.
        
        Returns:
            True if in WSL
        """
        if sys.platform != 'linux':
            return False
        
        try:
            with open('/proc/version', 'r') as f:
                content = f.read().lower()
                return 'microsoft' in content or 'wsl' in content
        except Exception:
            return False
    
    def _check_virtual_machine(self) -> bool:
        """
        Check if running in a virtual machine.
        
        Returns:
            True if in a VM
        """
        vm_indicators = {
            'vmware': ['/sys/class/dmi/id/product_name', 'VMware'],
            'virtualbox': ['/sys/class/dmi/id/product_name', 'VirtualBox'],
            'kvm': ['/sys/class/dmi/id/sys_vendor', 'KVM'],
            'xen': ['/sys/class/dmi/id/sys_vendor', 'Xen'],
            'hyperv': ['/sys/class/dmi/id/sys_vendor', 'Microsoft Corporation'],
        }
        
        for vm_name, (filepath, keyword) in vm_indicators.items():
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        if keyword.lower() in f.read().lower():
                            return True
                except Exception:
                    pass
        
        return False
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """
        Check which external tools are available.
        
        Returns:
            Dictionary of tool availability
        """
        tools = {
            'nmap': False,
            'whois': False,
            'dig': False,
            'nslookup': False,
            'curl': False,
            'wget': False,
            'git': False,
            'tor': False,
            'proxychains': False,
            'sqlmap': False,
            'nikto': False,
            'dirb': False,
        }
        
        for tool in tools:
            tools[tool] = shutil.which(tool) is not None
        
        return tools
    
    def _get_limitations(
        self,
        platform_type: PlatformType,
        is_termux: bool,
        is_root: bool
    ) -> list:
        """
        Get platform limitations.
        
        Args:
            platform_type: Detected platform type
            is_termux: Whether running in Termux
            is_root: Whether running as root
            
        Returns:
            List of limitation strings
        """
        limitations = []
        
        if is_termux:
            limitations.append("Limited multi-threading support")
            limitations.append("No raw socket access")
            limitations.append("Reduced attack module capabilities")
            limitations.append("AI engine runs in lite mode")
            limitations.append("Browser automation not available")
            limitations.append("Some external tools unavailable")
        
        if platform_type == PlatformType.WINDOWS:
            limitations.append("Some Linux-specific features unavailable")
            limitations.append("Signal handling differences")
            limitations.append("Path separator differences")
        
        if not is_root:
            limitations.append("Raw socket operations restricted")
            limitations.append("Some port scanning techniques unavailable")
            limitations.append("ICMP operations may be limited")
        
        return limitations
    
    def _get_recommendations(self, platform_type: PlatformType) -> list:
        """
        Get platform recommendations.
        
        Args:
            platform_type: Detected platform type
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if platform_type == PlatformType.TERMUX:
            recommendations.append("Use Kali Linux for full power scanning")
            recommendations.append("Deploy via Docker for complete feature set")
            recommendations.append("Use VPS for 24/7 scanning capability")
        elif platform_type == PlatformType.WINDOWS:
            recommendations.append("Consider using WSL for better compatibility")
            recommendations.append("Run via Docker for full Linux feature set")
        elif platform_type == PlatformType.MACOS:
            recommendations.append("Install via Homebrew for best compatibility")
            recommendations.append("Use Docker for isolated testing environment")
        
        return recommendations
    
    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get comprehensive platform information.
        
        Returns:
            Dictionary with platform information
        """
        info = self.platform_info
        return {
            'platform': info.platform.value,
            'environment': info.environment.value,
            'os_name': info.os_name,
            'os_version': info.os_version,
            'architecture': info.architecture,
            'python_version': info.python_version,
            'hostname': info.hostname,
            'is_root': info.is_root,
            'is_termux': info.is_termux,
            'is_docker': info.is_docker,
            'available_tools': info.available_tools,
            'limitations': info.limitations,
            'recommendations': info.recommendations,
        }
    
    def is_compatible(self) -> bool:
        """
        Check if current platform is compatible.
        
        Returns:
            True if compatible
        """
        return self.platform_info.platform != PlatformType.UNKNOWN
    
    def get_feature_flags(self) -> Dict[str, bool]:
        """
        Get feature availability flags based on platform.
        
        Returns:
            Dictionary of feature availability
        """
        info = self.platform_info
        
        return {
            'full_power': not info.is_termux,
            'raw_sockets': info.is_root and not info.is_termux,
            'multi_threading': True,
            'ai_engine': not info.is_termux,
            'stealth_mode': not info.is_termux,
            'browser_automation': not info.is_termux,
            'advanced_attacks': info.is_root and not info.is_termux,
            'tor_routing': True,
            'proxy_support': True,
            'report_generation': True,
        }
    
    def print_info(self) -> None:
        """Print platform information to console."""
        info = self.get_platform_info()
        
        print("\n" + "=" * 50)
        print("PLATFORM INFORMATION")
        print("=" * 50)
        print(f"  Platform:      {info['platform']}")
        print(f"  Environment:   {info['environment']}")
        print(f"  OS:            {info['os_name']} {info['os_version']}")
        print(f"  Architecture:  {info['architecture']}")
        print(f"  Python:        {info['python_version']}")
        print(f"  Root:          {info['is_root']}")
        print(f"  Termux:        {info['is_termux']}")
        print(f"  Docker:        {info['is_docker']}")
        
        if info['limitations']:
            print(f"\n  Limitations:")
            for limitation in info['limitations']:
                print(f"    - {limitation}")
        
        if info['recommendations']:
            print(f"\n  Recommendations:")
            for recommendation in info['recommendations']:
                print(f"    - {recommendation}")
        
        print("=" * 50 + "\n")