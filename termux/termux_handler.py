# termux/termux_handler.py

"""
Termux Environment Handler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Handles Termux-specific environment detection,
feature limitations, and resource optimization
for Android devices.
"""

import os
import sys
import platform
import subprocess
from typing import Dict, List, Any, Optional, Tuple


class TermuxHandler:
    """
    Termux environment handler.
    
    Detects Termux environment, manages feature
    limitations, and optimizes for Android devices.
    """
    
    TERMUX_INDICATORS = [
        '/data/data/com.termux',
        'com.termux',
    ]
    
    AVAILABLE_FEATURES = {
        'recon': True,
        'subdomain_enum': True,
        'whois_lookup': True,
        'dns_enum': True,
        'port_scanner': True,
        'service_detect': True,
        'vuln_scanner': True,
        'xss_scanner': True,
        'sqli_scanner': True,
        'lfi_rfi_scanner': True,
        'crawler': True,
        'spider': True,
        'header_analyzer': True,
        'cookie_analyzer': True,
        'ssl_analyzer': True,
        'reporting': True,
        'terminal_report': True,
        'json_export': True,
        'ai_engine': False,
        'full_ai': False,
        'advanced_attacks': False,
        'sqli_exploit': False,
        'xss_exploit': False,
        'jwt_attacks': False,
        'deserialization': False,
        'browser_automation': False,
        'ajax_crawler': False,
        'raw_sockets': False,
        'multi_threading_high': False,
        'os_fingerprint': False,
        'pdf_generator': False,
    }
    
    LIMITATIONS = [
        'Limited multi-threading support',
        'No raw socket access for advanced scanning',
        'Reduced attack module capabilities',
        'AI engine runs in lite mode',
        'Browser automation not available',
        'PDF report generation disabled',
        'Advanced OS fingerprinting disabled',
        'Maximum concurrent threads limited to 20',
    ]
    
    RECOMMENDATIONS = [
        'Use Kali Linux for full power scanning',
        'Deploy via Docker for complete feature set',
        'Use VPS or cloud instance for 24/7 scanning',
        'Install Termux from F-Droid for latest version',
        'Run "pkg update && pkg upgrade" regularly',
    ]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Termux handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.is_termux = self._detect_termux()
        self.features = self._get_available_features()
        self.limitations = self.LIMITATIONS.copy()
        self.recommendations = self.RECOMMENDATIONS.copy()
    
    def _detect_termux(self) -> bool:
        """
        Detect if running in Termux environment.
        
        Returns:
            True if running in Termux
        """
        for indicator in self.TERMUX_INDICATORS:
            if os.path.exists(indicator):
                return True
        
        if 'PREFIX' in os.environ:
            prefix = os.environ.get('PREFIX', '')
            if 'com.termux' in prefix:
                return True
        
        return False
    
    def _get_available_features(self) -> Dict[str, bool]:
        """
        Get feature availability based on environment.
        
        Returns:
            Dictionary with feature availability
        """
        features = self.AVAILABLE_FEATURES.copy()
        
        if not self.is_termux:
            for key in features:
                features[key] = True
            return features
        
        installed_packages = self._get_installed_packages()
        
        if 'nmap' in installed_packages:
            features['port_scanner'] = True
        
        if 'python-nmap' in installed_packages:
            features['service_detect'] = True
        
        available_memory = self._get_available_memory()
        
        if available_memory > 500:
            features['multi_threading_high'] = True
            features['crawler'] = True
        
        return features
    
    def _get_installed_packages(self) -> List[str]:
        """
        Get list of installed Termux packages.
        
        Returns:
            List of installed package names
        """
        try:
            result = subprocess.run(
                ['pkg', 'list-installed'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            packages = []
            for line in result.stdout.split('\n'):
                if '/' in line:
                    pkg_name = line.split('/')[0].strip()
                    packages.append(pkg_name)
            
            return packages
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
    
    def _get_available_memory(self) -> int:
        """
        Get available memory in MB.
        
        Returns:
            Available memory in megabytes
        """
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemAvailable' in line:
                        parts = line.split()
                        kb_value = int(parts[1])
                        return kb_value // 1024
            
            return 256
            
        except (FileNotFoundError, ValueError, IndexError):
            return 256
    
    def is_feature_available(self, feature_name: str) -> bool:
        """
        Check if a specific feature is available.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            True if feature is available
        """
        return self.features.get(feature_name, False)
    
    def get_disabled_features(self) -> List[str]:
        """
        Get list of disabled features.
        
        Returns:
            List of disabled feature names
        """
        return [
            name for name, available in self.features.items()
            if not available
        ]
    
    def get_optimized_threads(self, requested: int) -> int:
        """
        Get optimized thread count for Termux.
        
        Args:
            requested: Requested thread count
            
        Returns:
            Optimized thread count
        """
        if not self.is_termux:
            return min(requested, 200)
        
        available_memory = self._get_available_memory()
        
        if available_memory > 1000:
            max_threads = 30
        elif available_memory > 500:
            max_threads = 20
        elif available_memory > 200:
            max_threads = 10
        else:
            max_threads = 5
        
        return min(requested, max_threads)
    
    def get_optimized_timeout(self, requested: int) -> int:
        """
        Get optimized timeout for Termux.
        
        Args:
            requested: Requested timeout in seconds
            
        Returns:
            Optimized timeout value
        """
        if not self.is_termux:
            return requested
        
        return max(requested, 15)
    
    def get_environment_info(self) -> Dict[str, Any]:
        """
        Get Termux environment information.
        
        Returns:
            Dictionary with environment details
        """
        info = {
            'is_termux': self.is_termux,
            'platform': platform.system(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
            'available_memory_mb': self._get_available_memory(),
        }
        
        if self.is_termux:
            try:
                result = subprocess.run(
                    ['getprop', 'ro.product.model'],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                info['device_model'] = result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                info['device_model'] = 'Unknown Android Device'
            
            try:
                result = subprocess.run(
                    ['getprop', 'ro.build.version.release'],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                info['android_version'] = result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                info['android_version'] = 'Unknown'
        
        return info
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get Termux handler statistics.
        
        Returns:
            Dictionary with handler statistics
        """
        return {
            'is_termux': self.is_termux,
            'total_features': len(self.features),
            'available_features': sum(1 for v in self.features.values() if v),
            'disabled_features': sum(1 for v in self.features.values() if not v),
            'limitations_count': len(self.limitations),
            'recommendations_count': len(self.recommendations),
            'environment': self.get_environment_info(),
        }
    
    def print_info(self) -> None:
        """Print Termux environment information."""
        print("\n" + "=" * 60)
        print("  TERMUX ENVIRONMENT INFORMATION")
        print("=" * 60)
        
        env_info = self.get_environment_info()
        
        print(f"  Platform:      {env_info.get('platform', 'Unknown')}")
        print(f"  Machine:       {env_info.get('machine', 'Unknown')}")
        print(f"  Python:        {env_info.get('python_version', 'Unknown')}")
        print(f"  Memory:        {env_info.get('available_memory_mb', 'Unknown')} MB")
        
        if self.is_termux:
            print(f"  Device:        {env_info.get('device_model', 'Unknown')}")
            print(f"  Android:       {env_info.get('android_version', 'Unknown')}")
        
        print(f"\n  Features:      {sum(1 for v in self.features.values() if v)}/{len(self.features)} available")
        
        print(f"\n  Limitations:")
        for limitation in self.limitations[:5]:
            print(f"    - {limitation}")
        
        print(f"\n  Recommendations:")
        for recommendation in self.recommendations[:3]:
            print(f"    - {recommendation}")
        
        print("=" * 60 + "\n")