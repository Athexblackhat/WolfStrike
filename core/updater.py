# core/updater.py

"""
Update Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Handles checking for updates, downloading new versions,
and managing the update lifecycle for WOLFSTRIKE.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import subprocess
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


class UpdateChannel(Enum):
    """Update release channels."""
    STABLE = "stable"
    BETA = "beta"
    DEV = "dev"


class UpdateStatus(Enum):
    """Update check status."""
    UP_TO_DATE = "up_to_date"
    UPDATE_AVAILABLE = "update_available"
    CHECK_FAILED = "check_failed"
    UPDATE_IN_PROGRESS = "update_in_progress"
    UPDATE_COMPLETE = "update_complete"
    UPDATE_FAILED = "update_failed"


@dataclass
class UpdateInfo:
    """Information about an available update."""
    current_version: str
    latest_version: str
    release_date: str
    channel: UpdateChannel
    changelog: str
    download_url: str
    file_size: int
    sha256_checksum: str
    is_critical: bool
    breaking_changes: List[str]


class UpdateManager:
    """
    Manages WOLFSTRIKE updates.
    
    Checks for new versions, downloads updates,
    verifies integrity, and applies updates.
    """
    
    UPDATE_URL = "https://api.github.com/repos/WolfIntelligencePK/WolfStrike/releases/latest"
    VERSION_FILE = ".version"
    BACKUP_DIR = "backups"
    
    def __init__(
        self,
        current_version: str = "1.0.0",
        channel: UpdateChannel = UpdateChannel.STABLE,
        auto_check: bool = True
    ):
        """
        Initialize the update manager.
        
        Args:
            current_version: Current tool version
            channel: Update channel to use
            auto_check: Whether to auto-check on startup
        """
        self.current_version = current_version
        self.channel = channel
        self.auto_check = auto_check
        
        self.last_check_time: Optional[float] = None
        self.last_check_result: Optional[UpdateInfo] = None
        self.update_status = UpdateStatus.UP_TO_DATE
    
    def check_for_updates(self) -> Tuple[UpdateStatus, Optional[UpdateInfo]]:
        """
        Check for available updates.
        
        Returns:
            Tuple of update status and update info if available
        """
        self.last_check_time = time.time()
        
        try:
            request = Request(
                self.UPDATE_URL,
                headers={
                    'User-Agent': 'WOLFSTRIKE-UpdateChecker/1.0',
                    'Accept': 'application/vnd.github.v3+json',
                }
            )
            
            with urlopen(request, timeout=10) as response:
                release_data = json.loads(response.read().decode('utf-8'))
            
            latest_version = release_data.get('tag_name', '').lstrip('v')
            
            if not latest_version:
                self.update_status = UpdateStatus.CHECK_FAILED
                return UpdateStatus.CHECK_FAILED, None
            
            if self._compare_versions(latest_version, self.current_version) <= 0:
                self.update_status = UpdateStatus.UP_TO_DATE
                return UpdateStatus.UP_TO_DATE, None
            
            assets = release_data.get('assets', [])
            download_url = ''
            file_size = 0
            
            for asset in assets:
                if asset.get('name', '').endswith('.tar.gz'):
                    download_url = asset.get('browser_download_url', '')
                    file_size = asset.get('size', 0)
                    break
            
            update_info = UpdateInfo(
                current_version=self.current_version,
                latest_version=latest_version,
                release_date=release_data.get('published_at', ''),
                channel=self.channel,
                changelog=release_data.get('body', 'No changelog available'),
                download_url=download_url,
                file_size=file_size,
                sha256_checksum='',
                is_critical=release_data.get('prerelease', False) is False,
                breaking_changes=self._extract_breaking_changes(release_data.get('body', '')),
            )
            
            self.last_check_result = update_info
            self.update_status = UpdateStatus.UPDATE_AVAILABLE
            
            return UpdateStatus.UPDATE_AVAILABLE, update_info
            
        except HTTPError as e:
            self.update_status = UpdateStatus.CHECK_FAILED
            return UpdateStatus.CHECK_FAILED, None
        except URLError as e:
            self.update_status = UpdateStatus.CHECK_FAILED
            return UpdateStatus.CHECK_FAILED, None
        except Exception as e:
            self.update_status = UpdateStatus.CHECK_FAILED
            return UpdateStatus.CHECK_FAILED, None
    
    def download_update(self, update_info: UpdateInfo, output_dir: Optional[str] = None) -> Optional[str]:
        """
        Download an available update.
        
        Args:
            update_info: Update information
            output_dir: Output directory for download
            
        Returns:
            Path to downloaded file or None
        """
        if not update_info.download_url:
            return None
        
        if output_dir is None:
            output_dir = tempfile.gettempdir()
        
        filename = f"wolfstrike-{update_info.latest_version}.tar.gz"
        filepath = os.path.join(output_dir, filename)
        
        try:
            self.update_status = UpdateStatus.UPDATE_IN_PROGRESS
            
            request = Request(
                update_info.download_url,
                headers={'User-Agent': 'WOLFSTRIKE-Downloader/1.0'}
            )
            
            with urlopen(request, timeout=300) as response:
                with open(filepath, 'wb') as f:
                    total_size = update_info.file_size
                    downloaded = 0
                    
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            
                            if int(progress) % 10 == 0:
                                pass
            
            if self._verify_checksum(filepath, update_info.sha256_checksum):
                self.update_status = UpdateStatus.UPDATE_COMPLETE
                return filepath
            else:
                os.remove(filepath)
                self.update_status = UpdateStatus.UPDATE_FAILED
                return None
                
        except Exception as e:
            self.update_status = UpdateStatus.UPDATE_FAILED
            if os.path.exists(filepath):
                os.remove(filepath)
            return None
    
    def _verify_checksum(self, filepath: str, expected_checksum: str) -> bool:
        """
        Verify file checksum.
        
        Args:
            filepath: Path to file
            expected_checksum: Expected SHA256 checksum
            
        Returns:
            True if checksum matches
        """
        if not expected_checksum:
            return True
        
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            actual_checksum = sha256_hash.hexdigest()
            return actual_checksum == expected_checksum
        except Exception:
            return False
    
    def apply_update(self, archive_path: str, backup: bool = True) -> bool:
        """
        Apply a downloaded update.
        
        Args:
            archive_path: Path to update archive
            backup: Whether to create backup before update
            
        Returns:
            True if update applied successfully
        """
        try:
            if backup:
                self._create_backup()
            
            import tarfile
            
            extract_dir = tempfile.mkdtemp(prefix='wolfstrike_update_')
            
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(path=extract_dir)
            
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            for item in os.listdir(extract_dir):
                source = os.path.join(extract_dir, item)
                destination = os.path.join(current_dir, item)
                
                if os.path.isdir(source):
                    if os.path.exists(destination):
                        shutil.rmtree(destination)
                    shutil.copytree(source, destination)
                else:
                    shutil.copy2(source, destination)
            
            shutil.rmtree(extract_dir)
            
            if os.path.exists(archive_path):
                os.remove(archive_path)
            
            return True
            
        except Exception:
            return False
    
    def _create_backup(self) -> Optional[str]:
        """
        Create a backup of current installation.
        
        Returns:
            Path to backup or None
        """
        try:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            backup_name = f"wolfstrike_backup_{self.current_version}_{int(time.time())}"
            backup_path = os.path.join(self.BACKUP_DIR, backup_name)
            
            os.makedirs(self.BACKUP_DIR, exist_ok=True)
            
            shutil.make_archive(backup_path, 'gztar', current_dir)
            
            return backup_path + '.tar.gz'
        except Exception:
            return None
    
    def restore_backup(self, backup_path: str) -> bool:
        """
        Restore from a backup.
        
        Args:
            backup_path: Path to backup archive
            
        Returns:
            True if restored successfully
        """
        try:
            import tarfile
            
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall(path=current_dir)
            
            return True
        except Exception:
            return False
    
    def _compare_versions(self, version_a: str, version_b: str) -> int:
        """
        Compare two version strings.
        
        Args:
            version_a: First version
            version_b: Second version
            
        Returns:
            1 if a > b, -1 if a < b, 0 if equal
        """
        try:
            parts_a = [int(x) for x in version_a.split('.')]
            parts_b = [int(x) for x in version_b.split('.')]
            
            max_length = max(len(parts_a), len(parts_b))
            parts_a.extend([0] * (max_length - len(parts_a)))
            parts_b.extend([0] * (max_length - len(parts_b)))
            
            for a, b in zip(parts_a, parts_b):
                if a > b:
                    return 1
                elif a < b:
                    return -1
            
            return 0
        except ValueError:
            if version_a > version_b:
                return 1
            elif version_a < version_b:
                return -1
            return 0
    
    def _extract_breaking_changes(self, changelog: str) -> List[str]:
        """
        Extract breaking changes from changelog.
        
        Args:
            changelog: Changelog text
            
        Returns:
            List of breaking change descriptions
        """
        breaking_changes = []
        
        for line in changelog.split('\n'):
            line = line.strip().lower()
            if 'breaking' in line or 'deprecated' in line or 'removed' in line:
                breaking_changes.append(line)
        
        return breaking_changes
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current update status.
        
        Returns:
            Dictionary with status information
        """
        return {
            'current_version': self.current_version,
            'channel': self.channel.value,
            'status': self.update_status.value,
            'last_check': datetime.fromtimestamp(self.last_check_time).isoformat() if self.last_check_time else None,
            'update_available': self.update_status == UpdateStatus.UPDATE_AVAILABLE,
            'latest_version': self.last_check_result.latest_version if self.last_check_result else None,
        }
    
    def should_check(self, check_interval: int = 86400) -> bool:
        """
        Check if enough time has passed since last check.
        
        Args:
            check_interval: Minimum interval in seconds
            
        Returns:
            True if should check for updates
        """
        if self.last_check_time is None:
            return True
        
        return (time.time() - self.last_check_time) >= check_interval