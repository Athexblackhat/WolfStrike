# integrations/discord_webhook.py

"""
Discord Webhook Notification Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Sends scan notifications and vulnerability alerts
to Discord channels via webhook integration.
"""

import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class DiscordNotifier:
    """
    Discord notification integration for WOLFSTRIKE.
    
    Sends formatted messages to Discord channels
    using webhook integration with embed support.
    """
    
    SEVERITY_COLORS = {
        'critical': 0xFF0000,
        'high': 0xFF6600,
        'medium': 0xFFCC00,
        'low': 0x00FF00,
        'info': 0x439FE0,
    }
    
    def __init__(
        self,
        webhook_url: str,
        username: str = "WOLFSTRIKE",
        avatar_url: Optional[str] = None,
        enabled: bool = True
    ):
        """
        Initialize the Discord notifier.
        
        Args:
            webhook_url: Discord webhook URL
            username: Bot display name
            avatar_url: Bot avatar URL
            enabled: Whether notifications are enabled
        """
        self.webhook_url = webhook_url
        self.username = username
        self.avatar_url = avatar_url
        self.enabled = enabled and bool(webhook_url)
        self.rate_limit_delay = 1.0
        self.last_send_time = 0.0
    
    def send_embed(
        self,
        title: str,
        description: str,
        color: int = 0x439FE0,
        fields: Optional[List[Dict[str, Any]]] = None,
        footer: str = "WOLFSTRIKE by Wolf Intelligence PK",
        include_timestamp: bool = True
    ) -> bool:
        """
        Send an embed message to Discord.
        
        Args:
            title: Embed title
            description: Embed description
            color: Embed color (integer)
            fields: List of field dictionaries
            footer: Footer text
            include_timestamp: Whether to include timestamp
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            return False
        
        current_time = time.time()
        if current_time - self.last_send_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_send_time))
        
        embed = {
            'title': title,
            'description': description,
            'color': color,
        }
        
        if fields:
            embed['fields'] = fields
        
        if footer:
            embed['footer'] = {'text': footer}
        
        if include_timestamp:
            embed['timestamp'] = datetime.utcnow().isoformat()
        
        payload = {
            'username': self.username,
            'embeds': [embed],
        }
        
        if self.avatar_url:
            payload['avatar_url'] = self.avatar_url
        
        try:
            data = json.dumps(payload).encode('utf-8')
            
            request = Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urlopen(request, timeout=10) as response:
                if response.status in [200, 204]:
                    self.last_send_time = time.time()
                    return True
                return False
                
        except HTTPError:
            return False
        except URLError:
            return False
        except Exception:
            return False
    
    def send_scan_started(self, target: str, mode: str) -> bool:
        """
        Send scan started notification.
        
        Args:
            target: Scan target
            mode: Scan mode
            
        Returns:
            True if sent successfully
        """
        return self.send_embed(
            title="Scan Started",
            description=f"WOLFSTRIKE scan initiated on target: `{target}`",
            color=self.SEVERITY_COLORS['info'],
            fields=[
                {'name': 'Target', 'value': target, 'inline': True},
                {'name': 'Mode', 'value': mode, 'inline': True},
                {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': True},
            ]
        )
    
    def send_scan_completed(
        self,
        target: str,
        vulnerabilities: int,
        errors: int,
        duration: float
    ) -> bool:
        """
        Send scan completed notification.
        
        Args:
            target: Scan target
            vulnerabilities: Number of vulnerabilities found
            errors: Number of errors encountered
            duration: Scan duration in seconds
            
        Returns:
            True if sent successfully
        """
        color = self.SEVERITY_COLORS['high'] if vulnerabilities > 0 else self.SEVERITY_COLORS['info']
        
        return self.send_embed(
            title="Scan Completed",
            description=f"WOLFSTRIKE scan completed on target: `{target}`",
            color=color,
            fields=[
                {'name': 'Target', 'value': target, 'inline': True},
                {'name': 'Duration', 'value': f'{duration:.2f}s', 'inline': True},
                {'name': 'Vulnerabilities', 'value': str(vulnerabilities), 'inline': True},
                {'name': 'Errors', 'value': str(errors), 'inline': True},
            ]
        )
    
    def send_vulnerability_alert(
        self,
        target: str,
        vuln_type: str,
        severity: str,
        endpoint: str,
        description: str
    ) -> bool:
        """
        Send vulnerability alert notification.
        
        Args:
            target: Scan target
            vuln_type: Vulnerability type
            severity: Vulnerability severity
            endpoint: Affected endpoint
            description: Vulnerability description
            
        Returns:
            True if sent successfully
        """
        color = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS['info'])
        
        return self.send_embed(
            title=f"Vulnerability Found: {vuln_type.upper()}",
            description=description,
            color=color,
            fields=[
                {'name': 'Target', 'value': target, 'inline': True},
                {'name': 'Severity', 'value': severity.upper(), 'inline': True},
                {'name': 'Type', 'value': vuln_type, 'inline': True},
                {'name': 'Endpoint', 'value': endpoint, 'inline': False},
            ]
        )
    
    def send_error_alert(
        self,
        target: str,
        error_message: str,
        module: Optional[str] = None
    ) -> bool:
        """
        Send error alert notification.
        
        Args:
            target: Scan target
            error_message: Error message
            module: Module that generated the error
            
        Returns:
            True if sent successfully
        """
        fields = [
            {'name': 'Target', 'value': target, 'inline': True},
            {'name': 'Error', 'value': error_message[:200], 'inline': False},
        ]
        
        if module:
            fields.insert(0, {'name': 'Module', 'value': module, 'inline': True})
        
        return self.send_embed(
            title="Scan Error",
            description=f"An error occurred during scan of `{target}`",
            color=0xFF0000,
            fields=fields
        )
    
    def send_report_ready(
        self,
        target: str,
        report_path: str,
        report_format: str
    ) -> bool:
        """
        Send report ready notification.
        
        Args:
            target: Scan target
            report_path: Path to report file
            report_format: Report format
            
        Returns:
            True if sent successfully
        """
        return self.send_embed(
            title="Report Generated",
            description=f"Scan report for `{target}` is ready",
            color=self.SEVERITY_COLORS['info'],
            fields=[
                {'name': 'Target', 'value': target, 'inline': True},
                {'name': 'Format', 'value': report_format.upper(), 'inline': True},
                {'name': 'Path', 'value': report_path, 'inline': False},
            ]
        )
    
    def test_connection(self) -> bool:
        """
        Test the Discord webhook connection.
        
        Returns:
            True if connection successful
        """
        return self.send_embed(
            title="Connection Test",
            description="WOLFSTRIKE Discord integration test message",
            color=0x439FE0
        )