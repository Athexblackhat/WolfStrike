# integrations/slack_notify.py

"""
Slack Notification Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Sends scan notifications and vulnerability alerts
to Slack channels via webhook integration.
"""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class NotificationPriority:
    """Notification priority levels for Slack messages."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SlackMessage:
    """Represents a Slack message to be sent."""
    title: str
    text: str
    priority: str = NotificationPriority.INFO
    fields: List[Dict[str, str]] = field(default_factory=list)
    color: str = "#36a64f"
    footer: str = "WOLFSTRIKE by Wolf Intelligence PK"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SlackNotifier:
    """
    Slack notification integration for WOLFSTRIKE.
    
    Sends formatted messages to Slack channels
    for scan status, vulnerability alerts, and reports.
    """
    
    PRIORITY_COLORS = {
        NotificationPriority.CRITICAL: "#ff0000",
        NotificationPriority.HIGH: "#ff6600",
        NotificationPriority.MEDIUM: "#ffcc00",
        NotificationPriority.LOW: "#36a64f",
        NotificationPriority.INFO: "#439FE0",
    }
    
    def __init__(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "WOLFSTRIKE",
        icon_emoji: str = ":wolf:",
        enabled: bool = True
    ):
        """
        Initialize the Slack notifier.
        
        Args:
            webhook_url: Slack webhook URL
            channel: Target channel (optional, overrides webhook default)
            username: Bot display name
            icon_emoji: Bot icon emoji
            enabled: Whether notifications are enabled
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.enabled = enabled and bool(webhook_url)
        self.rate_limit_delay = 1.0
        self.last_send_time = 0.0
    
    def send_notification(
        self,
        title: str,
        message: str,
        priority: str = NotificationPriority.INFO,
        fields: Optional[List[Dict[str, str]]] = None,
        include_timestamp: bool = True
    ) -> bool:
        """
        Send a notification to Slack.
        
        Args:
            title: Notification title
            message: Notification message text
            priority: Notification priority level
            fields: Additional fields for the message attachment
            include_timestamp: Whether to include timestamp
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            return False
        
        current_time = time.time()
        if current_time - self.last_send_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_send_time))
        
        color = self.PRIORITY_COLORS.get(priority, self.PRIORITY_COLORS[NotificationPriority.INFO])
        
        slack_message = SlackMessage(
            title=title,
            text=message,
            priority=priority,
            fields=fields or [],
            color=color,
        )
        
        payload = self._build_payload(slack_message)
        
        try:
            data = json.dumps(payload).encode('utf-8')
            
            request = Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urlopen(request, timeout=10) as response:
                response_text = response.read().decode('utf-8')
                
                if response.status == 200 and response_text == 'ok':
                    self.last_send_time = time.time()
                    return True
                else:
                    return False
                    
        except HTTPError as e:
            return False
        except URLError as e:
            return False
        except Exception:
            return False
    
    def _build_payload(self, message: SlackMessage) -> Dict[str, Any]:
        """
        Build Slack message payload.
        
        Args:
            message: SlackMessage object
            
        Returns:
            Dictionary payload for Slack API
        """
        payload = {
            'username': self.username,
            'icon_emoji': self.icon_emoji,
            'attachments': [
                {
                    'fallback': f"{message.title}: {message.text}",
                    'color': message.color,
                    'title': message.title,
                    'text': message.text,
                    'fields': message.fields,
                    'footer': message.footer,
                    'ts': int(time.time()),
                }
            ]
        }
        
        if self.channel:
            payload['channel'] = self.channel
        
        return payload
    
    def send_scan_started(self, target: str, mode: str) -> bool:
        """
        Send scan started notification.
        
        Args:
            target: Scan target
            mode: Scan mode
            
        Returns:
            True if sent successfully
        """
        return self.send_notification(
            title="Scan Started",
            message=f"WOLFSTRIKE scan initiated on target: `{target}`",
            priority=NotificationPriority.INFO,
            fields=[
                {'title': 'Target', 'value': target, 'short': True},
                {'title': 'Mode', 'value': mode, 'short': True},
                {'title': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'short': True},
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
        priority = NotificationPriority.HIGH if vulnerabilities > 0 else NotificationPriority.INFO
        
        return self.send_notification(
            title="Scan Completed",
            message=f"WOLFSTRIKE scan completed on target: `{target}`",
            priority=priority,
            fields=[
                {'title': 'Target', 'value': target, 'short': True},
                {'title': 'Duration', 'value': f'{duration:.2f}s', 'short': True},
                {'title': 'Vulnerabilities', 'value': str(vulnerabilities), 'short': True},
                {'title': 'Errors', 'value': str(errors), 'short': True},
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
        priority_map = {
            'critical': NotificationPriority.CRITICAL,
            'high': NotificationPriority.HIGH,
            'medium': NotificationPriority.MEDIUM,
            'low': NotificationPriority.LOW,
        }
        
        priority = priority_map.get(severity, NotificationPriority.INFO)
        
        return self.send_notification(
            title=f"Vulnerability Found: {vuln_type.upper()}",
            message=description,
            priority=priority,
            fields=[
                {'title': 'Target', 'value': target, 'short': True},
                {'title': 'Severity', 'value': severity.upper(), 'short': True},
                {'title': 'Type', 'value': vuln_type, 'short': True},
                {'title': 'Endpoint', 'value': endpoint, 'short': True},
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
            {'title': 'Target', 'value': target, 'short': True},
            {'title': 'Error', 'value': error_message[:200], 'short': False},
        ]
        
        if module:
            fields.insert(0, {'title': 'Module', 'value': module, 'short': True})
        
        return self.send_notification(
            title="Scan Error",
            message=f"An error occurred during scan of `{target}`",
            priority=NotificationPriority.HIGH,
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
        return self.send_notification(
            title="Report Generated",
            message=f"Scan report for `{target}` is ready",
            priority=NotificationPriority.INFO,
            fields=[
                {'title': 'Target', 'value': target, 'short': True},
                {'title': 'Format', 'value': report_format.upper(), 'short': True},
                {'title': 'Path', 'value': report_path, 'short': False},
            ]
        )
    
    def test_connection(self) -> bool:
        """
        Test the Slack webhook connection.
        
        Returns:
            True if connection successful
        """
        return self.send_notification(
            title="Connection Test",
            message="WOLFSTRIKE Slack integration test message",
            priority=NotificationPriority.INFO
        )