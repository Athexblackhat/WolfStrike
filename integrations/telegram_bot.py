# integrations/telegram_bot.py

"""
Telegram Bot Notification Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Sends scan notifications and vulnerability alerts
to Telegram chats via Bot API integration.
"""

import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode


class TelegramNotifier:
    """
    Telegram notification integration for WOLFSTRIKE.
    
    Sends formatted messages to Telegram chats
    using the Telegram Bot API.
    """
    
    API_BASE_URL = "https://api.telegram.org/bot"
    
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        enabled: bool = True
    ):
        """
        Initialize the Telegram notifier.
        
        Args:
            bot_token: Telegram Bot API token
            chat_id: Target chat ID
            enabled: Whether notifications are enabled
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled and bool(bot_token) and bool(chat_id)
        self.rate_limit_delay = 1.0
        self.last_send_time = 0.0
    
    def _make_request(self, method: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Make a request to Telegram Bot API.
        
        Args:
            method: API method name
            data: Request data dictionary
            
        Returns:
            Response dictionary or None
        """
        if not self.enabled:
            return None
        
        url = f"{self.API_BASE_URL}{self.bot_token}/{method}"
        
        try:
            encoded_data = urlencode(data).encode('utf-8')
            
            request = Request(
                url,
                data=encoded_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            with urlopen(request, timeout=10) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                if response_data.get('ok'):
                    return response_data.get('result')
                else:
                    return None
                    
        except HTTPError as e:
            return None
        except URLError as e:
            return None
        except Exception:
            return None
    
    def send_message(
        self,
        text: str,
        parse_mode: str = "HTML",
        disable_notification: bool = False
    ) -> bool:
        """
        Send a text message to Telegram.
        
        Args:
            text: Message text (supports HTML formatting)
            parse_mode: Parse mode (HTML or Markdown)
            disable_notification: Whether to mute notification
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            return False
        
        current_time = time.time()
        if current_time - self.last_send_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_send_time))
        
        data = {
            'chat_id': self.chat_id,
            'text': text,
            'parse_mode': parse_mode,
            'disable_notification': disable_notification,
        }
        
        result = self._make_request('sendMessage', data)
        
        if result is not None:
            self.last_send_time = time.time()
            return True
        
        return False
    
    def _format_vulnerability_message(
        self,
        target: str,
        vuln_type: str,
        severity: str,
        endpoint: str,
        description: str
    ) -> str:
        """
        Format a vulnerability alert message.
        
        Args:
            target: Scan target
            vuln_type: Vulnerability type
            severity: Vulnerability severity
            endpoint: Affected endpoint
            description: Vulnerability description
            
        Returns:
            Formatted HTML message string
        """
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵',
        }
        
        emoji = severity_emoji.get(severity, '⚪')
        
        message = f"""
{emoji} <b>VULNERABILITY FOUND</b> {emoji}

<b>Target:</b> <code>{target}</code>
<b>Type:</b> {vuln_type.upper()}
<b>Severity:</b> {severity.upper()}
<b>Endpoint:</b> <code>{endpoint}</code>

<b>Description:</b>
{description}

<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Tool:</b> WOLFSTRIKE by Wolf Intelligence PK
        """
        
        return message.strip()
    
    def _format_scan_message(
        self,
        target: str,
        status: str,
        vulnerabilities: int,
        errors: int,
        duration: Optional[float] = None
    ) -> str:
        """
        Format a scan status message.
        
        Args:
            target: Scan target
            status: Scan status
            vulnerabilities: Number of vulnerabilities
            errors: Number of errors
            duration: Scan duration
            
        Returns:
            Formatted HTML message string
        """
        status_emoji = {
            'started': '🚀',
            'completed': '✅',
            'failed': '❌',
            'cancelled': '⏹️',
        }
        
        emoji = status_emoji.get(status, '📡')
        
        message = f"""
{emoji} <b>SCAN {status.upper()}</b> {emoji}

<b>Target:</b> <code>{target}</code>
<b>Status:</b> {status.capitalize()}
        """
        
        if vulnerabilities > 0:
            message += f"\n<b>Vulnerabilities:</b> {vulnerabilities}"
        
        if errors > 0:
            message += f"\n<b>Errors:</b> {errors}"
        
        if duration:
            message += f"\n<b>Duration:</b> {duration:.2f}s"
        
        message += f"""
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Tool:</b> WOLFSTRIKE by Wolf Intelligence PK
        """
        
        return message.strip()
    
    def send_scan_started(self, target: str, mode: str) -> bool:
        """
        Send scan started notification.
        
        Args:
            target: Scan target
            mode: Scan mode
            
        Returns:
            True if sent successfully
        """
        text = self._format_scan_message(target, 'started', 0, 0)
        text += f"\n<b>Mode:</b> {mode}"
        
        return self.send_message(text)
    
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
        status = 'completed'
        if errors > 10:
            status = 'failed'
        
        text = self._format_scan_message(target, status, vulnerabilities, errors, duration)
        
        disable_notification = vulnerabilities == 0 and errors == 0
        
        return self.send_message(text, disable_notification=disable_notification)
    
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
        text = self._format_vulnerability_message(
            target, vuln_type, severity, endpoint, description
        )
        
        disable_notification = severity in ['low', 'info']
        
        return self.send_message(text, disable_notification=disable_notification)
    
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
        module_text = f"\n<b>Module:</b> {module}" if module else ""
        
        text = f"""
⚠️ <b>SCAN ERROR</b> ⚠️

<b>Target:</b> <code>{target}</code>{module_text}
<b>Error:</b> {error_message[:300]}

<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Tool:</b> WOLFSTRIKE by Wolf Intelligence PK
        """
        
        return self.send_message(text.strip())
    
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
        text = f"""
📊 <b>REPORT GENERATED</b> 📊

<b>Target:</b> <code>{target}</code>
<b>Format:</b> {report_format.upper()}
<b>Path:</b> <code>{report_path}</code>

<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Tool:</b> WOLFSTRIKE by Wolf Intelligence PK
        """
        
        return self.send_message(text.strip())
    
    def test_connection(self) -> bool:
        """
        Test the Telegram Bot API connection.
        
        Returns:
            True if connection successful
        """
        return self.send_message(
            "<b>Connection Test</b>\nWOLFSTRIKE Telegram integration test message"
        )