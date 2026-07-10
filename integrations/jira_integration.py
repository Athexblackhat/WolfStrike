# integrations/jira_integration.py

"""
JIRA Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Creates JIRA tickets for discovered vulnerabilities
with automatic severity mapping and remediation details.
"""

import json
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class JiraIntegration:
    """
    JIRA integration for WOLFSTRIKE.
    
    Creates and manages JIRA tickets for vulnerability
    tracking and remediation workflow.
    """
    
    PRIORITY_MAP = {
        'critical': 'Highest',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Lowest',
    }
    
    ISSUE_TYPE_MAP = {
        'critical': 'Bug',
        'high': 'Bug',
        'medium': 'Task',
        'low': 'Task',
        'info': 'Story',
    }
    
    def __init__(
        self,
        jira_url: str,
        username: str,
        api_token: str,
        project_key: str,
        enabled: bool = True
    ):
        """
        Initialize the JIRA integration.
        
        Args:
            jira_url: JIRA instance URL
            username: JIRA username/email
            api_token: JIRA API token
            project_key: JIRA project key
            enabled: Whether integration is enabled
        """
        self.jira_url = jira_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        self.enabled = enabled and bool(jira_url) and bool(api_token)
        self.auth_header = self._create_auth_header()
    
    def _create_auth_header(self) -> str:
        """
        Create Basic Auth header value.
        
        Returns:
            Base64 encoded auth string
        """
        credentials = f"{self.username}:{self.api_token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    def _make_request(
        self,
        endpoint: str,
        method: str = 'GET',
        data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Make a request to JIRA REST API.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            data: Request data for POST/PUT
            
        Returns:
            Response dictionary or None
        """
        if not self.enabled:
            return None
        
        url = f"{self.jira_url}/rest/api/2/{endpoint}"
        
        try:
            json_data = json.dumps(data).encode('utf-8') if data else None
            
            request = Request(
                url,
                data=json_data,
                headers={
                    'Authorization': self.auth_header,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                method=method
            )
            
            with urlopen(request, timeout=15) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                return response_data
                
        except HTTPError as e:
            return None
        except URLError:
            return None
        except Exception:
            return None
    
    def create_vulnerability_ticket(
        self,
        target: str,
        vuln_type: str,
        severity: str,
        endpoint: str,
        description: str,
        remediation: str,
        assignee: Optional[str] = None,
        labels: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Create a JIRA ticket for a vulnerability.
        
        Args:
            target: Scan target
            vuln_type: Vulnerability type
            severity: Vulnerability severity
            endpoint: Affected endpoint
            description: Vulnerability description
            remediation: Remediation steps
            assignee: JIRA user to assign
            labels: Ticket labels
            
        Returns:
            Ticket key if created, None otherwise
        """
        if not self.enabled:
            return None
        
        priority = self.PRIORITY_MAP.get(severity, 'Medium')
        issue_type = self.ISSUE_TYPE_MAP.get(severity, 'Task')
        
        summary = f"[{severity.upper()}] {vuln_type.upper()} - {target}"
        
        description_text = f"""
h2. Vulnerability Details

*Target:* {target}
*Type:* {vuln_type.upper()}
*Severity:* {severity.upper()}
*Endpoint:* {endpoint}
*Detected by:* WOLFSTRIKE v1.0.0

h2. Description

{description}

h2. Remediation

{remediation}

h2. Additional Information

*Detection Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
*Tool:* WOLFSTRIKE by Wolf Intelligence PK
*Scanner:* ATHEX BLACK HAT
        """
        
        issue_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description_text.strip(),
                'issuetype': {'name': issue_type},
                'priority': {'name': priority},
            }
        }
        
        if assignee:
            issue_data['fields']['assignee'] = {'name': assignee}
        
        if labels:
            issue_data['fields']['labels'] = labels + ['wolfstrike', 'security', severity]
        else:
            issue_data['fields']['labels'] = ['wolfstrike', 'security', severity]
        
        result = self._make_request('issue', method='POST', data=issue_data)
        
        if result and 'key' in result:
            return result['key']
        
        return None
    
    def create_scan_summary_ticket(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        scan_duration: float
    ) -> Optional[str]:
        """
        Create a summary ticket for a completed scan.
        
        Args:
            target: Scan target
            vulnerabilities: List of vulnerability dictionaries
            scan_duration: Scan duration in seconds
            
        Returns:
            Ticket key if created, None otherwise
        """
        if not self.enabled:
            return None
        
        total = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        
        summary = f"Security Scan Summary - {target}"
        
        description = f"""
h2. Scan Summary

*Target:* {target}
*Scan Duration:* {scan_duration:.2f}s
*Total Vulnerabilities:* {total}

h2. Severity Breakdown

| Severity | Count |
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |

h2. Vulnerability Details

        """
        
        for i, vuln in enumerate(vulnerabilities[:20], 1):
            description += f"""
h3. {i}. {vuln.get('type', 'Unknown').upper()} - {vuln.get('severity', 'N/A').upper()}

*Endpoint:* {vuln.get('endpoint', 'N/A')}
*Description:* {vuln.get('description', 'N/A')[:200]}
            """
        
        if total > 20:
            description += f"\n\n*...and {total - 20} more vulnerabilities*"
        
        description += f"""

h2. Additional Information

*Detection Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
*Tool:* WOLFSTRIKE v1.0.0
*Scanner:* ATHEX BLACK HAT | Wolf Intelligence PK
        """
        
        issue_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description.strip(),
                'issuetype': {'name': 'Task'},
                'priority': {'name': 'High' if critical > 0 else 'Medium'},
                'labels': ['wolfstrike', 'security-scan', 'summary'],
            }
        }
        
        result = self._make_request('issue', method='POST', data=issue_data)
        
        if result and 'key' in result:
            return result['key']
        
        return None
    
    def add_comment(self, issue_key: str, comment: str) -> bool:
        """
        Add a comment to a JIRA ticket.
        
        Args:
            issue_key: JIRA issue key
            comment: Comment text
            
        Returns:
            True if successful
        """
        data = {'body': comment}
        result = self._make_request(f'issue/{issue_key}/comment', method='POST', data=data)
        return result is not None
    
    def transition_issue(self, issue_key: str, transition_id: str) -> bool:
        """
        Transition a JIRA issue to a new status.
        
        Args:
            issue_key: JIRA issue key
            transition_id: Transition ID
            
        Returns:
            True if successful
        """
        data = {'transition': {'id': transition_id}}
        result = self._make_request(
            f'issue/{issue_key}/transitions',
            method='POST',
            data=data
        )
        return result is not None
    
    def get_issue(self, issue_key: str) -> Optional[Dict[str, Any]]:
        """
        Get issue details.
        
        Args:
            issue_key: JIRA issue key
            
        Returns:
            Issue data dictionary or None
        """
        return self._make_request(f'issue/{issue_key}')
    
    def test_connection(self) -> bool:
        """
        Test JIRA connection.
        
        Returns:
            True if connection successful
        """
        result = self._make_request('myself')
        return result is not None and 'name' in result