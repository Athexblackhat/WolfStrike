# integrations/ci_cd.py

"""
CI/CD Pipeline Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Integrates WOLFSTRIKE into CI/CD pipelines for automated
security testing during build and deployment processes.
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum


class ExitCode(Enum):
    """Exit codes for CI/CD pipeline integration."""
    SUCCESS = 0
    VULNERABILITIES_FOUND = 1
    CRITICAL_FOUND = 2
    SCAN_FAILED = 3
    CONFIGURATION_ERROR = 4


class FailureCriteria(Enum):
    """Criteria for pipeline failure."""
    ANY_VULNERABILITY = "any"
    CRITICAL_ONLY = "critical"
    HIGH_AND_ABOVE = "high"
    MEDIUM_AND_ABOVE = "medium"
    CUSTOM_THRESHOLD = "custom"


class CICDIntegration:
    """
    CI/CD pipeline integration for WOLFSTRIKE.
    
    Enables automated security scanning in CI/CD pipelines
    with configurable failure criteria and exit codes.
    """
    
    def __init__(
        self,
        target: str,
        failure_criteria: FailureCriteria = FailureCriteria.HIGH_AND_ABOVE,
        max_critical: int = 0,
        max_high: int = 5,
        max_medium: int = 10,
        max_total: int = 50,
        fail_on_error: bool = True,
        output_format: str = "json",
        output_file: Optional[str] = None,
    ):
        """
        Initialize CI/CD integration.
        
        Args:
            target: Scan target
            failure_criteria: When to fail the pipeline
            max_critical: Maximum allowed critical vulnerabilities
            max_high: Maximum allowed high vulnerabilities
            max_medium: Maximum allowed medium vulnerabilities
            max_total: Maximum allowed total vulnerabilities
            fail_on_error: Whether to fail on scan errors
            output_format: Output format for results
            output_file: File to write results
        """
        self.target = target
        self.failure_criteria = failure_criteria
        self.max_critical = max_critical
        self.max_high = max_high
        self.max_medium = max_medium
        self.max_total = max_total
        self.fail_on_error = fail_on_error
        self.output_format = output_format
        self.output_file = output_file
        
        self.scan_start_time = 0.0
        self.scan_end_time = 0.0
        self.results: Dict[str, Any] = {}
    
    def run_scan(self, scan_function: Callable) -> int:
        """
        Run a security scan and evaluate results.
        
        Args:
            scan_function: Function that executes the scan
            
        Returns:
            Exit code for CI/CD pipeline
        """
        print(f"[WOLFSTRIKE CI/CD] Starting security scan on {self.target}")
        print(f"[WOLFSTRIKE CI/CD] Failure criteria: {self.failure_criteria.value}")
        
        self.scan_start_time = time.time()
        
        try:
            scan_result = scan_function(self.target)
            self.scan_end_time = time.time()
            self.results = scan_result if isinstance(scan_result, dict) else {}
            
        except Exception as e:
            print(f"[WOLFSTRIKE CI/CD] Scan failed with error: {str(e)}")
            self.scan_end_time = time.time()
            
            if self.fail_on_error:
                self._write_output({'error': str(e), 'status': 'failed'})
                return ExitCode.SCAN_FAILED.value
            else:
                self._write_output({'error': str(e), 'status': 'completed_with_errors'})
                return ExitCode.SUCCESS.value
        
        exit_code = self._evaluate_results()
        
        self._write_output(self.results)
        self._print_summary(exit_code)
        
        return exit_code
    
    def _evaluate_results(self) -> int:
        """
        Evaluate scan results against failure criteria.
        
        Returns:
            Exit code based on evaluation
        """
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        critical_count = sum(
            1 for v in vulnerabilities
            if v.get('severity') == 'critical' and not v.get('is_false_positive', False)
        )
        high_count = sum(
            1 for v in vulnerabilities
            if v.get('severity') == 'high' and not v.get('is_false_positive', False)
        )
        medium_count = sum(
            1 for v in vulnerabilities
            if v.get('severity') == 'medium' and not v.get('is_false_positive', False)
        )
        low_count = sum(
            1 for v in vulnerabilities
            if v.get('severity') == 'low' and not v.get('is_false_positive', False)
        )
        total_count = len(vulnerabilities)
        
        self.results['counts'] = {
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'total': total_count,
        }
        
        if critical_count > self.max_critical:
            self.results['failure_reason'] = f"Critical vulnerabilities ({critical_count}) exceed maximum ({self.max_critical})"
            return ExitCode.CRITICAL_FOUND.value
        
        if self.failure_criteria == FailureCriteria.ANY_VULNERABILITY and total_count > 0:
            self.results['failure_reason'] = f"Vulnerabilities found ({total_count})"
            return ExitCode.VULNERABILITIES_FOUND.value
        
        if self.failure_criteria == FailureCriteria.CRITICAL_ONLY and critical_count > 0:
            self.results['failure_reason'] = f"Critical vulnerabilities found ({critical_count})"
            return ExitCode.CRITICAL_FOUND.value
        
        if self.failure_criteria == FailureCriteria.HIGH_AND_ABOVE:
            if high_count > self.max_high:
                self.results['failure_reason'] = f"High vulnerabilities ({high_count}) exceed maximum ({self.max_high})"
                return ExitCode.VULNERABILITIES_FOUND.value
        
        if self.failure_criteria == FailureCriteria.MEDIUM_AND_ABOVE:
            if medium_count > self.max_medium:
                self.results['failure_reason'] = f"Medium vulnerabilities ({medium_count}) exceed maximum ({self.max_medium})"
                return ExitCode.VULNERABILITIES_FOUND.value
        
        if total_count > self.max_total:
            self.results['failure_reason'] = f"Total vulnerabilities ({total_count}) exceed maximum ({self.max_total})"
            return ExitCode.VULNERABILITIES_FOUND.value
        
        return ExitCode.SUCCESS.value
    
    def _write_output(self, data: Dict[str, Any]) -> None:
        """
        Write scan results to output file or stdout.
        
        Args:
            data: Results data to write
        """
        output_data = {
            'tool': 'WOLFSTRIKE',
            'version': '1.0.0',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'duration': self.scan_end_time - self.scan_start_time,
            'failure_criteria': self.failure_criteria.value,
            'results': data,
        }
        
        if self.output_format == 'json':
            formatted_output = json.dumps(output_data, indent=2)
        else:
            formatted_output = str(output_data)
        
        if self.output_file:
            output_dir = os.path.dirname(self.output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(self.output_file, 'w') as f:
                f.write(formatted_output)
            
            print(f"[WOLFSTRIKE CI/CD] Results written to: {self.output_file}")
        else:
            print(formatted_output)
    
    def _print_summary(self, exit_code: int) -> None:
        """
        Print scan summary to console.
        
        Args:
            exit_code: Pipeline exit code
        """
        counts = self.results.get('counts', {})
        duration = self.scan_end_time - self.scan_start_time
        
        print("\n" + "=" * 60)
        print("  WOLFSTRIKE CI/CD SCAN SUMMARY")
        print("=" * 60)
        print(f"  Target:           {self.target}")
        print(f"  Duration:         {duration:.2f}s")
        print(f"  Failure Criteria: {self.failure_criteria.value}")
        print("-" * 60)
        print(f"  Critical:  {counts.get('critical', 0)}")
        print(f"  High:      {counts.get('high', 0)}")
        print(f"  Medium:    {counts.get('medium', 0)}")
        print(f"  Low:       {counts.get('low', 0)}")
        print(f"  Total:     {counts.get('total', 0)}")
        print("-" * 60)
        
        if exit_code == ExitCode.SUCCESS.value:
            print("  Status: PASSED")
        elif exit_code == ExitCode.VULNERABILITIES_FOUND.value:
            print("  Status: FAILED - Vulnerabilities exceed threshold")
        elif exit_code == ExitCode.CRITICAL_FOUND.value:
            print("  Status: FAILED - Critical vulnerabilities found")
        elif exit_code == ExitCode.SCAN_FAILED.value:
            print("  Status: FAILED - Scan execution error")
        else:
            print(f"  Status: EXIT CODE {exit_code}")
        
        print("=" * 60 + "\n")
    
    @staticmethod
    def generate_gitlab_report(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate GitLab-compatible SAST report.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            GitLab SAST report dictionary
        """
        report = {
            'schema': 'https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.0.0/sast-report-format.json',
            'version': '15.0.0',
            'vulnerabilities': [],
        }
        
        for vuln in vulnerabilities:
            severity_map = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'info': 'Info',
            }
            
            report['vulnerabilities'].append({
                'id': vuln.get('id', ''),
                'category': 'sast',
                'name': vuln.get('type', 'Unknown'),
                'message': vuln.get('description', ''),
                'description': vuln.get('description', ''),
                'severity': severity_map.get(vuln.get('severity', 'info'), 'Info'),
                'confidence': vuln.get('confidence', 'Unknown'),
                'scanner': {
                    'id': 'wolfstrike',
                    'name': 'WOLFSTRIKE',
                },
                'location': {
                    'file': vuln.get('endpoint', ''),
                    'start_line': 1,
                },
                'identifiers': [
                    {
                        'type': 'wolfstrike_id',
                        'name': vuln.get('type', 'Unknown'),
                        'value': vuln.get('id', ''),
                    }
                ],
            })
        
        return report
    
    @staticmethod
    def generate_github_annotation(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate GitHub Actions annotation format.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of annotation dictionaries
        """
        annotations = []
        
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'warning',
            'info': 'notice',
        }
        
        for vuln in vulnerabilities:
            annotations.append({
                'annotation_level': severity_map.get(vuln.get('severity', 'info'), 'notice'),
                'title': f"{vuln.get('type', 'Unknown').upper()} - {vuln.get('severity', 'N/A').upper()}",
                'message': vuln.get('description', 'No description'),
                'raw_details': json.dumps(vuln),
            })
        
        return annotations
    
    @staticmethod
    def parse_environment() -> Dict[str, Any]:
        """
        Parse CI/CD environment variables for auto-configuration.
        
        Returns:
            Dictionary of detected CI/CD environment settings
        """
        env_info = {
            'ci_platform': 'local',
            'branch': None,
            'commit': None,
            'job_id': None,
        }
        
        if os.environ.get('GITLAB_CI'):
            env_info['ci_platform'] = 'gitlab'
            env_info['branch'] = os.environ.get('CI_COMMIT_BRANCH')
            env_info['commit'] = os.environ.get('CI_COMMIT_SHA')
            env_info['job_id'] = os.environ.get('CI_JOB_ID')
        elif os.environ.get('GITHUB_ACTIONS'):
            env_info['ci_platform'] = 'github'
            env_info['branch'] = os.environ.get('GITHUB_REF_NAME')
            env_info['commit'] = os.environ.get('GITHUB_SHA')
            env_info['job_id'] = os.environ.get('GITHUB_RUN_ID')
        elif os.environ.get('JENKINS_HOME'):
            env_info['ci_platform'] = 'jenkins'
            env_info['branch'] = os.environ.get('GIT_BRANCH')
            env_info['commit'] = os.environ.get('GIT_COMMIT')
            env_info['job_id'] = os.environ.get('BUILD_NUMBER')
        elif os.environ.get('AZURE_HTTP_USER_AGENT'):
            env_info['ci_platform'] = 'azure'
            env_info['branch'] = os.environ.get('BUILD_SOURCEBRANCH')
            env_info['commit'] = os.environ.get('BUILD_SOURCEVERSION')
            env_info['job_id'] = os.environ.get('BUILD_BUILDID')
        
        return env_info