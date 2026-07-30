# core/engine.py

"""
Main Scanning Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Core scanning engine that orchestrates all modules,
manages scan lifecycle, and coordinates results collection.
"""

import time
import uuid
import traceback
import importlib
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from core.logger import Logger
from core.config import ConfigManager
from core.exceptions import ScanError, ModuleError


class ScanStatus(Enum):
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    STEALTH = "stealth"


@dataclass
class ScanResult:
    scan_id: str
    target: str
    mode: ScanMode
    start_time: float
    end_time: Optional[float] = None
    status: ScanStatus = ScanStatus.INITIALIZED
    modules_executed: List[str] = field(default_factory=list)
    vulnerabilities_found: int = 0
    errors_encountered: int = 0
    total_requests: int = 0
    total_time: float = 0.0
    results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    module_name: str
    success: bool
    findings: List[Dict[str, Any]]
    errors: List[str]
    execution_time: float
    metadata: Dict[str, Any]


class ScanEngine:

    def __init__(
        self,
        target: str,
        config: Dict[str, Any],
        platform_checker: Optional[Any] = None,
        logger: Optional[Logger] = None
    ):
        self.target = target
        self.config = config
        self.platform_checker = platform_checker
        self.logger = logger or Logger(name="ScanEngine")

        self.scan_id = str(uuid.uuid4())[:8]
        self.status = ScanStatus.INITIALIZED
        self.mode = ScanMode.CUSTOM

        self.module_results: Dict[str, ModuleResult] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.total_requests = 0
        self._total_modules = 0
        self._completed_modules = 0
        self._module_cache: Dict[str, Any] = {}

        self.start_time = 0.0
        self.end_time = 0.0

        self._module_registry = self._build_module_registry()
        self.logger.info(f"ScanEngine initialized for target: {target}")

    def _build_module_registry(self) -> Dict[str, str]:
        return {
            'recon': 'modules.recon',
            'scanner': 'modules.scanner',
            'vuln_scanner': 'modules.vuln_scanner',
            'attacks': 'modules.attacks',
            'auth_tester': 'modules.auth_tester',
            'crawler': 'modules.crawler',
            'api_tester': 'modules.api_tester',
            'osint': 'modules.osint',
        }

    def _normalize_finding(self, finding: Any) -> Dict[str, Any]:
        """
        Normalize a finding to a consistent dictionary format.
        
        Args:
            finding: Raw finding from module
            
        Returns:
            Normalized finding dictionary
        """
        if isinstance(finding, dict):
            # Ensure required fields exist
            normalized = finding.copy()
            if 'type' not in normalized:
                normalized['type'] = 'Unknown'
            if 'severity' not in normalized:
                normalized['severity'] = 'info'
            if 'description' not in normalized:
                normalized['description'] = str(finding)
            if 'endpoint' not in normalized:
                normalized['endpoint'] = self.target
            return normalized
        elif isinstance(finding, str):
            return {
                'type': 'Finding',
                'severity': 'info',
                'description': finding,
                'endpoint': self.target,
            }
        else:
            return {
                'type': 'Unknown',
                'severity': 'info',
                'description': str(finding),
                'endpoint': self.target,
            }

    def _validate_module_result(self, result: Any) -> Dict[str, Any]:
        """
        Validate and normalize module result.
        
        Args:
            result: Raw result from module
            
        Returns:
            Validated result dictionary with findings and errors
        """
        if result is None:
            return {'findings': [], 'errors': ['Module returned None']}
        
        if isinstance(result, dict):
            # Ensure findings is a list
            findings = result.get('findings', [])
            if not isinstance(findings, list):
                findings = [findings] if findings else []
            
            # Normalize each finding
            normalized_findings = [self._normalize_finding(f) for f in findings]
            
            # Ensure errors is a list
            errors = result.get('errors', [])
            if not isinstance(errors, list):
                errors = [str(errors)] if errors else []
            
            return {
                'findings': normalized_findings,
                'errors': errors,
            }
        elif isinstance(result, list):
            # List of findings
            return {
                'findings': [self._normalize_finding(f) for f in result],
                'errors': [],
            }
        else:
            # Single result
            return {
                'findings': [self._normalize_finding(result)],
                'errors': [],
            }

    def _check_module_availability(self, module_name: str) -> bool:
        """
        Check if a module is available and importable.
        
        Args:
            module_name: Name of the module
            
        Returns:
            True if module is available
        """
        if module_name not in self._module_registry:
            return False
        
        module_path = self._module_registry[module_name]
        
        try:
            if module_path in self._module_cache:
                return True
            importlib.import_module(module_path)
            return True
        except ImportError:
            return False

    def _update_progress(self, module_name: str, success: bool) -> None:
        """Update progress counters."""
        self._completed_modules += 1
        if not success:
            self._total_modules = max(self._total_modules, self._completed_modules)

    def run_quick_scan(self, modules: Optional[List[str]] = None) -> ScanResult:
        self.mode = ScanMode.QUICK
        self.logger.info("Starting quick scan")
        if modules is None:
            modules = ['recon', 'scanner', 'vuln_scanner']
        return self._execute_scan(modules)

    def run_full_scan(self) -> ScanResult:
        self.mode = ScanMode.FULL
        self.logger.info("Starting full power scan")
        modules = list(self._module_registry.keys())
        self._total_modules = len(modules)
        return self._execute_scan(modules)

    def run_custom_scan(self, modules: List[str]) -> ScanResult:
        self.mode = ScanMode.CUSTOM
        self.logger.info(f"Starting custom scan with modules: {modules}")
        self._total_modules = len(modules)
        return self._execute_scan(modules)

    def run_stealth_scan(self, modules: Optional[List[str]] = None) -> ScanResult:
        self.mode = ScanMode.STEALTH
        self.config['stealth'] = True
        self.logger.info("Starting stealth scan")
        if modules is None:
            modules = ['recon', 'scanner', 'vuln_scanner']
        self._total_modules = len(modules)
        return self._execute_scan(modules)

    def _execute_scan(self, modules: List[str]) -> ScanResult:
        self.status = ScanStatus.RUNNING
        self.start_time = time.time()
        self._completed_modules = 0

        scan_result = ScanResult(
            scan_id=self.scan_id,
            target=self.target,
            mode=self.mode,
            start_time=self.start_time,
            status=ScanStatus.RUNNING,
            metadata={
                'config': {k: v for k, v in self.config.items() if k not in ['api_keys']},
                'platform': str(self.platform_checker) if self.platform_checker else 'unknown',
                'timestamp': datetime.now().isoformat(),
            }
        )

        valid_modules = []
        invalid_modules = []

        for module_name in modules:
            if module_name in self._module_registry:
                if self._check_module_availability(module_name):
                    valid_modules.append(module_name)
                else:
                    invalid_modules.append(f"{module_name} (module not importable)")
            else:
                invalid_modules.append(f"{module_name} (not in registry)")

        if invalid_modules:
            self.logger.warning(f"Invalid modules ignored: {invalid_modules}")

        if not valid_modules:
            raise ScanError(f"No valid modules specified for scan. Invalid: {invalid_modules}")

        self._total_modules = len(valid_modules)

        for module_name in valid_modules:
            try:
                result = self._run_module(module_name)
                self.module_results[module_name] = result
                scan_result.modules_executed.append(module_name)

                if result.findings:
                    self.vulnerabilities.extend(result.findings)

                if result.errors:
                    self.errors.extend(result.errors)

                self._update_progress(module_name, result.success)

            except Exception as e:
                self.logger.error(f"Module {module_name} failed: {str(e)}")
                self.errors.append(f"Module {module_name}: {str(e)}")
                self.module_results[module_name] = ModuleResult(
                    module_name=module_name,
                    success=False,
                    findings=[],
                    errors=[str(e)],
                    execution_time=0.0,
                    metadata={}
                )
                self._update_progress(module_name, False)

        self.status = ScanStatus.COMPLETED
        self.end_time = time.time()

        scan_result.end_time = self.end_time
        scan_result.status = self.status
        scan_result.vulnerabilities_found = len(self.vulnerabilities)
        scan_result.errors_encountered = len(self.errors)
        scan_result.total_requests = self.total_requests
        scan_result.total_time = self.end_time - self.start_time
        scan_result.results = {
            'vulnerabilities': self.vulnerabilities,
            'errors': self.errors,
            'module_results': {
                name: {
                    'success': result.success,
                    'findings_count': len(result.findings),
                    'errors_count': len(result.errors),
                    'execution_time': result.execution_time,
                }
                for name, result in self.module_results.items()
            }
        }

        self.logger.info(
            f"Scan completed: {scan_result.vulnerabilities_found} vulnerabilities, "
            f"{scan_result.errors_encountered} errors, "
            f"{scan_result.total_time:.2f}s"
        )

        return scan_result

    def _run_module(self, module_name: str) -> ModuleResult:
        self.logger.info(f"Executing module: {module_name}")
        start_time = time.time()
        findings = []
        errors = []
        success = True

        try:
            module_path = self._module_registry[module_name]
            
            # Use cached module if available
            if module_path not in self._module_cache:
                self._module_cache[module_path] = importlib.import_module(module_path)
            
            module = self._module_cache[module_path]

            if hasattr(module, 'run'):
                try:
                    result = module.run(
                        target=self.target,
                        config=self.config.get(module_name, {})
                    )
                except TypeError as e:
                    # Handle modules that don't accept config parameter
                    if "unexpected keyword argument" in str(e):
                        result = module.run(target=self.target)
                    else:
                        raise
                
                # Validate and normalize the result
                validated = self._validate_module_result(result)
                findings = validated.get('findings', [])
                errors = validated.get('errors', [])
                
                if not findings and not errors:
                    self.logger.debug(f"Module {module_name} returned empty result")
            else:
                raise ModuleError(f"Module {module_name} has no run() function")

        except ImportError as e:
            success = False
            errors.append(f"Failed to import module: {str(e)}")
            self.logger.error(f"Import error in {module_name}: {str(e)}")
        except ModuleError as e:
            success = False
            errors.append(str(e))
            self.logger.error(f"Module error in {module_name}: {str(e)}")
        except Exception as e:
            success = False
            errors.append(f"Unexpected error: {str(e)}")
            self.logger.error(f"Unexpected error in {module_name}: {str(e)}")
            self.logger.debug(traceback.format_exc())

        execution_time = time.time() - start_time

        return ModuleResult(
            module_name=module_name,
            success=success,
            findings=findings,
            errors=errors,
            execution_time=execution_time,
            metadata={
                'start_time': start_time,
                'execution_time': execution_time,
            }
        )

    def pause_scan(self) -> bool:
        if self.status != ScanStatus.RUNNING:
            return False
        self.status = ScanStatus.PAUSED
        self.logger.info("Scan paused")
        return True

    def resume_scan(self) -> bool:
        if self.status != ScanStatus.PAUSED:
            return False
        self.status = ScanStatus.RUNNING
        self.logger.info("Scan resumed")
        return True

    def cancel_scan(self) -> bool:
        if self.status not in [ScanStatus.RUNNING, ScanStatus.PAUSED]:
            return False
        self.status = ScanStatus.CANCELLED
        self.end_time = time.time()
        self.logger.info("Scan cancelled")
        return True

    def get_scan_summary(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'status': self.status.value,
            'mode': self.mode.value,
            'modules_executed': len(self.module_results),
            'modules_total': len(self._module_registry),
            'vulnerabilities_found': len(self.vulnerabilities),
            'errors_encountered': len(self.errors),
            'total_requests': self.total_requests,
            'elapsed_time': time.time() - self.start_time if self.start_time > 0 else 0,
            'progress': self.get_progress(),
        }

    def get_progress(self) -> Dict[str, Any]:
        """Get real-time scan progress."""
        total = self._total_modules or 1
        completed = self._completed_modules
        
        return {
            'total_modules': total,
            'completed_modules': completed,
            'percentage': round((completed / total) * 100, 1),
            'is_running': self.status == ScanStatus.RUNNING,
            'is_paused': self.status == ScanStatus.PAUSED,
            'is_completed': self.status == ScanStatus.COMPLETED,
        }

    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == ScanStatus.RUNNING

    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status == ScanStatus.COMPLETED

    def get_module_result(self, module_name: str) -> Optional[ModuleResult]:
        return self.module_results.get(module_name)

    def export_results(self, format_type: str = 'json') -> str:
        if format_type == 'json':
            import json
            return json.dumps({
                'scan_id': self.scan_id,
                'target': self.target,
                'mode': self.mode.value,
                'status': self.status.value,
                'vulnerabilities': self.vulnerabilities,
                'errors': self.errors,
                'module_results': {
                    name: {
                        'success': result.success,
                        'findings': result.findings,
                        'errors': result.errors,
                        'execution_time': result.execution_time,
                    }
                    for name, result in self.module_results.items()
                },
                'total_time': self.end_time - self.start_time if self.end_time else 0,
            }, indent=2)

        return str({
            'scan_id': self.scan_id,
            'target': self.target,
            'status': self.status.value,
        })

    def reset(self) -> None:
        self.scan_id = str(uuid.uuid4())[:8]
        self.status = ScanStatus.INITIALIZED
        self.module_results.clear()
        self.vulnerabilities.clear()
        self.errors.clear()
        self.total_requests = 0
        self.start_time = 0.0
        self.end_time = 0.0
        self._completed_modules = 0
        self._total_modules = 0
        self._module_cache.clear()
        self.logger.info("ScanEngine reset")
