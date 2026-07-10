# cli/progress_bars.py

"""
Progress Display Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides real-time progress bars, status indicators,
and scan progress visualization for terminal output.
"""

import sys
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class ProgressStyle(Enum):
    """Styles for progress bars."""
    SIMPLE = "simple"
    DETAILED = "detailed"
    MINIMAL = "minimal"
    PERCENTAGE = "percentage"


@dataclass
class ProgressTask:
    """Represents a task being tracked."""
    task_id: str
    description: str
    total: int
    current: int = 0
    status: str = "pending"
    start_time: float = 0.0
    end_time: float = 0.0
    errors: int = 0
    warnings: int = 0
    
    @property
    def percentage(self) -> float:
        """Calculate completion percentage."""
        if self.total == 0:
            return 0.0
        return min(100.0, (self.current / self.total) * 100)
    
    @property
    def elapsed(self) -> float:
        """Calculate elapsed time."""
        if self.start_time == 0:
            return 0.0
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time
    
    @property
    def eta(self) -> float:
        """Estimate time remaining."""
        if self.current == 0 or self.total == 0:
            return 0.0
        rate = self.current / self.elapsed if self.elapsed > 0 else 0
        if rate == 0:
            return 0.0
        remaining = (self.total - self.current) / rate
        return remaining


class ProgressManager:
    """
    Manages multiple progress indicators for scan operations.
    
    Provides real-time progress tracking with multiple display
    styles and automatic refresh capabilities.
    """
    
    def __init__(self, style: ProgressStyle = ProgressStyle.DETAILED):
        """
        Initialize the progress manager.
        
        Args:
            style: Display style for progress bars
        """
        self.style = style
        self.tasks: Dict[str, ProgressTask] = {}
        self.lock = threading.Lock()
        self.refresh_thread: Optional[threading.Thread] = None
        self.running = False
        self.last_lines = 0
        
        self.bar_length = 40
        self.fill_char = "="
        self.empty_char = "-"
        self.show_eta = True
        self.show_rate = True
        self.refresh_interval = 0.1
    
    def create_task(
        self,
        task_id: str,
        description: str,
        total: int
    ) -> ProgressTask:
        """
        Create a new progress task.
        
        Args:
            task_id: Unique task identifier
            description: Task description
            total: Total items to process
            
        Returns:
            Created ProgressTask object
        """
        with self.lock:
            task = ProgressTask(
                task_id=task_id,
                description=description,
                total=total,
                start_time=time.time()
            )
            self.tasks[task_id] = task
            return task
    
    def update_task(
        self,
        task_id: str,
        increment: int = 1,
        status: Optional[str] = None,
        error: bool = False,
        warning: bool = False
    ) -> None:
        """
        Update a task's progress.
        
        Args:
            task_id: Task identifier
            increment: Amount to increment current count
            status: New status string
            error: Whether to increment error count
            warning: Whether to increment warning count
        """
        with self.lock:
            if task_id not in self.tasks:
                return
            
            task = self.tasks[task_id]
            task.current = min(task.total, task.current + increment)
            
            if status:
                task.status = status
            
            if error:
                task.errors += 1
            
            if warning:
                task.warnings += 1
            
            if task.current >= task.total:
                task.end_time = time.time()
                task.status = "completed"
    
    def complete_task(self, task_id: str, status: str = "completed") -> None:
        """
        Mark a task as complete.
        
        Args:
            task_id: Task identifier
            status: Completion status
        """
        with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.current = task.total
                task.end_time = time.time()
                task.status = status
    
    def fail_task(self, task_id: str, reason: str = "failed") -> None:
        """
        Mark a task as failed.
        
        Args:
            task_id: Task identifier
            reason: Failure reason
        """
        with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.end_time = time.time()
                task.status = f"failed: {reason}"
    
    def _format_bar(self, task: ProgressTask) -> str:
        """
        Format a progress bar for a task.
        
        Args:
            task: ProgressTask to format
            
        Returns:
            Formatted progress bar string
        """
        if self.style == ProgressStyle.MINIMAL:
            return f"{task.description}: {task.current}/{task.total}"
        
        if self.style == ProgressStyle.PERCENTAGE:
            return f"{task.description}: {task.percentage:.1f}%"
        
        filled_length = int(self.bar_length * task.current / task.total) if task.total > 0 else 0
        bar = self.fill_char * filled_length + self.empty_char * (self.bar_length - filled_length)
        
        if task.status == "completed":
            bar = self.fill_char * self.bar_length
        
        parts = [f"{task.description}"]
        parts.append(f"[{bar}]")
        parts.append(f"{task.current}/{task.total}")
        
        if self.show_rate and task.elapsed > 0 and task.current > 0:
            rate = task.current / task.elapsed
            if rate >= 1:
                parts.append(f"{rate:.0f}/s")
            else:
                parts.append(f"{rate:.1f}/s")
        
        if self.show_eta and task.current > 0 and task.current < task.total:
            eta = task.eta
            if eta < 60:
                parts.append(f"ETA: {eta:.0f}s")
            elif eta < 3600:
                parts.append(f"ETA: {eta/60:.1f}m")
            else:
                parts.append(f"ETA: {eta/3600:.1f}h")
        
        if task.errors > 0:
            parts.append(f"Errors: {task.errors}")
        
        if task.status and task.status not in ["pending", "running", "completed"]:
            parts.append(f"[{task.status}]")
        
        return " ".join(parts)
    
    def _render(self) -> str:
        """
        Render all progress bars.
        
        Returns:
            String containing all progress bars
        """
        with self.lock:
            lines = []
            for task in self.tasks.values():
                lines.append(self._format_bar(task))
            return "\n".join(lines)
    
    def _clear_lines(self) -> None:
        """Clear previously rendered lines."""
        if self.last_lines > 0:
            sys.stdout.write(f"\033[{self.last_lines}A")
            sys.stdout.write("\033[J")
    
    def _refresh_display(self) -> None:
        """Refresh the progress display."""
        while self.running:
            self._clear_lines()
            rendered = self._render()
            self.last_lines = rendered.count('\n') + 1
            sys.stdout.write(rendered + "\n")
            sys.stdout.flush()
            time.sleep(self.refresh_interval)
    
    def start(self) -> None:
        """Start the progress display."""
        self.running = True
        self.refresh_thread = threading.Thread(
            target=self._refresh_display,
            daemon=True
        )
        self.refresh_thread.start()
    
    def stop(self) -> None:
        """Stop the progress display."""
        self.running = False
        if self.refresh_thread:
            self.refresh_thread.join(timeout=1.0)
        
        self._clear_lines()
        rendered = self._render()
        sys.stdout.write(rendered + "\n")
        sys.stdout.flush()
        self.last_lines = 0
    
    def get_task(self, task_id: str) -> Optional[ProgressTask]:
        """
        Get a task by ID.
        
        Args:
            task_id: Task identifier
            
        Returns:
            ProgressTask or None if not found
        """
        return self.tasks.get(task_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics for all tasks.
        
        Returns:
            Dictionary with task statistics
        """
        with self.lock:
            stats = {
                'total_tasks': len(self.tasks),
                'completed_tasks': 0,
                'failed_tasks': 0,
                'running_tasks': 0,
                'total_errors': 0,
                'total_warnings': 0,
                'tasks': {}
            }
            
            for task_id, task in self.tasks.items():
                if task.status == "completed":
                    stats['completed_tasks'] += 1
                elif task.status.startswith("failed"):
                    stats['failed_tasks'] += 1
                else:
                    stats['running_tasks'] += 1
                
                stats['total_errors'] += task.errors
                stats['total_warnings'] += task.warnings
                
                stats['tasks'][task_id] = {
                    'description': task.description,
                    'total': task.total,
                    'current': task.current,
                    'percentage': task.percentage,
                    'status': task.status,
                    'elapsed': task.elapsed,
                    'errors': task.errors,
                    'warnings': task.warnings
                }
            
            return stats
    
    def print_summary(self) -> None:
        """Print a summary of all tasks."""
        print("\n" + "=" * 60)
        print("SCAN PROGRESS SUMMARY")
        print("=" * 60)
        
        with self.lock:
            for task in self.tasks.values():
                status_symbol = "+" if task.status == "completed" else "*" if task.status.startswith("failed") else "."
                print(f"  [{status_symbol}] {task.description}")
                print(f"      Progress: {task.current}/{task.total} ({task.percentage:.1f}%)")
                print(f"      Time: {task.elapsed:.1f}s")
                if task.errors > 0:
                    print(f"      Errors: {task.errors}")
                if task.warnings > 0:
                    print(f"      Warnings: {task.warnings}")
                print()
        
        print("=" * 60)
    
    def reset(self) -> None:
        """Reset all tasks."""
        with self.lock:
            self.tasks.clear()