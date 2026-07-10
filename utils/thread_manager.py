# utils/thread_manager.py

"""
Thread Pool Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages thread pools for concurrent operations with
configurable limits and progress tracking.
"""

import threading
import time
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass, field


@dataclass
class ThreadTask:
    """Represents a task in the thread pool."""
    task_id: str
    function: Callable
    args: tuple
    kwargs: dict
    submitted_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    result: Any = None
    error: Optional[str] = None
    status: str = 'pending'


class ThreadManager:
    """
    Thread pool manager for concurrent operations.
    
    Provides controlled thread execution with
    progress tracking and error handling.
    """
    
    def __init__(
        self,
        max_workers: int = 10,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the thread manager.
        
        Args:
            max_workers: Maximum worker threads
            config: Configuration dictionary
        """
        self.max_workers = max_workers
        self.config = config or {}
        
        self.executor: Optional[ThreadPoolExecutor] = None
        self.tasks: Dict[str, ThreadTask] = {}
        self.futures: Dict[Future, str] = {}
        self.lock = threading.Lock()
        
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.start_time = 0.0
        self.end_time = 0.0
    
    def create_executor(self) -> ThreadPoolExecutor:
        """
        Create a new thread pool executor.
        
        Returns:
            ThreadPoolExecutor instance
        """
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self.executor
    
    def submit_task(
        self,
        task_id: str,
        function: Callable,
        *args,
        **kwargs
    ) -> Future:
        """
        Submit a task to the thread pool.
        
        Args:
            task_id: Unique task identifier
            function: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Future object for the task
        """
        if self.executor is None:
            self.create_executor()
        
        task = ThreadTask(
            task_id=task_id,
            function=function,
            args=args,
            kwargs=kwargs,
            submitted_at=time.time(),
        )
        
        with self.lock:
            self.tasks[task_id] = task
            self.total_tasks += 1
        
        def wrapped_function():
            task.started_at = time.time()
            task.status = 'running'
            
            try:
                result = function(*args, **kwargs)
                task.result = result
                task.status = 'completed'
                
                with self.lock:
                    self.completed_tasks += 1
                
                return result
                
            except Exception as e:
                task.error = str(e)
                task.status = 'failed'
                
                with self.lock:
                    self.failed_tasks += 1
                
                raise
        
        future = self.executor.submit(wrapped_function)
        
        with self.lock:
            self.futures[future] = task_id
        
        return future
    
    def submit_tasks(
        self,
        tasks: List[Tuple[str, Callable, tuple, dict]]
    ) -> List[Future]:
        """
        Submit multiple tasks.
        
        Args:
            tasks: List of (task_id, function, args, kwargs) tuples
            
        Returns:
            List of Future objects
        """
        futures = []
        
        for task_id, function, args, kwargs in tasks:
            future = self.submit_task(task_id, function, *args, **kwargs)
            futures.append(future)
        
        return futures
    
    def wait_all(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Wait for all tasks to complete.
        
        Args:
            timeout: Maximum wait time in seconds
            
        Returns:
            Dictionary with completion results
        """
        self.start_time = time.time()
        
        if self.executor is None:
            return {'completed': 0, 'failed': 0, 'pending': 0}
        
        try:
            for future in as_completed(self.futures, timeout=timeout):
                task_id = self.futures.get(future)
                
                if task_id and task_id in self.tasks:
                    task = self.tasks[task_id]
                    
                    try:
                        task.result = future.result()
                        task.status = 'completed'
                        task.completed_at = time.time()
                    except Exception as e:
                        task.error = str(e)
                        task.status = 'failed'
                        task.completed_at = time.time()
        except TimeoutError:
            pass
        
        self.end_time = time.time()
        
        return self.get_progress()
    
    def get_progress(self) -> Dict[str, Any]:
        """
        Get current progress statistics.
        
        Returns:
            Dictionary with progress information
        """
        with self.lock:
            completed = sum(
                1 for t in self.tasks.values()
                if t.status in ['completed', 'failed']
            )
            running = sum(
                1 for t in self.tasks.values()
                if t.status == 'running'
            )
            pending = sum(
                1 for t in self.tasks.values()
                if t.status == 'pending'
            )
            
            elapsed = time.time() - self.start_time if self.start_time > 0 else 0
            
            if completed > 0 and elapsed > 0:
                rate = completed / elapsed
                eta = (pending / rate) if rate > 0 else 0
            else:
                rate = 0
                eta = 0
        
        return {
            'total': self.total_tasks,
            'completed': self.completed_tasks,
            'failed': self.failed_tasks,
            'running': running,
            'pending': pending,
            'elapsed': elapsed,
            'rate': rate,
            'eta': eta,
            'percent_complete': (completed / self.total_tasks * 100) if self.total_tasks > 0 else 0,
        }
    
    def get_task_result(self, task_id: str) -> Optional[Any]:
        """
        Get result of a specific task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task result or None
        """
        task = self.tasks.get(task_id)
        
        if task:
            return task.result
        
        return None
    
    def get_failed_tasks(self) -> List[Dict[str, Any]]:
        """
        Get list of failed tasks.
        
        Returns:
            List of failed task dictionaries
        """
        return [
            {
                'task_id': task_id,
                'error': task.error,
                'function': task.function.__name__,
            }
            for task_id, task in self.tasks.items()
            if task.status == 'failed'
        ]
    
    def cancel_all(self) -> None:
        """Cancel all pending tasks."""
        if self.executor:
            for future in self.futures:
                future.cancel()
    
    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the thread pool.
        
        Args:
            wait: Whether to wait for running tasks
        """
        if self.executor:
            self.executor.shutdown(wait=wait)
            self.executor = None
    
    def __del__(self) -> None:
        """Cleanup on deletion."""
        self.shutdown(wait=False)