# core/cache.py

"""
Cache Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

In-memory caching system with TTL support for storing
frequently accessed data and reducing redundant operations.
"""

import time
import threading
from typing import Dict, Any, Optional, List, Tuple
from collections import OrderedDict
from dataclasses import dataclass, field
from core.exceptions import CacheError


@dataclass
class CacheEntry:
    """Represents a single cache entry."""
    key: str
    value: Any
    created_at: float
    expires_at: float
    access_count: int = 0
    last_accessed: float = 0.0


class CacheManager:
    """
    Thread-safe in-memory cache manager.
    
    Provides fast data storage and retrieval with
    TTL expiration, size limits, and eviction policies.
    """
    
    def __init__(
        self,
        max_size_mb: int = 256,
        default_ttl: int = 3600,
        eviction_policy: str = 'lru'
    ):
        """
        Initialize the cache manager.
        
        Args:
            max_size_mb: Maximum cache size in megabytes
            default_ttl: Default time-to-live in seconds
            eviction_policy: Cache eviction policy ('lru' or 'fifo')
        """
        self.max_size_mb = max_size_mb
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.eviction_policy = eviction_policy
        
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._current_size = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from cache.
        
        Args:
            key: Cache key
            default: Default value if key not found
            
        Returns:
            Cached value or default
        """
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._misses += 1
                return default
            
            if entry.expires_at < time.time():
                self._remove_entry(key)
                self._misses += 1
                return default
            
            entry.access_count += 1
            entry.last_accessed = time.time()
            
            if self.eviction_policy == 'lru':
                self._cache.move_to_end(key)
            
            self._hits += 1
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Store a value in cache.
        
        Args:
            key: Cache key
            value: Value to store
            ttl: Time-to-live in seconds (uses default if None)
            
        Returns:
            True if stored successfully
        """
        if ttl is None:
            ttl = self.default_ttl
        
        with self._lock:
            try:
                value_size = self._estimate_size(value)
                
                if value_size > self.max_size_bytes:
                    return False
                
                while self._current_size + value_size > self.max_size_bytes and self._cache:
                    self._evict_one()
                
                now = time.time()
                entry = CacheEntry(
                    key=key,
                    value=value,
                    created_at=now,
                    expires_at=now + ttl,
                    access_count=0,
                    last_accessed=now
                )
                
                if key in self._cache:
                    old_size = self._estimate_size(self._cache[key].value)
                    self._current_size -= old_size
                
                self._cache[key] = entry
                
                if self.eviction_policy == 'lru':
                    self._cache.move_to_end(key)
                
                self._current_size += value_size
                return True
                
            except Exception as e:
                raise CacheError(f"Failed to set cache key {key}: {str(e)}")
    
    def delete(self, key: str) -> bool:
        """
        Remove a value from cache.
        
        Args:
            key: Cache key to remove
            
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            return self._remove_entry(key)
    
    def exists(self, key: str) -> bool:
        """
        Check if key exists in cache and is not expired.
        
        Args:
            key: Cache key
            
        Returns:
            True if key exists and is valid
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.expires_at < time.time():
                self._remove_entry(key)
                return False
            return True
    
    def _remove_entry(self, key: str) -> bool:
        """
        Remove an entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if removed
        """
        if key in self._cache:
            entry = self._cache[key]
            self._current_size -= self._estimate_size(entry.value)
            del self._cache[key]
            return True
        return False
    
    def _evict_one(self) -> None:
        """Evict one entry based on eviction policy."""
        if not self._cache:
            return
        
        if self.eviction_policy == 'lru':
            key, _ = next(iter(self._cache.items()))
        else:
            key, _ = next(iter(self._cache.items()))
        
        self._remove_entry(key)
        self._evictions += 1
    
    def _cleanup_loop(self) -> None:
        """Background thread to clean expired entries."""
        while True:
            time.sleep(60)
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            now = time.time()
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.expires_at < now
            ]
            
            for key in expired_keys:
                self._remove_entry(key)
            
            return len(expired_keys)
    
    def _estimate_size(self, value: Any) -> int:
        """
        Estimate memory size of a value.
        
        Args:
            value: Value to estimate
            
        Returns:
            Estimated size in bytes
        """
        import sys
        
        try:
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (int, float, bool)):
                return sys.getsizeof(value)
            elif isinstance(value, (list, tuple)):
                return sum(self._estimate_size(item) for item in value) + 64
            elif isinstance(value, dict):
                return sum(
                    self._estimate_size(k) + self._estimate_size(v)
                    for k, v in value.items()
                ) + 64
            elif isinstance(value, bytes):
                return len(value)
            else:
                return sys.getsizeof(value)
        except Exception:
            return 1024
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._current_size = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'total_entries': len(self._cache),
                'current_size_bytes': self._current_size,
                'current_size_mb': round(self._current_size / (1024 * 1024), 2),
                'max_size_mb': self.max_size_mb,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': round(hit_rate, 2),
                'evictions': self._evictions,
                'default_ttl': self.default_ttl,
                'eviction_policy': self.eviction_policy,
            }
    
    def get_keys(self) -> List[str]:
        """
        Get all valid cache keys.
        
        Returns:
            List of cache keys
        """
        with self._lock:
            return list(self._cache.keys())