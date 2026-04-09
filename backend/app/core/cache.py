import time
from typing import Dict, Optional, Any
from functools import lru_cache

class CacheManager:
    def __init__(self, default_ttl=300):  # 5 minutes default TTL
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            item = self.cache[key]
            # Check if item is expired
            if time.time() < item['expiry']:
                return item['value']
            else:
                # Remove expired item
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with optional TTL"""
        expiry = time.time() + (ttl or self.default_ttl)
        self.cache[key] = {
            'value': value,
            'expiry': expiry
        }
    
    def delete(self, key: str) -> bool:
        """Delete item from cache"""
        if key in self.cache:
            del self.cache[key]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cache"""
        self.cache.clear()
    
    def get_cache_size(self) -> int:
        """Get current cache size"""
        return len(self.cache)
    
    def cleanup_expired(self) -> int:
        """Clean up expired items and return count"""
        now = time.time()
        expired_keys = [key for key, item in self.cache.items() if item['expiry'] < now]
        for key in expired_keys:
            del self.cache[key]
        return len(expired_keys)

# Create singleton instance
cache_manager = CacheManager()

# Decorator for caching function results
def cache_result(ttl: Optional[int] = None):
    """Decorator to cache function results"""
    def decorator(func):
        @lru_cache(maxsize=128)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{args}:{tuple(sorted(kwargs.items()))}"
            
            # Check cache first
            cached_value = cache_manager.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call the function
            result = func(*args, **kwargs)
            
            # Cache the result
            cache_manager.set(cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator