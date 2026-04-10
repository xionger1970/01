import redis
import json
from typing import Optional, Any
from datetime import timedelta

class CacheManager:
    def __init__(self):
        self.redis_client = redis.Redis(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=True
        )
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存数据"""
        try:
            value = self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            print(f"Cache get error: {e}")
            return None
    
    def set(self, key: str, value: Any, expire: int = 300) -> bool:
        """设置缓存数据"""
        try:
            self.redis_client.setex(
                key,
                expire,
                json.dumps(value, default=str)
            )
            return True
        except Exception as e:
            print(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """删除缓存数据"""
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            print(f"Cache delete error: {e}")
            return False
    
    def clear(self, pattern: str = "*") -> int:
        """清除匹配模式的缓存"""
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except Exception as e:
            print(f"Cache clear error: {e}")
            return 0

# 创建单例实例
cache_manager = CacheManager()