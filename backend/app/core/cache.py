import redis
import json
from typing import Optional, Any
from datetime import timedelta
import time

class CacheManager:
    def __init__(self):
        # 使用Redis连接池
        self.redis_pool = redis.ConnectionPool(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=True,
            max_connections=50
        )
        self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        self.namespace = "web_attack_awareness:"
        self.retry_attempts = 3
    
    def _get_namespaced_key(self, key: str) -> str:
        """获取带命名空间的缓存键"""
        return f"{self.namespace}{key}"
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存数据"""
        namespaced_key = self._get_namespaced_key(key)
        for attempt in range(self.retry_attempts):
            try:
                value = self.redis_client.get(namespaced_key)
                if value:
                    return json.loads(value)
                return None
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    print(f"Cache get error: {e}")
                    return None
                time.sleep(0.1)
        return None
    
    def set(self, key: str, value: Any, expire: int = 300) -> bool:
        """设置缓存数据"""
        namespaced_key = self._get_namespaced_key(key)
        for attempt in range(self.retry_attempts):
            try:
                self.redis_client.setex(
                    namespaced_key,
                    expire,
                    json.dumps(value, default=str)
                )
                return True
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    print(f"Cache set error: {e}")
                    return False
                time.sleep(0.1)
        return False
    
    def delete(self, key: str) -> bool:
        """删除缓存数据"""
        namespaced_key = self._get_namespaced_key(key)
        for attempt in range(self.retry_attempts):
            try:
                self.redis_client.delete(namespaced_key)
                return True
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    print(f"Cache delete error: {e}")
                    return False
                time.sleep(0.1)
        return False
    
    def clear(self, pattern: str = "*") -> int:
        """清除匹配模式的缓存"""
        namespaced_pattern = self._get_namespaced_key(pattern)
        for attempt in range(self.retry_attempts):
            try:
                keys = self.redis_client.keys(namespaced_pattern)
                if keys:
                    return self.redis_client.delete(*keys)
                return 0
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    print(f"Cache clear error: {e}")
                    return 0
                time.sleep(0.1)
        return 0
    
    def batch_set(self, key_value_pairs: dict, expire: int = 300) -> bool:
        """批量设置缓存数据"""
        pipeline = self.redis_client.pipeline()
        try:
            for key, value in key_value_pairs.items():
                namespaced_key = self._get_namespaced_key(key)
                pipeline.setex(
                    namespaced_key,
                    expire,
                    json.dumps(value, default=str)
                )
            pipeline.execute()
            return True
        except Exception as e:
            print(f"Cache batch set error: {e}")
            return False
    
    def batch_get(self, keys: list) -> dict:
        """批量获取缓存数据"""
        pipeline = self.redis_client.pipeline()
        try:
            for key in keys:
                namespaced_key = self._get_namespaced_key(key)
                pipeline.get(namespaced_key)
            results = pipeline.execute()
            return {key: json.loads(result) if result else None for key, result in zip(keys, results)}
        except Exception as e:
            print(f"Cache batch get error: {e}")
            return {}

# 创建单例实例
cache_manager = CacheManager()