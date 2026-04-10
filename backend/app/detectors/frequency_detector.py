from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

class FrequencyDetector:
    def __init__(self, window_size: int = 60, max_events: int = 10, cooldown: int = 300):
        """
        初始化频率检测器
        :param window_size: 时间窗口大小（秒）
        :param max_events: 最大事件数量
        :param cooldown: 冷却时间（秒）
        """
        self.window_size = window_size
        self.max_events = max_events
        self.cooldown = cooldown
        self.events = {}  # 存储事件，键为实体（如IP地址），值为事件时间列表
        self.blocked = {}  # 存储被阻止的实体，键为实体，值为解除阻止的时间
    
    def add_event(self, entity: str, timestamp: Optional[datetime] = None) -> bool:
        """
        添加事件
        :param entity: 实体（如IP地址）
        :param timestamp: 事件时间戳，默认为当前时间
        :return: 是否超过频率阈值
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # 检查是否在冷却期
        if self.is_blocked(entity, timestamp):
            return True
        
        # 确保实体存在
        if entity not in self.events:
            self.events[entity] = []
        
        # 添加事件
        self.events[entity].append(timestamp)
        
        # 清理过期事件
        self._clean_expired_events(entity, timestamp)
        
        # 检查是否超过频率阈值
        if len(self.events[entity]) > self.max_events:
            # 阻止该实体
            self.blocked[entity] = timestamp + timedelta(seconds=self.cooldown)
            return True
        
        return False
    
    def _clean_expired_events(self, entity: str, current_time: datetime):
        """
        清理过期事件
        :param entity: 实体
        :param current_time: 当前时间
        """
        if entity in self.events:
            # 计算时间窗口的开始时间
            window_start = current_time - timedelta(seconds=self.window_size)
            
            # 过滤掉过期事件
            self.events[entity] = [
                event_time for event_time in self.events[entity]
                if event_time >= window_start
            ]
            
            # 如果没有事件了，删除实体
            if not self.events[entity]:
                del self.events[entity]
    
    def is_blocked(self, entity: str, timestamp: Optional[datetime] = None) -> bool:
        """
        检查实体是否被阻止
        :param entity: 实体
        :param timestamp: 检查时间，默认为当前时间
        :return: 是否被阻止
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        if entity in self.blocked:
            # 检查是否还在阻止期内
            if timestamp < self.blocked[entity]:
                return True
            else:
                # 解除阻止
                del self.blocked[entity]
        
        return False
    
    def get_event_count(self, entity: str, timestamp: Optional[datetime] = None) -> int:
        """
        获取实体的事件数量
        :param entity: 实体
        :param timestamp: 检查时间，默认为当前时间
        :return: 事件数量
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        if entity in self.events:
            # 清理过期事件
            self._clean_expired_events(entity, timestamp)
            return len(self.events.get(entity, []))
        
        return 0
    
    def get_blocked_entities(self, timestamp: Optional[datetime] = None) -> List[Tuple[str, datetime]]:
        """
        获取被阻止的实体
        :param timestamp: 检查时间，默认为当前时间
        :return: (实体, 解除阻止时间) 列表
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        blocked = []
        expired = []
        
        for entity, unblock_time in self.blocked.items():
            if timestamp < unblock_time:
                blocked.append((entity, unblock_time))
            else:
                expired.append(entity)
        
        # 清理过期的阻止
        for entity in expired:
            del self.blocked[entity]
        
        return blocked
    
    def unblock_entity(self, entity: str):
        """
        解除对实体的阻止
        :param entity: 实体
        """
        if entity in self.blocked:
            del self.blocked[entity]
    
    def clear_events(self, entity: str = None):
        """
        清理事件
        :param entity: 实体，None 表示清理所有事件
        """
        if entity is None:
            # 清理所有事件
            self.events.clear()
            self.blocked.clear()
        else:
            # 清理指定实体的事件
            if entity in self.events:
                del self.events[entity]
            if entity in self.blocked:
                del self.blocked[entity]
    
    def set_window_size(self, window_size: int):
        """
        设置时间窗口大小
        :param window_size: 时间窗口大小（秒）
        """
        self.window_size = window_size
        # 清理所有事件，因为时间窗口大小改变了
        self.clear_events()
    
    def set_max_events(self, max_events: int):
        """
        设置最大事件数量
        :param max_events: 最大事件数量
        """
        self.max_events = max_events
    
    def set_cooldown(self, cooldown: int):
        """
        设置冷却时间
        :param cooldown: 冷却时间（秒）
        """
        self.cooldown = cooldown
        # 清理所有阻止，因为冷却时间改变了
        self.blocked.clear()