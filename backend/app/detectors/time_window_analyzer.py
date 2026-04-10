from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

class TimeWindowAnalyzer:
    def __init__(self, window_size: int = 300, threshold: int = 5):
        """
        初始化时间窗口分析器
        :param window_size: 时间窗口大小（秒）
        :param threshold: 阈值（时间窗口内的事件数量）
        """
        self.window_size = window_size
        self.threshold = threshold
        self.events = {}  # 存储事件，键为事件类型，值为事件列表
    
    def add_event(self, event_type: str, key: str, timestamp: Optional[datetime] = None) -> bool:
        """
        添加事件到时间窗口
        :param event_type: 事件类型（如 'failed_login'）
        :param key: 事件键（如 'source_ip' 或 'username'）
        :param timestamp: 事件时间戳，默认为当前时间
        :return: 是否超过阈值
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # 确保事件类型存在
        if event_type not in self.events:
            self.events[event_type] = {}
        
        # 确保键存在
        if key not in self.events[event_type]:
            self.events[event_type][key] = []
        
        # 添加事件
        self.events[event_type][key].append(timestamp)
        
        # 清理过期事件
        self._clean_expired_events(event_type, key, timestamp)
        
        # 检查是否超过阈值
        return len(self.events[event_type][key]) >= self.threshold
    
    def _clean_expired_events(self, event_type: str, key: str, current_time: datetime):
        """
        清理过期事件
        :param event_type: 事件类型
        :param key: 事件键
        :param current_time: 当前时间
        """
        if event_type in self.events and key in self.events[event_type]:
            # 计算时间窗口的开始时间
            window_start = current_time - timedelta(seconds=self.window_size)
            
            # 过滤掉过期事件
            self.events[event_type][key] = [
                event_time for event_time in self.events[event_type][key]
                if event_time >= window_start
            ]
            
            # 如果没有事件了，删除键
            if not self.events[event_type][key]:
                del self.events[event_type][key]
                # 如果事件类型没有键了，删除事件类型
                if not self.events[event_type]:
                    del self.events[event_type]
    
    def check_threshold(self, event_type: str, key: str) -> bool:
        """
        检查是否超过阈值
        :param event_type: 事件类型
        :param key: 事件键
        :return: 是否超过阈值
        """
        if event_type in self.events and key in self.events[event_type]:
            # 清理过期事件
            self._clean_expired_events(event_type, key, datetime.now())
            # 检查是否超过阈值
            return len(self.events[event_type].get(key, [])) >= self.threshold
        return False
    
    def get_event_count(self, event_type: str, key: str) -> int:
        """
        获取事件数量
        :param event_type: 事件类型
        :param key: 事件键
        :return: 事件数量
        """
        if event_type in self.events:
            event_dict = self.events[event_type]
            if key in event_dict:
                # 清理过期事件
                self._clean_expired_events(event_type, key, datetime.now())
                # 再次检查 event_type 和 key 是否存在
                if event_type in self.events and key in self.events[event_type]:
                    return len(self.events[event_type][key])
        return 0
    
    def get_events(self, event_type: str, key: str) -> List[datetime]:
        """
        获取事件列表
        :param event_type: 事件类型
        :param key: 事件键
        :return: 事件列表
        """
        if event_type in self.events and key in self.events[event_type]:
            # 清理过期事件
            self._clean_expired_events(event_type, key, datetime.now())
            return self.events[event_type].get(key, [])
        return []
    
    def get_all_events(self, event_type: str) -> Dict[str, List[datetime]]:
        """
        获取所有事件
        :param event_type: 事件类型
        :return: 事件字典
        """
        if event_type in self.events:
            # 清理所有过期事件
            current_time = datetime.now()
            for key in list(self.events[event_type].keys()):
                self._clean_expired_events(event_type, key, current_time)
            return self.events.get(event_type, {})
        return {}
    
    def get_top_offenders(self, event_type: str, limit: int = 10) -> List[Tuple[str, int]]:
        """
        获取触发事件最多的键
        :param event_type: 事件类型
        :param limit: 返回数量限制
        :return: (键, 事件数量) 列表
        """
        if event_type not in self.events:
            return []
        
        # 清理过期事件
        current_time = datetime.now()
        for key in list(self.events[event_type].keys()):
            self._clean_expired_events(event_type, key, current_time)
        
        # 计算每个键的事件数量
        offender_counts = []
        for key, events in self.events[event_type].items():
            offender_counts.append((key, len(events)))
        
        # 按事件数量排序
        offender_counts.sort(key=lambda x: x[1], reverse=True)
        return offender_counts[:limit]
    
    def clear_events(self, event_type: str = None, key: str = None):
        """
        清理事件
        :param event_type: 事件类型，None 表示清理所有事件类型
        :param key: 事件键，None 表示清理所有键
        """
        if event_type is None:
            # 清理所有事件
            self.events.clear()
        elif key is None:
            # 清理指定事件类型的所有事件
            if event_type in self.events:
                del self.events[event_type]
        else:
            # 清理指定事件类型和键的事件
            if event_type in self.events and key in self.events[event_type]:
                del self.events[event_type][key]
                # 如果事件类型没有键了，删除事件类型
                if not self.events[event_type]:
                    del self.events[event_type]
    
    def set_window_size(self, window_size: int):
        """
        设置时间窗口大小
        :param window_size: 时间窗口大小（秒）
        """
        self.window_size = window_size
        # 清理所有事件，因为时间窗口大小改变了
        self.clear_events()
    
    def set_threshold(self, threshold: int):
        """
        设置阈值
        :param threshold: 阈值（时间窗口内的事件数量）
        """
        self.threshold = threshold