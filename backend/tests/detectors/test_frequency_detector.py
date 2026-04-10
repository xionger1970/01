import pytest
from datetime import datetime, timedelta
from app.detectors.frequency_detector import FrequencyDetector

class TestFrequencyDetector:
    def setup_method(self):
        self.detector = FrequencyDetector(window_size=5, max_events=3, cooldown=10)
    
    def test_add_event(self):
        """测试添加事件"""
        # 添加第一个事件
        result = self.detector.add_event('192.168.1.1')
        assert result is False
        
        # 添加第二个事件
        result = self.detector.add_event('192.168.1.1')
        assert result is False
        
        # 添加第三个事件（达到阈值）
        result = self.detector.add_event('192.168.1.1')
        assert result is False
        
        # 添加第四个事件（超过阈值）
        result = self.detector.add_event('192.168.1.1')
        assert result is True
    
    def test_is_blocked(self):
        """测试检查实体是否被阻止"""
        # 添加事件直到被阻止
        for i in range(4):
            self.detector.add_event('192.168.1.1')
        
        # 检查是否被阻止
        result = self.detector.is_blocked('192.168.1.1')
        assert result is True
    
    def test_get_event_count(self):
        """测试获取事件数量"""
        # 添加事件
        self.detector.add_event('192.168.1.1')
        self.detector.add_event('192.168.1.1')
        
        # 获取事件数量
        count = self.detector.get_event_count('192.168.1.1')
        assert count == 2
    
    def test_get_blocked_entities(self):
        """测试获取被阻止的实体"""
        # 添加事件直到被阻止
        for i in range(4):
            self.detector.add_event('192.168.1.1')
        
        # 获取被阻止的实体
        blocked = self.detector.get_blocked_entities()
        assert len(blocked) == 1
        assert blocked[0][0] == '192.168.1.1'
    
    def test_unblock_entity(self):
        """测试解除对实体的阻止"""
        # 添加事件直到被阻止
        for i in range(4):
            self.detector.add_event('192.168.1.1')
        
        # 解除阻止
        self.detector.unblock_entity('192.168.1.1')
        
        # 验证已解除阻止
        result = self.detector.is_blocked('192.168.1.1')
        assert result is False
    
    def test_expired_block(self):
        """测试过期的阻止"""
        # 添加事件直到被阻止
        for i in range(4):
            self.detector.add_event('192.168.1.1')
        
        # 模拟时间流逝
        future_time = datetime.now() + timedelta(seconds=15)
        result = self.detector.is_blocked('192.168.1.1', future_time)
        assert result is False
    
    def test_clear_events(self):
        """测试清理事件"""
        # 添加事件
        self.detector.add_event('192.168.1.1')
        self.detector.add_event('192.168.1.2')
        
        # 清理指定实体的事件
        self.detector.clear_events('192.168.1.1')
        
        # 验证事件已被清理
        count1 = self.detector.get_event_count('192.168.1.1')
        count2 = self.detector.get_event_count('192.168.1.2')
        assert count1 == 0
        assert count2 == 1
        
        # 清理所有事件
        self.detector.clear_events()
        
        # 验证事件已被清理
        count2 = self.detector.get_event_count('192.168.1.2')
        assert count2 == 0
    
    def test_set_window_size(self):
        """测试设置时间窗口大小"""
        # 添加事件
        self.detector.add_event('192.168.1.1')
        
        # 设置新的时间窗口大小
        self.detector.set_window_size(10)
        
        # 验证事件已被清理
        count = self.detector.get_event_count('192.168.1.1')
        assert count == 0
    
    def test_set_max_events(self):
        """测试设置最大事件数量"""
        # 设置新的最大事件数量
        self.detector.set_max_events(2)
        
        # 添加事件
        result = self.detector.add_event('192.168.1.1')
        assert result is False
        
        result = self.detector.add_event('192.168.1.1')
        assert result is False
        
        result = self.detector.add_event('192.168.1.1')
        assert result is True
    
    def test_set_cooldown(self):
        """测试设置冷却时间"""
        # 添加事件直到被阻止
        for i in range(4):
            self.detector.add_event('192.168.1.1')
        
        # 设置新的冷却时间
        self.detector.set_cooldown(5)
        
        # 验证阻止已被清理
        blocked = self.detector.get_blocked_entities()
        assert len(blocked) == 0