import pytest
from datetime import datetime, timedelta
from app.detectors.time_window_analyzer import TimeWindowAnalyzer

class TestTimeWindowAnalyzer:
    def setup_method(self):
        self.analyzer = TimeWindowAnalyzer(window_size=5, threshold=3)
    
    def test_add_event(self):
        """测试添加事件"""
        # 添加第一个事件
        result = self.analyzer.add_event('failed_login', '192.168.1.1')
        assert result is False
        
        # 添加第二个事件
        result = self.analyzer.add_event('failed_login', '192.168.1.1')
        assert result is False
        
        # 添加第三个事件（达到阈值）
        result = self.analyzer.add_event('failed_login', '192.168.1.1')
        assert result is True
    
    def test_check_threshold(self):
        """测试检查阈值"""
        # 添加事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('failed_login', '192.168.1.1')
        
        # 检查阈值
        result = self.analyzer.check_threshold('failed_login', '192.168.1.1')
        assert result is True
    
    def test_get_event_count(self):
        """测试获取事件数量"""
        # 添加事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('failed_login', '192.168.1.1')
        
        # 获取事件数量
        count = self.analyzer.get_event_count('failed_login', '192.168.1.1')
        assert count == 2
    
    def test_get_events(self):
        """测试获取事件列表"""
        # 添加事件
        timestamp1 = datetime.now()
        self.analyzer.add_event('failed_login', '192.168.1.1', timestamp1)
        
        timestamp2 = datetime.now() + timedelta(seconds=1)
        self.analyzer.add_event('failed_login', '192.168.1.1', timestamp2)
        
        # 获取事件列表
        events = self.analyzer.get_events('failed_login', '192.168.1.1')
        assert len(events) == 2
        assert events[0] == timestamp1
        assert events[1] == timestamp2
    
    def test_get_all_events(self):
        """测试获取所有事件"""
        # 添加事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('failed_login', '192.168.1.2')
        
        # 获取所有事件
        events = self.analyzer.get_all_events('failed_login')
        assert isinstance(events, dict)
        assert '192.168.1.1' in events
        assert '192.168.1.2' in events
    
    def test_get_top_offenders(self):
        """测试获取触发事件最多的键"""
        # 添加事件
        for i in range(3):
            self.analyzer.add_event('failed_login', '192.168.1.1')
        
        for i in range(2):
            self.analyzer.add_event('failed_login', '192.168.1.2')
        
        # 获取触发事件最多的键
        top_offenders = self.analyzer.get_top_offenders('failed_login')
        assert len(top_offenders) == 2
        assert top_offenders[0][0] == '192.168.1.1'
        assert top_offenders[0][1] == 3
    
    def test_expired_events(self):
        """测试过期事件"""
        # 添加事件
        timestamp = datetime.now() - timedelta(seconds=10)
        self.analyzer.add_event('failed_login', '192.168.1.1', timestamp)
        
        # 检查事件是否已过期
        count = self.analyzer.get_event_count('failed_login', '192.168.1.1')
        assert count == 0
    
    def test_clear_events(self):
        """测试清理事件"""
        # 添加事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('failed_login', '192.168.1.2')
        
        # 清理指定事件类型和键的事件
        self.analyzer.clear_events('failed_login', '192.168.1.1')
        
        # 验证事件已被清理
        count1 = self.analyzer.get_event_count('failed_login', '192.168.1.1')
        count2 = self.analyzer.get_event_count('failed_login', '192.168.1.2')
        assert count1 == 0
        assert count2 == 1
        
        # 清理指定事件类型的所有事件
        self.analyzer.clear_events('failed_login')
        
        # 验证事件已被清理
        count2 = self.analyzer.get_event_count('failed_login', '192.168.1.2')
        assert count2 == 0
        
        # 清理所有事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        self.analyzer.add_event('brute_force', '192.168.1.1')
        self.analyzer.clear_events()
        
        # 验证事件已被清理
        count1 = self.analyzer.get_event_count('failed_login', '192.168.1.1')
        count2 = self.analyzer.get_event_count('brute_force', '192.168.1.1')
        assert count1 == 0
        assert count2 == 0
    
    def test_set_window_size(self):
        """测试设置时间窗口大小"""
        # 添加事件
        self.analyzer.add_event('failed_login', '192.168.1.1')
        
        # 设置新的时间窗口大小
        self.analyzer.set_window_size(10)
        
        # 验证事件已被清理
        count = self.analyzer.get_event_count('failed_login', '192.168.1.1')
        assert count == 0
    
    def test_set_threshold(self):
        """测试设置阈值"""
        # 设置新的阈值
        self.analyzer.set_threshold(2)
        
        # 添加事件
        result = self.analyzer.add_event('failed_login', '192.168.1.1')
        assert result is False
        
        result = self.analyzer.add_event('failed_login', '192.168.1.1')
        assert result is True