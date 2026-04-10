import pytest
from datetime import datetime, timedelta
from app.responders.alert_prioritizer import AlertPrioritizer, AlertPriority

class TestAlertPrioritizer:
    def setup_method(self):
        self.prioritizer = AlertPrioritizer()
    
    def test_add_to_blacklist(self):
        """测试添加IP到黑名单"""
        self.prioritizer.add_to_blacklist('192.168.1.1')
        assert self.prioritizer.is_in_blacklist('192.168.1.1') is True
    
    def test_remove_from_blacklist(self):
        """测试从黑名单移除IP"""
        self.prioritizer.add_to_blacklist('192.168.1.1')
        self.prioritizer.remove_from_blacklist('192.168.1.1')
        assert self.prioritizer.is_in_blacklist('192.168.1.1') is False
    
    def test_set_asset_importance(self):
        """测试设置资产重要性"""
        self.prioritizer.set_asset_importance('server-001', 5)
        assert self.prioritizer.get_asset_importance('server-001') == 5
    
    def test_invalid_importance_score(self):
        """测试无效的重要性分数"""
        self.prioritizer.set_asset_importance('server-001', 6)
        assert self.prioritizer.get_asset_importance('server-001') == 1
    
    def test_record_attack(self):
        """测试记录攻击"""
        self.prioritizer.record_attack('192.168.1.1', 'SQL注入')
        frequency = self.prioritizer.get_attack_frequency('192.168.1.1', 'SQL注入')
        assert frequency == 1
    
    def test_multiple_attacks(self):
        """测试多次攻击"""
        for i in range(5):
            self.prioritizer.record_attack('192.168.1.1', 'SQL注入')
        
        frequency = self.prioritizer.get_attack_frequency('192.168.1.1', 'SQL注入')
        assert frequency == 5
    
    def test_calculate_priority_score_basic(self):
        """测试计算基本告警优先级分数"""
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'severity': 2
        }
        score = self.prioritizer.calculate_priority_score(alert)
        assert 1 <= score <= 10
    
    def test_calculate_priority_score_blacklist(self):
        """测试黑名单影响优先级分数"""
        self.prioritizer.add_to_blacklist('192.168.1.1')
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'severity': 1
        }
        score = self.prioritizer.calculate_priority_score(alert)
        assert score >= 3
    
    def test_calculate_priority_score_asset_importance(self):
        """测试资产重要性影响优先级分数"""
        self.prioritizer.set_asset_importance('critical-server', 5)
        alert = {
            'source_ip': '192.168.1.1',
            'target_asset': 'critical-server',
            'alert_type': 'SQL注入',
            'severity': 1
        }
        score = self.prioritizer.calculate_priority_score(alert)
        assert score >= 5
    
    def test_calculate_priority_score_frequency(self):
        """测试攻击频率影响优先级分数"""
        # 记录多次攻击
        for i in range(6):
            self.prioritizer.record_attack('192.168.1.1', 'SQL注入')
        
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'severity': 1
        }
        score = self.prioritizer.calculate_priority_score(alert)
        assert score >= 3
    
    def test_map_score_to_priority(self):
        """测试分数到优先级的映射"""
        assert self.prioritizer.map_score_to_priority(1) == AlertPriority.LOW
        assert self.prioritizer.map_score_to_priority(5) == AlertPriority.MEDIUM
        assert self.prioritizer.map_score_to_priority(7) == AlertPriority.HIGH
        assert self.prioritizer.map_score_to_priority(9) == AlertPriority.CRITICAL
    
    def test_prioritize_alert(self):
        """测试为告警添加优先级信息"""
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'severity': 3
        }
        prioritized = self.prioritizer.prioritize_alert(alert)
        
        assert 'priority_score' in prioritized
        assert 'priority' in prioritized
        assert 'priority_value' in prioritized
        assert 1 <= prioritized['priority_score'] <= 10
    
    def test_clear_old_attack_records(self):
        """测试清理旧的攻击记录"""
        # 记录攻击
        self.prioritizer.record_attack('192.168.1.1', 'SQL注入')
        
        # 清理旧记录
        self.prioritizer.clear_old_attack_records(0)
        
        # 验证记录已被清理
        frequency = self.prioritizer.get_attack_frequency('192.168.1.1', 'SQL注入')
        assert frequency == 0
    
    def test_get_statistics(self):
        """测试获取统计信息"""
        self.prioritizer.add_to_blacklist('192.168.1.1')
        self.prioritizer.set_asset_importance('server-001', 3)
        self.prioritizer.record_attack('192.168.1.2', 'XSS攻击')
        
        stats = self.prioritizer.get_statistics()
        
        assert stats['blacklist_count'] == 1
        assert stats['asset_count'] == 1
        assert stats['active_attacks_count'] == 1
