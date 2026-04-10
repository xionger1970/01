import pytest
from datetime import datetime, timedelta
from app.detectors.alert_aggregator import AlertAggregator

class TestAlertAggregator:
    def setup_method(self):
        self.aggregator = AlertAggregator(aggregation_window=5)
    
    def test_add_alert(self):
        """测试添加告警"""
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        result = self.aggregator.add_alert(alert)
        assert result is not None
        assert result['count'] == 1
        assert result['source_ip'] == '192.168.1.1'
    
    def test_aggregate_alerts(self):
        """测试聚合告警"""
        base_time = datetime.now()
        
        # 添加第一个告警
        alert1 = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': base_time,
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert1)
        
        # 添加第二个告警（同一源IP和类型）
        alert2 = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': base_time + timedelta(seconds=1),
            'severity': 3,
            'targets': ['192.168.1.101'],
            'details': {'port': 8080}
        }
        result = self.aggregator.add_alert(alert2)
        
        assert result['count'] == 2
        assert len(result['targets']) == 2
        assert '192.168.1.100' in result['targets']
        assert '192.168.1.101' in result['targets']
    
    def test_get_aggregated_alerts(self):
        """测试获取聚合告警"""
        # 添加告警
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert)
        
        # 获取聚合告警
        alerts = self.aggregator.get_aggregated_alerts()
        assert len(alerts) == 1
        assert alerts[0]['source_ip'] == '192.168.1.1'
    
    def test_get_alerts_by_source_ip(self):
        """测试根据源IP获取聚合告警"""
        # 添加告警
        alert1 = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert1)
        
        alert2 = {
            'source_ip': '192.168.1.2',
            'alert_type': 'XSS攻击',
            'timestamp': datetime.now(),
            'severity': 2,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert2)
        
        # 根据源IP获取告警
        alerts = self.aggregator.get_alerts_by_source_ip('192.168.1.1')
        assert len(alerts) == 1
        assert alerts[0]['alert_type'] == 'SQL注入'
    
    def test_get_alerts_by_type(self):
        """测试根据告警类型获取聚合告警"""
        # 添加告警
        alert1 = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert1)
        
        alert2 = {
            'source_ip': '192.168.1.2',
            'alert_type': 'XSS攻击',
            'timestamp': datetime.now(),
            'severity': 2,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert2)
        
        # 根据告警类型获取告警
        alerts = self.aggregator.get_alerts_by_type('SQL注入')
        assert len(alerts) == 1
        assert alerts[0]['source_ip'] == '192.168.1.1'
    
    def test_get_top_sources(self):
        """测试获取攻击次数最多的源IP"""
        # 添加告警
        for i in range(3):
            alert = {
                'source_ip': '192.168.1.1',
                'alert_type': f'SQL注入{i}',
                'timestamp': datetime.now(),
                'severity': 3,
                'targets': ['192.168.1.100'],
                'details': {'port': 80}
            }
            self.aggregator.add_alert(alert)
        
        for i in range(2):
            alert = {
                'source_ip': '192.168.1.2',
                'alert_type': f'XSS攻击{i}',
                'timestamp': datetime.now(),
                'severity': 2,
                'targets': ['192.168.1.100'],
                'details': {'port': 80}
            }
            self.aggregator.add_alert(alert)
        
        # 获取攻击次数最多的源IP
        top_sources = self.aggregator.get_top_sources()
        assert len(top_sources) == 2
        assert top_sources[0][0] == '192.168.1.1'
        assert top_sources[0][1] == 3
    
    def test_get_top_alert_types(self):
        """测试获取最常见的告警类型"""
        # 添加告警
        for i in range(3):
            alert = {
                'source_ip': f'192.168.1.{i+1}',
                'alert_type': 'SQL注入',
                'timestamp': datetime.now(),
                'severity': 3,
                'targets': ['192.168.1.100'],
                'details': {'port': 80}
            }
            self.aggregator.add_alert(alert)
        
        for i in range(2):
            alert = {
                'source_ip': f'192.168.1.{i+4}',
                'alert_type': 'XSS攻击',
                'timestamp': datetime.now(),
                'severity': 2,
                'targets': ['192.168.1.100'],
                'details': {'port': 80}
            }
            self.aggregator.add_alert(alert)
        
        # 获取最常见的告警类型
        top_types = self.aggregator.get_top_alert_types()
        assert len(top_types) == 2
        assert top_types[0][0] == 'SQL注入'
        assert top_types[0][1] == 3
    
    def test_clear_expired_alerts(self):
        """测试清理过期的聚合告警"""
        # 添加告警
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now() - timedelta(seconds=10),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert)
        
        # 清理过期告警
        self.aggregator.clear_expired_alerts()
        
        # 验证告警已被清理
        alerts = self.aggregator.get_aggregated_alerts()
        assert len(alerts) == 0
    
    def test_clear_all_alerts(self):
        """测试清空所有聚合告警"""
        # 添加告警
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert)
        
        # 清空所有告警
        self.aggregator.clear_all_alerts()
        
        # 验证告警已被清空
        alerts = self.aggregator.get_aggregated_alerts()
        assert len(alerts) == 0
    
    def test_get_alert_count(self):
        """测试获取告警数量"""
        # 添加告警
        alert = {
            'source_ip': '192.168.1.1',
            'alert_type': 'SQL注入',
            'timestamp': datetime.now(),
            'severity': 3,
            'targets': ['192.168.1.100'],
            'details': {'port': 80}
        }
        self.aggregator.add_alert(alert)
        
        # 获取告警数量
        count = self.aggregator.get_alert_count()
        assert count == 1