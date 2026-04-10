from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

class AlertAggregator:
    def __init__(self, aggregation_window: int = 300):
        """
        初始化告警聚合器
        :param aggregation_window: 聚合时间窗口（秒）
        """
        self.aggregation_window = aggregation_window
        self.aggregated_alerts = {}
    
    def add_alert(self, alert: Dict) -> Optional[Dict]:
        """
        添加新告警并进行聚合
        :param alert: 告警信息字典
        :return: 聚合后的告警信息
        """
        source_ip = alert.get('source_ip')
        alert_type = alert.get('alert_type')
        timestamp = alert.get('timestamp', datetime.now())
        
        if not source_ip:
            return alert
        
        # 生成聚合键
        aggregation_key = f"{source_ip}_{alert_type}"
        
        # 检查是否存在相同源IP和告警类型的聚合告警
        if aggregation_key in self.aggregated_alerts:
            existing_alert = self.aggregated_alerts[aggregation_key]
            
            # 检查是否在时间窗口内
            if (timestamp - existing_alert['last_seen']).total_seconds() <= self.aggregation_window:
                # 更新现有告警
                existing_alert['count'] += 1
                existing_alert['last_seen'] = timestamp
                existing_alert['targets'].update(alert.get('targets', set()))
                existing_alert['details'].append(alert.get('details', {}))
                
                # 更新严重性（如果新告警更严重）
                if alert.get('severity', 0) > existing_alert.get('severity', 0):
                    existing_alert['severity'] = alert.get('severity', 0)
                
                return existing_alert
        
        # 创建新的聚合告警
        new_aggregated_alert = {
            'source_ip': source_ip,
            'alert_type': alert_type,
            'count': 1,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'severity': alert.get('severity', 0),
            'targets': set(alert.get('targets', [])),
            'details': [alert.get('details', {})],
            'status': 'active'
        }
        
        self.aggregated_alerts[aggregation_key] = new_aggregated_alert
        return new_aggregated_alert
    
    def get_aggregated_alerts(self, active_only: bool = True) -> List[Dict]:
        """
        获取聚合后的告警
        :param active_only: 是否只返回活跃告警
        :return: 聚合告警列表
        """
        alerts = []
        current_time = datetime.now()
        
        for key, alert in list(self.aggregated_alerts.items()):
            # 检查告警是否过期
            if (current_time - alert['last_seen']).total_seconds() > self.aggregation_window:
                alert['status'] = 'expired'
                if active_only:
                    continue
            
            # 转换集合为列表以便序列化
            alert_copy = alert.copy()
            alert_copy['targets'] = list(alert_copy['targets'])
            alerts.append(alert_copy)
        
        # 按最后出现时间排序
        alerts.sort(key=lambda x: x['last_seen'], reverse=True)
        return alerts
    
    def get_alerts_by_source_ip(self, source_ip: str) -> List[Dict]:
        """
        根据源IP获取聚合告警
        :param source_ip: 源IP地址
        :return: 聚合告警列表
        """
        alerts = []
        for key, alert in self.aggregated_alerts.items():
            if alert.get('source_ip') == source_ip:
                alert_copy = alert.copy()
                alert_copy['targets'] = list(alert_copy['targets'])
                alerts.append(alert_copy)
        
        alerts.sort(key=lambda x: x['last_seen'], reverse=True)
        return alerts
    
    def get_alerts_by_type(self, alert_type: str) -> List[Dict]:
        """
        根据告警类型获取聚合告警
        :param alert_type: 告警类型
        :return: 聚合告警列表
        """
        alerts = []
        for key, alert in self.aggregated_alerts.items():
            if alert.get('alert_type') == alert_type:
                alert_copy = alert.copy()
                alert_copy['targets'] = list(alert_copy['targets'])
                alerts.append(alert_copy)
        
        alerts.sort(key=lambda x: x['last_seen'], reverse=True)
        return alerts
    
    def get_top_sources(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        获取攻击次数最多的源IP
        :param limit: 返回数量限制
        :return: (源IP, 攻击次数) 列表
        """
        source_counts = {}
        for alert in self.aggregated_alerts.values():
            source_ip = alert.get('source_ip')
            if source_ip:
                source_counts[source_ip] = source_counts.get(source_ip, 0) + alert.get('count', 0)
        
        # 按攻击次数排序
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_sources[:limit]
    
    def get_top_alert_types(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        获取最常见的告警类型
        :param limit: 返回数量限制
        :return: (告警类型, 出现次数) 列表
        """
        type_counts = {}
        for alert in self.aggregated_alerts.values():
            alert_type = alert.get('alert_type')
            if alert_type:
                type_counts[alert_type] = type_counts.get(alert_type, 0) + alert.get('count', 0)
        
        # 按出现次数排序
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_types[:limit]
    
    def clear_expired_alerts(self):
        """
        清理过期的聚合告警
        """
        current_time = datetime.now()
        expired_keys = []
        
        for key, alert in self.aggregated_alerts.items():
            if (current_time - alert['last_seen']).total_seconds() > self.aggregation_window:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.aggregated_alerts[key]
    
    def clear_all_alerts(self):
        """
        清空所有聚合告警
        """
        self.aggregated_alerts.clear()
    
    def get_alert_count(self, active_only: bool = True) -> int:
        """
        获取告警数量
        :param active_only: 是否只计算活跃告警
        :return: 告警数量
        """
        if active_only:
            current_time = datetime.now()
            count = 0
            for alert in self.aggregated_alerts.values():
                if (current_time - alert['last_seen']).total_seconds() <= self.aggregation_window:
                    count += 1
            return count
        else:
            return len(self.aggregated_alerts)