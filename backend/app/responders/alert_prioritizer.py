from datetime import datetime, timedelta
from typing import Dict, Optional, List
from enum import IntEnum

class AlertPriority(IntEnum):
    """告警优先级枚举"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AlertPrioritizer:
    def __init__(self):
        """
        初始化告警优先级管理器
        """
        self.blacklist = set()  # 威胁情报黑名单
        self.asset_importance = {}  # 资产重要性 {asset_id: importance_score}
        self.attack_frequencies = {}  # 攻击频率 {source_ip: {alert_type: (count, last_time)}}
        
    def add_to_blacklist(self, ip: str):
        """
        添加IP到黑名单
        """
        self.blacklist.add(ip)
    
    def remove_from_blacklist(self, ip: str):
        """
        从黑名单移除IP
        """
        if ip in self.blacklist:
            self.blacklist.remove(ip)
    
    def is_in_blacklist(self, ip: str) -> bool:
        """
        检查IP是否在黑名单中
        """
        return ip in self.blacklist
    
    def set_asset_importance(self, asset_id: str, importance_score: int):
        """
        设置资产重要性分数 (1-5)
        """
        if 1 <= importance_score <= 5:
            self.asset_importance[asset_id] = importance_score
    
    def get_asset_importance(self, asset_id: str) -> int:
        """
        获取资产重要性分数，默认1
        """
        return self.asset_importance.get(asset_id, 1)
    
    def record_attack(self, source_ip: str, alert_type: str):
        """
        记录攻击事件，用于频率分析
        """
        if source_ip not in self.attack_frequencies:
            self.attack_frequencies[source_ip] = {}
        
        if alert_type not in self.attack_frequencies[source_ip]:
            self.attack_frequencies[source_ip][alert_type] = (0, datetime.now())
        
        count, _ = self.attack_frequencies[source_ip][alert_type]
        self.attack_frequencies[source_ip][alert_type] = (count + 1, datetime.now())
    
    def get_attack_frequency(self, source_ip: str, alert_type: str, window_seconds: int = 300) -> int:
        """
        获取攻击频率（指定时间窗口内）
        """
        if source_ip not in self.attack_frequencies:
            return 0
        
        if alert_type not in self.attack_frequencies[source_ip]:
            return 0
        
        count, last_time = self.attack_frequencies[source_ip][alert_type]
        if (datetime.now() - last_time).total_seconds() <= window_seconds:
            return count
        return 0
    
    def calculate_priority_score(self, alert: Dict) -> int:
        """
        计算告警优先级分数
        :param alert: 告警信息字典
        :return: 优先级分数 (1-10)
        """
        score = 0
        
        # 1. 基于威胁情报（IP是否在黑名单）
        source_ip = alert.get('source_ip')
        if source_ip and self.is_in_blacklist(source_ip):
            score += 3
        
        # 2. 基于资产重要性（核心服务器vs普通终端）
        asset_id = alert.get('target_asset')
        if asset_id:
            asset_score = self.get_asset_importance(asset_id)
            score += asset_score
        
        # 3. 基于攻击频率（持续攻击vs单次试探）
        alert_type = alert.get('alert_type')
        if source_ip and alert_type:
            frequency = self.get_attack_frequency(source_ip, alert_type)
            if frequency >= 10:
                score += 3
            elif frequency >= 5:
                score += 2
            elif frequency >= 2:
                score += 1
        
        # 4. 基于原始告警严重性
        original_severity = alert.get('severity', 0)
        score += original_severity
        
        # 限制分数在1-10之间
        return max(1, min(10, score))
    
    def map_score_to_priority(self, score: int) -> AlertPriority:
        """
        将优先级分数映射到优先级枚举
        """
        if score >= 9:
            return AlertPriority.CRITICAL
        elif score >= 7:
            return AlertPriority.HIGH
        elif score >= 5:
            return AlertPriority.MEDIUM
        else:
            return AlertPriority.LOW
    
    def prioritize_alert(self, alert: Dict) -> Dict:
        """
        为告警添加优先级信息
        """
        # 记录攻击
        source_ip = alert.get('source_ip')
        alert_type = alert.get('alert_type')
        if source_ip and alert_type:
            self.record_attack(source_ip, alert_type)
        
        # 计算优先级
        priority_score = self.calculate_priority_score(alert)
        priority = self.map_score_to_priority(priority_score)
        
        # 更新告警
        alert['priority_score'] = priority_score
        alert['priority'] = priority.name
        alert['priority_value'] = priority.value
        
        return alert
    
    def clear_old_attack_records(self, max_age_seconds: int = 3600):
        """
        清理旧的攻击记录
        """
        current_time = datetime.now()
        expired_ips = []
        
        for source_ip, alerts in self.attack_frequencies.items():
            expired_types = []
            for alert_type, (count, last_time) in alerts.items():
                if (current_time - last_time).total_seconds() > max_age_seconds:
                    expired_types.append(alert_type)
            
            for alert_type in expired_types:
                del alerts[alert_type]
            
            if not alerts:
                expired_ips.append(source_ip)
        
        for source_ip in expired_ips:
            del self.attack_frequencies[source_ip]
    
    def get_statistics(self) -> Dict:
        """
        获取统计信息
        """
        return {
            'blacklist_count': len(self.blacklist),
            'asset_count': len(self.asset_importance),
            'active_attacks_count': len(self.attack_frequencies)
        }