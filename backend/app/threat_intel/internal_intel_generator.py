from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
import threading
import statistics
from collections import defaultdict, Counter

from app.core.data_processor import DataProcessor
from app.threat_intel.intel_manager import threat_intel_manager

class InternalIntelGenerator:
    def __init__(self):
        self.lock = threading.Lock()
        self.event_history = []
        self.event_window = timedelta(hours=24)  # 24小时事件窗口
        self.ip_behavior = defaultdict(list)  # IP行为记录
        self.service_behavior = defaultdict(list)  # 服务行为记录
        self.user_behavior = defaultdict(list)  # 用户行为记录
        self.anomaly_thresholds = {
            'ip_request_rate': 100,  # 每分钟请求数阈值
            'failed_login_attempts': 5,  # 失败登录尝试阈值
            'unusual_service_access': 3,  # 异常服务访问阈值
            'data_exfiltration': 1000000  # 数据传输阈值（字节）
        }
        self.internal_intel = {
            'internal_threats': [],
            'anomalies': [],
            'behavioral_patterns': [],
            'trusted_entities': set(),
            'suspicious_entities': set()
        }
        self.data_processor = DataProcessor()
    
    def process_event(self, event):
        """处理事件并生成内部威胁情报"""
        with self.lock:
            # 记录事件
            self.event_history.append(event)
            
            # 清理过期事件
            self._cleanup_old_events()
            
            # 分析事件
            self._analyze_event(event)
            
            # 检测异常
            anomalies = self._detect_anomalies()
            
            # 生成威胁情报
            if anomalies:
                self._generate_intel_from_anomalies(anomalies)
    
    def _cleanup_old_events(self):
        """清理过期事件"""
        current_time = datetime.now()
        self.event_history = [
            event for event in self.event_history 
            if self._get_event_time(event) > current_time - self.event_window
        ]
    
    def _get_event_time(self, event):
        """获取事件时间"""
        event_time = event.get('event_time') or event.get('timestamp')
        if isinstance(event_time, str):
            try:
                return datetime.fromisoformat(event_time)
            except:
                pass
        return datetime.now()
    
    def _analyze_event(self, event):
        """分析事件"""
        event_type = event.get('type')
        event_data = event.get('data') if isinstance(event, dict) else event
        
        if event_type == 'attack_event' or (isinstance(event_data, dict) and 'attack_type' in event_data):
            # 处理攻击事件
            self._analyze_attack_event(event_data)
        elif event_type == 'network_traffic' or (isinstance(event_data, dict) and 'source_ip' in event_data and 'target_ip' in event_data):
            # 处理网络流量
            self._analyze_network_traffic(event_data)
        elif event_type == 'log_entry' or (isinstance(event_data, dict) and 'request_path' in event_data):
            # 处理日志条目
            self._analyze_log_entry(event_data)
    
    def _analyze_attack_event(self, event):
        """分析攻击事件"""
        source_ip = event.get('source_ip')
        if source_ip:
            self.ip_behavior[source_ip].append({
                'timestamp': self._get_event_time(event),
                'event_type': 'attack',
                'attack_type': event.get('attack_type'),
                'severity': event.get('severity')
            })
    
    def _analyze_network_traffic(self, event):
        """分析网络流量"""
        source_ip = event.get('source_ip')
        target_ip = event.get('target_ip')
        target_port = event.get('target_port')
        bytes_sent = event.get('bytes_sent', 0)
        
        if source_ip:
            self.ip_behavior[source_ip].append({
                'timestamp': self._get_event_time(event),
                'event_type': 'network',
                'target_ip': target_ip,
                'target_port': target_port,
                'bytes_sent': bytes_sent
            })
        
        # 分析服务行为
        service_key = f"{target_ip}:{target_port}"
        self.service_behavior[service_key].append({
            'timestamp': self._get_event_time(event),
            'source_ip': source_ip,
            'bytes_sent': bytes_sent
        })
    
    def _analyze_log_entry(self, event):
        """分析日志条目"""
        source_ip = event.get('source_ip')
        user = event.get('user')
        request_path = event.get('request_path')
        status = event.get('status')
        
        if source_ip:
            self.ip_behavior[source_ip].append({
                'timestamp': self._get_event_time(event),
                'event_type': 'log',
                'request_path': request_path,
                'status': status
            })
        
        if user:
            self.user_behavior[user].append({
                'timestamp': self._get_event_time(event),
                'request_path': request_path,
                'status': status
            })
    
    def _detect_anomalies(self):
        """检测异常行为"""
        anomalies = []
        
        # 检测IP异常行为
        for ip, events in self.ip_behavior.items():
            recent_events = [e for e in events if e['timestamp'] > datetime.now() - timedelta(minutes=5)]
            
            # 检测请求速率异常
            if len(recent_events) > self.anomaly_thresholds['ip_request_rate']:
                anomalies.append({
                    'type': 'high_request_rate',
                    'entity': ip,
                    'severity': 'high',
                    'description': f'IP {ip} is making too many requests',
                    'timestamp': datetime.now().isoformat()
                })
            
            # 检测失败登录尝试
            failed_logins = [e for e in recent_events if e.get('status') == 401]
            if len(failed_logins) > self.anomaly_thresholds['failed_login_attempts']:
                anomalies.append({
                    'type': 'failed_login_attempts',
                    'entity': ip,
                    'severity': 'medium',
                    'description': f'IP {ip} has too many failed login attempts',
                    'timestamp': datetime.now().isoformat()
                })
            
            # 检测数据泄露
            data_transfer = sum(e.get('bytes_sent', 0) for e in recent_events)
            if data_transfer > self.anomaly_thresholds['data_exfiltration']:
                anomalies.append({
                    'type': 'data_exfiltration',
                    'entity': ip,
                    'severity': 'critical',
                    'description': f'IP {ip} is transferring large amounts of data',
                    'timestamp': datetime.now().isoformat()
                })
        
        # 检测服务异常访问
        for service, events in self.service_behavior.items():
            recent_events = [e for e in events if e['timestamp'] > datetime.now() - timedelta(minutes=5)]
            unique_ips = set(e['source_ip'] for e in recent_events)
            
            if len(unique_ips) > self.anomaly_thresholds['unusual_service_access']:
                anomalies.append({
                    'type': 'unusual_service_access',
                    'entity': service,
                    'severity': 'medium',
                    'description': f'Service {service} is being accessed by many unique IPs',
                    'timestamp': datetime.now().isoformat()
                })
        
        # 检测用户异常行为
        for user, events in self.user_behavior.items():
            recent_events = [e for e in events if e['timestamp'] > datetime.now() - timedelta(minutes=5)]
            failed_requests = [e for e in recent_events if e.get('status') >= 400]
            
            if len(failed_requests) / len(recent_events) > 0.5:  # 超过50%的失败请求
                anomalies.append({
                    'type': 'unusual_user_behavior',
                    'entity': user,
                    'severity': 'medium',
                    'description': f'User {user} has many failed requests',
                    'timestamp': datetime.now().isoformat()
                })
        
        return anomalies
    
    def _generate_intel_from_anomalies(self, anomalies):
        """从异常生成威胁情报"""
        for anomaly in anomalies:
            # 添加到内部威胁列表
            self.internal_intel['anomalies'].append(anomaly)
            
            # 根据异常类型生成威胁情报
            if anomaly['type'] == 'high_request_rate' or anomaly['type'] == 'failed_login_attempts':
                # 可能是暴力破解或扫描
                threat_intel_manager.add_malicious_ip(anomaly['entity'])
                
                # 添加到可疑实体
                self.internal_intel['suspicious_entities'].add(anomaly['entity'])
                
                # 生成威胁指标
                self._add_threat_indicator({
                    'type': 'suspicious_ip',
                    'indicator': anomaly['entity'],
                    'description': anomaly['description'],
                    'severity': anomaly['severity'],
                    'source': 'Internal Analysis',
                    'tags': ['scanning', 'brute_force']
                })
            elif anomaly['type'] == 'data_exfiltration':
                # 数据泄露
                threat_intel_manager.add_malicious_ip(anomaly['entity'])
                
                # 添加到可疑实体
                self.internal_intel['suspicious_entities'].add(anomaly['entity'])
                
                # 生成威胁指标
                self._add_threat_indicator({
                    'type': 'data_exfiltration',
                    'indicator': anomaly['entity'],
                    'description': anomaly['description'],
                    'severity': anomaly['severity'],
                    'source': 'Internal Analysis',
                    'tags': ['data_loss', 'exfiltration']
                })
            elif anomaly['type'] == 'unusual_service_access':
                # 异常服务访问
                # 提取服务IP
                service_ip = anomaly['entity'].split(':')[0]
                
                # 生成威胁指标
                self._add_threat_indicator({
                    'type': 'unusual_service_access',
                    'indicator': anomaly['entity'],
                    'description': anomaly['description'],
                    'severity': anomaly['severity'],
                    'source': 'Internal Analysis',
                    'tags': ['service_abuse']
                })
            elif anomaly['type'] == 'unusual_user_behavior':
                # 异常用户行为
                # 生成威胁指标
                self._add_threat_indicator({
                    'type': 'unusual_user_behavior',
                    'indicator': anomaly['entity'],
                    'description': anomaly['description'],
                    'severity': anomaly['severity'],
                    'source': 'Internal Analysis',
                    'tags': ['user_behaviour']
                })
    
    def _add_threat_indicator(self, indicator):
        """添加威胁指标"""
        threat_intel_manager.threat_intel_data['threat_indicators'].append({
            'id': f'internal_{int(datetime.now().timestamp())}',
            'type': indicator['type'],
            'indicator': indicator['indicator'],
            'description': indicator['description'],
            'severity': indicator['severity'],
            'created_at': datetime.now().isoformat(),
            'source': indicator['source'],
            'tags': indicator['tags']
        })
    
    def get_internal_intel(self):
        """获取内部威胁情报"""
        with self.lock:
            return {
                'internal_threats': self.internal_intel['internal_threats'],
                'anomalies': self.internal_intel['anomalies'],
                'behavioral_patterns': self.internal_intel['behavioral_patterns'],
                'trusted_entities': list(self.internal_intel['trusted_entities']),
                'suspicious_entities': list(self.internal_intel['suspicious_entities']),
                'event_count': len(self.event_history),
                'ip_count': len(self.ip_behavior),
                'user_count': len(self.user_behavior),
                'service_count': len(self.service_behavior)
            }
    
    def add_trusted_entity(self, entity):
        """添加可信实体"""
        with self.lock:
            self.internal_intel['trusted_entities'].add(entity)
            if entity in self.internal_intel['suspicious_entities']:
                self.internal_intel['suspicious_entities'].remove(entity)
    
    def add_suspicious_entity(self, entity):
        """添加可疑实体"""
        with self.lock:
            self.internal_intel['suspicious_entities'].add(entity)

# 创建单例实例
internal_intel_generator = InternalIntelGenerator()