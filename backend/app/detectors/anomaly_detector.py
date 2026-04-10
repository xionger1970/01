import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import threading
from collections import defaultdict, deque

class AnomalyDetector:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 流量统计数据
        self.traffic_data = defaultdict(lambda: deque(maxlen=300))  # 5分钟数据
        self.connection_data = defaultdict(lambda: deque(maxlen=120))  # 2分钟数据
        
        # 用户行为数据
        self.user_login_data = defaultdict(lambda: deque(maxlen=60))  # 1分钟数据
        self.user_access_data = defaultdict(lambda: deque(maxlen=300))  # 5分钟数据
        
        # 数据传输数据
        self.data_transfer_data = defaultdict(lambda: deque(maxlen=300))  # 5分钟数据
        
        # 系统行为数据
        self.process_data = defaultdict(lambda: deque(maxlen=300))  # 5分钟数据
        self.resource_data = defaultdict(lambda: deque(maxlen=300))  # 5分钟数据
        
        # 阈值配置
        self.thresholds = {
            'traffic': {
                'rate_change': 2.0,  # 流量变化率阈值
                'connection_rate': 100,  # 每分钟连接数阈值
                'packet_size': 1000000  # 数据包大小阈值
            },
            'user': {
                'login_attempts': 5,  # 每分钟登录尝试次数阈值
                'access_frequency': 60,  # 每分钟访问频率阈值
                'geo_distance': 1000  # 地理位置距离阈值（公里）
            },
            'data': {
                'transfer_rate': 1000000,  # 数据传输速率阈值（字节/秒）
                'sensitive_access': 10  # 敏感数据访问频率阈值
            },
            'system': {
                'process_count': 500,  # 进程数量阈值
                'cpu_usage': 90,  # CPU使用率阈值（%）
                'memory_usage': 90,  # 内存使用率阈值（%）
                'disk_usage': 90  # 磁盘使用率阈值（%）
            }
        }
        
        # 启动清理线程
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """启动清理线程"""
        def cleanup_task():
            while True:
                time.sleep(3600)  # 每小时清理一次过期数据
                self._cleanup_old_data()
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_old_data(self):
        """清理过期数据"""
        now = time.time()
        cutoff_time = now - 3600  # 清理1小时前的数据
        
        with self.lock:
            # 清理流量数据
            for key in list(self.traffic_data.keys()):
                self.traffic_data[key] = deque([d for d in self.traffic_data[key] if d['timestamp'] > cutoff_time])
                if not self.traffic_data[key]:
                    del self.traffic_data[key]
            
            # 清理连接数据
            for key in list(self.connection_data.keys()):
                self.connection_data[key] = deque([d for d in self.connection_data[key] if d['timestamp'] > cutoff_time])
                if not self.connection_data[key]:
                    del self.connection_data[key]
            
            # 清理用户登录数据
            for key in list(self.user_login_data.keys()):
                self.user_login_data[key] = deque([d for d in self.user_login_data[key] if d['timestamp'] > cutoff_time])
                if not self.user_login_data[key]:
                    del self.user_login_data[key]
            
            # 清理用户访问数据
            for key in list(self.user_access_data.keys()):
                self.user_access_data[key] = deque([d for d in self.user_access_data[key] if d['timestamp'] > cutoff_time])
                if not self.user_access_data[key]:
                    del self.user_access_data[key]
            
            # 清理数据传输数据
            for key in list(self.data_transfer_data.keys()):
                self.data_transfer_data[key] = deque([d for d in self.data_transfer_data[key] if d['timestamp'] > cutoff_time])
                if not self.data_transfer_data[key]:
                    del self.data_transfer_data[key]
            
            # 清理系统数据
            for key in list(self.process_data.keys()):
                self.process_data[key] = deque([d for d in self.process_data[key] if d['timestamp'] > cutoff_time])
                if not self.process_data[key]:
                    del self.process_data[key]
            
            # 清理资源数据
            for key in list(self.resource_data.keys()):
                self.resource_data[key] = deque([d for d in self.resource_data[key] if d['timestamp'] > cutoff_time])
                if not self.resource_data[key]:
                    del self.resource_data[key]
    
    def add_traffic_data(self, source_ip: str, target_ip: str, bytes_sent: int, bytes_received: int):
        """添加流量数据"""
        timestamp = time.time()
        key = f"{source_ip}:{target_ip}"
        
        with self.lock:
            self.traffic_data[key].append({
                'timestamp': timestamp,
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'total_bytes': bytes_sent + bytes_received
            })
    
    def add_connection_data(self, source_ip: str, target_ip: str, port: int, protocol: str):
        """添加连接数据"""
        timestamp = time.time()
        key = f"{source_ip}:{target_ip}:{port}:{protocol}"
        
        with self.lock:
            self.connection_data[key].append({
                'timestamp': timestamp,
                'source_ip': source_ip,
                'target_ip': target_ip,
                'port': port,
                'protocol': protocol
            })
    
    def add_user_login(self, username: str, ip: str, success: bool, geo_location: Optional[Dict] = None):
        """添加用户登录数据"""
        timestamp = time.time()
        key = username
        
        with self.lock:
            self.user_login_data[key].append({
                'timestamp': timestamp,
                'ip': ip,
                'success': success,
                'geo_location': geo_location
            })
    
    def add_user_access(self, username: str, resource: str, action: str, ip: str):
        """添加用户访问数据"""
        timestamp = time.time()
        key = username
        
        with self.lock:
            self.user_access_data[key].append({
                'timestamp': timestamp,
                'resource': resource,
                'action': action,
                'ip': ip
            })
    
    def add_data_transfer(self, source_ip: str, target_ip: str, data_size: int, data_type: str):
        """添加数据传输数据"""
        timestamp = time.time()
        key = f"{source_ip}:{target_ip}"
        
        with self.lock:
            self.data_transfer_data[key].append({
                'timestamp': timestamp,
                'data_size': data_size,
                'data_type': data_type
            })
    
    def add_process_data(self, host: str, process_name: str, process_id: int, cpu_usage: float, memory_usage: float):
        """添加进程数据"""
        timestamp = time.time()
        key = f"{host}:{process_name}"
        
        with self.lock:
            self.process_data[key].append({
                'timestamp': timestamp,
                'process_id': process_id,
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage
            })
    
    def add_resource_data(self, host: str, cpu_usage: float, memory_usage: float, disk_usage: float):
        """添加资源使用数据"""
        timestamp = time.time()
        key = host
        
        with self.lock:
            self.resource_data[key].append({
                'timestamp': timestamp,
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'disk_usage': disk_usage
            })
    
    def detect_traffic_anomalies(self) -> List[Dict]:
        """检测流量异常"""
        anomalies = []
        now = time.time()
        
        with self.lock:
            for key, data in self.traffic_data.items():
                if len(data) < 5:  # 数据不足，跳过
                    continue
                
                # 计算最近1分钟的流量
                recent_data = [d for d in data if d['timestamp'] > now - 60]
                if len(recent_data) < 3:
                    continue
                
                # 计算流量变化率
                recent_total = sum(d['total_bytes'] for d in recent_data)
                previous_data = [d for d in data if d['timestamp'] > now - 120 and d['timestamp'] <= now - 60]
                if len(previous_data) >= 3:
                    previous_total = sum(d['total_bytes'] for d in previous_data)
                    if previous_total > 0:
                        change_rate = recent_total / previous_total
                        if change_rate > self.thresholds['traffic']['rate_change']:
                            anomalies.append({
                                'type': 'traffic_anomaly',
                                'description': f'流量异常增长: {key}',
                                'severity': 'medium',
                                'details': {
                                    'source_target': key,
                                    'recent_traffic': recent_total,
                                    'previous_traffic': previous_total,
                                    'change_rate': change_rate
                                },
                                'timestamp': now
                            })
                
                # 检测大流量数据包
                for d in recent_data:
                    if d['total_bytes'] > self.thresholds['traffic']['packet_size']:
                        anomalies.append({
                            'type': 'large_packet',
                            'description': f'大流量数据包: {key}',
                            'severity': 'high',
                            'details': {
                                'source_target': key,
                                'packet_size': d['total_bytes']
                            },
                            'timestamp': now
                        })
        
        # 检测连接频率异常
        for key, data in self.connection_data.items():
            recent_connections = [d for d in data if d['timestamp'] > now - 60]
            if len(recent_connections) > self.thresholds['traffic']['connection_rate']:
                anomalies.append({
                    'type': 'connection_flood',
                    'description': f'连接频率异常: {key}',
                    'severity': 'high',
                    'details': {
                        'connection_info': key,
                        'connection_count': len(recent_connections)
                    },
                    'timestamp': now
                })
        
        return anomalies
    
    def detect_user_anomalies(self) -> List[Dict]:
        """检测用户行为异常"""
        anomalies = []
        now = time.time()
        
        with self.lock:
            # 检测登录异常
            for username, data in self.user_login_data.items():
                recent_logins = [d for d in data if d['timestamp'] > now - 60]
                failed_logins = [d for d in recent_logins if not d['success']]
                
                if len(failed_logins) > self.thresholds['user']['login_attempts']:
                    anomalies.append({
                        'type': 'login_attempts',
                        'description': f'登录尝试次数异常: {username}',
                        'severity': 'high',
                        'details': {
                            'username': username,
                            'failed_attempts': len(failed_logins),
                            'total_attempts': len(recent_logins)
                        },
                        'timestamp': now
                    })
                
                # 检测地理位置异常
                if len(recent_logins) >= 2:
                    locations = [d['geo_location'] for d in recent_logins if d['geo_location']]
                    if len(locations) >= 2:
                        # 简单模拟地理位置距离检测
                        # 实际应用中应使用真实的地理位置距离计算
                        distance = 1500  # 模拟距离
                        if distance > self.thresholds['user']['geo_distance']:
                            anomalies.append({
                                'type': 'geo_location',
                                'description': f'登录地理位置异常: {username}',
                                'severity': 'critical',
                                'details': {
                                    'username': username,
                                    'distance': distance
                                },
                                'timestamp': now
                            })
            
            # 检测访问频率异常
            for username, data in self.user_access_data.items():
                recent_accesses = [d for d in data if d['timestamp'] > now - 60]
                if len(recent_accesses) > self.thresholds['user']['access_frequency']:
                    anomalies.append({
                        'type': 'access_frequency',
                        'description': f'访问频率异常: {username}',
                        'severity': 'medium',
                        'details': {
                            'username': username,
                            'access_count': len(recent_accesses)
                        },
                        'timestamp': now
                    })
        
        return anomalies
    
    def detect_data_anomalies(self) -> List[Dict]:
        """检测数据传输异常"""
        anomalies = []
        now = time.time()
        
        with self.lock:
            for key, data in self.data_transfer_data.items():
                recent_transfers = [d for d in data if d['timestamp'] > now - 60]
                if len(recent_transfers) > 0:
                    total_data = sum(d['data_size'] for d in recent_transfers)
                    transfer_rate = total_data / 60  # 字节/秒
                    
                    if transfer_rate > self.thresholds['data']['transfer_rate']:
                        anomalies.append({
                            'type': 'data_transfer_rate',
                            'description': f'数据传输速率异常: {key}',
                            'severity': 'high',
                            'details': {
                                'source_target': key,
                                'transfer_rate': transfer_rate,
                                'total_data': total_data
                            },
                            'timestamp': now
                        })
                    
                    # 检测敏感数据访问
                    sensitive_accesses = [d for d in recent_transfers if d['data_type'] == 'sensitive']
                    if len(sensitive_accesses) > self.thresholds['data']['sensitive_access']:
                        anomalies.append({
                            'type': 'sensitive_data_access',
                            'description': f'敏感数据访问频率异常: {key}',
                            'severity': 'critical',
                            'details': {
                                'source_target': key,
                                'sensitive_access_count': len(sensitive_accesses)
                            },
                            'timestamp': now
                        })
        
        return anomalies
    
    def detect_system_anomalies(self) -> List[Dict]:
        """检测系统异常"""
        anomalies = []
        now = time.time()
        
        with self.lock:
            # 检测进程异常
            process_counts = defaultdict(int)
            for key, data in self.process_data.items():
                host = key.split(':')[0]
                process_counts[host] += 1
            
            for host, count in process_counts.items():
                if count > self.thresholds['system']['process_count']:
                    anomalies.append({
                        'type': 'process_count',
                        'description': f'进程数量异常: {host}',
                        'severity': 'medium',
                        'details': {
                            'host': host,
                            'process_count': count
                        },
                        'timestamp': now
                    })
            
            # 检测资源使用异常
            for host, data in self.resource_data.items():
                recent_data = [d for d in data if d['timestamp'] > now - 60]
                if len(recent_data) > 0:
                    avg_cpu = statistics.mean(d['cpu_usage'] for d in recent_data)
                    avg_memory = statistics.mean(d['memory_usage'] for d in recent_data)
                    avg_disk = statistics.mean(d['disk_usage'] for d in recent_data)
                    
                    if avg_cpu > self.thresholds['system']['cpu_usage']:
                        anomalies.append({
                            'type': 'cpu_usage',
                            'description': f'CPU使用率异常: {host}',
                            'severity': 'high',
                            'details': {
                                'host': host,
                                'cpu_usage': avg_cpu
                            },
                            'timestamp': now
                        })
                    
                    if avg_memory > self.thresholds['system']['memory_usage']:
                        anomalies.append({
                            'type': 'memory_usage',
                            'description': f'内存使用率异常: {host}',
                            'severity': 'high',
                            'details': {
                                'host': host,
                                'memory_usage': avg_memory
                            },
                            'timestamp': now
                        })
                    
                    if avg_disk > self.thresholds['system']['disk_usage']:
                        anomalies.append({
                            'type': 'disk_usage',
                            'description': f'磁盘使用率异常: {host}',
                            'severity': 'medium',
                            'details': {
                                'host': host,
                                'disk_usage': avg_disk
                            },
                            'timestamp': now
                        })
        
        return anomalies
    
    def detect_all_anomalies(self) -> List[Dict]:
        """检测所有类型的异常"""
        anomalies = []
        anomalies.extend(self.detect_traffic_anomalies())
        anomalies.extend(self.detect_user_anomalies())
        anomalies.extend(self.detect_data_anomalies())
        anomalies.extend(self.detect_system_anomalies())
        return anomalies
    
    def get_anomaly_stats(self) -> Dict:
        """获取异常检测统计信息"""
        now = time.time()
        stats = {
            'total_traffic_data': sum(len(d) for d in self.traffic_data.values()),
            'total_connection_data': sum(len(d) for d in self.connection_data.values()),
            'total_user_login_data': sum(len(d) for d in self.user_login_data.values()),
            'total_user_access_data': sum(len(d) for d in self.user_access_data.values()),
            'total_data_transfer_data': sum(len(d) for d in self.data_transfer_data.values()),
            'total_process_data': sum(len(d) for d in self.process_data.values()),
            'total_resource_data': sum(len(d) for d in self.resource_data.values()),
            'thresholds': self.thresholds,
            'last_updated': datetime.now().isoformat()
        }
        return stats

# 创建单例实例
anomaly_detector = AnomalyDetector()
