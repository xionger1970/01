import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import threading
from collections import defaultdict, deque, Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN

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
        
        # 机器学习模型
        self.ml_models = {
            'traffic': IsolationForest(contamination=0.1, random_state=42),
            'user': IsolationForest(contamination=0.1, random_state=42),
            'data': IsolationForest(contamination=0.1, random_state=42),
            'system': IsolationForest(contamination=0.1, random_state=42)
        }
        
        # 行为模式数据
        self.behavior_patterns = {
            'user_patterns': defaultdict(list),
            'ip_patterns': defaultdict(list),
            'service_patterns': defaultdict(list)
        }
        
        # 异常关联数据
        self.anomaly_correlations = defaultdict(list)
        
        # 启动清理线程
        self._start_cleanup_thread()
        
        # 训练初始模型
        self._train_initial_models()
    
    def _start_cleanup_thread(self):
        """启动清理线程"""
        def cleanup_task():
            while True:
                time.sleep(3600)  # 每小时清理一次过期数据
                self._cleanup_old_data()
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def _train_initial_models(self):
        """训练初始机器学习模型"""
        # 生成模拟数据用于初始训练
        # 实际应用中，应该使用真实的历史数据进行训练
        try:
            # 生成流量数据
            traffic_data = []
            for i in range(1000):
                traffic_data.append([
                    np.random.normal(1000, 100),  # 正常流量
                    np.random.normal(50, 10)       # 正常连接数
                ])
            
            # 生成异常数据
            for i in range(100):
                traffic_data.append([
                    np.random.normal(10000, 1000),  # 异常流量
                    np.random.normal(200, 50)       # 异常连接数
                ])
            
            # 训练流量模型
            if traffic_data:
                self.ml_models['traffic'].fit(np.array(traffic_data))
            
            # 生成用户数据
            user_data = []
            for i in range(1000):
                user_data.append([
                    np.random.normal(5, 2),  # 正常登录次数
                    np.random.normal(20, 5)  # 正常访问次数
                ])
            
            # 生成异常数据
            for i in range(100):
                user_data.append([
                    np.random.normal(20, 5),  # 异常登录次数
                    np.random.normal(100, 20) # 异常访问次数
                ])
            
            # 训练用户模型
            if user_data:
                self.ml_models['user'].fit(np.array(user_data))
            
            # 生成数据传输数据
            data_data = []
            for i in range(1000):
                data_data.append([
                    np.random.normal(100000, 10000),  # 正常数据传输量
                    np.random.normal(5, 2)            # 正常敏感访问次数
                ])
            
            # 生成异常数据
            for i in range(100):
                data_data.append([
                    np.random.normal(1000000, 100000),  # 异常数据传输量
                    np.random.normal(20, 5)             # 异常敏感访问次数
                ])
            
            # 训练数据模型
            if data_data:
                self.ml_models['data'].fit(np.array(data_data))
            
            # 生成系统数据
            system_data = []
            for i in range(1000):
                system_data.append([
                    np.random.normal(50, 10),  # 正常CPU使用率
                    np.random.normal(60, 15),  # 正常内存使用率
                    np.random.normal(40, 10)   # 正常磁盘使用率
                ])
            
            # 生成异常数据
            for i in range(100):
                system_data.append([
                    np.random.normal(90, 5),  # 异常CPU使用率
                    np.random.normal(90, 5),  # 异常内存使用率
                    np.random.normal(90, 5)   # 异常磁盘使用率
                ])
            
            # 训练系统模型
            if system_data:
                self.ml_models['system'].fit(np.array(system_data))
                
        except Exception as e:
            print(f"Error training initial models: {e}")
    
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
            
            # 清理行为模式数据
            for key in list(self.behavior_patterns['user_patterns'].keys()):
                self.behavior_patterns['user_patterns'][key] = [p for p in self.behavior_patterns['user_patterns'][key] if p['timestamp'] > cutoff_time]
                if not self.behavior_patterns['user_patterns'][key]:
                    del self.behavior_patterns['user_patterns'][key]
            
            for key in list(self.behavior_patterns['ip_patterns'].keys()):
                self.behavior_patterns['ip_patterns'][key] = [p for p in self.behavior_patterns['ip_patterns'][key] if p['timestamp'] > cutoff_time]
                if not self.behavior_patterns['ip_patterns'][key]:
                    del self.behavior_patterns['ip_patterns'][key]
            
            for key in list(self.behavior_patterns['service_patterns'].keys()):
                self.behavior_patterns['service_patterns'][key] = [p for p in self.behavior_patterns['service_patterns'][key] if p['timestamp'] > cutoff_time]
                if not self.behavior_patterns['service_patterns'][key]:
                    del self.behavior_patterns['service_patterns'][key]
            
            # 清理异常关联数据
            self.anomaly_correlations = defaultdict(list)
    
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
    
    def learn_behavior_patterns(self):
        """学习行为模式"""
        now = time.time()
        
        with self.lock:
            # 学习用户行为模式
            for username, data in self.user_access_data.items():
                recent_data = [d for d in data if d['timestamp'] > now - 3600]  # 最近1小时
                if len(recent_data) > 10:
                    # 分析访问频率和模式
                    access_times = sorted([d['timestamp'] for d in recent_data])
                    time_diffs = [access_times[i] - access_times[i-1] for i in range(1, len(access_times))]
                    
                    if time_diffs:
                        avg_interval = statistics.mean(time_diffs)
                        std_interval = statistics.stdev(time_diffs) if len(time_diffs) > 1 else 0
                        
                        # 分析访问资源类型
                        resources = [d['resource'] for d in recent_data]
                        resource_counts = Counter(resources)
                        
                        self.behavior_patterns['user_patterns'][username].append({
                            'timestamp': now,
                            'avg_access_interval': avg_interval,
                            'std_access_interval': std_interval,
                            'resource_distribution': dict(resource_counts),
                            'total_accesses': len(recent_data)
                        })
            
            # 学习IP行为模式
            for key, data in self.traffic_data.items():
                source_ip = key.split(':')[0]
                recent_data = [d for d in data if d['timestamp'] > now - 3600]  # 最近1小时
                if len(recent_data) > 10:
                    # 分析流量模式
                    total_bytes = [d['total_bytes'] for d in recent_data]
                    avg_bytes = statistics.mean(total_bytes)
                    std_bytes = statistics.stdev(total_bytes) if len(total_bytes) > 1 else 0
                    
                    self.behavior_patterns['ip_patterns'][source_ip].append({
                        'timestamp': now,
                        'avg_traffic': avg_bytes,
                        'std_traffic': std_bytes,
                        'total_connections': len(recent_data)
                    })
            
            # 学习服务行为模式
            for key, data in self.connection_data.items():
                service_key = ':'.join(key.split(':')[1:])  # 目标IP:端口:协议
                recent_data = [d for d in data if d['timestamp'] > now - 3600]  # 最近1小时
                if len(recent_data) > 10:
                    # 分析连接模式
                    connection_times = sorted([d['timestamp'] for d in recent_data])
                    time_diffs = [connection_times[i] - connection_times[i-1] for i in range(1, len(connection_times))]
                    
                    if time_diffs:
                        avg_interval = statistics.mean(time_diffs)
                        std_interval = statistics.stdev(time_diffs) if len(time_diffs) > 1 else 0
                        
                        # 分析来源IP分布
                        source_ips = [d['source_ip'] for d in recent_data]
                        source_counts = Counter(source_ips)
                        
                        self.behavior_patterns['service_patterns'][service_key].append({
                            'timestamp': now,
                            'avg_connection_interval': avg_interval,
                            'std_connection_interval': std_interval,
                            'source_ip_distribution': dict(source_counts),
                            'total_connections': len(recent_data)
                        })
    
    def detect_behavioral_anomalies(self) -> List[Dict]:
        """检测行为异常"""
        anomalies = []
        now = time.time()
        
        with self.lock:
            # 检测用户行为异常
            for username, patterns in self.behavior_patterns['user_patterns'].items():
                if len(patterns) >= 2:
                    # 比较最近的模式与历史模式
                    recent_pattern = patterns[-1]
                    historical_patterns = patterns[:-1]
                    
                    if historical_patterns:
                        # 计算历史平均访问间隔
                        historical_intervals = [p['avg_access_interval'] for p in historical_patterns]
                        avg_historical_interval = statistics.mean(historical_intervals)
                        std_historical_interval = statistics.stdev(historical_intervals) if len(historical_intervals) > 1 else 0
                        
                        # 检测访问间隔异常
                        if abs(recent_pattern['avg_access_interval'] - avg_historical_interval) > 2 * std_historical_interval and std_historical_interval > 0:
                            anomalies.append({
                                'type': 'user_behavior_anomaly',
                                'description': f'用户行为模式异常: {username}',
                                'severity': 'medium',
                                'details': {
                                    'username': username,
                                    'recent_interval': recent_pattern['avg_access_interval'],
                                    'historical_interval': avg_historical_interval,
                                    'deviation': abs(recent_pattern['avg_access_interval'] - avg_historical_interval)
                                },
                                'timestamp': now
                            })
            
            # 检测IP行为异常
            for ip, patterns in self.behavior_patterns['ip_patterns'].items():
                if len(patterns) >= 2:
                    # 比较最近的模式与历史模式
                    recent_pattern = patterns[-1]
                    historical_patterns = patterns[:-1]
                    
                    if historical_patterns:
                        # 计算历史平均流量
                        historical_traffic = [p['avg_traffic'] for p in historical_patterns]
                        avg_historical_traffic = statistics.mean(historical_traffic)
                        std_historical_traffic = statistics.stdev(historical_traffic) if len(historical_traffic) > 1 else 0
                        
                        # 检测流量异常
                        if recent_pattern['avg_traffic'] > avg_historical_traffic * 2 and avg_historical_traffic > 0:
                            anomalies.append({
                                'type': 'ip_behavior_anomaly',
                                'description': f'IP行为模式异常: {ip}',
                                'severity': 'high',
                                'details': {
                                    'ip': ip,
                                    'recent_traffic': recent_pattern['avg_traffic'],
                                    'historical_traffic': avg_historical_traffic,
                                    'increase_factor': recent_pattern['avg_traffic'] / avg_historical_traffic
                                },
                                'timestamp': now
                            })
            
            # 检测服务行为异常
            for service, patterns in self.behavior_patterns['service_patterns'].items():
                if len(patterns) >= 2:
                    # 比较最近的模式与历史模式
                    recent_pattern = patterns[-1]
                    historical_patterns = patterns[:-1]
                    
                    if historical_patterns:
                        # 计算历史平均连接数
                        historical_connections = [p['total_connections'] for p in historical_patterns]
                        avg_historical_connections = statistics.mean(historical_connections)
                        
                        # 检测连接数异常
                        if recent_pattern['total_connections'] > avg_historical_connections * 3 and avg_historical_connections > 0:
                            anomalies.append({
                                'type': 'service_behavior_anomaly',
                                'description': f'服务行为模式异常: {service}',
                                'severity': 'high',
                                'details': {
                                    'service': service,
                                    'recent_connections': recent_pattern['total_connections'],
                                    'historical_connections': avg_historical_connections,
                                    'increase_factor': recent_pattern['total_connections'] / avg_historical_connections
                                },
                                'timestamp': now
                            })
        
        return anomalies
    
    def detect_machine_learning_anomalies(self) -> List[Dict]:
        """使用机器学习检测异常"""
        anomalies = []
        now = time.time()
        
        try:
            with self.lock:
                # 检测流量异常
                traffic_features = []
                traffic_keys = []
                
                for key, data in self.traffic_data.items():
                    recent_data = [d for d in data if d['timestamp'] > now - 60]  # 最近1分钟
                    if len(recent_data) > 0:
                        total_bytes = sum(d['total_bytes'] for d in recent_data)
                        connection_count = len(recent_data)
                        traffic_features.append([total_bytes, connection_count])
                        traffic_keys.append(key)
                
                if traffic_features:
                    traffic_features = np.array(traffic_features)
                    predictions = self.ml_models['traffic'].predict(traffic_features)
                    
                    for i, prediction in enumerate(predictions):
                        if prediction == -1:  # -1表示异常
                            anomalies.append({
                                'type': 'ml_traffic_anomaly',
                                'description': f'机器学习检测到流量异常: {traffic_keys[i]}',
                                'severity': 'high',
                                'details': {
                                    'source_target': traffic_keys[i],
                                    'total_bytes': traffic_features[i][0],
                                    'connection_count': traffic_features[i][1]
                                },
                                'timestamp': now
                            })
                
                # 检测用户异常
                user_features = []
                user_keys = []
                
                for username, data in self.user_login_data.items():
                    recent_logins = [d for d in data if d['timestamp'] > now - 60]  # 最近1分钟
                    failed_logins = [d for d in recent_logins if not d['success']]
                    
                    if len(recent_logins) > 0:
                        user_features.append([len(failed_logins), len(recent_logins)])
                        user_keys.append(username)
                
                if user_features:
                    user_features = np.array(user_features)
                    predictions = self.ml_models['user'].predict(user_features)
                    
                    for i, prediction in enumerate(predictions):
                        if prediction == -1:  # -1表示异常
                            anomalies.append({
                                'type': 'ml_user_anomaly',
                                'description': f'机器学习检测到用户异常: {user_keys[i]}',
                                'severity': 'high',
                                'details': {
                                    'username': user_keys[i],
                                    'failed_logins': user_features[i][0],
                                    'total_logins': user_features[i][1]
                                },
                                'timestamp': now
                            })
                
                # 检测数据传输异常
                data_features = []
                data_keys = []
                
                for key, data in self.data_transfer_data.items():
                    recent_transfers = [d for d in data if d['timestamp'] > now - 60]  # 最近1分钟
                    if len(recent_transfers) > 0:
                        total_data = sum(d['data_size'] for d in recent_transfers)
                        sensitive_accesses = len([d for d in recent_transfers if d['data_type'] == 'sensitive'])
                        data_features.append([total_data, sensitive_accesses])
                        data_keys.append(key)
                
                if data_features:
                    data_features = np.array(data_features)
                    predictions = self.ml_models['data'].predict(data_features)
                    
                    for i, prediction in enumerate(predictions):
                        if prediction == -1:  # -1表示异常
                            anomalies.append({
                                'type': 'ml_data_anomaly',
                                'description': f'机器学习检测到数据传输异常: {data_keys[i]}',
                                'severity': 'critical',
                                'details': {
                                    'source_target': data_keys[i],
                                    'total_data': data_features[i][0],
                                    'sensitive_accesses': data_features[i][1]
                                },
                                'timestamp': now
                            })
                
                # 检测系统异常
                system_features = []
                system_keys = []
                
                for host, data in self.resource_data.items():
                    recent_data = [d for d in data if d['timestamp'] > now - 60]  # 最近1分钟
                    if len(recent_data) > 0:
                        avg_cpu = statistics.mean(d['cpu_usage'] for d in recent_data)
                        avg_memory = statistics.mean(d['memory_usage'] for d in recent_data)
                        avg_disk = statistics.mean(d['disk_usage'] for d in recent_data)
                        system_features.append([avg_cpu, avg_memory, avg_disk])
                        system_keys.append(host)
                
                if system_features:
                    system_features = np.array(system_features)
                    predictions = self.ml_models['system'].predict(system_features)
                    
                    for i, prediction in enumerate(predictions):
                        if prediction == -1:  # -1表示异常
                            anomalies.append({
                                'type': 'ml_system_anomaly',
                                'description': f'机器学习检测到系统异常: {system_keys[i]}',
                                'severity': 'high',
                                'details': {
                                    'host': system_keys[i],
                                    'cpu_usage': system_features[i][0],
                                    'memory_usage': system_features[i][1],
                                    'disk_usage': system_features[i][2]
                                },
                                'timestamp': now
                            })
        except Exception as e:
            print(f"Error in machine learning anomaly detection: {e}")
        
        return anomalies
    
    def correlate_anomalies(self, anomalies: List[Dict]) -> List[Dict]:
        """关联分析异常"""
        correlated_anomalies = []
        now = time.time()
        
        # 按时间分组异常
        time_groups = defaultdict(list)
        for anomaly in anomalies:
            time_key = int(anomaly['timestamp'] // 60)  # 按分钟分组
            time_groups[time_key].append(anomaly)
        
        # 分析每组内的异常关联
        for time_key, group_anomalies in time_groups.items():
            if len(group_anomalies) >= 2:
                # 提取IP和服务信息
                ips = set()
                services = set()
                anomaly_types = set()
                
                for anomaly in group_anomalies:
                    details = anomaly.get('details', {})
                    if 'source_target' in details:
                        parts = details['source_target'].split(':')
                        if len(parts) >= 2:
                            ips.add(parts[0])
                            services.add(':'.join(parts[1:]))
                    elif 'ip' in details:
                        ips.add(details['ip'])
                    elif 'host' in details:
                        services.add(details['host'])
                    elif 'username' in details:
                        ips.add(details['username'])  # 用户名作为特殊IP处理
                    
                    anomaly_types.add(anomaly['type'])
                
                # 如果有多个异常类型和共同的IP或服务，认为是相关的
                if len(anomaly_types) >= 2 and (len(ips) >= 1 or len(services) >= 1):
                    correlated_anomalies.append({
                        'type': 'correlated_anomalies',
                        'description': f'检测到相关异常集群',
                        'severity': 'critical',
                        'details': {
                            'anomaly_count': len(group_anomalies),
                            'anomaly_types': list(anomaly_types),
                            'related_ips': list(ips),
                            'related_services': list(services),
                            'timestamp': now
                        },
                        'timestamp': now,
                        'correlated_anomalies': group_anomalies
                    })
        
        return correlated_anomalies
    
    def detect_all_anomalies(self) -> List[Dict]:
        """检测所有类型的异常"""
        anomalies = []
        
        # 学习行为模式
        self.learn_behavior_patterns()
        
        # 检测传统异常
        anomalies.extend(self.detect_traffic_anomalies())
        anomalies.extend(self.detect_user_anomalies())
        anomalies.extend(self.detect_data_anomalies())
        anomalies.extend(self.detect_system_anomalies())
        
        # 检测行为异常
        anomalies.extend(self.detect_behavioral_anomalies())
        
        # 检测机器学习异常
        anomalies.extend(self.detect_machine_learning_anomalies())
        
        # 关联分析异常
        correlated_anomalies = self.correlate_anomalies(anomalies)
        anomalies.extend(correlated_anomalies)
        
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
            'behavior_patterns': {
                'user_patterns_count': len(self.behavior_patterns['user_patterns']),
                'ip_patterns_count': len(self.behavior_patterns['ip_patterns']),
                'service_patterns_count': len(self.behavior_patterns['service_patterns'])
            },
            'thresholds': self.thresholds,
            'last_updated': datetime.now().isoformat()
        }
        return stats
    
    def get_behavior_patterns(self) -> Dict:
        """获取行为模式"""
        return self.behavior_patterns

# 创建单例实例
anomaly_detector = AnomalyDetector()
