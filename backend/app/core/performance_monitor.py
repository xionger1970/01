import time
import psutil
import threading
import json
from datetime import datetime
from typing import Dict, List

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            'cpu': [],
            'memory': [],
            'disk': [],
            'network': [],
            'response_times': [],
            'request_counts': []
        }
        self.lock = threading.Lock()
        self.running = False
        self.monitor_thread = None
    
    def start_monitoring(self, interval: int = 5):
        """开始性能监控"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止性能监控"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self, interval: int):
        """监控循环"""
        while self.running:
            self._collect_metrics()
            time.sleep(interval)
    
    def _collect_metrics(self):
        """收集性能指标"""
        timestamp = datetime.now().isoformat()
        
        # 收集CPU使用率
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        
        # 收集内存使用情况
        memory = psutil.virtual_memory()
        memory_used = memory.used / (1024 * 1024 * 1024)  # GB
        memory_total = memory.total / (1024 * 1024 * 1024)  # GB
        memory_percent = memory.percent
        
        # 收集磁盘使用情况
        disk = psutil.disk_usage('/')
        disk_used = disk.used / (1024 * 1024 * 1024)  # GB
        disk_total = disk.total / (1024 * 1024 * 1024)  # GB
        disk_percent = disk.percent
        
        # 收集网络流量
        net_io = psutil.net_io_counters()
        network_sent = net_io.bytes_sent / (1024 * 1024)  # MB
        network_recv = net_io.bytes_recv / (1024 * 1024)  # MB
        
        with self.lock:
            # 限制每个指标的历史数据数量
            max_history = 1000
            
            self.metrics['cpu'].append({
                'timestamp': timestamp,
                'percent': cpu_percent,
                'count': cpu_count
            })
            if len(self.metrics['cpu']) > max_history:
                self.metrics['cpu'] = self.metrics['cpu'][-max_history:]
            
            self.metrics['memory'].append({
                'timestamp': timestamp,
                'used': memory_used,
                'total': memory_total,
                'percent': memory_percent
            })
            if len(self.metrics['memory']) > max_history:
                self.metrics['memory'] = self.metrics['memory'][-max_history:]
            
            self.metrics['disk'].append({
                'timestamp': timestamp,
                'used': disk_used,
                'total': disk_total,
                'percent': disk_percent
            })
            if len(self.metrics['disk']) > max_history:
                self.metrics['disk'] = self.metrics['disk'][-max_history:]
            
            self.metrics['network'].append({
                'timestamp': timestamp,
                'sent': network_sent,
                'recv': network_recv
            })
            if len(self.metrics['network']) > max_history:
                self.metrics['network'] = self.metrics['network'][-max_history:]
    
    def record_response_time(self, endpoint: str, response_time: float):
        """记录API响应时间"""
        timestamp = datetime.now().isoformat()
        with self.lock:
            self.metrics['response_times'].append({
                'timestamp': timestamp,
                'endpoint': endpoint,
                'response_time': response_time
            })
            if len(self.metrics['response_times']) > 1000:
                self.metrics['response_times'] = self.metrics['response_times'][-1000:]
    
    def record_request(self, endpoint: str, method: str, status_code: int):
        """记录API请求"""
        timestamp = datetime.now().isoformat()
        with self.lock:
            self.metrics['request_counts'].append({
                'timestamp': timestamp,
                'endpoint': endpoint,
                'method': method,
                'status_code': status_code
            })
            if len(self.metrics['request_counts']) > 1000:
                self.metrics['request_counts'] = self.metrics['request_counts'][-1000:]
    
    def get_metrics(self, metric_type: str = None, limit: int = 100):
        """获取性能指标"""
        with self.lock:
            if metric_type:
                if metric_type in self.metrics:
                    return self.metrics[metric_type][-limit:]
                else:
                    return []
            else:
                result = {}
                for key, value in self.metrics.items():
                    result[key] = value[-limit:]
                return result
    
    def get_summary(self):
        """获取性能摘要"""
        with self.lock:
            # 计算最近5分钟的平均值
            five_minutes_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
            
            # 过滤最近5分钟的数据
            recent_cpu = [m for m in self.metrics['cpu'] if m['timestamp'] >= five_minutes_ago]
            recent_memory = [m for m in self.metrics['memory'] if m['timestamp'] >= five_minutes_ago]
            recent_disk = [m for m in self.metrics['disk'] if m['timestamp'] >= five_minutes_ago]
            recent_network = [m for m in self.metrics['network'] if m['timestamp'] >= five_minutes_ago]
            recent_response_times = [m for m in self.metrics['response_times'] if m['timestamp'] >= five_minutes_ago]
            recent_requests = [m for m in self.metrics['request_counts'] if m['timestamp'] >= five_minutes_ago]
            
            # 计算平均值
            cpu_avg = sum(m['percent'] for m in recent_cpu) / len(recent_cpu) if recent_cpu else 0
            memory_avg = sum(m['percent'] for m in recent_memory) / len(recent_memory) if recent_memory else 0
            disk_avg = sum(m['percent'] for m in recent_disk) / len(recent_disk) if recent_disk else 0
            network_sent_avg = sum(m['sent'] for m in recent_network) / len(recent_network) if recent_network else 0
            network_recv_avg = sum(m['recv'] for m in recent_network) / len(recent_network) if recent_network else 0
            response_time_avg = sum(m['response_time'] for m in recent_response_times) / len(recent_response_times) if recent_response_times else 0
            request_count = len(recent_requests)
            
            # 计算错误率
            error_count = sum(1 for m in recent_requests if m['status_code'] >= 400)
            error_rate = (error_count / request_count) * 100 if request_count > 0 else 0
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'average_percent': cpu_avg,
                    'count': psutil.cpu_count()
                },
                'memory': {
                    'average_percent': memory_avg,
                    'total_gb': psutil.virtual_memory().total / (1024 * 1024 * 1024)
                },
                'disk': {
                    'average_percent': disk_avg,
                    'total_gb': psutil.disk_usage('/').total / (1024 * 1024 * 1024)
                },
                'network': {
                    'average_sent_mb': network_sent_avg,
                    'average_recv_mb': network_recv_avg
                },
                'api': {
                    'average_response_time_ms': response_time_avg * 1000,
                    'request_count': request_count,
                    'error_rate_percent': error_rate
                }
            }

# 创建单例实例
from datetime import timedelta
performance_monitor = PerformanceMonitor()