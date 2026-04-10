import time
import json
from datetime import datetime
from typing import Dict, List, Optional
import threading
from collections import defaultdict

class CloudSecurityManager:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 云环境配置
        self.cloud_environments = []
        
        # 容器环境配置
        self.container_environments = []
        
        # 云安全状态
        self.cloud_security_status = {}
        
        # 容器安全状态
        self.container_security_status = {}
        
        # 云安全事件
        self.cloud_security_events = []
        
        # 容器安全事件
        self.container_security_events = []
        
        # 支持的云服务提供商
        self.supported_cloud_providers = {
            'aws': 'Amazon Web Services',
            'azure': 'Microsoft Azure',
            'gcp': 'Google Cloud Platform',
            'alibaba': 'Alibaba Cloud',
            'tencent': 'Tencent Cloud'
        }
        
        # 支持的容器平台
        self.supported_container_platforms = {
            'docker': 'Docker',
            'kubernetes': 'Kubernetes',
            'openshift': 'OpenShift',
            'containerd': 'Containerd'
        }
        
        # 云安全检查项
        self.cloud_security_checks = {
            'iam_config': 'IAM 配置安全',
            'network_security': '网络安全配置',
            'storage_encryption': '存储加密',
            'logging_monitoring': '日志和监控',
            'compliance': '合规性检查',
            'vulnerability_scanning': '漏洞扫描'
        }
        
        # 容器安全检查项
        self.container_security_checks = {
            'image_scanning': '镜像扫描',
            'runtime_monitoring': '运行时监控',
            'network_policies': '网络策略',
            'resource_limits': '资源限制',
            'secrets_management': '密钥管理',
            'compliance': '合规性检查'
        }
        
        # 启动监控线程
        self._start_monitoring_thread()
    
    def _start_monitoring_thread(self):
        """启动监控线程"""
        def monitor_cloud_security():
            while True:
                time.sleep(300)  # 每5分钟检查一次云环境安全状态
                self._check_cloud_security()
                self._check_container_security()
        
        monitoring_thread = threading.Thread(target=monitor_cloud_security, daemon=True)
        monitoring_thread.start()
    
    def add_cloud_environment(self, environment: Dict) -> Dict:
        """添加云环境配置"""
        with self.lock:
            env_id = len(self.cloud_environments) + 1
            env_with_id = {
                'id': env_id,
                'name': environment.get('name'),
                'provider': environment.get('provider'),
                'region': environment.get('region'),
                'api_key': environment.get('api_key'),
                'secret_key': environment.get('secret_key'),
                'status': 'offline',
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.cloud_environments.append(env_with_id)
            self.cloud_security_status[env_id] = {
                'status': 'offline',
                'last_check': None,
                'issues': []
            }
            
            # 立即检查云环境状态
            self._check_single_cloud_environment(env_with_id)
            
            return env_with_id
    
    def add_container_environment(self, environment: Dict) -> Dict:
        """添加容器环境配置"""
        with self.lock:
            env_id = len(self.container_environments) + 1
            env_with_id = {
                'id': env_id,
                'name': environment.get('name'),
                'platform': environment.get('platform'),
                'endpoint': environment.get('endpoint'),
                'api_key': environment.get('api_key'),
                'status': 'offline',
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.container_environments.append(env_with_id)
            self.container_security_status[env_id] = {
                'status': 'offline',
                'last_check': None,
                'issues': []
            }
            
            # 立即检查容器环境状态
            self._check_single_container_environment(env_with_id)
            
            return env_with_id
    
    def _check_cloud_security(self):
        """检查所有云环境的安全状态"""
        for env in self.cloud_environments:
            self._check_single_cloud_environment(env)
    
    def _check_single_cloud_environment(self, env: Dict):
        """检查单个云环境的安全状态"""
        try:
            # 模拟云环境安全检查
            import random
            status = random.choice(['healthy', 'warning', 'critical'])
            issues = []
            
            if status == 'warning':
                issues = [
                    {'type': 'iam_config', 'severity': 'medium', 'description': '发现未使用的IAM权限'},
                    {'type': 'logging_monitoring', 'severity': 'low', 'description': '部分资源缺少日志配置'}
                ]
            elif status == 'critical':
                issues = [
                    {'type': 'network_security', 'severity': 'high', 'description': '安全组配置过于宽松'},
                    {'type': 'storage_encryption', 'severity': 'high', 'description': '未启用存储加密'},
                    {'type': 'compliance', 'severity': 'medium', 'description': '不符合PCI DSS要求'}
                ]
            
            with self.lock:
                self.cloud_security_status[env['id']] = {
                    'status': status,
                    'last_check': datetime.now(),
                    'issues': issues
                }
                
                # 更新环境状态
                for e in self.cloud_environments:
                    if e['id'] == env['id']:
                        e['status'] = status
                        e['updated_at'] = datetime.now()
                        break
            
            # 生成安全事件
            if issues:
                for issue in issues:
                    self._create_cloud_security_event(env, issue)
        except Exception as e:
            print(f"Error checking cloud environment: {e}")
            with self.lock:
                self.cloud_security_status[env['id']] = {
                    'status': 'error',
                    'last_check': datetime.now(),
                    'issues': [{'type': 'connection', 'severity': 'critical', 'description': str(e)}]
                }
                
                # 更新环境状态
                for e in self.cloud_environments:
                    if e['id'] == env['id']:
                        e['status'] = 'error'
                        e['updated_at'] = datetime.now()
                        break
    
    def _check_container_security(self):
        """检查所有容器环境的安全状态"""
        for env in self.container_environments:
            self._check_single_container_environment(env)
    
    def _check_single_container_environment(self, env: Dict):
        """检查单个容器环境的安全状态"""
        try:
            # 模拟容器环境安全检查
            import random
            status = random.choice(['healthy', 'warning', 'critical'])
            issues = []
            
            if status == 'warning':
                issues = [
                    {'type': 'image_scanning', 'severity': 'medium', 'description': '发现低风险漏洞'},
                    {'type': 'resource_limits', 'severity': 'low', 'description': '部分容器缺少资源限制'}
                ]
            elif status == 'critical':
                issues = [
                    {'type': 'image_scanning', 'severity': 'high', 'description': '发现高危漏洞'},
                    {'type': 'network_policies', 'severity': 'high', 'description': '未配置网络策略'},
                    {'type': 'secrets_management', 'severity': 'medium', 'description': '明文存储密钥'}
                ]
            
            with self.lock:
                self.container_security_status[env['id']] = {
                    'status': status,
                    'last_check': datetime.now(),
                    'issues': issues
                }
                
                # 更新环境状态
                for e in self.container_environments:
                    if e['id'] == env['id']:
                        e['status'] = status
                        e['updated_at'] = datetime.now()
                        break
            
            # 生成安全事件
            if issues:
                for issue in issues:
                    self._create_container_security_event(env, issue)
        except Exception as e:
            print(f"Error checking container environment: {e}")
            with self.lock:
                self.container_security_status[env['id']] = {
                    'status': 'error',
                    'last_check': datetime.now(),
                    'issues': [{'type': 'connection', 'severity': 'critical', 'description': str(e)}]
                }
                
                # 更新环境状态
                for e in self.container_environments:
                    if e['id'] == env['id']:
                        e['status'] = 'error'
                        e['updated_at'] = datetime.now()
                        break
    
    def _create_cloud_security_event(self, env: Dict, issue: Dict):
        """创建云安全事件"""
        event_id = len(self.cloud_security_events) + 1
        event = {
            'id': event_id,
            'cloud_env_id': env['id'],
            'cloud_env_name': env['name'],
            'cloud_provider': env['provider'],
            'issue_type': issue['type'],
            'severity': issue['severity'],
            'description': issue['description'],
            'status': 'open',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        self.cloud_security_events.append(event)
    
    def _create_container_security_event(self, env: Dict, issue: Dict):
        """创建容器安全事件"""
        event_id = len(self.container_security_events) + 1
        event = {
            'id': event_id,
            'container_env_id': env['id'],
            'container_env_name': env['name'],
            'container_platform': env['platform'],
            'issue_type': issue['type'],
            'severity': issue['severity'],
            'description': issue['description'],
            'status': 'open',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        self.container_security_events.append(event)
    
    def get_cloud_environments(self) -> List[Dict]:
        """获取云环境列表"""
        with self.lock:
            return self.cloud_environments.copy()
    
    def get_container_environments(self) -> List[Dict]:
        """获取容器环境列表"""
        with self.lock:
            return self.container_environments.copy()
    
    def get_cloud_security_status(self, env_id: Optional[int] = None) -> Dict:
        """获取云安全状态"""
        with self.lock:
            if env_id:
                return self.cloud_security_status.get(env_id, {})
            return self.cloud_security_status.copy()
    
    def get_container_security_status(self, env_id: Optional[int] = None) -> Dict:
        """获取容器安全状态"""
        with self.lock:
            if env_id:
                return self.container_security_status.get(env_id, {})
            return self.container_security_status.copy()
    
    def get_cloud_security_events(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取云安全事件"""
        with self.lock:
            events = self.cloud_security_events.copy()
            
            if filters:
                filtered_events = []
                for event in events:
                    match = True
                    for key, value in filters.items():
                        if event.get(key) != value:
                            match = False
                    if match:
                        filtered_events.append(event)
                return filtered_events
            
            return events
    
    def get_container_security_events(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取容器安全事件"""
        with self.lock:
            events = self.container_security_events.copy()
            
            if filters:
                filtered_events = []
                for event in events:
                    match = True
                    for key, value in filters.items():
                        if event.get(key) != value:
                            match = False
                    if match:
                        filtered_events.append(event)
                return filtered_events
            
            return events
    
    def update_cloud_security_event_status(self, event_id: int, status: str) -> Optional[Dict]:
        """更新云安全事件状态"""
        with self.lock:
            for event in self.cloud_security_events:
                if event['id'] == event_id:
                    event['status'] = status
                    event['updated_at'] = datetime.now()
                    return event
        return None
    
    def update_container_security_event_status(self, event_id: int, status: str) -> Optional[Dict]:
        """更新容器安全事件状态"""
        with self.lock:
            for event in self.container_security_events:
                if event['id'] == event_id:
                    event['status'] = status
                    event['updated_at'] = datetime.now()
                    return event
        return None
    
    def get_cloud_security_stats(self) -> Dict:
        """获取云安全统计信息"""
        with self.lock:
            stats = {
                'total_cloud_environments': len(self.cloud_environments),
                'status_counts': defaultdict(int),
                'issue_counts': defaultdict(int),
                'events_by_severity': defaultdict(int)
            }
            
            # 统计状态
            for env_id, status in self.cloud_security_status.items():
                stats['status_counts'][status.get('status', 'unknown')] += 1
                
                # 统计问题
                for issue in status.get('issues', []):
                    stats['issue_counts'][issue['type']] += 1
            
            # 统计事件
            for event in self.cloud_security_events:
                stats['events_by_severity'][event['severity']] += 1
            
            return stats
    
    def get_container_security_stats(self) -> Dict:
        """获取容器安全统计信息"""
        with self.lock:
            stats = {
                'total_container_environments': len(self.container_environments),
                'status_counts': defaultdict(int),
                'issue_counts': defaultdict(int),
                'events_by_severity': defaultdict(int)
            }
            
            # 统计状态
            for env_id, status in self.container_security_status.items():
                stats['status_counts'][status.get('status', 'unknown')] += 1
                
                # 统计问题
                for issue in status.get('issues', []):
                    stats['issue_counts'][issue['type']] += 1
            
            # 统计事件
            for event in self.container_security_events:
                stats['events_by_severity'][event['severity']] += 1
            
            return stats
    
    def get_supported_cloud_providers(self) -> Dict:
        """获取支持的云服务提供商"""
        return self.supported_cloud_providers
    
    def get_supported_container_platforms(self) -> Dict:
        """获取支持的容器平台"""
        return self.supported_container_platforms
    
    def get_cloud_security_checks(self) -> Dict:
        """获取云安全检查项"""
        return self.cloud_security_checks
    
    def get_container_security_checks(self) -> Dict:
        """获取容器安全检查项"""
        return self.container_security_checks

# 创建单例实例
cloud_security_manager = CloudSecurityManager()