import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
import threading
import requests
from dotenv import load_dotenv

load_dotenv()

class ThreatIntelManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.threat_intel_data = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'malicious_urls': set(),
            'apt_groups': {},
            'threat_indicators': [],
            'last_updated': None
        }
        
        self.intel_sources = {
            'internal': {
                'enabled': True,
                'update_interval': 3600  # 1 hour
            },
            'public_feeds': {
                'enabled': True,
                'update_interval': 7200  # 2 hours
            },
            'custom_feeds': {
                'enabled': False,
                'update_interval': 10800  # 3 hours
            }
        }
        
        self._load_initial_data()
        self._start_update_thread()
    
    def _load_initial_data(self):
        """加载初始威胁情报数据"""
        # 加载内置的威胁情报数据
        self._load_builtin_intel()
        
        # 尝试从本地文件加载数据
        self._load_from_file()
        
        # 从公开情报源更新
        self.update_from_public_feeds()
    
    def _load_builtin_intel(self):
        """加载内置的威胁情报数据"""
        # 内置的恶意IP样本
        builtin_malicious_ips = {
            '1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5',
            '10.0.0.1', '192.168.1.100', '172.16.0.50'
        }
        
        # 内置的恶意域名样本
        builtin_malicious_domains = {
            'malicious.com', 'attackers.net', 'phishing.org',
            'malware.in', 'botnet.com'
        }
        
        # 内置的恶意URL样本
        builtin_malicious_urls = {
            'http://malicious.com/exploit',
            'https://phishing.org/login',
            'http://botnet.com/c2'
        }
        
        # 内置的APT组织样本
        builtin_apt_groups = {
            'APT1': {
                'name': 'APT1',
                'country': 'China',
                'description': 'Advanced Persistent Threat group',
                'tactics': ['Spear Phishing', 'Malware', 'Data Exfiltration'],
                'indicators': ['1.1.1.1', 'malicious.com']
            },
            'Lazarus': {
                'name': 'Lazarus Group',
                'country': 'North Korea',
                'description': 'State-sponsored hacking group',
                'tactics': ['Ransomware', 'Financial Fraud', 'Espionage'],
                'indicators': ['2.2.2.2', 'attackers.net']
            }
        }
        
        with self.lock:
            self.threat_intel_data['malicious_ips'].update(builtin_malicious_ips)
            self.threat_intel_data['malicious_domains'].update(builtin_malicious_domains)
            self.threat_intel_data['malicious_urls'].update(builtin_malicious_urls)
            self.threat_intel_data['apt_groups'].update(builtin_apt_groups)
    
    def _load_from_file(self):
        """从本地文件加载威胁情报数据"""
        intel_file = os.path.join(os.path.dirname(__file__), 'threat_intel.json')
        try:
            if os.path.exists(intel_file):
                with open(intel_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    with self.lock:
                        if 'malicious_ips' in data:
                            self.threat_intel_data['malicious_ips'].update(set(data['malicious_ips']))
                        if 'malicious_domains' in data:
                            self.threat_intel_data['malicious_domains'].update(set(data['malicious_domains']))
                        if 'malicious_urls' in data:
                            self.threat_intel_data['malicious_urls'].update(set(data['malicious_urls']))
                        if 'apt_groups' in data:
                            self.threat_intel_data['apt_groups'].update(data['apt_groups'])
        except Exception as e:
            print(f"Error loading threat intel from file: {e}")
    
    def _save_to_file(self):
        """保存威胁情报数据到本地文件"""
        intel_file = os.path.join(os.path.dirname(__file__), 'threat_intel.json')
        try:
            with self.lock:
                data_to_save = {
                    'malicious_ips': list(self.threat_intel_data['malicious_ips']),
                    'malicious_domains': list(self.threat_intel_data['malicious_domains']),
                    'malicious_urls': list(self.threat_intel_data['malicious_urls']),
                    'apt_groups': self.threat_intel_data['apt_groups'],
                    'last_updated': datetime.now().isoformat()
                }
            with open(intel_file, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving threat intel to file: {e}")
    
    def update_from_public_feeds(self):
        """从公开情报源更新威胁情报"""
        try:
            # 模拟从公开情报源获取数据
            # 在实际应用中，这里可以调用真实的威胁情报API
            new_malicious_ips = self._fetch_public_malicious_ips()
            new_malicious_domains = self._fetch_public_malicious_domains()
            new_threat_indicators = self._fetch_public_threat_indicators()
            
            with self.lock:
                self.threat_intel_data['malicious_ips'].update(new_malicious_ips)
                self.threat_intel_data['malicious_domains'].update(new_malicious_domains)
                self.threat_intel_data['threat_indicators'].extend(new_threat_indicators)
                self.threat_intel_data['last_updated'] = datetime.now()
            
            self._save_to_file()
            print(f"Threat intelligence updated from public feeds at {self.threat_intel_data['last_updated']}")
        except Exception as e:
            print(f"Error updating threat intel from public feeds: {e}")
    
    def _fetch_public_malicious_ips(self) -> Set[str]:
        """模拟获取公开恶意IP列表"""
        # 模拟数据
        return {
            '6.6.6.6', '7.7.7.7', '8.8.8.8', '9.9.9.9', '10.10.10.10'
        }
    
    def _fetch_public_malicious_domains(self) -> Set[str]:
        """模拟获取公开恶意域名列表"""
        # 模拟数据
        return {
            'evil.com', 'hacker.net', 'spam.org', 'trojan.in', 'backdoor.com'
        }
    
    def _fetch_public_threat_indicators(self) -> List[Dict]:
        """模拟获取公开威胁指标"""
        # 模拟数据
        return [
            {
                'id': f'threat_{int(time.time()) + i}',
                'type': 'malware',
                'indicator': f'malware_sample_{i}.exe',
                'description': f'Malware sample {i}',
                'severity': 'high',
                'created_at': datetime.now().isoformat()
            }
            for i in range(5)
        ]
    
    def _start_update_thread(self):
        """启动更新线程"""
        def update_task():
            while True:
                try:
                    for source, config in self.intel_sources.items():
                        if config['enabled']:
                            if source == 'public_feeds':
                                self.update_from_public_feeds()
                            # 其他数据源的更新逻辑
                        time.sleep(config['update_interval'])
                except Exception as e:
                    print(f"Error in threat intel update thread: {e}")
                    time.sleep(60)  # 出错后暂停1分钟
        
        update_thread = threading.Thread(target=update_task, daemon=True)
        update_thread.start()
    
    def check_ip(self, ip: str) -> bool:
        """检查IP是否在恶意IP列表中"""
        with self.lock:
            return ip in self.threat_intel_data['malicious_ips']
    
    def check_domain(self, domain: str) -> bool:
        """检查域名是否在恶意域名列表中"""
        with self.lock:
            return domain in self.threat_intel_data['malicious_domains']
    
    def check_url(self, url: str) -> bool:
        """检查URL是否在恶意URL列表中"""
        with self.lock:
            return any(malicious_url in url for malicious_url in self.threat_intel_data['malicious_urls'])
    
    def get_apt_group_info(self, group_name: str) -> Optional[Dict]:
        """获取APT组织信息"""
        with self.lock:
            return self.threat_intel_data['apt_groups'].get(group_name)
    
    def get_all_apt_groups(self) -> Dict:
        """获取所有APT组织信息"""
        with self.lock:
            return self.threat_intel_data['apt_groups'].copy()
    
    def get_threat_indicators(self, limit: int = 100) -> List[Dict]:
        """获取威胁指标"""
        with self.lock:
            return self.threat_intel_data['threat_indicators'][-limit:]
    
    def add_malicious_ip(self, ip: str):
        """添加恶意IP"""
        with self.lock:
            self.threat_intel_data['malicious_ips'].add(ip)
            self._save_to_file()
    
    def add_malicious_domain(self, domain: str):
        """添加恶意域名"""
        with self.lock:
            self.threat_intel_data['malicious_domains'].add(domain)
            self._save_to_file()
    
    def add_malicious_url(self, url: str):
        """添加恶意URL"""
        with self.lock:
            self.threat_intel_data['malicious_urls'].add(url)
            self._save_to_file()
    
    def get_stats(self) -> Dict:
        """获取威胁情报统计信息"""
        with self.lock:
            return {
                'malicious_ips_count': len(self.threat_intel_data['malicious_ips']),
                'malicious_domains_count': len(self.threat_intel_data['malicious_domains']),
                'malicious_urls_count': len(self.threat_intel_data['malicious_urls']),
                'apt_groups_count': len(self.threat_intel_data['apt_groups']),
                'threat_indicators_count': len(self.threat_intel_data['threat_indicators']),
                'last_updated': self.threat_intel_data['last_updated'].isoformat() if self.threat_intel_data['last_updated'] else None
            }

# 创建单例实例
threat_intel_manager = ThreatIntelManager()
