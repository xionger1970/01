import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
import threading
import requests
from dotenv import load_dotenv
import hashlib

load_dotenv()

class ThreatIntelManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.threat_intel_data = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'malicious_urls': set(),
            'malicious_hashes': set(),  # 添加恶意文件哈希
            'apt_groups': {},
            'threat_indicators': [],
            'threat_campaigns': {},  # 添加威胁活动
            'vulnerabilities': {},  # 添加漏洞情报
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
            },
            'alienvault_otx': {
                'enabled': False,
                'api_key': os.getenv('ALIENVAULT_OTX_API_KEY'),
                'update_interval': 14400  # 4 hours
            },
            'misp': {
                'enabled': False,
                'url': os.getenv('MISP_URL'),
                'api_key': os.getenv('MISP_API_KEY'),
                'update_interval': 18000  # 5 hours
            },
            'abuseipdb': {
                'enabled': False,
                'api_key': os.getenv('ABUSEIPDB_API_KEY'),
                'update_interval': 18000  # 5 hours
            },
            'virustotal': {
                'enabled': False,
                'api_key': os.getenv('VIRUSTOTAL_API_KEY'),
                'update_interval': 21600  # 6 hours
            }
        }
        
        # 威胁情报评分系统
        self.threat_score_system = {
            'ip_score': {},
            'domain_score': {},
            'url_score': {},
            'hash_score': {}
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
        
        # 内置的恶意文件哈希样本
        builtin_malicious_hashes = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # SHA1 of empty string
            'd41d8cd98f00b204e9800998ecf8427e',  # MD5 of empty string
            '098f6bcd4621d373cade4e832627b4f6'   # MD5 test
        }
        
        # 内置的APT组织样本
        builtin_apt_groups = {
            'APT1': {
                'name': 'APT1',
                'country': 'China',
                'description': 'Advanced Persistent Threat group',
                'tactics': ['Spear Phishing', 'Malware', 'Data Exfiltration'],
                'indicators': ['1.1.1.1', 'malicious.com'],
                'activity': 'Active since 2006',
                'targets': ['Government', 'Military', 'Financial']
            },
            'Lazarus': {
                'name': 'Lazarus Group',
                'country': 'North Korea',
                'description': 'State-sponsored hacking group',
                'tactics': ['Ransomware', 'Financial Fraud', 'Espionage'],
                'indicators': ['2.2.2.2', 'attackers.net'],
                'activity': 'Active since 2009',
                'targets': ['Financial', 'Critical Infrastructure', 'Military']
            },
            'Emotet': {
                'name': 'Emotet',
                'country': 'Unknown',
                'description': 'Malware-as-a-Service',
                'tactics': ['Phishing', 'Malware', 'Lateral Movement'],
                'indicators': ['3.3.3.3', 'malware.in'],
                'activity': 'Active since 2014',
                'targets': ['Businesses', 'Government', 'Individuals']
            }
        }
        
        # 内置的威胁活动样本
        builtin_threat_campaigns = {
            'Campaign1': {
                'name': 'Operation Cloud Hopper',
                'description': 'APT campaign targeting managed service providers',
                'start_date': '2017-01-01',
                'apt_group': 'APT1',
                'targets': ['MSPs', 'Enterprise'],
                'tactics': ['Spear Phishing', 'Lateral Movement', 'Data Exfiltration']
            },
            'Campaign2': {
                'name': 'WannaCry',
                'description': 'Ransomware campaign exploiting EternalBlue',
                'start_date': '2017-05-12',
                'apt_group': 'Lazarus',
                'targets': ['Healthcare', 'Government', 'Businesses'],
                'tactics': ['Ransomware', 'Exploit', 'Worm']
            }
        }
        
        # 内置的漏洞情报样本
        builtin_vulnerabilities = {
            'CVE-2021-44228': {
                'cve_id': 'CVE-2021-44228',
                'name': 'Log4Shell',
                'severity': 'Critical',
                'cvss_score': 10.0,
                'description': 'Remote code execution vulnerability in Log4j',
                'affected_software': ['Log4j 2.x'],
                'published_date': '2021-12-09',
                'exploit_available': True
            },
            'CVE-2023-21701': {
                'cve_id': 'CVE-2023-21701',
                'name': 'Windows Print Spooler Vulnerability',
                'severity': 'High',
                'cvss_score': 8.8,
                'description': 'Remote code execution in Windows Print Spooler',
                'affected_software': ['Windows Server 2012', 'Windows 10'],
                'published_date': '2023-01-10',
                'exploit_available': True
            }
        }
        
        with self.lock:
            self.threat_intel_data['malicious_ips'].update(builtin_malicious_ips)
            self.threat_intel_data['malicious_domains'].update(builtin_malicious_domains)
            self.threat_intel_data['malicious_urls'].update(builtin_malicious_urls)
            self.threat_intel_data['malicious_hashes'].update(builtin_malicious_hashes)
            self.threat_intel_data['apt_groups'].update(builtin_apt_groups)
            self.threat_intel_data['threat_campaigns'].update(builtin_threat_campaigns)
            self.threat_intel_data['vulnerabilities'].update(builtin_vulnerabilities)
    
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
                        if 'malicious_hashes' in data:
                            self.threat_intel_data['malicious_hashes'].update(set(data['malicious_hashes']))
                        if 'apt_groups' in data:
                            self.threat_intel_data['apt_groups'].update(data['apt_groups'])
                        if 'threat_campaigns' in data:
                            self.threat_intel_data['threat_campaigns'].update(data['threat_campaigns'])
                        if 'vulnerabilities' in data:
                            self.threat_intel_data['vulnerabilities'].update(data['vulnerabilities'])
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
                    'malicious_hashes': list(self.threat_intel_data['malicious_hashes']),
                    'apt_groups': self.threat_intel_data['apt_groups'],
                    'threat_campaigns': self.threat_intel_data['threat_campaigns'],
                    'vulnerabilities': self.threat_intel_data['vulnerabilities'],
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
            new_malicious_hashes = self._fetch_public_malicious_hashes()
            new_threat_indicators = self._fetch_public_threat_indicators()
            new_threat_campaigns = self._fetch_public_threat_campaigns()
            new_vulnerabilities = self._fetch_public_vulnerabilities()
            
            with self.lock:
                self.threat_intel_data['malicious_ips'].update(new_malicious_ips)
                self.threat_intel_data['malicious_domains'].update(new_malicious_domains)
                self.threat_intel_data['malicious_hashes'].update(new_malicious_hashes)
                self.threat_intel_data['threat_indicators'].extend(new_threat_indicators)
                self.threat_intel_data['threat_campaigns'].update(new_threat_campaigns)
                self.threat_intel_data['vulnerabilities'].update(new_vulnerabilities)
                self.threat_intel_data['last_updated'] = datetime.now()
            
            # 更新威胁评分
            self._update_threat_scores()
            
            self._save_to_file()
            print(f"Threat intelligence updated from public feeds at {self.threat_intel_data['last_updated']}")
        except Exception as e:
            print(f"Error updating threat intel from public feeds: {e}")
    
    def _fetch_public_malicious_ips(self) -> Set[str]:
        """模拟获取公开恶意IP列表"""
        # 模拟数据
        return {
            '6.6.6.6', '7.7.7.7', '8.8.8.8', '9.9.9.9', '10.10.10.10',
            '11.11.11.11', '12.12.12.12', '13.13.13.13', '14.14.14.14', '15.15.15.15'
        }
    
    def _fetch_public_malicious_domains(self) -> Set[str]:
        """模拟获取公开恶意域名列表"""
        # 模拟数据
        return {
            'evil.com', 'hacker.net', 'spam.org', 'trojan.in', 'backdoor.com',
            'malicious-site.com', 'phishing-site.org', 'botnet-command.com', 'ransomware-c2.net', 'exploit-kit.com'
        }
    
    def _fetch_public_malicious_hashes(self) -> Set[str]:
        """模拟获取公开恶意文件哈希列表"""
        # 模拟数据
        return {
            '5f4dcc3b5aa765d61d8327deb882cf99',  # MD5 of 'password'
            'e10adc3949ba59abbe56e057f20f883e',  # MD5 of '123456'
            '25f9e794323b453885f5181f1b624d0b',  # MD5 of '123456789'
            'c33367701511b4f6020ec61ded352059',  # MD5 of 'password123'
            '3f230640b78d7e71ac5514e63a07804f'   # MD5 of 'qwerty'
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
                'created_at': datetime.now().isoformat(),
                'source': 'Public Feed',
                'tags': ['ransomware', 'trojan']
            }
            for i in range(5)
        ]
    
    def _fetch_public_threat_campaigns(self) -> Dict:
        """模拟获取公开威胁活动"""
        # 模拟数据
        return {
            f'Campaign{int(time.time())}': {
                'name': 'Operation Fox Hunt',
                'description': 'APT campaign targeting financial institutions',
                'start_date': datetime.now().strftime('%Y-%m-%d'),
                'apt_group': 'Unknown',
                'targets': ['Banks', 'Financial Services'],
                'tactics': ['Spear Phishing', 'Malware', 'Data Exfiltration'],
                'status': 'Active'
            }
        }
    
    def _fetch_public_vulnerabilities(self) -> Dict:
        """模拟获取公开漏洞情报"""
        # 模拟数据
        return {
            f'CVE-{datetime.now().year}-{int(time.time()) % 10000}': {
                'cve_id': f'CVE-{datetime.now().year}-{int(time.time()) % 10000}',
                'name': 'Critical Web Application Vulnerability',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'description': 'Remote code execution vulnerability in popular web framework',
                'affected_software': ['Web Framework 2.x', 'Web Framework 3.x'],
                'published_date': datetime.now().strftime('%Y-%m-%d'),
                'exploit_available': True,
                'patch_available': False
            }
        }
    
    def _update_threat_scores(self):
        """更新威胁评分"""
        # 简单的威胁评分算法
        with self.lock:
            # 为IP评分
            for ip in self.threat_intel_data['malicious_ips']:
                # 基于IP地址的简单评分
                score = 0.5 + (hash(ip) % 50) / 100.0
                self.threat_score_system['ip_score'][ip] = min(score, 1.0)
            
            # 为域名评分
            for domain in self.threat_intel_data['malicious_domains']:
                # 基于域名长度和特征的简单评分
                score = 0.4 + (len(domain) % 30) / 100.0
                self.threat_score_system['domain_score'][domain] = min(score, 1.0)
            
            # 为URL评分
            for url in self.threat_intel_data['malicious_urls']:
                # 基于URL长度和特征的简单评分
                score = 0.6 + (len(url) % 20) / 100.0
                self.threat_score_system['url_score'][url] = min(score, 1.0)
            
            # 为哈希评分
            for hash_val in self.threat_intel_data['malicious_hashes']:
                # 基于哈希类型的简单评分
                score = 0.7 + (hash(hash_val) % 30) / 100.0
                self.threat_score_system['hash_score'][hash_val] = min(score, 1.0)
    
    def _start_update_thread(self):
        """启动更新线程"""
        def update_task():
            while True:
                try:
                    for source, config in self.intel_sources.items():
                        if config['enabled']:
                            if source == 'public_feeds':
                                self.update_from_public_feeds()
                            elif source == 'alienvault_otx':
                                self.update_from_alienvault_otx()
                            elif source == 'misp':
                                self.update_from_misp()
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
    
    def check_hash(self, hash_val: str) -> bool:
        """检查文件哈希是否在恶意哈希列表中"""
        with self.lock:
            return hash_val in self.threat_intel_data['malicious_hashes']
    
    def get_threat_campaigns(self) -> Dict:
        """获取所有威胁活动"""
        with self.lock:
            return self.threat_intel_data['threat_campaigns'].copy()
    
    def get_vulnerabilities(self) -> Dict:
        """获取所有漏洞情报"""
        with self.lock:
            return self.threat_intel_data['vulnerabilities'].copy()
    
    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict]:
        """根据CVE ID获取漏洞情报"""
        with self.lock:
            return self.threat_intel_data['vulnerabilities'].get(cve_id)
    
    def get_threat_score(self, indicator: str, indicator_type: str) -> float:
        """获取威胁指标的评分"""
        with self.lock:
            if indicator_type == 'ip':
                return self.threat_score_system['ip_score'].get(indicator, 0.0)
            elif indicator_type == 'domain':
                return self.threat_score_system['domain_score'].get(indicator, 0.0)
            elif indicator_type == 'url':
                return self.threat_score_system['url_score'].get(indicator, 0.0)
            elif indicator_type == 'hash':
                return self.threat_score_system['hash_score'].get(indicator, 0.0)
            return 0.0
    
    def add_malicious_hash(self, hash_val: str):
        """添加恶意文件哈希"""
        with self.lock:
            self.threat_intel_data['malicious_hashes'].add(hash_val)
            self._save_to_file()
    
    def get_stats(self) -> Dict:
        """获取威胁情报统计信息"""
        with self.lock:
            return {
                'malicious_ips_count': len(self.threat_intel_data['malicious_ips']),
                'malicious_domains_count': len(self.threat_intel_data['malicious_domains']),
                'malicious_urls_count': len(self.threat_intel_data['malicious_urls']),
                'malicious_hashes_count': len(self.threat_intel_data['malicious_hashes']),
                'apt_groups_count': len(self.threat_intel_data['apt_groups']),
                'threat_campaigns_count': len(self.threat_intel_data['threat_campaigns']),
                'vulnerabilities_count': len(self.threat_intel_data['vulnerabilities']),
                'threat_indicators_count': len(self.threat_intel_data['threat_indicators']),
                'last_updated': self.threat_intel_data['last_updated'].isoformat() if self.threat_intel_data['last_updated'] else None
            }
    
    def update_from_alienvault_otx(self):
        """从 AlienVault OTX 更新威胁情报"""
        try:
            config = self.intel_sources['alienvault_otx']
            api_key = config.get('api_key')
            
            if not api_key:
                print("AlienVault OTX API key not configured")
                return
            
            # OTX API 端点
            base_url = "https://otx.alienvault.com/api/v1"
            headers = {"X-OTX-API-KEY": api_key}
            
            # 获取最新的威胁指标
            response = requests.get(f"{base_url}/pulses/subscribed", headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                
                new_ips = set()
                new_domains = set()
                new_urls = set()
                new_hashes = set()
                new_indicators = []
                
                for pulse in pulses:
                    indicators = pulse.get('indicators', [])
                    for indicator in indicators:
                        indicator_type = indicator.get('type')
                        indicator_value = indicator.get('indicator')
                        
                        if indicator_type == 'IPv4':
                            new_ips.add(indicator_value)
                        elif indicator_type == 'domain':
                            new_domains.add(indicator_value)
                        elif indicator_type == 'URL':
                            new_urls.add(indicator_value)
                        elif indicator_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                            new_hashes.add(indicator_value)
                        
                        # 添加威胁指标
                        new_indicators.append({
                            'id': f'otx_{indicator.get("id")}',
                            'type': indicator_type,
                            'indicator': indicator_value,
                            'description': pulse.get('description', ''),
                            'severity': 'high' if pulse.get('severity') else 'medium',
                            'created_at': pulse.get('created', datetime.now().isoformat()),
                            'source': 'AlienVault OTX',
                            'tags': pulse.get('tags', [])
                        })
                
                with self.lock:
                    self.threat_intel_data['malicious_ips'].update(new_ips)
                    self.threat_intel_data['malicious_domains'].update(new_domains)
                    self.threat_intel_data['malicious_urls'].update(new_urls)
                    self.threat_intel_data['malicious_hashes'].update(new_hashes)
                    self.threat_intel_data['threat_indicators'].extend(new_indicators)
                    self.threat_intel_data['last_updated'] = datetime.now()
                
                self._update_threat_scores()
                self._save_to_file()
                print(f"Threat intelligence updated from AlienVault OTX at {self.threat_intel_data['last_updated']}")
            else:
                print(f"Error updating from AlienVault OTX: {response.status_code}")
        except Exception as e:
            print(f"Error updating from AlienVault OTX: {e}")
    
    def update_from_misp(self):
        """从 MISP 更新威胁情报"""
        try:
            config = self.intel_sources['misp']
            url = config.get('url')
            api_key = config.get('api_key')
            
            if not url or not api_key:
                print("MISP URL or API key not configured")
                return
            
            # MISP API 端点
            headers = {"Authorization": api_key, "Accept": "application/json"}
            
            # 获取最新的事件
            response = requests.get(f"{url}/events/restSearch", headers=headers, params={"limit": 10}, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('response', [])
                
                new_ips = set()
                new_domains = set()
                new_urls = set()
                new_hashes = set()
                new_indicators = []
                
                for event in events:
                    attributes = event.get('Attribute', [])
                    for attribute in attributes:
                        attribute_type = attribute.get('type')
                        attribute_value = attribute.get('value')
                        
                        if attribute_type == 'ip-dst' or attribute_type == 'ip-src':
                            new_ips.add(attribute_value)
                        elif attribute_type == 'domain':
                            new_domains.add(attribute_value)
                        elif attribute_type == 'url':
                            new_urls.add(attribute_value)
                        elif attribute_type in ['md5', 'sha1', 'sha256']:
                            new_hashes.add(attribute_value)
                        
                        # 添加威胁指标
                        new_indicators.append({
                            'id': f'misp_{attribute.get("id")}',
                            'type': attribute_type,
                            'indicator': attribute_value,
                            'description': event.get('info', ''),
                            'severity': 'high' if event.get('threat_level_id') == 1 else 'medium',
                            'created_at': attribute.get('timestamp', datetime.now().timestamp()),
                            'source': 'MISP',
                            'tags': [tag.get('name') for tag in event.get('Tag', [])]
                        })
                
                with self.lock:
                    self.threat_intel_data['malicious_ips'].update(new_ips)
                    self.threat_intel_data['malicious_domains'].update(new_domains)
                    self.threat_intel_data['malicious_urls'].update(new_urls)
                    self.threat_intel_data['malicious_hashes'].update(new_hashes)
                    self.threat_intel_data['threat_indicators'].extend(new_indicators)
                    self.threat_intel_data['last_updated'] = datetime.now()
                
                self._update_threat_scores()
                self._save_to_file()
                print(f"Threat intelligence updated from MISP at {self.threat_intel_data['last_updated']}")
            else:
                print(f"Error updating from MISP: {response.status_code}")
        except Exception as e:
            print(f"Error updating from MISP: {e}")

# 创建单例实例
threat_intel_manager = ThreatIntelManager()
