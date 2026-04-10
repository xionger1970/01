import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Set
import threading


class CVEDetector:
    def __init__(self):
        self.lock = threading.Lock()
        self.cve_rules = self._load_cve_rules()
        self.enabled = True
    
    def _load_cve_rules(self) -> List[Dict]:
        """加载CVE漏洞规则"""
        
        # 内置的CVE规则
        cve_rules = [
            # Log4Shell - CVE-2021-44228
            {
                'id': 1,
                'cve_id': 'CVE-2021-44228',
                'name': 'Log4Shell',
                'description': 'Remote code execution vulnerability in Log4j',
                'severity': 'critical',
                'cvss_score': 10.0,
                'affected_software': ['Log4j 2.x'],
                'detection_pattern': r'\$\{jndi:ldap://|\$\{jndi:rmi://|\$\{jndi:dns://',
                'mitigation': 'Update to Log4j 2.17.1 or later',
                'published_date': '2021-12-09',
                'last_updated': '2021-12-10',
                'enabled': True
            },
            # Spring4Shell - CVE-2022-22965
            {
                'id': 2,
                'cve_id': 'CVE-2022-22965',
                'name': 'Spring4Shell',
                'description': 'Remote code execution in Spring Framework',
                'severity': 'critical',
                'cvss_score': 9.8,
                'affected_software': ['Spring Framework 5.3.x', 'Spring Boot 2.6.x'],
                'detection_pattern': r'class\.module\.classLoader|Class\.forName|Runtime\.getRuntime\.exec',
                'mitigation': 'Update to Spring Framework 5.3.18 or later',
                'published_date': '2022-03-31',
                'last_updated': '2022-04-01',
                'enabled': True
            },
            # CVE-2023-21701 - Windows Print Spooler
            {
                'id': 3,
                'cve_id': 'CVE-2023-21701',
                'name': 'Windows Print Spooler Vulnerability',
                'description': 'Remote code execution in Windows Print Spooler',
                'severity': 'high',
                'cvss_score': 8.8,
                'affected_software': ['Windows Server 2012', 'Windows 10'],
                'detection_pattern': r'SpoolSS\.dll|PrintIsolationHost\.exe',
                'mitigation': 'Apply security updates from Microsoft',
                'published_date': '2023-01-10',
                'last_updated': '2023-01-11',
                'enabled': True
            },
            # CVE-2024-21626 - Apache Struts 2
            {
                'id': 4,
                'cve_id': 'CVE-2024-21626',
                'name': 'Apache Struts 2 Remote Code Execution',
                'description': 'RCE vulnerability in Apache Struts 2',
                'severity': 'critical',
                'cvss_score': 9.8,
                'affected_software': ['Apache Struts 2.5.x', 'Apache Struts 6.0.x'],
                'detection_pattern': r'\$\{#context\.get\("com\.opensymphony\.xwork2\.ActionContext\.container"\)|\$\{#_memberAccess\.allowStaticMethodAccess',
                'mitigation': 'Update to Apache Struts 2.5.33 or 6.3.0.2',
                'published_date': '2024-02-06',
                'last_updated': '2024-02-07',
                'enabled': True
            },
            # CVE-2024-3094 - OpenSSL
            {
                'id': 5,
                'cve_id': 'CVE-2024-3094',
                'name': 'OpenSSL 3.0.x Information Disclosure',
                'description': 'Information disclosure vulnerability in OpenSSL 3.0.x',
                'severity': 'high',
                'cvss_score': 7.5,
                'affected_software': ['OpenSSL 3.0.0 - 3.0.13'],
                'detection_pattern': r'OpenSSL/3\.0\.[0-9]+',
                'mitigation': 'Update to OpenSSL 3.0.14 or later',
                'published_date': '2024-04-09',
                'last_updated': '2024-04-10',
                'enabled': True
            },
            # CVE-2024-4871 - PHP
            {
                'id': 6,
                'cve_id': 'CVE-2024-4871',
                'name': 'PHP Phar Deserialization Vulnerability',
                'description': 'Deserialization vulnerability in PHP Phar extension',
                'severity': 'high',
                'cvss_score': 8.8,
                'affected_software': ['PHP 8.1.x', 'PHP 8.2.x', 'PHP 8.3.x'],
                'detection_pattern': r'\.phar|Phar::loadPhar',
                'mitigation': 'Update to PHP 8.1.29, 8.2.20, 8.3.8 or later',
                'published_date': '2024-06-13',
                'last_updated': '2024-06-14',
                'enabled': True
            }
        ]
        
        return cve_rules
    
    def add_cve_rule(self, rule: Dict) -> Dict:
        """添加CVE规则"""
        
        with self.lock:
            rule_id = len(self.cve_rules) + 1
            rule['id'] = rule_id
            rule['created_at'] = datetime.now().isoformat()
            rule['updated_at'] = datetime.now().isoformat()
            self.cve_rules.append(rule)
            return rule
    
    def update_cve_rule(self, rule_id: int, updates: Dict) -> Optional[Dict]:
        """更新CVE规则"""
        
        with self.lock:
            for rule in self.cve_rules:
                if rule['id'] == rule_id:
                    rule.update(updates)
                    rule['updated_at'] = datetime.now().isoformat()
                    return rule
        return None
    
    def delete_cve_rule(self, rule_id: int) -> bool:
        """删除CVE规则"""
        
        with self.lock:
            for i, rule in enumerate(self.cve_rules):
                if rule['id'] == rule_id:
                    self.cve_rules.pop(i)
                    return True
        return False
    
    def get_cve_rule(self, cve_id: str) -> Optional[Dict]:
        """根据CVE ID获取规则"""
        
        with self.lock:
            for rule in self.cve_rules:
                if rule.get('cve_id') == cve_id and rule.get('enabled', True):
                    return rule
        return None
    
    def get_cve_rules(self) -> List[Dict]:
        """获取所有CVE规则"""
        
        with self.lock:
            return [rule for rule in self.cve_rules if rule.get('enabled', True)]
    
    def detect_cve(self, data: Dict) -> List[Dict]:
        """检测CVE漏洞"""
        
        if not self.enabled:
            return []
        
        detections = []
        fields_to_check = ['request_path', 'request_params', 'user_agent', 'request', 'response_body']
        
        with self.lock:
            for rule in self.cve_rules:
                if not rule.get('enabled', True):
                    continue
                
                pattern = rule.get('detection_pattern')
                if not pattern:
                    continue
                
                for field in fields_to_check:
                    if field in data:
                        value = str(data[field])
                        if re.search(pattern, value, re.IGNORECASE):
                            detections.append({
                                'rule_id': rule['id'],
                                'cve_id': rule['cve_id'],
                                'name': rule['name'],
                                'severity': rule['severity'],
                                'cvss_score': rule.get('cvss_score'),
                                'description': rule['description'],
                                'affected_software': rule.get('affected_software', []),
                                'mitigation': rule.get('mitigation'),
                                'matched_field': field,
                                'matched_value': value,
                                'timestamp': datetime.now().isoformat()
                            })
                            break  # 每个规则只匹配一次
        
        return detections
    
    def get_severity_counts(self) -> Dict[str, int]:
        """获取各严重程度的规则数量"""
        
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        with self.lock:
            for rule in self.cve_rules:
                if rule.get('enabled', True):
                    severity = rule.get('severity', 'low')
                    if severity in counts:
                        counts[severity] += 1
        
        return counts
    
    def search_cve_rules(self, keyword: str) -> List[Dict]:
        """搜索CVE规则"""
        
        results = []
        keyword_lower = keyword.lower()
        
        with self.lock:
            for rule in self.cve_rules:
                if rule.get('enabled', True):
                    if (keyword_lower in rule.get('cve_id', '').lower() or
                        keyword_lower in rule.get('name', '').lower() or
                        keyword_lower in rule.get('description', '').lower()):
                        results.append(rule)
        
        return results
    
    def export_cve_rules(self) -> List[Dict]:
        """导出CVE规则"""
        
        with self.lock:
            return self.cve_rules.copy()
    
    def import_cve_rules(self, rules: List[Dict]) -> int:
        """导入CVE规则"""
        
        imported = 0
        with self.lock:
            for rule in rules:
                # 检查是否已存在
                existing = False
                cve_id = rule.get('cve_id')
                if cve_id:
                    for existing_rule in self.cve_rules:
                        if existing_rule.get('cve_id') == cve_id:
                            existing = True
                            break
                
                if not existing:
                    rule_id = len(self.cve_rules) + 1
                    rule['id'] = rule_id
                    rule['created_at'] = datetime.now().isoformat()
                    rule['updated_at'] = datetime.now().isoformat()
                    self.cve_rules.append(rule)
                    imported += 1
        
        return imported


cve_detector = CVEDetector()
