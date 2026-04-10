import re
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading
from app.threat_intel.intel_manager import threat_intel_manager

class AdvancedThreatDetector:
    def __init__(self):
        self.lock = threading.Lock()
        self.detection_rules = {
            'sql_injection': {
                'patterns': [
                    r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*['\"].*[;]?",
                    r"(?i)UNION\s+SELECT",
                    r"(?i)OR\s+1=1",
                    r"(?i)AND\s+1=1",
                    r"(?i)DROP\s+TABLE",
                    r"(?i)CREATE\s+TABLE",
                    r"(?i)ALTER\s+TABLE",
                    r"(?i)EXEC\s+xp_",
                    r"(?i)EXECUTE\s+sp_",
                    r"(?i)INFORMATION_SCHEMA",
                    r"(?i)sys\.tables",
                    r"(?i)sys\.columns",
                ],
                'severity': 'high'
            },
            'xss': {
                'patterns': [
                    r"(?i)<script[\s\S]*?>[\s\S]*?</script>",
                    r"(?i)javascript:[^\s]+",
                    r"(?i)on\w+\s*=\s*['\"][^'\"]*['\"]",
                    r"(?i)data:text/html",
                    r"(?i)vbscript:",
                    r"(?i)expression\s*\(",
                ],
                'severity': 'high'
            },
            'csrf': {
                'patterns': [
                    r"(?i)csrf",
                    r"(?i)token",
                    r"(?i)sessionid",
                ],
                'severity': 'medium'
            },
            'command_injection': {
                'patterns': [
                    r"(?i)(cmd|command|exec|system|shell)\s*=\s*['\"].*[;|&].*['\"]",
                    r"(?i);\s*(ls|cat|whoami|pwd|id|uname|ps)\s*",
                    r"(?i)\|\s*(ls|cat|whoami|pwd|id|uname|ps)\s*",
                    r"(?i)&\s*(ls|cat|whoami|pwd|id|uname|ps)\s*",
                    r"(?i)\$\(.*\)",
                    r"(?i)\`.*\`",
                ],
                'severity': 'critical'
            },
            'ransomware': {
                'patterns': [
                    r"(?i)ransom",
                    r"(?i)encrypt",
                    r"(?i)decrypt",
                    r"(?i)bitcoin",
                    r"(?i)monero",
                    r"(?i)wallet",
                    r"(?i)payment",
                    r"(?i)key",
                    r"(?i)lock",
                    r"(?i)unlock",
                ],
                'severity': 'critical'
            },
            'phishing': {
                'patterns': [
                    r"(?i)(login|signin|sign\s*in|log\s*in)\s*['\"].*['\"]",
                    r"(?i)password",
                    r"(?i)account",
                    r"(?i)verify",
                    r"(?i)confirm",
                    r"(?i)secure",
                    r"(?i)bank",
                    r"(?i)paypal",
                    r"(?i)amazon",
                    r"(?i)ebay",
                    r"(?i)google",
                    r"(?i)microsoft",
                ],
                'severity': 'high'
            },
            'c2_communication': {
                'patterns': [
                    r"(?i)beacon",
                    r"(?i)callback",
                    r"(?i)c2",
                    r"(?i)command\s*and\s*control",
                    r"(?i)botnet",
                    r"(?i)zombie",
                    r"(?i)trojan",
                    r"(?i)backdoor",
                    r"(?i)remote\s*access",
                ],
                'severity': 'critical'
            }
        }
        
        self.apt_indicators = {
            'APT1': {
                'ips': ['1.1.1.1', '192.168.1.100'],
                'domains': ['malicious.com', 'attackers.net'],
                'patterns': ['APT1', 'Comment Team', 'Shanghai Group']
            },
            'Lazarus': {
                'ips': ['2.2.2.2', '10.0.0.1'],
                'domains': ['hacker.net', 'botnet.com'],
                'patterns': ['Lazarus', 'Hidden Cobra', 'North Korea']
            }
        }
    
    def detect_sql_injection(self, data: str) -> Tuple[bool, str]:
        """检测SQL注入攻击"""
        patterns = self.detection_rules['sql_injection']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, 'SQL注入攻击'
        return False, ''
    
    def detect_xss(self, data: str) -> Tuple[bool, str]:
        """检测XSS攻击"""
        patterns = self.detection_rules['xss']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, 'XSS攻击'
        return False, ''
    
    def detect_csrf(self, data: str) -> Tuple[bool, str]:
        """检测CSRF攻击"""
        patterns = self.detection_rules['csrf']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, 'CSRF攻击'
        return False, ''
    
    def detect_command_injection(self, data: str) -> Tuple[bool, str]:
        """检测命令注入攻击"""
        patterns = self.detection_rules['command_injection']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, '命令注入攻击'
        return False, ''
    
    def detect_ransomware(self, data: str) -> Tuple[bool, str]:
        """检测勒索软件攻击"""
        patterns = self.detection_rules['ransomware']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, '勒索软件攻击'
        return False, ''
    
    def detect_phishing(self, data: str) -> Tuple[bool, str]:
        """检测钓鱼攻击"""
        patterns = self.detection_rules['phishing']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, '钓鱼攻击'
        return False, ''
    
    def detect_c2_communication(self, data: str) -> Tuple[bool, str]:
        """检测C2通信"""
        patterns = self.detection_rules['c2_communication']['patterns']
        for pattern in patterns:
            if re.search(pattern, data):
                return True, 'C2通信'
        return False, ''
    
    def detect_apt_attack(self, ip: str, domain: str, data: str) -> Tuple[bool, str, Optional[str]]:
        """检测APT攻击"""
        for apt_group, indicators in self.apt_indicators.items():
            # 检查IP
            if ip in indicators['ips']:
                return True, f'APT攻击 - {apt_group}', apt_group
            # 检查域名
            if domain in indicators['domains']:
                return True, f'APT攻击 - {apt_group}', apt_group
            # 检查模式
            for pattern in indicators['patterns']:
                if pattern.lower() in data.lower():
                    return True, f'APT攻击 - {apt_group}', apt_group
        return False, '', None
    
    def detect_web_attack(self, data: str) -> List[Dict]:
        """检测Web攻击"""
        detections = []
        
        # 检测SQL注入
        is_sql_injection, description = self.detect_sql_injection(data)
        if is_sql_injection:
            detections.append({
                'type': 'SQL Injection',
                'description': description,
                'severity': self.detection_rules['sql_injection']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测XSS
        is_xss, description = self.detect_xss(data)
        if is_xss:
            detections.append({
                'type': 'XSS',
                'description': description,
                'severity': self.detection_rules['xss']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测CSRF
        is_csrf, description = self.detect_csrf(data)
        if is_csrf:
            detections.append({
                'type': 'CSRF',
                'description': description,
                'severity': self.detection_rules['csrf']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测命令注入
        is_command_injection, description = self.detect_command_injection(data)
        if is_command_injection:
            detections.append({
                'type': 'Command Injection',
                'description': description,
                'severity': self.detection_rules['command_injection']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        return detections
    
    def detect_advanced_threats(self, ip: str, domain: str, data: str) -> List[Dict]:
        """检测高级威胁"""
        detections = []
        
        # 检测Web攻击
        web_attacks = self.detect_web_attack(data)
        detections.extend(web_attacks)
        
        # 检测勒索软件
        is_ransomware, description = self.detect_ransomware(data)
        if is_ransomware:
            detections.append({
                'type': 'Ransomware',
                'description': description,
                'severity': self.detection_rules['ransomware']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测钓鱼攻击
        is_phishing, description = self.detect_phishing(data)
        if is_phishing:
            detections.append({
                'type': 'Phishing',
                'description': description,
                'severity': self.detection_rules['phishing']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测C2通信
        is_c2, description = self.detect_c2_communication(data)
        if is_c2:
            detections.append({
                'type': 'C2 Communication',
                'description': description,
                'severity': self.detection_rules['c2_communication']['severity'],
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测APT攻击
        is_apt, description, apt_group = self.detect_apt_attack(ip, domain, data)
        if is_apt:
            detections.append({
                'type': 'APT Attack',
                'description': description,
                'severity': 'critical',
                'apt_group': apt_group,
                'timestamp': datetime.now().isoformat()
            })
        
        # 检测威胁情报匹配
        if threat_intel_manager.check_ip(ip):
            detections.append({
                'type': 'Threat Intelligence Match',
                'description': f'Malicious IP detected: {ip}',
                'severity': 'high',
                'timestamp': datetime.now().isoformat()
            })
        
        if domain and threat_intel_manager.check_domain(domain):
            detections.append({
                'type': 'Threat Intelligence Match',
                'description': f'Malicious domain detected: {domain}',
                'severity': 'high',
                'timestamp': datetime.now().isoformat()
            })
        
        return detections
    
    def analyze_file(self, file_content: bytes) -> Dict:
        """分析文件以检测恶意代码"""
        analysis_result = {
            'file_hash': hashlib.sha256(file_content).hexdigest(),
            'file_size': len(file_content),
            'detections': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # 检测文件特征
        file_str = file_content.decode('utf-8', errors='ignore')
        
        # 检测恶意代码模式
        if re.search(r'(?i)malware|virus|trojan|backdoor|ransom', file_str):
            analysis_result['detections'].append({
                'type': 'Malicious Code',
                'description': 'Malicious code patterns detected',
                'severity': 'high'
            })
        
        # 检测加密货币相关代码
        if re.search(r'(?i)bitcoin|ethereum|crypto|wallet|miner', file_str):
            analysis_result['detections'].append({
                'type': 'Cryptocurrency Mining',
                'description': 'Cryptocurrency mining code detected',
                'severity': 'medium'
            })
        
        # 检测网络连接代码
        if re.search(r'(?i)connect|socket|http|https|request', file_str):
            analysis_result['detections'].append({
                'type': 'Network Connection',
                'description': 'Network connection code detected',
                'severity': 'low'
            })
        
        return analysis_result
    
    def get_detection_stats(self) -> Dict:
        """获取检测统计信息"""
        return {
            'enabled_detection_types': list(self.detection_rules.keys()),
            'apt_groups_monitored': list(self.apt_indicators.keys()),
            'total_rules': sum(len(rule['patterns']) for rule in self.detection_rules.values()),
            'last_updated': datetime.now().isoformat()
        }

# 创建单例实例
advanced_detector = AdvancedThreatDetector()
