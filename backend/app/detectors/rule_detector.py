import re
from typing import Dict, List, Optional

class RuleDetector:
    def __init__(self):
        self.rules = self._load_rules()
    
    def _load_rules(self):
        """Load detection rules"""
        return [
            # SQL Injection rules
            {
                'id': 'sql_injection_1',
                'name': 'SQL Injection - OR 1=1',
                'pattern': r"(?i)(OR|or)\s+1\s*=\s*1",
                'attack_type': 'sql_injection',
                'severity': 'high'
            },
            {
                'id': 'sql_injection_2',
                'name': 'SQL Injection - UNION SELECT',
                'pattern': r"(?i)UNION\s+SELECT",
                'attack_type': 'sql_injection',
                'severity': 'high'
            },
            {
                'id': 'sql_injection_3',
                'name': 'SQL Injection - Comments',
                'pattern': r"(--|#|/\*.*?\*/)",
                'attack_type': 'sql_injection',
                'severity': 'medium'
            },
            {
                'id': 'sql_injection_4',
                'name': 'SQL Injection - SQL Functions',
                'pattern': r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+",
                'attack_type': 'sql_injection',
                'severity': 'high'
            },
            # XSS rules
            {
                'id': 'xss_1',
                'name': 'XSS - Script Tag',
                'pattern': r"<script[^>]*>.*?</script>",
                'attack_type': 'xss',
                'severity': 'medium'
            },
            {
                'id': 'xss_2',
                'name': 'XSS - Event Handler',
                'pattern': r"(?i)(on\w+)\s*=",
                'attack_type': 'xss',
                'severity': 'medium'
            },
            {
                'id': 'xss_3',
                'name': 'XSS - JavaScript URLs',
                'pattern': r"(?i)javascript:\s*",
                'attack_type': 'xss',
                'severity': 'medium'
            },
            {
                'id': 'xss_4',
                'name': 'XSS - HTML Entities',
                'pattern': r"&lt;script[^&]*&gt;.*?&lt;/script&gt;",
                'attack_type': 'xss',
                'severity': 'medium'
            },
            # Command Injection rules
            {
                'id': 'command_injection_1',
                'name': 'Command Injection - Shell Metacharacters',
                'pattern': r"(;|\|\||&|&&|\|)\s*[a-z0-9]+",
                'attack_type': 'command_injection',
                'severity': 'critical'
            },
            {
                'id': 'command_injection_2',
                'name': 'Command Injection - File Path Traversal',
                'pattern': r"(\.\./|\.\.\\)",
                'attack_type': 'command_injection',
                'severity': 'high'
            },
            # Brute Force rules
            {
                'id': 'brute_force_1',
                'name': 'Brute Force - Multiple Failed Logins',
                'type': 'frequency',
                'threshold': 5,
                'time_window': 60,  # seconds
                'attack_type': 'brute_force',
                'severity': 'medium'
            },
            # CSRF rules
            {
                'id': 'csrf_1',
                'name': 'CSRF - Missing CSRF Token',
                'type': 'missing_token',
                'attack_type': 'csrf',
                'severity': 'low'
            },
            # DDoS rules
            {
                'id': 'ddos_1',
                'name': 'DDoS - High Request Rate',
                'type': 'rate',
                'threshold': 100,  # requests per second
                'attack_type': 'ddos',
                'severity': 'high'
            },
            # Malware rules
            {
                'id': 'malware_1',
                'name': 'Malware - Known Malicious User Agent',
                'pattern': r"(?i)(bot|crawler|spider|virus|trojan|worm)",
                'attack_type': 'malware',
                'severity': 'medium'
            },
            # Phishing rules
            {
                'id': 'phishing_1',
                'name': 'Phishing - Suspicious URLs',
                'pattern': r"(?i)(login|signin|auth|account).*\.(php|asp|jsp)",
                'attack_type': 'phishing',
                'severity': 'medium'
            },
            # RCE rules
            {
                'id': 'rce_1',
                'name': 'Remote Code Execution - PHP Execution',
                'pattern': r"(?i)eval\(|exec\(|system\(|passthru\(|shell_exec\(",
                'attack_type': 'rce',
                'severity': 'critical'
            },
            # Information Disclosure rules
            {
                'id': 'info_disclosure_1',
                'name': 'Information Disclosure - Error Messages',
                'pattern': r"(?i)(error|exception|stack trace|debug)",
                'attack_type': 'info_disclosure',
                'severity': 'low'
            },
            # Clickjacking rules
            {
                'id': 'clickjacking_1',
                'name': 'Clickjacking - Missing X-Frame-Options',
                'type': 'missing_header',
                'header': 'X-Frame-Options',
                'attack_type': 'clickjacking',
                'severity': 'low'
            },
            # CORS rules
            {
                'id': 'cors_1',
                'name': 'CORS - Wildcard Origin',
                'pattern': r"Access-Control-Allow-Origin: .*\*",
                'attack_type': 'cors',
                'severity': 'low'
            }
        ]
    
    def detect(self, data: Dict) -> List[Dict]:
        """Detect attacks based on rules"""
        detections = []
        
        # Check each rule
        for rule in self.rules:
            if 'pattern' in rule:
                # Pattern-based rule
                match = self._check_pattern_rule(rule, data)
                if match:
                    detections.append(match)
            elif rule.get('type') == 'frequency':
                # Frequency-based rule (would require state tracking)
                pass
            elif rule.get('type') == 'rate':
                # Rate-based rule (would require state tracking)
                pass
            elif rule.get('type') == 'missing_token':
                # Missing token rule
                match = self._check_missing_token_rule(rule, data)
                if match:
                    detections.append(match)
            elif rule.get('type') == 'missing_header':
                # Missing header rule
                match = self._check_missing_header_rule(rule, data)
                if match:
                    detections.append(match)
        
        return detections
    
    def _check_pattern_rule(self, rule: Dict, data: Dict) -> Optional[Dict]:
        """Check pattern-based rule"""
        pattern = re.compile(rule['pattern'])
        
        # Check various fields for the pattern
        fields_to_check = ['request_path', 'request_params', 'user_agent', 'request']
        
        for field in fields_to_check:
            if field in data:
                value = str(data[field])
                if pattern.search(value):
                    return {
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'attack_type': rule['attack_type'],
                        'severity': rule['severity'],
                        'matched_field': field,
                        'matched_value': value
                    }
        
        return None
    
    def _check_missing_token_rule(self, rule: Dict, data: Dict) -> Optional[Dict]:
        """Check missing token rule"""
        # For CSRF, check if POST request is missing CSRF token
        if data.get('request_method') == 'POST':
            # Check if CSRF token is present in request parameters or headers
            has_csrf_token = False
            
            # Check request params
            if 'request_params' in data:
                params = data['request_params']
                if isinstance(params, dict):
                    has_csrf_token = any('csrf' in k.lower() for k in params.keys())
                elif isinstance(params, str):
                    has_csrf_token = 'csrf' in params.lower()
            
            # Check headers (if present)
            if not has_csrf_token and 'headers' in data:
                headers = data['headers']
                if isinstance(headers, dict):
                    has_csrf_token = any('csrf' in k.lower() for k in headers.keys())
            
            if not has_csrf_token:
                return {
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'attack_type': rule['attack_type'],
                    'severity': rule['severity'],
                    'matched_field': 'request_method',
                    'matched_value': 'POST'
                }
        
        return None
    
    def _check_missing_header_rule(self, rule: Dict, data: Dict) -> Optional[Dict]:
        """Check missing header rule"""
        # Check if specified header is missing
        header_name = rule.get('header')
        if header_name:
            # Check headers (if present)
            has_header = False
            if 'headers' in data:
                headers = data['headers']
                if isinstance(headers, dict):
                    has_header = any(header_name.lower() in k.lower() for k in headers.keys())
            
            if not has_header:
                return {
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'attack_type': rule['attack_type'],
                    'severity': rule['severity'],
                    'matched_field': 'headers',
                    'matched_value': 'Missing header: ' + header_name
                }
        
        return None
