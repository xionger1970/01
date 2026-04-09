from datetime import datetime
import json

class DataProcessor:
    def __init__(self):
        self.attack_types = {
            'sql_injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'brute_force': 'Brute Force',
            'csrf': 'Cross-Site Request Forgery',
            'command_injection': 'Command Injection',
            'ddos': 'DDoS Attack',
            'malware': 'Malware Infection',
            'phishing': 'Phishing Attempt'
        }
    
    def process(self, data):
        """Process collected data"""
        if 'attack_type' in data:
            return self._process_attack_event(data)
        elif 'source_ip' in data and 'target_ip' in data:
            return self._process_network_traffic(data)
        elif 'request' in data or 'request_path' in data:
            return self._process_log_entry(data)
        else:
            return self._process_generic_data(data)
    
    def _process_attack_event(self, data):
        """Process attack event data"""
        attack_event = {
            'attack_type': data.get('attack_type'),
            'source_ip': data.get('source_ip'),
            'target_ip': data.get('target_ip', '10.0.0.1'),
            'target_port': data.get('target_port', 80),
            'user_agent': data.get('user_agent'),
            'status': data.get('status', 'attempted'),
            'request_method': data.get('request_method', 'GET'),
            'request_path': data.get('request_path', '/'),
            'request_params': data.get('request_params', {}),
            'response_code': data.get('status', 200),
            'severity': data.get('severity', 'medium'),
            'details': data.get('details', {}),
            'event_time': data.get('timestamp', datetime.now().isoformat())
        }
        return {'type': 'attack_event', 'data': attack_event}
    
    def _process_network_traffic(self, data):
        """Process network traffic data"""
        network_traffic = {
            'protocol': data.get('protocol', 'TCP'),
            'source_ip': data.get('source_ip'),
            'target_ip': data.get('target_ip'),
            'source_port': data.get('source_port'),
            'target_port': data.get('target_port'),
            'direction': data.get('direction', 'inbound'),
            'bytes_sent': data.get('bytes_sent', 0),
            'bytes_received': data.get('bytes_received', 0),
            'packet_count': data.get('packet_count', 1),
            'duration': data.get('duration', 0.0),
            'event_time': data.get('timestamp', datetime.now().isoformat())
        }
        return {'type': 'network_traffic', 'data': network_traffic}
    
    def _process_log_entry(self, data):
        """Process log entry data"""
        # Parse request if it's in combined format
        request = data.get('request')
        request_method = data.get('request_method')
        request_path = data.get('request_path')
        
        if request and not request_method:
            # Parse request string like "GET /path HTTP/1.1"
            parts = request.split(' ', 2)
            if len(parts) >= 2:
                request_method = parts[0]
                request_path = parts[1]
        
        log_entry = {
            'source_ip': data.get('source_ip'),
            'user': data.get('user'),
            'request_method': request_method or 'GET',
            'request_path': request_path or '/',
            'status': data.get('status', 200),
            'body_bytes_sent': data.get('body_bytes_sent', 0),
            'referer': data.get('referer'),
            'user_agent': data.get('user_agent'),
            'event_time': data.get('timestamp', datetime.now().isoformat())
        }
        
        # Check for attack patterns in log entry
        if self._detect_attack(log_entry):
            log_entry['attack_type'] = self._detect_attack(log_entry)
            log_entry['severity'] = self._get_attack_severity(log_entry['attack_type'])
            return {'type': 'attack_event', 'data': log_entry}
        
        return {'type': 'log_entry', 'data': log_entry}
    
    def _process_generic_data(self, data):
        """Process generic data"""
        return {'type': 'generic', 'data': data}
    
    def _detect_attack(self, log_entry):
        """Detect attack patterns in log entry"""
        request_path = log_entry.get('request_path', '')
        user_agent = log_entry.get('user_agent', '')
        
        # Simple attack detection patterns
        if ' OR ' in request_path or "' OR '" in request_path:
            return 'sql_injection'
        elif '<script>' in request_path or '</script>' in request_path:
            return 'xss'
        elif 'admin' in request_path and log_entry.get('status') == 401:
            return 'brute_force'
        elif 'bot' in user_agent.lower() or 'crawler' in user_agent.lower():
            return 'malicious_crawler'
        return None
    
    def _get_attack_severity(self, attack_type):
        """Get severity level for attack type"""
        severity_map = {
            'sql_injection': 'high',
            'xss': 'medium',
            'brute_force': 'medium',
            'csrf': 'low',
            'command_injection': 'critical',
            'ddos': 'high',
            'malware': 'critical',
            'phishing': 'medium',
            'malicious_crawler': 'low'
        }
        return severity_map.get(attack_type, 'medium')
