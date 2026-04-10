from typing import Dict, List, Optional
import requests
import json

class SecurityToolIntegrator:
    def __init__(self):
        self.integrations = {
            'waf': None,
            'ids': None,
            'ips': None,
            'siem': None
        }
    
    def configure_waf(self, config: Dict):
        """Configure WAF integration"""
        self.integrations['waf'] = config
        print(f"WAF integration configured: {config}")
    
    def configure_ids(self, config: Dict):
        """Configure IDS integration"""
        self.integrations['ids'] = config
        print(f"IDS integration configured: {config}")
    
    def configure_ips(self, config: Dict):
        """Configure IPS integration"""
        self.integrations['ips'] = config
        print(f"IPS integration configured: {config}")
    
    def configure_siem(self, config: Dict):
        """Configure SIEM integration"""
        self.integrations['siem'] = config
        print(f"SIEM integration configured: {config}")
    
    def get_waf_logs(self) -> List[Dict]:
        """Get logs from WAF"""
        if not self.integrations['waf']:
            return []
        
        # In production, this would call the WAF API
        # For demonstration, return mock data
        return [
            {
                'timestamp': '2023-10-01T12:00:00Z',
                'source_ip': '192.168.1.100',
                'target_host': 'example.com',
                'request_uri': '/login',
                'action': 'block',
                'rule_id': 'SQLI-001',
                'rule_message': 'SQL injection attempt detected'
            },
            {
                'timestamp': '2023-10-01T12:01:00Z',
                'source_ip': '192.168.1.101',
                'target_host': 'example.com',
                'request_uri': '/search',
                'action': 'block',
                'rule_id': 'XSS-001',
                'rule_message': 'XSS attack attempt detected'
            }
        ]
    
    def get_ids_alerts(self) -> List[Dict]:
        """Get alerts from IDS"""
        if not self.integrations['ids']:
            return []
        
        # In production, this would call the IDS API
        # For demonstration, return mock data
        return [
            {
                'timestamp': '2023-10-01T12:02:00Z',
                'source_ip': '192.168.1.102',
                'target_ip': '10.0.0.1',
                'alert_type': 'port_scan',
                'severity': 'medium',
                'description': 'Port scan detected'
            },
            {
                'timestamp': '2023-10-01T12:03:00Z',
                'source_ip': '192.168.1.103',
                'target_ip': '10.0.0.1',
                'alert_type': 'brute_force',
                'severity': 'high',
                'description': 'Brute force attack detected'
            }
        ]
    
    def block_ip(self, ip: str, reason: str) -> bool:
        """Block an IP address using IPS"""
        if not self.integrations['ips']:
            return False
        
        # In production, this would call the IPS API
        # For demonstration, just print the action
        print(f"Blocking IP {ip} for reason: {reason}")
        return True
    
    def send_to_siem(self, event: Dict) -> bool:
        """Send an event to SIEM"""
        if not self.integrations['siem']:
            return False
        
        # In production, this would call the SIEM API
        # For demonstration, just print the event
        print(f"Sending event to SIEM: {json.dumps(event, indent=2)}")
        return True
    
    def get_integration_status(self) -> Dict:
        """Get the status of all integrations"""
        status = {}
        for tool, config in self.integrations.items():
            status[tool] = {
                'configured': config is not None,
                'config': config
            }
        return status
