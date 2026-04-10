from typing import Dict, List
from collections import Counter

class TargetAnalyzer:
    def __init__(self):
        self.attack_targets = []
    
    def add_attack(self, attack: Dict):
        """Add an attack to the target history"""
        self.attack_targets.append(attack)
    
    def analyze_targets(self) -> Dict:
        """Analyze attack targets"""
        # Count attacks by target path
        target_paths = Counter()
        for attack in self.attack_targets:
            target_path = attack.get('request_path', '/')
            target_paths[target_path] += 1
        
        # Count attacks by target port
        target_ports = Counter()
        for attack in self.attack_targets:
            target_port = attack.get('target_port', 80)
            target_ports[target_port] += 1
        
        # Count attacks by target IP
        target_ips = Counter()
        for attack in self.attack_targets:
            target_ip = attack.get('target_ip')
            if target_ip:
                target_ips[target_ip] += 1
        
        # Get top target paths
        top_paths = target_paths.most_common(10)
        
        # Get top target ports
        top_ports = target_ports.most_common(10)
        
        # Get top target IPs
        top_ips = target_ips.most_common(10)
        
        return {
            'total_attacks': len(self.attack_targets),
            'top_paths': [
                {
                    'path': path,
                    'count': count,
                    'attack_types': self._get_attack_types_for_target('request_path', path)
                }
                for path, count in top_paths
            ],
            'top_ports': [
                {
                    'port': port,
                    'count': count
                }
                for port, count in top_ports
            ],
            'top_ips': [
                {
                    'ip': ip,
                    'count': count
                }
                for ip, count in top_ips
            ]
        }
    
    def _get_attack_types_for_target(self, target_field: str, target_value: any) -> Dict:
        """Get attack types for a specific target"""
        attack_types = Counter()
        for attack in self.attack_targets:
            if attack.get(target_field) == target_value:
                attack_type = attack.get('attack_type', 'unknown')
                attack_types[attack_type] += 1
        return dict(attack_types)
    
    def get_target_details(self, target_path: str) -> Dict:
        """Get detailed information about a specific target path"""
        target_attacks = [a for a in self.attack_targets if a.get('request_path') == target_path]
        
        # Count attacks by type for this target
        attack_types = Counter()
        for attack in target_attacks:
            attack_type = attack.get('attack_type', 'unknown')
            attack_types[attack_type] += 1
        
        # Count attacks by severity for this target
        severity_levels = Counter()
        for attack in target_attacks:
            severity = attack.get('severity', 'medium')
            severity_levels[severity] += 1
        
        return {
            'target_path': target_path,
            'total_attacks': len(target_attacks),
            'attack_types': dict(attack_types),
            'severity_distribution': dict(severity_levels),
            'recent_attacks': target_attacks[-5:]  # Last 5 attacks
        }
