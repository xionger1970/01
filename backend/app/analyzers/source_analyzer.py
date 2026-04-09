from typing import Dict, List
from collections import Counter

class SourceAnalyzer:
    def __init__(self):
        self.attack_sources = []
    
    def add_attack(self, attack: Dict):
        """Add an attack to the source history"""
        self.attack_sources.append(attack)
    
    def analyze_sources(self) -> Dict:
        """Analyze attack sources"""
        # Count attacks by source IP
        source_ips = Counter()
        for attack in self.attack_sources:
            source_ip = attack.get('source_ip')
            if source_ip:
                source_ips[source_ip] += 1
        
        # Count attacks by attack type
        attack_types = Counter()
        for attack in self.attack_sources:
            attack_type = attack.get('attack_type', 'unknown')
            attack_types[attack_type] += 1
        
        # Count attacks by severity
        severity_levels = Counter()
        for attack in self.attack_sources:
            severity = attack.get('severity', 'medium')
            severity_levels[severity] += 1
        
        # Get top source IPs
        top_sources = source_ips.most_common(10)
        
        # Get top attack types
        top_attack_types = attack_types.most_common(10)
        
        return {
            'total_attacks': len(self.attack_sources),
            'top_sources': [
                {
                    'ip': ip,
                    'count': count,
                    'attacks': [a for a in self.attack_sources if a.get('source_ip') == ip]
                }
                for ip, count in top_sources
            ],
            'attack_types': [
                {
                    'type': attack_type,
                    'count': count
                }
                for attack_type, count in top_attack_types
            ],
            'severity_distribution': dict(severity_levels)
        }
    
    def get_source_details(self, source_ip: str) -> Dict:
        """Get detailed information about a specific source IP"""
        source_attacks = [a for a in self.attack_sources if a.get('source_ip') == source_ip]
        
        # Count attacks by type for this source
        attack_types = Counter()
        for attack in source_attacks:
            attack_type = attack.get('attack_type', 'unknown')
            attack_types[attack_type] += 1
        
        # Count attacks by severity for this source
        severity_levels = Counter()
        for attack in source_attacks:
            severity = attack.get('severity', 'medium')
            severity_levels[severity] += 1
        
        return {
            'source_ip': source_ip,
            'total_attacks': len(source_attacks),
            'attack_types': dict(attack_types),
            'severity_distribution': dict(severity_levels),
            'recent_attacks': source_attacks[-5:]  # Last 5 attacks
        }
