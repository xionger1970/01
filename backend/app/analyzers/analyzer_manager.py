from app.analyzers.trend_analyzer import TrendAnalyzer
from app.analyzers.source_analyzer import SourceAnalyzer
from app.analyzers.target_analyzer import TargetAnalyzer
from typing import Dict, List

class AnalyzerManager:
    def __init__(self):
        self.trend_analyzer = TrendAnalyzer()
        self.source_analyzer = SourceAnalyzer()
        self.target_analyzer = TargetAnalyzer()
    
    def add_attack(self, attack: Dict):
        """Add an attack to all analyzers"""
        self.trend_analyzer.add_attack(attack)
        self.source_analyzer.add_attack(attack)
        self.target_analyzer.add_attack(attack)
    
    def analyze_all(self, time_range: str = '24h') -> Dict:
        """Run all analyzers and return combined results"""
        trend_results = self.trend_analyzer.analyze_trend(time_range)
        source_results = self.source_analyzer.analyze_sources()
        target_results = self.target_analyzer.analyze_targets()
        
        return {
            'trend_analysis': trend_results,
            'source_analysis': source_results,
            'target_analysis': target_results,
            'summary': {
                'total_attacks': source_results['total_attacks'],
                'top_attack_types': source_results['attack_types'][:5],
                'top_sources': source_results['top_sources'][:5],
                'top_targets': target_results['top_paths'][:5]
            }
        }
    
    def get_peak_hours(self) -> List[Dict]:
        """Get peak attack hours"""
        return self.trend_analyzer.get_peak_hours()
    
    def get_source_details(self, source_ip: str) -> Dict:
        """Get details for a specific source IP"""
        return self.source_analyzer.get_source_details(source_ip)
    
    def get_target_details(self, target_path: str) -> Dict:
        """Get details for a specific target path"""
        return self.target_analyzer.get_target_details(target_path)
