from datetime import datetime, timedelta
from typing import Dict, List, Optional

class TrendAnalyzer:
    def __init__(self):
        self.attack_history = []
    
    def add_attack(self, attack: Dict):
        """Add an attack to the history"""
        self.attack_history.append(attack)
        # Keep only recent attacks (last 7 days)
        cutoff_time = datetime.now() - timedelta(days=7)
        self.attack_history = [a for a in self.attack_history 
                             if datetime.fromisoformat(a.get('event_time', datetime.now().isoformat())) > cutoff_time]
    
    def analyze_trend(self, time_range: str = '24h') -> Dict:
        """Analyze attack trends over time"""
        # Determine time range
        if time_range == '24h':
            hours = 24
            interval = 1  # 1 hour intervals
        elif time_range == '7d':
            hours = 7 * 24
            interval = 6  # 6 hour intervals
        elif time_range == '30d':
            hours = 30 * 24
            interval = 24  # 24 hour intervals
        else:
            hours = 24
            interval = 1
        
        # Create time buckets
        now = datetime.now()
        buckets = []
        for i in range(0, hours, interval):
            bucket_time = now - timedelta(hours=i)
            buckets.append({
                'timestamp': bucket_time.isoformat(),
                'count': 0,
                'attack_types': {}
            })
        buckets.reverse()  # Sort from oldest to newest
        
        # Fill buckets with attacks
        for attack in self.attack_history:
            attack_time = datetime.fromisoformat(attack.get('event_time', datetime.now().isoformat()))
            if (now - attack_time).total_seconds() / 3600 <= hours:
                # Find the bucket this attack belongs to
                for bucket in buckets:
                    bucket_time = datetime.fromisoformat(bucket['timestamp'])
                    next_bucket_time = bucket_time + timedelta(hours=interval)
                    if bucket_time <= attack_time < next_bucket_time:
                        bucket['count'] += 1
                        attack_type = attack.get('attack_type', 'unknown')
                        bucket['attack_types'][attack_type] = bucket['attack_types'].get(attack_type, 0) + 1
                        break
        
        # Calculate statistics
        total_attacks = len(self.attack_history)
        attack_types = {}
        for attack in self.attack_history:
            attack_type = attack.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        return {
            'time_range': time_range,
            'total_attacks': total_attacks,
            'trend': buckets,
            'attack_types': attack_types,
            'start_time': buckets[0]['timestamp'] if buckets else now.isoformat(),
            'end_time': buckets[-1]['timestamp'] if buckets else now.isoformat()
        }
    
    def get_peak_hours(self) -> List[Dict]:
        """Get the hours with the most attacks"""
        # Group attacks by hour
        hourly_attacks = {}
        for attack in self.attack_history:
            attack_time = datetime.fromisoformat(attack.get('event_time', datetime.now().isoformat()))
            hour_key = attack_time.strftime('%H')
            hourly_attacks[hour_key] = hourly_attacks.get(hour_key, 0) + 1
        
        # Sort by attack count
        sorted_hours = sorted(hourly_attacks.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {
                'hour': hour,
                'attack_count': count
            }
            for hour, count in sorted_hours[:5]  # Top 5 peak hours
        ]
