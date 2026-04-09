import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, DefaultDict
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, window_size=100, threshold=3):
        self.window_size = window_size  # Number of events to consider for statistics
        self.threshold = threshold      # Standard deviation threshold for anomaly detection
        self.event_history = {}         # History of events by type
        self.request_history = {}       # History of requests by IP
        self.behavior_history = defaultdict(list)  # Behavior patterns by IP
        self.geolocation_history = defaultdict(list)  # Geolocation history by IP
        self.session_history = defaultdict(list)  # Session data by IP
    
    def detect(self, data: Dict) -> List[Dict]:
        """Detect anomalies in data"""
        anomalies = []
        
        # Check for request rate anomalies
        request_anomaly = self._detect_request_rate_anomaly(data)
        if request_anomaly:
            anomalies.append(request_anomaly)
        
        # Check for status code anomalies
        status_anomaly = self._detect_status_code_anomaly(data)
        if status_anomaly:
            anomalies.append(status_anomaly)
        
        # Check for payload size anomalies
        payload_anomaly = self._detect_payload_size_anomaly(data)
        if payload_anomaly:
            anomalies.append(payload_anomaly)
        
        # Check for behavior pattern anomalies
        behavior_anomaly = self._detect_behavior_pattern_anomaly(data)
        if behavior_anomaly:
            anomalies.append(behavior_anomaly)
        
        # Check for geolocation anomalies
        geo_anomaly = self._detect_geolocation_anomaly(data)
        if geo_anomaly:
            anomalies.append(geo_anomaly)
        
        # Check for session anomalies
        session_anomaly = self._detect_session_anomaly(data)
        if session_anomaly:
            anomalies.append(session_anomaly)
        
        return anomalies
    
    def _detect_request_rate_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect abnormal request rates from a single IP"""
        source_ip = data.get('source_ip')
        if not source_ip:
            return None
        
        # Initialize history for this IP
        if source_ip not in self.request_history:
            self.request_history[source_ip] = []
        
        # Add current request time
        current_time = datetime.now()
        self.request_history[source_ip].append(current_time)
        
        # Remove old requests (older than 1 minute)
        cutoff_time = current_time - timedelta(minutes=1)
        self.request_history[source_ip] = [t for t in self.request_history[source_ip] if t > cutoff_time]
        
        # Calculate requests per second
        request_count = len(self.request_history[source_ip])
        request_rate = request_count / 60.0  # requests per second
        
        # Check if rate is abnormally high
        if request_rate > 10:  # More than 10 requests per second
            return {
                'rule_id': 'anomaly_request_rate',
                'rule_name': 'Anomaly - High Request Rate',
                'attack_type': 'ddos',
                'severity': 'high',
                'details': {
                    'source_ip': source_ip,
                    'request_rate': request_rate,
                    'request_count': request_count
                }
            }
        
        return None
    
    def _detect_status_code_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect abnormal patterns of status codes"""
        status = data.get('status')
        if not status:
            return None
        
        # Track 4xx and 5xx status codes
        if status >= 400:
            source_ip = data.get('source_ip')
            if source_ip:
                key = f"{source_ip}_error"
                if key not in self.event_history:
                    self.event_history[key] = []
                
                self.event_history[key].append(status)
                # Keep only recent events
                if len(self.event_history[key]) > self.window_size:
                    self.event_history[key].pop(0)
                
                # Check if error rate is high
                error_count = len(self.event_history[key])
                if error_count > self.window_size * 0.5:  # More than 50% errors
                    return {
                        'rule_id': 'anomaly_error_rate',
                        'rule_name': 'Anomaly - High Error Rate',
                        'attack_type': 'brute_force',
                        'severity': 'medium',
                        'details': {
                            'source_ip': source_ip,
                            'error_count': error_count,
                            'window_size': self.window_size
                        }
                    }
        
        return None
    
    def _detect_payload_size_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect abnormal payload sizes"""
        payload_size = data.get('body_bytes_sent') or data.get('bytes_sent')
        if not payload_size:
            return None
        
        # Track payload sizes for the current path
        request_path = data.get('request_path', '/')
        key = f"{request_path}_payload"
        
        if key not in self.event_history:
            self.event_history[key] = []
        
        self.event_history[key].append(payload_size)
        # Keep only recent events
        if len(self.event_history[key]) > self.window_size:
            self.event_history[key].pop(0)
        
        # Calculate statistics
        if len(self.event_history[key]) > 10:  # Need enough data for statistics
            mean = statistics.mean(self.event_history[key])
            stdev = statistics.stdev(self.event_history[key]) if len(self.event_history[key]) > 1 else 0
            
            # Check if current payload is significantly larger than average
            if stdev > 0 and payload_size > mean + self.threshold * stdev:
                return {
                    'rule_id': 'anomaly_payload_size',
                    'rule_name': 'Anomaly - Abnormal Payload Size',
                    'attack_type': 'possible_exploit',
                    'severity': 'medium',
                    'details': {
                        'request_path': request_path,
                        'payload_size': payload_size,
                        'average_size': mean,
                        'standard_deviation': stdev
                    }
                }
        
        return None
    
    def _detect_behavior_pattern_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect abnormal behavior patterns"""
        source_ip = data.get('source_ip')
        if not source_ip:
            return None
        
        # Extract behavior features
        request_method = data.get('request_method', 'GET')
        request_path = data.get('request_path', '/')
        user_agent = data.get('user_agent', '')
        
        # Create behavior signature
        behavior_signature = {
            'method': request_method,
            'path': request_path,
            'user_agent': user_agent[:50]  # Truncate for consistency
        }
        
        # Track behavior for this IP
        self.behavior_history[source_ip].append(behavior_signature)
        
        # Keep only recent behavior
        if len(self.behavior_history[source_ip]) > self.window_size:
            self.behavior_history[source_ip].pop(0)
        
        # Analyze behavior patterns
        if len(self.behavior_history[source_ip]) > 10:
            # Check for sudden changes in behavior
            recent_behavior = self.behavior_history[source_ip][-5:]
            previous_behavior = self.behavior_history[source_ip][:-5]
            
            if previous_behavior:
                # Calculate behavior change score
                change_score = 0
                for recent in recent_behavior:
                    for previous in previous_behavior:
                        if recent['method'] != previous['method']:
                            change_score += 1
                        if recent['path'] != previous['path']:
                            change_score += 2
                        if recent['user_agent'] != previous['user_agent']:
                            change_score += 3
                
                # Check if change score is abnormally high
                avg_change_score = change_score / (len(recent_behavior) * len(previous_behavior))
                if avg_change_score > 2.0:
                    return {
                        'rule_id': 'anomaly_behavior_pattern',
                        'rule_name': 'Anomaly - Abnormal Behavior Pattern',
                        'attack_type': 'suspicious_activity',
                        'severity': 'medium',
                        'details': {
                            'source_ip': source_ip,
                            'change_score': avg_change_score,
                            'recent_behavior': recent_behavior[:2],  # Show first 2 recent behaviors
                            'previous_behavior': previous_behavior[:2]  # Show first 2 previous behaviors
                        }
                    }
        
        return None
    
    def _detect_geolocation_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect geolocation anomalies"""
        source_ip = data.get('source_ip')
        if not source_ip:
            return None
        
        # Simulate geolocation data (in production, use a real geolocation service)
        # For demonstration, we'll generate random country codes
        import random
        countries = ['US', 'CN', 'JP', 'GB', 'DE', 'FR', 'IN', 'BR', 'RU', 'AU']
        current_country = random.choice(countries)
        
        # Track geolocation for this IP
        self.geolocation_history[source_ip].append({
            'country': current_country,
            'timestamp': datetime.now()
        })
        
        # Keep only recent geolocation data
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.geolocation_history[source_ip] = [
            entry for entry in self.geolocation_history[source_ip] 
            if entry['timestamp'] > cutoff_time
        ]
        
        # Check for impossible travel
        if len(self.geolocation_history[source_ip]) >= 2:
            recent_entries = self.geolocation_history[source_ip][-2:]
            time_diff = (recent_entries[1]['timestamp'] - recent_entries[0]['timestamp']).total_seconds()
            
            # If country changed and time is too short (less than 1 hour), flag as anomaly
            if recent_entries[0]['country'] != recent_entries[1]['country'] and time_diff < 3600:
                return {
                    'rule_id': 'anomaly_geolocation',
                    'rule_name': 'Anomaly - Impossible Travel',
                    'attack_type': 'account_takeover',
                    'severity': 'high',
                    'details': {
                        'source_ip': source_ip,
                        'previous_country': recent_entries[0]['country'],
                        'current_country': recent_entries[1]['country'],
                        'time_diff_seconds': time_diff
                    }
                }
        
        return None
    
    def _detect_session_anomaly(self, data: Dict) -> Optional[Dict]:
        """Detect session anomalies"""
        source_ip = data.get('source_ip')
        if not source_ip:
            return None
        
        # Extract session features
        request_path = data.get('request_path', '/')
        request_method = data.get('request_method', 'GET')
        status = data.get('status', 200)
        
        # Track session data
        self.session_history[source_ip].append({
            'path': request_path,
            'method': request_method,
            'status': status,
            'timestamp': datetime.now()
        })
        
        # Keep only recent session data
        cutoff_time = datetime.now() - timedelta(minutes=30)
        self.session_history[source_ip] = [
            entry for entry in self.session_history[source_ip] 
            if entry['timestamp'] > cutoff_time
        ]
        
        # Check for session anomalies
        session_data = self.session_history[source_ip]
        if len(session_data) > 5:
            # Check for rapid sequence of different paths (possible scanning)
            paths = [entry['path'] for entry in session_data]
            unique_paths = len(set(paths))
            
            # If more than 80% unique paths in a short time, flag as scanning
            if unique_paths / len(paths) > 0.8:
                return {
                    'rule_id': 'anomaly_session_scanning',
                    'rule_name': 'Anomaly - Possible Scanning Activity',
                    'attack_type': 'scanning',
                    'severity': 'medium',
                    'details': {
                        'source_ip': source_ip,
                        'unique_paths': unique_paths,
                        'total_requests': len(paths),
                        'paths': paths[:5]  # Show first 5 paths
                    }
                }
            
            # Check for authentication brute force
            auth_attempts = [entry for entry in session_data if '/login' in entry['path'] or '/auth' in entry['path']]
            if len(auth_attempts) > 5:
                error_attempts = [entry for entry in auth_attempts if entry['status'] >= 400]
                if len(error_attempts) / len(auth_attempts) > 0.8:
                    return {
                        'rule_id': 'anomaly_session_brute_force',
                        'rule_name': 'Anomaly - Possible Brute Force Attack',
                        'attack_type': 'brute_force',
                        'severity': 'high',
                        'details': {
                            'source_ip': source_ip,
                            'auth_attempts': len(auth_attempts),
                            'failed_attempts': len(error_attempts)
                        }
                    }
        
        return None