import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque


class TrafficStatistics:
    def __init__(self):
        self.lock = threading.Lock()
        
        self.ip_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packet_count': 0,
            'connection_count': 0,
            'first_seen': None,
            'last_seen': None,
            'protocols': set(),
            'target_ips': set()
        })
        
        self.port_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packet_count': 0,
            'connection_count': 0
        })
        
        self.protocol_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packet_count': 0,
            'connection_count': 0
        })
        
        self.time_series_data = deque(maxlen=3600)
        self.top_talkers = []
        self.top_ports = []
        
        self.alert_thresholds = {
            'bytes_per_second': 10000000,
            'packets_per_second': 1000,
            'connections_per_minute': 100
        }
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_task, daemon=True)
        self.cleanup_thread.start()
    
    def add_flow_data(self, flow_data: Dict):
        with self.lock:
            source_ip = flow_data.get('source_ip')
            target_ip = flow_data.get('target_ip')
            protocol = flow_data.get('protocol', 'UNKNOWN')
            source_port = flow_data.get('source_port')
            target_port = flow_data.get('target_port')
            bytes_sent = flow_data.get('bytes_sent', 0)
            bytes_received = flow_data.get('bytes_received', 0)
            packet_count = flow_data.get('packet_count', 0)
            timestamp = datetime.now()
            
            if source_ip:
                self._update_ip_stats(source_ip, bytes_sent, bytes_received, 
                                     packet_count, protocol, target_ip, timestamp)
            
            if target_ip:
                self._update_ip_stats(target_ip, bytes_received, bytes_sent,
                                     packet_count, protocol, source_ip, timestamp)
            
            if source_port:
                self._update_port_stats(source_port, bytes_sent, bytes_received, packet_count)
            
            if target_port:
                self._update_port_stats(target_port, bytes_received, bytes_sent, packet_count)
            
            if protocol:
                self._update_protocol_stats(protocol, bytes_sent, bytes_received, packet_count)
            
            self._add_time_series_data(timestamp, bytes_sent + bytes_received, packet_count)
            
            self._update_top_talkers()
            self._update_top_ports()
    
    def add_http_data(self, http_data: Dict):
        with self.lock:
            source_ip = http_data.get('source_ip')
            target_ip = http_data.get('target_ip')
            timestamp = datetime.now()
            
            if source_ip:
                ip_stat = self.ip_stats[source_ip]
                if not ip_stat['first_seen']:
                    ip_stat['first_seen'] = timestamp
                ip_stat['last_seen'] = timestamp
                ip_stat['protocols'].add('HTTP')
    
    def add_dns_data(self, dns_data: Dict):
        with self.lock:
            source_ip = dns_data.get('source_ip')
            target_ip = dns_data.get('target_ip')
            timestamp = datetime.now()
            
            if source_ip:
                ip_stat = self.ip_stats[source_ip]
                if not ip_stat['first_seen']:
                    ip_stat['first_seen'] = timestamp
                ip_stat['last_seen'] = timestamp
                ip_stat['protocols'].add('DNS')
    
    def _update_ip_stats(self, ip: str, bytes_sent: int, bytes_received: int,
                        packet_count: int, protocol: str, target_ip: Optional[str],
                        timestamp: datetime):
        stat = self.ip_stats[ip]
        stat['bytes_sent'] += bytes_sent
        stat['bytes_received'] += bytes_received
        stat['packet_count'] += packet_count
        stat['connection_count'] += 1
        stat['protocols'].add(protocol)
        if target_ip:
            stat['target_ips'].add(target_ip)
        if not stat['first_seen']:
            stat['first_seen'] = timestamp
        stat['last_seen'] = timestamp
    
    def _update_port_stats(self, port: int, bytes_sent: int, bytes_received: int, packet_count: int):
        stat = self.port_stats[port]
        stat['bytes_sent'] += bytes_sent
        stat['bytes_received'] += bytes_received
        stat['packet_count'] += packet_count
        stat['connection_count'] += 1
    
    def _update_protocol_stats(self, protocol: str, bytes_sent: int, bytes_received: int, packet_count: int):
        stat = self.protocol_stats[protocol]
        stat['bytes_sent'] += bytes_sent
        stat['bytes_received'] += bytes_received
        stat['packet_count'] += packet_count
        stat['connection_count'] += 1
    
    def _add_time_series_data(self, timestamp: datetime, bytes_total: int, packets: int):
        self.time_series_data.append({
            'timestamp': timestamp,
            'bytes': bytes_total,
            'packets': packets
        })
    
    def _update_top_talkers(self, limit: int = 10):
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'],
            reverse=True
        )
        self.top_talkers = [
            {
                'ip': ip,
                'bytes_sent': stat['bytes_sent'],
                'bytes_received': stat['bytes_received'],
                'total_bytes': stat['bytes_sent'] + stat['bytes_received'],
                'packet_count': stat['packet_count'],
                'connection_count': stat['connection_count'],
                'protocols': list(stat['protocols']),
                'last_seen': stat['last_seen'].isoformat() if stat['last_seen'] else None
            }
            for ip, stat in sorted_ips[:limit]
        ]
    
    def _update_top_ports(self, limit: int = 10):
        sorted_ports = sorted(
            self.port_stats.items(),
            key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'],
            reverse=True
        )
        self.top_ports = [
            {
                'port': port,
                'bytes_sent': stat['bytes_sent'],
                'bytes_received': stat['bytes_received'],
                'total_bytes': stat['bytes_sent'] + stat['bytes_received'],
                'packet_count': stat['packet_count'],
                'connection_count': stat['connection_count']
            }
            for port, stat in sorted_ports[:limit]
        ]
    
    def get_overview(self) -> Dict:
        with self.lock:
            now = datetime.now()
            one_minute_ago = now - timedelta(minutes=1)
            
            recent_data = [
                d for d in self.time_series_data
                if d['timestamp'] > one_minute_ago
            ]
            
            bytes_per_second = sum(d['bytes'] for d in recent_data) / 60 if recent_data else 0
            packets_per_second = sum(d['packets'] for d in recent_data) / 60 if recent_data else 0
            
            total_bytes = sum(
                stat['bytes_sent'] + stat['bytes_received']
                for stat in self.ip_stats.values()
            )
            total_packets = sum(
                stat['packet_count'] for stat in self.ip_stats.values()
            )
            total_connections = sum(
                stat['connection_count'] for stat in self.ip_stats.values()
            )
            
            return {
                'total_ips': len(self.ip_stats),
                'total_ports': len(self.port_stats),
                'total_protocols': len(self.protocol_stats),
                'total_bytes': total_bytes,
                'total_packets': total_packets,
                'total_connections': total_connections,
                'bytes_per_second': bytes_per_second,
                'packets_per_second': packets_per_second,
                'top_talkers': self.top_talkers,
                'top_ports': self.top_ports,
                'protocol_distribution': self._get_protocol_distribution(),
                'last_updated': now.isoformat()
            }
    
    def _get_protocol_distribution(self) -> List[Dict]:
        total_bytes = sum(
            stat['bytes_sent'] + stat['bytes_received']
            for stat in self.protocol_stats.values()
        )
        
        distribution = []
        for protocol, stat in self.protocol_stats.items():
            proto_bytes = stat['bytes_sent'] + stat['bytes_received']
            percentage = (proto_bytes / total_bytes * 100) if total_bytes > 0 else 0
            distribution.append({
                'protocol': protocol,
                'bytes': proto_bytes,
                'percentage': percentage,
                'packet_count': stat['packet_count'],
                'connection_count': stat['connection_count']
            })
        
        return sorted(distribution, key=lambda x: x['bytes'], reverse=True)
    
    def get_ip_details(self, ip: str) -> Optional[Dict]:
        with self.lock:
            if ip not in self.ip_stats:
                return None
            
            stat = self.ip_stats[ip]
            return {
                'ip': ip,
                'bytes_sent': stat['bytes_sent'],
                'bytes_received': stat['bytes_received'],
                'total_bytes': stat['bytes_sent'] + stat['bytes_received'],
                'packet_count': stat['packet_count'],
                'connection_count': stat['connection_count'],
                'protocols': list(stat['protocols']),
                'target_ips': list(stat['target_ips']),
                'first_seen': stat['first_seen'].isoformat() if stat['first_seen'] else None,
                'last_seen': stat['last_seen'].isoformat() if stat['last_seen'] else None
            }
    
    def get_time_series(self, minutes: int = 60) -> List[Dict]:
        with self.lock:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            return [
                {
                    'timestamp': d['timestamp'].isoformat(),
                    'bytes': d['bytes'],
                    'packets': d['packets']
                }
                for d in self.time_series_data
                if d['timestamp'] > cutoff
            ]
    
    def check_alerts(self) -> List[Dict]:
        with self.lock:
            alerts = []
            now = datetime.now()
            one_minute_ago = now - timedelta(minutes=1)
            
            recent_data = [
                d for d in self.time_series_data
                if d['timestamp'] > one_minute_ago
            ]
            
            bytes_per_second = sum(d['bytes'] for d in recent_data) / 60 if recent_data else 0
            packets_per_second = sum(d['packets'] for d in recent_data) / 60 if recent_data else 0
            
            if bytes_per_second > self.alert_thresholds['bytes_per_second']:
                alerts.append({
                    'type': 'high_bandwidth',
                    'severity': 'high',
                    'message': f'High bandwidth detected: {bytes_per_second / 1000000:.2f} MB/s',
                    'value': bytes_per_second,
                    'threshold': self.alert_thresholds['bytes_per_second'],
                    'timestamp': now.isoformat()
                })
            
            if packets_per_second > self.alert_thresholds['packets_per_second']:
                alerts.append({
                    'type': 'high_packet_rate',
                    'severity': 'high',
                    'message': f'High packet rate detected: {packets_per_second:.0f} pps',
                    'value': packets_per_second,
                    'threshold': self.alert_thresholds['packets_per_second'],
                    'timestamp': now.isoformat()
                })
            
            for ip, stat in self.ip_stats.items():
                if stat['last_seen'] and stat['last_seen'] > one_minute_ago:
                    connections_in_minute = stat['connection_count']
                    if connections_in_minute > self.alert_thresholds['connections_per_minute']:
                        alerts.append({
                            'type': 'high_connection_rate',
                            'severity': 'medium',
                            'message': f'High connection rate from {ip}: {connections_in_minute} connections/min',
                            'ip': ip,
                            'value': connections_in_minute,
                            'threshold': self.alert_thresholds['connections_per_minute'],
                            'timestamp': now.isoformat()
                        })
            
            return alerts
    
    def _cleanup_task(self):
        while True:
            time.sleep(3600)
            self._cleanup_old_data()
    
    def _cleanup_old_data(self):
        with self.lock:
            cutoff = datetime.now() - timedelta(hours=24)
            
            ips_to_remove = []
            for ip, stat in self.ip_stats.items():
                if stat['last_seen'] and stat['last_seen'] < cutoff:
                    ips_to_remove.append(ip)
            
            for ip in ips_to_remove:
                del self.ip_stats[ip]
            
            self.port_stats.clear()
            self.protocol_stats.clear()
            
            self._update_top_talkers()
            self._update_top_ports()


traffic_statistics = TrafficStatistics()
