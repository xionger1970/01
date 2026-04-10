import os
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict
import socket
import struct


class NetworkFlow:
    def __init__(self):
        self.source_ip = None
        self.source_port = None
        self.target_ip = None
        self.target_port = None
        self.protocol = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packet_count = 0
        self.start_time = None
        self.end_time = None
        self.tcp_flags = set()


class NetworkCollector:
    def __init__(self, eve_log_paths=None, log_type='suricata'):
        self.eve_log_paths = eve_log_paths or ['/var/log/suricata/eve.json']
        self.log_type = log_type
        self.running = False
        self.threads = []
        self.callback = None
        self.file_positions = {}
        self.active_flows = {}
        self.lock = threading.Lock()
        
        self.protocol_parsers = {
            'http': self._parse_http,
            'dns': self._parse_dns,
            'ftp': self._parse_ftp
        }
        
    def start(self, callback=None):
        self.running = True
        self.callback = callback
        
        for log_path in self.eve_log_paths:
            if os.path.exists(log_path):
                self.file_positions[log_path] = os.path.getsize(log_path)
            else:
                self.file_positions[log_path] = 0
        
        for log_path in self.eve_log_paths:
            thread = threading.Thread(target=self._collect, args=(log_path,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"Network collector started for {len(self.eve_log_paths)} log files")
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            thread.join()
        print("Network collector stopped")
    
    def _collect(self, log_path):
        while self.running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue
                
                current_size = os.path.getsize(log_path)
                if current_size < self.file_positions.get(log_path, 0):
                    self.file_positions[log_path] = 0
                
                with open(log_path, 'r') as f:
                    f.seek(self.file_positions.get(log_path, 0))
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                log_entry = json.loads(line)
                                parsed_data = self._parse_eve_log(log_entry)
                                if parsed_data and self.callback:
                                    self.callback(parsed_data)
                            except json.JSONDecodeError:
                                pass
                    self.file_positions[log_path] = f.tell()
                
                time.sleep(0.1)
            except Exception as e:
                    print(f"Error collecting network logs from {log_path}: {e}")
                    time.sleep(1)
    
    def _parse_eve_log(self, log_entry):
        event_type = log_entry.get('event_type')
        
        if event_type == 'flow':
            return self._parse_flow_event(log_entry)
        elif event_type == 'http':
            return self._parse_http_event(log_entry)
        elif event_type == 'dns':
            return self._parse_dns_event(log_entry)
        elif event_type == 'alert':
            return self._parse_alert_event(log_entry)
        elif event_type == 'fileinfo':
            return self._parse_file_event(log_entry)
        
        return None
    
    def _parse_flow_event(self, log_entry):
        src_ip = log_entry.get('src_ip')
        src_port = log_entry.get('src_port')
        dest_ip = log_entry.get('dest_ip')
        dest_port = log_entry.get('dest_port')
        proto = log_entry.get('proto')
        
        flow_tuple = (src_ip, src_port, dest_ip, dest_port, proto)
        reverse_tuple = (dest_ip, dest_port, src_ip, src_port, proto)
        
        with self.lock:
            flow = self.active_flows.get(flow_tuple) or self.active_flows.get(reverse_tuple)
            
            if not flow:
                flow = NetworkFlow()
                flow.source_ip = src_ip
                flow.source_port = src_port
                flow.target_ip = dest_ip
                flow.target_port = dest_port
                flow.protocol = proto
                flow.start_time = datetime.fromtimestamp(log_entry.get('timestamp'))
                self.active_flows[flow_tuple] = flow
            
            flow.bytes_sent += log_entry.get('bytes_toserver', 0)
            flow.bytes_received += log_entry.get('bytes_toclient', 0)
            flow.packet_count += log_entry.get('pkts_toserver', 0) + log_entry.get('pkts_toclient', 0)
            flow.end_time = datetime.fromtimestamp(log_entry.get('end_time', log_entry.get('timestamp'))
        
        return {
            'type': 'flow',
            'source_ip': src_ip,
            'source_port': src_port,
            'target_ip': dest_ip,
            'target_port': dest_port,
            'protocol': proto,
            'bytes_sent': flow.bytes_sent,
            'bytes_received': flow.bytes_received,
            'packet_count': flow.packet_count,
            'duration': int((flow.end_time - flow.start_time).total_seconds()) if flow.end_time else 0,
            'start_time': flow.start_time.isoformat() if flow.start_time else None,
            'end_time': flow.end_time.isoformat() if flow.end_time else None,
            'timestamp': datetime.now().isoformat()
        }
    
    def _parse_http_event(self, log_entry):
        http_data = log_entry.get('http', {})
        
        return {
            'type': 'http',
            'source_ip': log_entry.get('src_ip'),
            'source_port': log_entry.get('src_port'),
            'target_ip': log_entry.get('dest_ip'),
            'target_port': log_entry.get('dest_port'),
            'protocol': log_entry.get('proto'),
            'method': http_data.get('http_method'),
            'host': http_data.get('hostname'),
            'url': http_data.get('url'),
            'uri': http_data.get('http_uri'),
            'status_code': http_data.get('status'),
            'user_agent': http_data.get('http_user_agent'),
            'referer': http_data.get('http_refer'),
            'request_headers': http_data.get('request_headers', {}),
            'response_headers': http_data.get('response_headers', {}),
            'content_type': http_data.get('http_content_type'),
            'content_length': http_data.get('length'),
            'timestamp': datetime.fromtimestamp(log_entry.get('timestamp')).isoformat()
        }
    
    def _parse_dns_event(self, log_entry):
        dns_data = log_entry.get('dns', {})
        query_type = dns_data.get('type')
        query_name = dns_data.get('rrname', '').rstrip('.')
        
        answers = []
        for answer in dns_data.get('answers', []):
            answers.append({
                'rrname': answer.get('rrname', '').rstrip('.'),
                'rrtype': answer.get('rrtype'),
                'rdata': answer.get('rdata')
            })
        
        return {
            'type': 'dns',
            'source_ip': log_entry.get('src_ip'),
            'source_port': log_entry.get('src_port'),
            'target_ip': log_entry.get('dest_ip'),
            'target_port': log_entry.get('dest_port'),
            'protocol': log_entry.get('proto'),
            'query_type': query_type,
            'query_name': query_name,
            'answers': answers,
            'response_code': dns_data.get('rcode'),
            'timestamp': datetime.fromtimestamp(log_entry.get('timestamp')).isoformat()
        }
    
    def _parse_ftp_event(self, log_entry):
        return None
    
    def _parse_alert_event(self, log_entry):
        alert_data = log_entry.get('alert', {})
        
        return {
            'type': 'alert',
            'source_ip': log_entry.get('src_ip'),
            'source_port': log_entry.get('src_port'),
            'target_ip': log_entry.get('dest_ip'),
            'target_port': log_entry.get('dest_port'),
            'protocol': log_entry.get('proto'),
            'alert_signature_id': alert_data.get('signature_id'),
            'alert_signature': alert_data.get('signature'),
            'alert_category': alert_data.get('category'),
            'alert_severity': alert_data.get('severity'),
            'timestamp': datetime.fromtimestamp(log_entry.get('timestamp')).isoformat()
        }
    
    def _parse_file_event(self, log_entry):
        file_data = log_entry.get('fileinfo', {})
        
        return {
            'type': 'file',
            'source_ip': log_entry.get('src_ip'),
            'source_port': log_entry.get('src_port'),
            'target_ip': log_entry.get('dest_ip'),
            'target_port': log_entry.get('dest_port'),
            'protocol': log_entry.get('proto'),
            'filename': file_data.get('filename'),
            'file_size': file_data.get('size'),
            'file_magic': file_data.get('magic'),
            'file_md5': file_data.get('md5'),
            'file_sha1': file_data.get('sha1'),
            'file_sha256': file_data.get('sha256'),
            'timestamp': datetime.fromtimestamp(log_entry.get('timestamp')).isoformat()
        }
    
    def _parse_http(self, data):
        return self._parse_http_event(data)
    
    def _parse_dns(self, data):
        return self._parse_dns_event(data)
    
    def _parse_ftp(self, data):
        return self._parse_ftp_event(data)
    
    def get_flow_stats(self) -> Dict:
        with self.lock:
            return {
                'active_flows': len(self.active_flows),
                'total_connections': sum(
                    flow.packet_count for flow in self.active_flows.values()
                ),
                'total_bytes': sum(
                    flow.bytes_sent + flow.bytes_received
                    for flow in self.active_flows.values()
                ),
                'last_updated': datetime.now().isoformat()
            }


network_collector = NetworkCollector()
