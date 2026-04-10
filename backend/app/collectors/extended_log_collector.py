import os
import re
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


class ExtendedLogCollector:
    def __init__(self):
        self.running = False
        self.threads = []
        self.callback = None
        self.file_positions = {}
        self.lock = threading.Lock()
        self.log_configs = []
    
    def add_log_source(self, config: Dict):
        with self.lock:
            self.log_configs.append(config)
    
    def start(self, callback=None):
        self.running = True
        self.callback = callback
        
        for config in self.log_configs:
            log_path = config.get('path')
            if log_path and os.path.exists(log_path):
                self.file_positions[log_path] = os.path.getsize(log_path)
            elif log_path:
                self.file_positions[log_path] = 0
        
        for config in self.log_configs:
            log_type = config.get('type')
            log_path = config.get('path')
            if log_path:
                thread = threading.Thread(
                    target=self._collect,
                    args=(log_path, log_type, config)
                )
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
        
        print(f"Extended log collector started for {len(self.log_configs)} log sources")
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            thread.join()
        print("Extended log collector stopped")
    
    def _collect(self, log_path: str, log_type: str, config: Dict):
        while self.running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue
                
                current_size = os.path.getsize(log_path)
                if current_size < self.file_positions.get(log_path, 0):
                    self.file_positions[log_path] = 0
                
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self.file_positions.get(log_path, 0))
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                parsed_data = self._parse_log(line, log_type, config)
                                if parsed_data and self.callback:
                                    self.callback(parsed_data)
                            except Exception as e:
                                print(f"Error parsing log line: {e}")
                    self.file_positions[log_path] = f.tell()
                
                time.sleep(0.1)
            except Exception as e:
                print(f"Error collecting logs from {log_path}: {e}")
                time.sleep(1)
    
    def _parse_log(self, line: str, log_type: str, config: Dict) -> Optional[Dict]:
        if log_type == 'firewall':
            return self._parse_firewall_log(line, config)
        elif log_type == 'waf':
            return self._parse_waf_log(line, config)
        elif log_type == 'system':
            return self._parse_system_log(line, config)
        return None
    
    def _parse_firewall_log(self, line: str, config: Dict) -> Optional[Dict]:
        device_name = config.get('device_name', 'unknown')
        format_type = config.get('format', 'generic')
        
        if format_type == 'paloalto':
            return self._parse_paloalto_firewall(line, device_name)
        elif format_type == 'fortinet':
            return self._parse_fortinet_firewall(line, device_name)
        elif format_type == 'cisco':
            return self._parse_cisco_firewall(line, device_name)
        else:
            return self._parse_generic_firewall(line, device_name)
    
    def _parse_paloalto_firewall(self, line: str, device_name: str) -> Optional[Dict]:
        pattern = r'^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<action>\w+)\s+(?P<src_ip>[\d\.]+)\s+(?P<dst_ip>[\d\.]+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)\s+(?P<protocol>\w+)\s+(?P<rule>.*?)$'
        match = re.match(pattern, line)
        if match:
            groups = match.groupdict()
            return {
                'type': 'firewall',
                'device_name': device_name,
                'timestamp': datetime.now().isoformat(),
                'action': groups.get('action', '').lower(),
                'source_ip': groups.get('src_ip'),
                'source_port': int(groups.get('src_port', 0)) if groups.get('src_port') else None,
                'target_ip': groups.get('dst_ip'),
                'target_port': int(groups.get('dst_port', 0)) if groups.get('dst_port') else None,
                'protocol': groups.get('protocol'),
                'rule_name': groups.get('rule'),
                'raw_log': line
            }
        return None
    
    def _parse_fortinet_firewall(self, line: str, device_name: str) -> Optional[Dict]:
        fields = {}
        for part in line.split():
            if '=' in part:
                key, value = part.split('=', 1)
                fields[key] = value.strip('"')
        
        if fields:
            return {
                'type': 'firewall',
                'device_name': device_name,
                'timestamp': datetime.now().isoformat(),
                'action': fields.get('action', '').lower(),
                'source_ip': fields.get('srcip'),
                'source_port': int(fields.get('srcport', 0)) if fields.get('srcport') else None,
                'source_zone': fields.get('srcintf'),
                'target_ip': fields.get('dstip'),
                'target_port': int(fields.get('dstport', 0)) if fields.get('dstport') else None,
                'target_zone': fields.get('dstintf'),
                'protocol': fields.get('proto'),
                'rule_id': int(fields.get('policyid', 0)) if fields.get('policyid') else None,
                'bytes_sent': int(fields.get('sentbyte', 0)) if fields.get('sentbyte') else None,
                'bytes_received': int(fields.get('rcvdbyte', 0)) if fields.get('rcvdbyte') else None,
                'packet_count': int(fields.get('pktcount', 0)) if fields.get('pktcount') else None,
                'raw_log': line
            }
        return None
    
    def _parse_cisco_firewall(self, line: str, device_name: str) -> Optional[Dict]:
        pattern = r'%ASA-\d+-(?P<message_id>\d+):\s+(?P<action>Built|Teardown)\s+(?P<connection_type>\w+)\s+connection\s+.*?from\s+(?P<src_ip>[\d\.]+)/(?P<src_port>\d+)\s+to\s+(?P<dst_ip>[\d\.]+)/(?P<dst_port>\d+)'
        match = re.search(pattern, line)
        if match:
            groups = match.groupdict()
            return {
                'type': 'firewall',
                'device_name': device_name,
                'timestamp': datetime.now().isoformat(),
                'action': groups.get('action', '').lower(),
                'source_ip': groups.get('src_ip'),
                'source_port': int(groups.get('src_port', 0)) if groups.get('src_port') else None,
                'target_ip': groups.get('dst_ip'),
                'target_port': int(groups.get('dst_port', 0)) if groups.get('dst_port') else None,
                'raw_log': line
            }
        return None
    
    def _parse_generic_firewall(self, line: str, device_name: str) -> Optional[Dict]:
        return {
            'type': 'firewall',
            'device_name': device_name,
            'timestamp': datetime.now().isoformat(),
            'action': 'unknown',
            'raw_log': line
        }
    
    def _parse_waf_log(self, line: str, config: Dict) -> Optional[Dict]:
        device_name = config.get('device_name', 'unknown')
        format_type = config.get('format', 'generic')
        
        if format_type == 'modsecurity':
            return self._parse_modsecurity_log(line, device_name)
        elif format_type == 'cloudflare':
            return self._parse_cloudflare_log(line, device_name)
        else:
            return self._parse_generic_waf_log(line, device_name)
    
    def _parse_modsecurity_log(self, line: str, device_name: str) -> Optional[Dict]:
        if '[client' not in line:
            return None
        
        try:
            match = re.search(r'\[client\s+(?P<ip>[\d\.]+)\]', line)
            source_ip = match.group('ip') if match else None
            
            match = re.search(r'Message: "([^"]+)"', line)
            message = match.group(1) if match else None
            
            match = re.search(r'\[id "([^"]+)"\]', line)
            rule_id = match.group(1) if match else None
            
            match = re.search(r'\[msg "([^"]+)"\]', line)
            rule_msg = match.group(1) if match else None
            
            match = re.search(r'\[severity "([^"]+)"\]', line)
            severity = match.group(1) if match else None
            
            return {
                'type': 'waf',
                'device_name': device_name,
                'timestamp': datetime.now().isoformat(),
                'action': 'block' if severity in ['CRITICAL', 'ERROR'] else 'allow',
                'rule_id': rule_id,
                'rule_name': rule_msg,
                'severity': severity,
                'source_ip': source_ip,
                'raw_log': line
            }
        except:
            return None
    
    def _parse_cloudflare_log(self, line: str, device_name: str) -> Optional[Dict]:
        try:
            data = json.loads(line)
            return {
                'type': 'waf',
                'device_name': device_name,
                'timestamp': data.get('EdgeStartTimestamp'),
                'action': data.get('Action', '').lower(),
                'source_ip': data.get('ClientIP'),
                'method': data.get('ClientRequestMethod'),
                'uri': data.get('ClientRequestURI'),
                'user_agent': data.get('ClientRequestUserAgent'),
                'response_code': data.get('EdgeResponseStatus'),
                'country': data.get('ClientCountry'),
                'raw_log': line
            }
        except:
            return None
    
    def _parse_generic_waf_log(self, line: str, device_name: str) -> Optional[Dict]:
        return {
            'type': 'waf',
            'device_name': device_name,
            'timestamp': datetime.now().isoformat(),
            'action': 'unknown',
            'raw_log': line
        }
    
    def _parse_system_log(self, line: str, config: Dict) -> Optional[Dict]:
        device_name = config.get('device_name', 'unknown')
        os_type = config.get('os_type', 'linux')
        
        if os_type == 'windows':
            return self._parse_windows_event_log(line, device_name)
        else:
            return self._parse_linux_syslog(line, device_name)
    
    def _parse_linux_syslog(self, line: str, device_name: str) -> Optional[Dict]:
        pattern = r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
        match = re.match(pattern, line)
        
        if match:
            groups = match.groupdict()
            return {
                'type': 'system',
                'hostname': groups.get('hostname', device_name),
                'os_type': 'linux',
                'timestamp': datetime.now().isoformat(),
                'program': groups.get('program'),
                'pid': int(groups.get('pid', 0)) if groups.get('pid') else None,
                'message': groups.get('message'),
                'severity': 'info',
                'raw_log': line
            }
        
        return {
            'type': 'system',
            'hostname': device_name,
            'os_type': 'linux',
            'timestamp': datetime.now().isoformat(),
            'message': line,
            'severity': 'info',
            'raw_log': line
        }
    
    def _parse_windows_event_log(self, line: str, device_name: str) -> Optional[Dict]:
        try:
            if 'EventCode' in line:
                match = re.search(r'EventCode=(?P<event_code>\d+)', line)
                event_code = int(match.group('event_code')) if match else None
                
                match = re.search(r'ComputerName=(?P<hostname>\S+)', line)
                hostname = match.group('hostname') if match else device_name
                
                return {
                    'type': 'system',
                    'hostname': hostname,
                    'os_type': 'windows',
                    'timestamp': datetime.now().isoformat(),
                    'event_code': event_code,
                    'message': line,
                    'severity': 'info',
                    'raw_log': line
                }
        except:
            pass
        
        return {
            'type': 'system',
            'hostname': device_name,
            'os_type': 'windows',
            'timestamp': datetime.now().isoformat(),
            'message': line,
            'severity': 'info',
            'raw_log': line
        }


extended_log_collector = ExtendedLogCollector()
