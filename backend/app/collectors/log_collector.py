import os
import time
import threading
from datetime import datetime
import re

class LogCollector:
    def __init__(self, log_paths=None, log_type='nginx'):
        self.log_paths = log_paths or ['/var/log/nginx/access.log']
        self.log_type = log_type
        self.running = False
        self.threads = []
        self.callback = None
        self.file_positions = {}
    
    def start(self, callback=None):
        self.running = True
        self.callback = callback
        
        # Initialize file positions
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                self.file_positions[log_path] = os.path.getsize(log_path)
            else:
                self.file_positions[log_path] = 0
        
        # Start a thread for each log file
        for log_path in self.log_paths:
            thread = threading.Thread(target=self._collect, args=(log_path,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"Log collector started for {len(self.log_paths)} log files")
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            thread.join()
        print("Log collector stopped")
    
    def _collect(self, log_path):
        while self.running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue
                
                current_size = os.path.getsize(log_path)
                if current_size < self.file_positions[log_path]:
                    # Log file rotated
                    self.file_positions[log_path] = 0
                
                with open(log_path, 'r') as f:
                    f.seek(self.file_positions[log_path])
                    for line in f:
                        line = line.strip()
                        if line:
                            log_entry = self._parse_log_line(line)
                            if log_entry and self.callback:
                                self.callback(log_entry)
                    self.file_positions[log_path] = f.tell()
                
                time.sleep(0.1)
            except Exception as e:
                print(f"Error collecting logs from {log_path}: {e}")
                time.sleep(1)
    
    def _parse_log_line(self, line):
        if self.log_type == 'nginx':
            return self._parse_nginx_log(line)
        elif self.log_type == 'apache':
            return self._parse_apache_log(line)
        elif self.log_type == 'iis':
            return self._parse_iis_log(line)
        else:
            return self._parse_generic_log(line)
    
    def _parse_nginx_log(self, line):
        # Nginx log format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        pattern = r'([\d.]+) - ([^\s]+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        if match:
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': match.group(1),
                'user': match.group(2) if match.group(2) != '-' else None,
                'request': match.group(4),
                'status': int(match.group(5)),
                'body_bytes_sent': int(match.group(6)),
                'referer': match.group(7) if match.group(7) != '-' else None,
                'user_agent': match.group(8) if match.group(8) != '-' else None
            }
        return None
    
    def _parse_apache_log(self, line):
        # Apache log format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
        pattern = r'([\d.]+) ([^\s]+) ([^\s]+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        if match:
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': match.group(1),
                'user': match.group(3) if match.group(3) != '-' else None,
                'request': match.group(5),
                'status': int(match.group(6)),
                'body_bytes_sent': int(match.group(7)) if match.group(7) != '-' else 0,
                'referer': match.group(8) if match.group(8) != '-' else None,
                'user_agent': match.group(9) if match.group(9) != '-' else None
            }
        return None
    
    def _parse_iis_log(self, line):
        # IIS log format: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
        pattern = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) ([\d.]+) (\w+) ([^\s]+) ([^\s]+) (\d+) ([^\s]+) ([\d.]+) "(.*?)" (\d+) (\d+) (\d+) (\d+)'
        match = re.match(pattern, line)
        if match:
            return {
                'timestamp': f"{match.group(1)}T{match.group(2)}",
                'source_ip': match.group(9),
                'user': match.group(8) if match.group(8) != '-' else None,
                'request_method': match.group(4),
                'request_path': match.group(5),
                'request_params': match.group(6) if match.group(6) != '-' else None,
                'status': int(match.group(11)),
                'user_agent': match.group(10) if match.group(10) != '-' else None,
                'time_taken': int(match.group(14))
            }
        return None
    
    def _parse_generic_log(self, line):
        # For demonstration, generate mock log data
        import random
        
        source_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.2']
        paths = ['/login', '/admin', '/search', '/api', '/profile']
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        status_codes = [200, 400, 401, 403, 404, 500]
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': random.choice(source_ips),
            'request_method': random.choice(methods),
            'request_path': random.choice(paths),
            'status': random.choice(status_codes),
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Simulate some attacks
        if random.random() < 0.1:  # 10% chance of attack
            attack_types = ['sql_injection', 'xss', 'brute_force', 'csrf']
            log_entry['attack_type'] = random.choice(attack_types)
            log_entry['severity'] = random.choice(['low', 'medium', 'high', 'critical'])
        
        return log_entry
