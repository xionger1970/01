import threading
import time
import random
from datetime import datetime
from app.core.database import db_manager


class DataSimulator:
    def __init__(self):
        self.running = False
        self.thread = None

        self.attack_types = [
            'SQL Injection', 'XSS', 'DDoS', 'Brute Force',
            'CSRF', 'Command Injection', 'Path Traversal',
            'RCE', 'File Inclusion', 'Other'
        ]

        self.source_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.20',
            '192.168.2.150', '10.1.1.80', '203.0.113.10',
            '198.51.100.25', '192.0.2.30', '185.220.101.15',
            '45.33.32.156', '91.219.237.229', '104.248.12.37'
        ]

        self.target_ips = [
            '192.168.10.1', '192.168.10.2', '192.168.10.3',
            '10.0.0.1', '10.0.0.2', '172.16.0.1'
        ]

        self.request_paths = [
            '/api/v1/login', '/api/v1/users', '/admin/dashboard',
            '/wp-admin/login.php', '/phpmyadmin/', '/api/v1/search',
            '/cgi-bin/test', '/api/v1/upload', '/admin/config',
            '/api/v1/data/export', '/login', '/register'
        ]

        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'sqlmap/1.5', 'Nikto/2.1.6', 'Nmap/7.80',
            'Python-requests/2.28.0', 'curl/7.84.0',
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            'DirBuster/1.0-RC1'
        ]

        self.severities = ['critical', 'high', 'medium', 'low', 'info']
        self.severity_weights = [5, 15, 35, 30, 15]

        self.statuses = ['detected', 'blocked', 'investigating', 'resolved']
        self.status_weights = [40, 35, 15, 10]

        self.methods = ['GET', 'POST', 'PUT', 'DELETE']
        self.method_weights = [40, 35, 15, 10]

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._simulate, daemon=True)
        self.thread.start()
        print("数据模拟器已启动")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("数据模拟器已停止")

    def _simulate(self):
        time.sleep(10)
        while self.running:
            try:
                self._generate_attack_event()
                time.sleep(random.randint(3, 8))
            except Exception as e:
                print(f"数据模拟器错误: {e}")
                time.sleep(5)

    def _generate_attack_event(self):
        data_store = db_manager.pg_conn.data_store.get('attack_events', [])
        max_id = max((e.get('id', 0) for e in data_store), default=0)

        attack_type = random.choice(self.attack_types)
        source_ip = random.choice(self.source_ips)
        target_ip = random.choice(self.target_ips)
        target_port = random.choice([80, 443, 8080, 8443, 3306, 5432, 22, 21])
        severity = random.choices(self.severities, weights=self.severity_weights, k=1)[0]
        status = random.choices(self.statuses, weights=self.status_weights, k=1)[0]
        method = random.choices(self.methods, weights=self.method_weights, k=1)[0]
        path = random.choice(self.request_paths)
        user_agent = random.choice(self.user_agents)
        response_code = random.choice([200, 301, 403, 404, 500, 503])

        event = {
            'id': max_id + 1,
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'source_ip': source_ip,
            'target_ip': target_ip,
            'target_port': target_port,
            'user_agent': user_agent,
            'status': status,
            'request_method': method,
            'request_path': path,
            'request_params': {'param': f'value{random.randint(1, 999)}'},
            'response_code': response_code,
            'severity': severity,
            'details': {
                'description': f'检测到来自 {source_ip} 的{attack_type}攻击',
                'payload': f'{method} {path}',
                'rule_id': f'rule_{random.randint(1000, 9999)}'
            }
        }

        data_store.append(event)
        if len(data_store) > 500:
            data_store.pop(0)


data_simulator = DataSimulator()
