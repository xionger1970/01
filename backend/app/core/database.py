import os
from dotenv import load_dotenv
from datetime import datetime
from typing import List, Dict, Any, Optional
import threading

load_dotenv()

USE_MOCK_DATABASE = os.getenv('USE_MOCK_DATABASE', 'true').lower() == 'true'

class MockCursor:
    def __init__(self, data: List[Dict]):
        self.data = data
        self.index = 0
    
    def execute(self, query, params=None):
        pass
    
    def fetchall(self):
        return [tuple(d.values()) for d in self.data]
    
    def fetchone(self):
        if self.index < len(self.data):
            result = tuple(self.data[self.index].values())
            self.index += 1
            return result
        return None
    
    def close(self):
        pass

class MockConnection:
    def __init__(self):
        self.data_store = {
            'attack_events': [],
            'alerts': [],
            'users': [{'id': 1, 'username': 'admin', 'password': 'hashed_password', 'role': 'admin'}],
            'configurations': [],
            'notification_channels': [],
            'dashboard_configs': []
        }
        self.lock = threading.Lock()
    
    def cursor(self):
        return MockCursor([])
    
    def commit(self):
        pass
    
    def rollback(self):
        pass
    
    def close(self):
        pass

class MockDatabaseManager:
    def __init__(self):
        self.pg_conn = MockConnection()
        self.pg_cursor = self.pg_conn.cursor()
        
        self.influx_data = []
        self.lock = threading.Lock()
        
        self._init_mock_data()
    
    def _init_mock_data(self):
        now = datetime.now()
        
        self.pg_conn.data_store['attack_events'] = [
            {
                'id': i,
                'timestamp': datetime(now.year, now.month, now.day, (now.hour + i) % 24, i % 60).isoformat(),
                'attack_type': ['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'CSRF'][i % 5],
                'source_ip': f'192.168.1.{i}',
                'target_ip': f'10.0.0.{i % 10}',
                'target_port': [80, 443, 8080, 3306, 22][i % 5],
                'user_agent': f'Mozilla/5.0 (Agent-{i})',
                'status': ['detected', 'blocked', 'investigating'][i % 3],
                'request_method': ['GET', 'POST', 'PUT', 'DELETE'][i % 4],
                'request_path': f'/api/v1/resource/{i}',
                'request_params': {"param": f"value{i}"},
                'response_code': [200, 403, 404, 500][i % 4],
                'severity': ['low', 'medium', 'high', 'critical'][i % 4],
                'details': {"description": f"Attack details for event {i}", "payload": f"payload_{i}"}
            }
            for i in range(1, 51)
        ]
        
        self.pg_conn.data_store['alerts'] = [
            {
                'id': i,
                'title': f'Alert {i}',
                'message': f'Alert message for event {i}',
                'severity': ['low', 'medium', 'high', 'critical'][i % 4],
                'status': ['active', 'acknowledged', 'resolved'][i % 3],
                'created_at': datetime(now.year, now.month, now.day, (now.hour + i) % 24, i % 60).isoformat()
            }
            for i in range(1, 21)
        ]
        
        self.pg_conn.data_store['configurations'] = [
            {
                'id': 1,
                'key': 'detection_sensitivity',
                'value': 'high',
                'description': 'Detection sensitivity level'
            },
            {
                'id': 2,
                'key': 'alert_threshold',
                'value': '10',
                'description': 'Alert threshold per minute'
            }
        ]
        
        self.pg_conn.data_store['notification_channels'] = [
            {
                'id': 1,
                'name': 'Email Notification',
                'type': 'email',
                'config': '{"recipient": "admin@example.com"}',
                'enabled': True
            },
            {
                'id': 2,
                'name': 'Slack Notification',
                'type': 'slack',
                'config': '{"webhook_url": "https://hooks.slack.com/..."}',
                'enabled': False
            }
        ]
    
    def close(self):
        if self.pg_cursor:
            self.pg_cursor.close()
        if self.pg_conn:
            self.pg_conn.close()
    
    def execute_pg_query(self, query, params=None):
        try:
            query_lower = query.lower().strip()
            
            if query_lower.startswith('select'):
                if 'attack_events' in query_lower:
                    return MockCursor(self.pg_conn.data_store['attack_events'])
                elif 'alerts' in query_lower:
                    return MockCursor(self.pg_conn.data_store['alerts'])
                elif 'users' in query_lower:
                    return MockCursor(self.pg_conn.data_store['users'])
                elif 'configurations' in query_lower:
                    return MockCursor(self.pg_conn.data_store['configurations'])
                elif 'notification_channels' in query_lower:
                    return MockCursor(self.pg_conn.data_store['notification_channels'])
                elif 'dashboard_configs' in query_lower:
                    return MockCursor(self.pg_conn.data_store['dashboard_configs'])
            
            elif query_lower.startswith('insert'):
                return MockCursor([])
            
            elif query_lower.startswith('update'):
                return MockCursor([])
            
            elif query_lower.startswith('delete'):
                return MockCursor([])
            
            return MockCursor([])
        except Exception as e:
            raise e
    
    def insert_influx_data(self, measurement, tags, fields, time=None):
        with self.lock:
            self.influx_data.append({
                'measurement': measurement,
                'tags': tags,
                'fields': fields,
                'time': time or datetime.now().isoformat()
            })
    
    def query_influx_data(self, query):
        return self.influx_data

if USE_MOCK_DATABASE:
    db_manager = MockDatabaseManager()
else:
    import psycopg2
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS
    
    class DatabaseManager:
        def __init__(self):
            self.pg_conn = psycopg2.connect(
                host=os.getenv('POSTGRES_HOST', 'localhost'),
                port=os.getenv('POSTGRES_PORT', '5432'),
                database=os.getenv('POSTGRES_DB', 'web_attack_awareness'),
                user=os.getenv('POSTGRES_USER', 'admin'),
                password=os.getenv('POSTGRES_PASSWORD', 'password123')
            )
            self.pg_cursor = self.pg_conn.cursor()
            
            self.influx_client = InfluxDBClient(
                url=os.getenv('INFLUXDB_URL', 'http://localhost:8086'),
                token=os.getenv('INFLUXDB_TOKEN', 'your-token'),
                org=os.getenv('INFLUXDB_ORG', 'your-org'),
                bucket=os.getenv('INFLUXDB_BUCKET', 'web_attack_awareness')
            )
            self.influx_write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            self.influx_query_api = self.influx_client.query_api()
        
        def close(self):
            if self.pg_cursor:
                self.pg_cursor.close()
            if self.pg_conn:
                self.pg_conn.close()
            if self.influx_client:
                self.influx_client.close()
        
        def execute_pg_query(self, query, params=None):
            try:
                self.pg_cursor.execute(query, params or ())
                self.pg_conn.commit()
                return self.pg_cursor
            except Exception as e:
                self.pg_conn.rollback()
                raise e
        
        def insert_influx_data(self, measurement, tags, fields, time=None):
            point = Point(measurement)
            for key, value in tags.items():
                point = point.tag(key, value)
            for key, value in fields.items():
                point = point.field(key, value)
            if time:
                point = point.time(time)
            self.influx_write_api.write(
                bucket=os.getenv('INFLUXDB_BUCKET', 'web_attack_awareness'),
                org=os.getenv('INFLUXDB_ORG', 'your-org'),
                record=point
            )
        
        def query_influx_data(self, query):
            result = self.influx_query_api.query(
                query=query,
                org=os.getenv('INFLUXDB_ORG', 'your-org')
            )
            return result
    
    db_manager = DatabaseManager()
