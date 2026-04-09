import os
from dotenv import load_dotenv
import psycopg2
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Load environment variables
load_dotenv()

class DatabaseManager:
    def __init__(self):
        # PostgreSQL connection
        self.pg_conn = psycopg2.connect(
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            port=os.getenv('POSTGRES_PORT', '5432'),
            database=os.getenv('POSTGRES_DB', 'web_attack_awareness'),
            user=os.getenv('POSTGRES_USER', 'admin'),
            password=os.getenv('POSTGRES_PASSWORD', 'password123')
        )
        self.pg_cursor = self.pg_conn.cursor()
        
        # InfluxDB connection
        self.influx_client = InfluxDBClient(
            url=os.getenv('INFLUXDB_URL', 'http://localhost:8086'),
            token=os.getenv('INFLUXDB_TOKEN', 'your-token'),
            org=os.getenv('INFLUXDB_ORG', 'your-org'),
            bucket=os.getenv('INFLUXDB_BUCKET', 'web_attack_awareness')
        )
        self.influx_write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
        self.influx_query_api = self.influx_client.query_api()
    
    def close(self):
        """Close database connections"""
        if self.pg_cursor:
            self.pg_cursor.close()
        if self.pg_conn:
            self.pg_conn.close()
        if self.influx_client:
            self.influx_client.close()
    
    def execute_pg_query(self, query, params=None):
        """Execute PostgreSQL query"""
        try:
            self.pg_cursor.execute(query, params or ())
            self.pg_conn.commit()
            return self.pg_cursor
        except Exception as e:
            self.pg_conn.rollback()
            raise e
    
    def insert_influx_data(self, measurement, tags, fields, time=None):
        """Insert data into InfluxDB"""
        point = Point(measurement)
        
        # Add tags
        for key, value in tags.items():
            point = point.tag(key, value)
        
        # Add fields
        for key, value in fields.items():
            point = point.field(key, value)
        
        # Add time if provided
        if time:
            point = point.time(time)
        
        # Write to InfluxDB
        self.influx_write_api.write(
            bucket=os.getenv('INFLUXDB_BUCKET', 'web_attack_awareness'),
            org=os.getenv('INFLUXDB_ORG', 'your-org'),
            record=point
        )
    
    def query_influx_data(self, query):
        """Query data from InfluxDB"""
        result = self.influx_query_api.query(
            query=query,
            org=os.getenv('INFLUXDB_ORG', 'your-org')
        )
        return result

# Create singleton instance
db_manager = DatabaseManager()