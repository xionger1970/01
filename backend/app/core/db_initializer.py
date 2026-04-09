from app.core.database import db_manager

class DatabaseInitializer:
    @staticmethod
    def initialize_database():
        """Initialize database schema"""
        # Create tables if they don't exist
        DatabaseInitializer._create_tables()
        print("Database initialization completed")
    
    @staticmethod
    def _create_tables():
        """Create database tables"""
        # Create attack_events table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS attack_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP NOT NULL,
            source_ip VARCHAR(50) NOT NULL,
            target_ip VARCHAR(50) NOT NULL,
            source_port INTEGER,
            target_port INTEGER,
            protocol VARCHAR(10),
            attack_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            description TEXT,
            details JSONB,
            status VARCHAR(20) DEFAULT 'detected'
        )
        ''')
        
        # Create alerts table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP NOT NULL,
            attack_event_id INTEGER REFERENCES attack_events(id),
            severity VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'unresolved',
            resolution TEXT
        )
        ''')
        
        # Create notification_channels table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS notification_channels (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            type VARCHAR(50) NOT NULL,
            config JSONB NOT NULL,
            enabled BOOLEAN DEFAULT TRUE
        )
        ''')
        
        # Create configurations table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS configurations (
            id SERIAL PRIMARY KEY,
            key VARCHAR(100) NOT NULL UNIQUE,
            value JSONB NOT NULL,
            description TEXT
        )
        ''')
        
        # Create users table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create integrations table
        db_manager.execute_pg_query('''
        CREATE TABLE IF NOT EXISTS integrations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            type VARCHAR(50) NOT NULL,
            config JSONB NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            last_sync TIMESTAMP
        )
        ''')

# Initialize database when module is imported
DatabaseInitializer.initialize_database()