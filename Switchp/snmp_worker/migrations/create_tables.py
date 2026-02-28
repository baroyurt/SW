"""
Database migration script for SNMP Worker tables.
Creates all necessary tables in MySQL or PostgreSQL database.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import create_engine, text
from snmp_worker.models.database import Base
from snmp_worker.config.config_loader import Config


def run_migration():
    """Run database migration to create all tables."""
    print("=" * 60)
    print("SNMP Worker Database Migration")
    print("=" * 60)
    
    # Load configuration
    try:
        config = Config()
        print(f"\n✓ Configuration loaded successfully")
        print(f"  Database: {config.database.name}")
        print(f"  Host: {config.database.host}:{config.database.port}")
        print(f"  User: {config.database.user}")
    except Exception as e:
        print(f"\n✗ Error loading configuration: {e}")
        return False
    
    # Create database engine
    try:
        db_url = config.get_database_url()
        engine = create_engine(db_url, echo=False)
        print(f"\n✓ Database engine created")
    except Exception as e:
        print(f"\n✗ Error creating database engine: {e}")
        return False
    
    # Test connection
    try:
        with engine.connect() as conn:
            # Try MySQL version query first, then PostgreSQL
            try:
                result = conn.execute(text("SELECT VERSION()"))
                version = result.fetchone()[0]
                db_type = "MySQL" if "mysql" in version.lower() or "maria" in version.lower() else "Database"
            except:
                result = conn.execute(text("SELECT version()"))
                version = result.fetchone()[0]
                db_type = "PostgreSQL"
            
            print(f"\n✓ Database connection successful")
            print(f"  {db_type} version: {version.split(',')[0]}")
    except Exception as e:
        print(f"\n✗ Error connecting to database: {e}")
        print(f"\nPlease ensure:")
        print(f"  1. Database server is running (MySQL on port 3306 or PostgreSQL on port 5432)")
        print(f"  2. Database '{config.database.name}' exists")
        print(f"  3. User '{config.database.user}' has appropriate permissions")
        return False
    
    # Create tables
    try:
        print(f"\n→ Creating tables...")
        Base.metadata.create_all(engine)
        print(f"✓ All tables created successfully")
        
        # List created tables
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        print(f"\n→ Created tables:")
        for table in sorted(tables):
            if table.startswith('snmp_') or table in ['device_polling_data', 'port_status_data', 'alarms', 'alarm_history']:
                print(f"  • {table}")
        
    except Exception as e:
        print(f"\n✗ Error creating tables: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("Migration completed successfully!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
