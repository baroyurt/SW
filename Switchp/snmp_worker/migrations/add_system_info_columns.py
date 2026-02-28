#!/usr/bin/env python3
"""
Database migration to add system info columns to snmp_devices table.

Adds these columns if they don't exist:
- system_description (TEXT)
- system_uptime (INTEGER)
- last_poll_time (DATETIME)
- last_successful_poll (DATETIME)
- poll_failures (INTEGER)

This migration is safe to run multiple times (idempotent).
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text, inspect
from config.config_loader import Config
from models.database import Base
from sqlalchemy import create_engine


def check_column_exists(inspector, table_name: str, column_name: str) -> bool:
    """Check if a column exists in the table."""
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def add_system_info_columns():
    """Add system info columns to snmp_devices table if they don't exist."""
    
    print("="*60)
    print("SNMP Worker - Add System Info Columns Migration")
    print("="*60)
    print()
    
    # Load configuration
    try:
        config = Config()
        db_config = config.database
        
        print("✓ Configuration loaded successfully")
        print(f"  Database: {db_config.name}")
        print(f"  Host: {db_config.host}:{db_config.port}")
        print(f"  User: {db_config.user}")
        print()
        
    except Exception as e:
        print(f"✗ Error loading configuration: {e}")
        return 1
    
    # Create database engine
    try:
        db_url = config.get_database_url()
        engine = create_engine(db_url, echo=False)
        
        print("✓ Database engine created")
        print()
        
    except Exception as e:
        print(f"✗ Error creating database engine: {e}")
        return 1
    
    # Test connection and get database info
    try:
        with engine.connect() as conn:
            # Try to get MySQL/MariaDB version
            try:
                result = conn.execute(text("SELECT VERSION()"))
                version = result.scalar()
                print("✓ Database connection successful")
                print(f"  MySQL version: {version}")
            except:
                # For PostgreSQL
                result = conn.execute(text("SELECT version()"))
                version = result.scalar()
                print("✓ Database connection successful")
                print(f"  PostgreSQL version: {version}")
        print()
        
    except Exception as e:
        print(f"✗ Error connecting to database: {e}")
        return 1
    
    # Check which columns exist
    try:
        inspector = inspect(engine)
        table_name = 'snmp_devices'
        
        # Check if table exists
        if not inspector.has_table(table_name):
            print(f"✗ Table '{table_name}' does not exist!")
            print("  Please run create_tables.py first.")
            return 1
        
        print("→ Checking existing columns...")
        
        # Columns to add
        columns_to_add = {
            'system_description': 'TEXT',
            'system_uptime': 'INTEGER',
            'last_poll_time': 'DATETIME',
            'last_successful_poll': 'DATETIME',
            'poll_failures': 'INTEGER DEFAULT 0'
        }
        
        missing_columns = []
        for column_name in columns_to_add.keys():
            if not check_column_exists(inspector, table_name, column_name):
                missing_columns.append(column_name)
        
        if not missing_columns:
            print("✓ All required columns already exist")
            print("  No migration needed!")
            print()
            print("="*60)
            print("Migration check completed - already up to date!")
            print("="*60)
            return 0
        
        print(f"  Missing columns: {', '.join(missing_columns)}")
        print()
        
    except Exception as e:
        print(f"✗ Error checking columns: {e}")
        return 1
    
    # Add missing columns
    try:
        print("→ Adding missing columns...")
        
        with engine.connect() as conn:
            for column_name in missing_columns:
                column_type = columns_to_add[column_name]
                
                try:
                    # Different syntax for MySQL vs PostgreSQL
                    if 'mysql' in str(engine.url).lower() or 'mariadb' in str(engine.url).lower():
                        # MySQL/MariaDB syntax
                        sql = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                    else:
                        # PostgreSQL syntax
                        sql = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                    
                    conn.execute(sql)
                    conn.commit()
                    print(f"  ✓ Added column: {column_name}")
                    
                except Exception as e:
                    # Column might already exist due to race condition
                    if "Duplicate column" in str(e) or "already exists" in str(e):
                        print(f"  • Column {column_name} already exists (skipped)")
                    else:
                        print(f"  ✗ Error adding column {column_name}: {e}")
                        raise
        
        print()
        print("✓ Migration completed successfully!")
        print()
        print("="*60)
        print("Migration completed successfully!")
        print("="*60)
        return 0
        
    except Exception as e:
        print()
        print(f"✗ Error during migration: {e}")
        print()
        print("="*60)
        print("Migration failed!")
        print("="*60)
        return 1


if __name__ == "__main__":
    sys.exit(add_system_info_columns())
