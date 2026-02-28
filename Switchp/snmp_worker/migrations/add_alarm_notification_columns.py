#!/usr/bin/env python3
"""
Add Alarm Notification Columns Migration

This script adds missing notification tracking columns to the alarms table.

Missing columns:
- notification_sent (Boolean, NOT NULL, DEFAULT FALSE)
- last_notification_sent (DateTime, NULL)

These columns are needed for tracking alarm notification status.
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def check_column_exists(engine, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def add_alarm_notification_columns(engine, db_type: str = "mysql"):
    """Add notification tracking columns to alarms table."""
    
    # Define columns to add
    columns_to_add = {
        'notification_sent': 'BOOLEAN NOT NULL DEFAULT FALSE',
        'last_notification_sent': 'DATETIME',
    }
    
    # Check which columns are missing
    missing_columns = {}
    for col_name, col_def in columns_to_add.items():
        if not check_column_exists(engine, 'alarms', col_name):
            missing_columns[col_name] = col_def
    
    if not missing_columns:
        print("✓ All required columns already exist")
        print("  No migration needed!")
        return True
    
    print(f"  Missing columns: {', '.join(missing_columns.keys())}")
    print()
    print("→ Adding missing columns...")
    
    # Add missing columns
    with engine.begin() as conn:
        for col_name, col_def in missing_columns.items():
            try:
                # Adjust for PostgreSQL if needed
                if db_type == "postgresql":
                    if "BOOLEAN" in col_def:
                        col_def = col_def.replace("DEFAULT FALSE", "DEFAULT false")
                    if "DATETIME" in col_def:
                        col_def = col_def.replace("DATETIME", "TIMESTAMP")
                
                sql = f"ALTER TABLE alarms ADD COLUMN {col_name} {col_def}"
                conn.execute(text(sql))
                print(f"  ✓ Added column: {col_name}")
            except SQLAlchemyError as e:
                print(f"  ✗ Failed to add column {col_name}: {e}")
                return False
    
    return True


def main():
    """Main migration function."""
    print("=" * 60)
    print("SNMP Worker - Add Alarm Notification Columns Migration")
    print("=" * 60)
    print()
    
    try:
        # Load configuration
        config = Config()
        db_config = config.database
        
        print("✓ Configuration loaded successfully")
        print(f"  Database: {db_config.name}")
        print(f"  Host: {db_config.host}:{db_config.port}")
        print(f"  User: {db_config.user}")
        print()
        
        # Create database engine
        db_url = config.get_database_url()
        engine = create_engine(db_url, echo=False)
        
        print("✓ Database engine created")
        print()
        
        # Test connection and get database info
        with engine.connect() as conn:
            # Detect database type
            db_type = "mysql"
            if "postgresql" in db_url:
                db_type = "postgresql"
                result = conn.execute(text("SELECT version()"))
            else:
                result = conn.execute(text("SELECT VERSION()"))
            
            version = result.scalar()
            print("✓ Database connection successful")
            print(f"  {db_type.capitalize()} version: {version}")
            print()
        
        # Check existing columns
        print("→ Checking existing columns...")
        
        # Add missing columns
        success = add_alarm_notification_columns(engine, db_type)
        
        if success:
            print()
            print("✓ Migration completed successfully!")
            print()
            print("=" * 60)
            print("Migration completed successfully!")
            print("=" * 60)
            return 0
        else:
            print()
            print("✗ Migration failed!")
            print()
            print("=" * 60)
            print("Migration failed!")
            print("=" * 60)
            return 1
            
    except Exception as e:
        print()
        print(f"✗ Error: {e}")
        print()
        print("=" * 60)
        print("Migration failed!")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
