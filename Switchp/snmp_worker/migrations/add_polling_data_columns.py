#!/usr/bin/env python3
"""
Migration script to add ALL polling data columns to device_polling_data table.

This migration adds:
- poll_duration_ms: Time taken to poll in milliseconds
- success: Boolean flag indicating poll success/failure
- error_message: Text field for error descriptions
- cpu_usage: CPU usage percentage
- memory_usage: Memory usage percentage
- temperature: Device temperature in Celsius
- uptime_seconds: Device uptime in seconds

Usage:
    python migrations/add_polling_data_columns.py
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def check_column_exists(inspector, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def main():
    """Main migration function."""
    print("=" * 60)
    print("SNMP Worker - Add Polling Data Columns Migration")
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
        
        # Test connection and get version
        with engine.connect() as conn:
            result = conn.execute(text("SELECT VERSION()"))
            version = result.scalar()
            print("✓ Database connection successful")
            print(f"  MySQL version: {version}")
            print()
        
        # Check existing columns
        inspector = inspect(engine)
        table_name = 'device_polling_data'
        
        print("→ Checking existing columns...")
        
        # Columns to check - ALL non-base columns from DevicePollingData model
        required_columns = {
            # Polling metrics
            'poll_duration_ms': 'FLOAT',
            'success': 'BOOLEAN NOT NULL DEFAULT TRUE',
            'error_message': 'TEXT',
            # Device metrics
            'cpu_usage': 'FLOAT',
            'memory_usage': 'FLOAT',
            'temperature': 'FLOAT',
            'uptime_seconds': 'INTEGER',
        }
        
        missing_columns = []
        for col_name, col_type in required_columns.items():
            if not check_column_exists(inspector, table_name, col_name):
                missing_columns.append((col_name, col_type))
        
        if not missing_columns:
            print("✓ All required columns already exist")
            print("  No migration needed!")
            print()
            print("=" * 60)
            print("Migration check completed - already up to date!")
            print("=" * 60)
            return 0
        
        print(f"  Missing columns: {', '.join([col[0] for col in missing_columns])}")
        print()
        
        # Add missing columns
        print("→ Adding missing columns...")
        
        with engine.connect() as conn:
            for col_name, col_type in missing_columns:
                # Build ALTER TABLE statement
                sql = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"
                
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"  ✓ Added column: {col_name}")
                except Exception as e:
                    print(f"  ✗ Failed to add column {col_name}: {e}")
                    raise
        
        print()
        print("✓ Migration completed successfully!")
        print()
        print("=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        print()
        print("✗ Migration failed!")
        print(f"  Error: {e}")
        print()
        print("=" * 60)
        print("Migration failed!")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
