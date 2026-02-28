#!/usr/bin/env python3
"""
Migration script to add port configuration columns to port_status_data table.

This migration adds missing columns that are required for SNMP worker to function:
- port_type: Port type (e.g., "ethernetCsmacd")
- port_speed: Port speed in bps
- port_mtu: Maximum Transmission Unit

These columns are defined in the PortStatusData model but missing from database,
causing SNMP worker to crash with "Unknown column" errors.

Usage:
    python migrations/add_port_config_columns.py
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def check_column_exists(inspector, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    try:
        columns = [col['name'] for col in inspector.get_columns(table_name)]
        return column_name in columns
    except Exception:
        return False


def main():
    """Main migration function."""
    print("=" * 70)
    print("SNMP Worker - Add Port Configuration Columns Migration")
    print("=" * 70)
    print()
    print("This migration adds missing columns to port_status_data table:")
    print("  - port_type: Port interface type")
    print("  - port_speed: Port speed in bps")
    print("  - port_mtu: Maximum Transmission Unit size")
    print()
    print("These columns are required for SNMP worker to poll devices correctly.")
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
        table_name = 'port_status_data'
        
        # Check if table exists
        if not inspector.has_table(table_name):
            print(f"✗ Table '{table_name}' does not exist!")
            print("  Please create the table first using create_tables.py")
            print()
            return 1
        
        print("→ Checking existing columns...")
        
        # Columns to add (from PortStatusData model)
        required_columns = {
            'port_type': 'VARCHAR(100)',  # e.g., "ethernetCsmacd", "gigabitEthernet"
            'port_speed': 'BIGINT',        # Port speed in bps (can be large!)
            'port_mtu': 'INTEGER',         # Maximum Transmission Unit
        }
        
        missing_columns = []
        for col_name, col_type in required_columns.items():
            if not check_column_exists(inspector, table_name, col_name):
                missing_columns.append((col_name, col_type))
                print(f"  ✗ Missing: {col_name}")
            else:
                print(f"  ✓ Exists: {col_name}")
        
        if not missing_columns:
            print()
            print("✓ All required columns already exist")
            print("  No migration needed!")
            print()
            print("=" * 70)
            print("Migration check completed - database is up to date!")
            print("=" * 70)
            return 0
        
        print()
        print(f"  Total missing columns: {len(missing_columns)}")
        print()
        
        # Add missing columns
        print("→ Adding missing columns to port_status_data...")
        print()
        
        with engine.connect() as conn:
            for col_name, col_type in missing_columns:
                # Build ALTER TABLE statement
                sql = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"
                
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"  ✓ Added column: {col_name} ({col_type})")
                except Exception as e:
                    # Check if it's a "duplicate column" error (safe to ignore)
                    if "Duplicate column" in str(e) or "already exists" in str(e):
                        print(f"  • Column {col_name} already exists (skipped)")
                    else:
                        print(f"  ✗ Failed to add column {col_name}: {e}")
                        raise
        
        print()
        print("✓ Migration completed successfully!")
        print()
        print("=" * 70)
        print("Next Steps:")
        print("=" * 70)
        print()
        print("1. Restart SNMP Worker:")
        print("   cd Switchp/snmp_worker")
        print("   python worker.py")
        print()
        print("2. Monitor logs for successful polling:")
        print("   tail -f logs/snmp_worker.log")
        print()
        print("3. Test description change detection:")
        print("   - Change port description on a switch")
        print("   - Check Port Değişiklik Alarmları page for new alarm")
        print()
        print("=" * 70)
        print("Migration completed successfully!")
        print("=" * 70)
        
        return 0
        
    except Exception as e:
        print()
        print("✗ Migration failed!")
        print(f"  Error: {e}")
        print()
        import traceback
        traceback.print_exc()
        print()
        print("=" * 70)
        print("Migration failed!")
        print("=" * 70)
        return 1


if __name__ == '__main__':
    sys.exit(main())
