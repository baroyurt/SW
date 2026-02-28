"""
Database migration script to add SNMP v3 columns to snmp_devices table.
This migration adds columns needed for SNMP v3 authentication if they don't exist.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import create_engine, text, inspect
from snmp_worker.config.config_loader import Config


def column_exists(inspector, table_name, column_name):
    """Check if a column exists in a table."""
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def run_migration():
    """Add SNMP v3 columns to snmp_devices table if they don't exist."""
    print("=" * 60)
    print("SNMP Worker - Add SNMP v3 Columns Migration")
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
        print(f"\nWarning: No configuration file found. Using defaults.")
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
        return False
    
    # Check if snmp_devices table exists
    inspector = inspect(engine)
    if 'snmp_devices' not in inspector.get_table_names():
        print(f"\n⚠ Warning: snmp_devices table does not exist")
        print(f"  Please run create_tables.py first")
        return False
    
    # Define columns to add
    columns_to_add = {
        'snmp_v3_username': 'VARCHAR(100)',
        'snmp_v3_auth_protocol': 'VARCHAR(20)',
        'snmp_v3_auth_password': 'VARCHAR(200)',
        'snmp_v3_priv_protocol': 'VARCHAR(20)',
        'snmp_v3_priv_password': 'VARCHAR(200)'
    }
    
    # Check which columns are missing
    print(f"\n→ Checking existing columns...")
    missing_columns = {}
    for col_name, col_type in columns_to_add.items():
        if not column_exists(inspector, 'snmp_devices', col_name):
            missing_columns[col_name] = col_type
    
    if not missing_columns:
        print(f"✓ All required columns already exist")
        print(f"  No migration needed!")
        print("\n" + "=" * 60)
        print("Migration check completed - already up to date!")
        print("=" * 60)
        return True
    
    print(f"  Missing columns: {', '.join(missing_columns.keys())}")
    
    # Add missing columns
    print(f"\n→ Adding missing columns...")
    try:
        with engine.connect() as conn:
            for col_name, col_type in missing_columns.items():
                try:
                    # MySQL and PostgreSQL both support this syntax
                    sql = text(f"ALTER TABLE snmp_devices ADD COLUMN {col_name} {col_type}")
                    conn.execute(sql)
                    conn.commit()
                    print(f"  ✓ Added column: {col_name}")
                except Exception as e:
                    # Column might already exist from a race condition
                    if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
                        print(f"  ℹ Column {col_name} already exists (skipped)")
                    else:
                        print(f"  ✗ Error adding column {col_name}: {e}")
                        raise
        
        print(f"\n✓ Migration completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Error during migration: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("Migration completed successfully!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    try:
        success = run_migration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nMigration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
