"""
SNMP Worker - Add Engine ID Column Migration
Adds snmp_engine_id column to snmp_devices table for SNMPv3 support.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, Column, String, text
from sqlalchemy.exc import OperationalError, ProgrammingError
from config.config_loader import Config

def run_migration():
    """Add snmp_engine_id column to snmp_devices table."""
    
    print("=" * 60)
    print("SNMP Worker - Add Engine ID Column Migration")
    print("=" * 60)
    print()
    
    # Load configuration
    try:
        config = Config()
        print("✓ Configuration loaded successfully")
        print(f"  Database: {config.database.name}")
        print(f"  Host: {config.database.host}:{config.database.port}")
        print(f"  User: {config.database.user}")
        print()
    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        return False
    
    # Create database engine
    try:
        db_url = config.get_database_url()
        engine = create_engine(db_url, echo=False)
        print("✓ Database engine created")
        print()
    except Exception as e:
        print(f"✗ Failed to create database engine: {e}")
        return False
    
    # Test database connection
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT VERSION()"))
            version = result.scalar()
            print("✓ Database connection successful")
            print(f"  MySQL version: {version}")
            print()
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False
    
    # Check if column already exists
    print("→ Checking existing columns...")
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = :schema 
                AND TABLE_NAME = 'snmp_devices' 
                AND COLUMN_NAME = 'snmp_engine_id'
            """), {"schema": config.database.name})
            
            if result.fetchone():
                print("✓ Column 'snmp_engine_id' already exists")
                print("  No migration needed!")
                print()
                print("=" * 60)
                print("Migration check completed - already up to date!")
                print("=" * 60)
                return True
    except Exception as e:
        print(f"⚠ Warning: Could not check existing columns: {e}")
    
    # Add column
    print("→ Adding snmp_engine_id column...")
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                ALTER TABLE snmp_devices 
                ADD COLUMN snmp_engine_id VARCHAR(100) NULL
                COMMENT 'SNMPv3 Engine ID (hex string)'
            """))
            conn.commit()
            print("✓ Column added successfully")
            print()
    except OperationalError as e:
        if "Duplicate column name" in str(e):
            print("✓ Column already exists (safe to ignore)")
            print()
        else:
            print(f"✗ Failed to add column: {e}")
            return False
    except Exception as e:
        print(f"✗ Failed to add column: {e}")
        return False
    
    # Verify migration
    print("→ Verifying migration...")
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_COMMENT
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = :schema 
                AND TABLE_NAME = 'snmp_devices' 
                AND COLUMN_NAME = 'snmp_engine_id'
            """), {"schema": config.database.name})
            
            row = result.fetchone()
            if row:
                print("✓ Migration verified successfully")
                print(f"  Column: {row[0]}")
                print(f"  Type: {row[1]}")
                print(f"  Nullable: {row[2]}")
                print(f"  Comment: {row[3]}")
                print()
            else:
                print("✗ Column not found after migration")
                return False
    except Exception as e:
        print(f"⚠ Warning: Could not verify migration: {e}")
    
    print("=" * 60)
    print("Migration completed successfully!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Update config.yml to add snmp_engine_id for your devices")
    print("  2. Restart the SNMP worker")
    print()
    
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
