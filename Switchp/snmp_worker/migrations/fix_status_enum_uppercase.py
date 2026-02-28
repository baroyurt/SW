"""
Migration: Fix status enum to use uppercase values
Date: 2026-02-13
Description: Updates snmp_devices status enum from lowercase to uppercase
             to match DeviceStatus enum in Python code
"""

import logging
from sqlalchemy import text
from models.database import Base

logger = logging.getLogger('snmp_worker.migration')


def upgrade(engine):
    """
    Upgrade database schema.
    Updates snmp_devices.status enum to use uppercase values.
    """
    logger.info("Starting migration: fix_status_enum_uppercase")
    
    with engine.connect() as conn:
        try:
            # First, update existing data to uppercase
            logger.info("Converting existing status values to uppercase...")
            conn.execute(text("""
                UPDATE snmp_devices 
                SET status = CASE 
                    WHEN status = 'online' THEN 'ONLINE'
                    WHEN status = 'offline' THEN 'OFFLINE'
                    WHEN status = 'error' THEN 'ERROR'
                    ELSE status
                END
                WHERE status IN ('online', 'offline', 'error')
            """))
            conn.commit()
            
            # Then, alter the enum column
            logger.info("Altering enum column definition...")
            conn.execute(text("""
                ALTER TABLE snmp_devices 
                MODIFY COLUMN status 
                enum('ONLINE','OFFLINE','UNREACHABLE','ERROR') 
                DEFAULT 'OFFLINE'
            """))
            conn.commit()
            
            logger.info("Migration completed successfully")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            conn.rollback()
            raise


def downgrade(engine):
    """
    Downgrade database schema (revert changes).
    """
    logger.info("Starting migration downgrade: fix_status_enum_uppercase")
    
    with engine.connect() as conn:
        try:
            # Convert data back to lowercase
            logger.info("Converting status values back to lowercase...")
            conn.execute(text("""
                UPDATE snmp_devices 
                SET status = CASE 
                    WHEN status = 'ONLINE' THEN 'online'
                    WHEN status = 'OFFLINE' THEN 'offline'
                    WHEN status = 'UNREACHABLE' THEN 'offline'
                    WHEN status = 'ERROR' THEN 'error'
                    ELSE status
                END
                WHERE status IN ('ONLINE', 'OFFLINE', 'UNREACHABLE', 'ERROR')
            """))
            conn.commit()
            
            # Revert enum definition
            logger.info("Reverting enum column definition...")
            conn.execute(text("""
                ALTER TABLE snmp_devices 
                MODIFY COLUMN status 
                enum('online','offline','error') 
                DEFAULT 'offline'
            """))
            conn.commit()
            
            logger.info("Migration downgrade completed successfully")
            
        except Exception as e:
            logger.error(f"Migration downgrade failed: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    # Allow running migration standalone for testing
    import sys
    from pathlib import Path
    
    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from config.config_loader import Config
    from sqlalchemy import create_engine
    
    # Load config
    config = Config()
    
    # Create engine
    engine = create_engine(config.get_database_url())
    
    # Run migration
    upgrade(engine)
    
    print("\n✓ Migration completed successfully!")
    print("\nTo verify, run:")
    print("  DESCRIBE snmp_devices;")
