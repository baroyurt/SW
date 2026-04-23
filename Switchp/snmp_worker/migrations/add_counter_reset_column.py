#!/usr/bin/env python3
"""
Migration script: add last_counter_reset_at column to port_status_data.

When the SNMP worker detects that an interface counter (ifInDiscards,
ifOutDiscards, ifInErrors, ifOutErrors) dropped to less than half its
previous stored value, it sets this timestamp so the UI can show a
"counter reset" badge in the Hata/Drop report.

Usage:
    python migrations/add_counter_reset_column.py
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def column_exists(inspector, table: str, column: str) -> bool:
    return column in [c['name'] for c in inspector.get_columns(table)]


def main():
    print("=" * 60)
    print("Migration: add last_counter_reset_at to port_status_data")
    print("=" * 60)

    config = Config()
    engine = create_engine(config.get_database_url(), echo=False)

    with engine.connect() as conn:
        inspector = inspect(engine)

        if column_exists(inspector, 'port_status_data', 'last_counter_reset_at'):
            print("✓ Column already exists — nothing to do.")
            return

        print("Adding last_counter_reset_at column …")
        conn.execute(text(
            "ALTER TABLE port_status_data "
            "ADD last_counter_reset_at DATETIME NULL DEFAULT NULL"
        ))
        conn.commit()
        print("✓ Column added successfully.")


if __name__ == '__main__':
    main()
