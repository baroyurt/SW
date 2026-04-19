#!/usr/bin/env python3
"""
MERGED: snmp_devices Tablosu Ek Sütunlar
Birleştirilen dosyalar:
  - add_snmp_v3_columns.py    (SNMPv3 auth sütunları)
  - add_system_info_columns.py (system_description, uptime, poll bilgileri)
  - add_engine_id.py           (snmp_engine_id)

Bu migration idempotent — defalarca çalıştırılabilir.
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def column_exists(engine, table: str, column: str) -> bool:
    insp = inspect(engine)
    return any(c['name'] == column for c in insp.get_columns(table))


def run_migration():
    print("=" * 60)
    print("MERGED: snmp_devices Tablosu Ek Sütunlar Migration")
    print("=" * 60)

    config = Config()
    engine = create_engine(config.get_database_url(), echo=False)

    with engine.connect() as conn:
        conn.execute(text("SELECT @@VERSION")).fetchone()
    print("✓ Veritabanı bağlantısı başarılı")

    columns_to_add = {
        # SNMPv3 auth sütunları
        'snmp_version':        'VARCHAR(10) DEFAULT \'2c\'',
        'snmp_v3_security_name': 'VARCHAR(255)',
        'snmp_v3_auth_protocol': 'VARCHAR(20)',
        'snmp_v3_auth_password': 'VARCHAR(255)',
        'snmp_v3_priv_protocol': 'VARCHAR(20)',
        'snmp_v3_priv_password': 'VARCHAR(255)',
        'snmp_v3_context_name': 'VARCHAR(255)',
        # Engine ID
        'snmp_engine_id':      'VARCHAR(255)',
        # Sistem bilgisi sütunları
        'system_description':  'NVARCHAR(MAX)',
        'system_uptime':       'BIGINT',
        'last_poll_time':      'DATETIME',
        'last_successful_poll':'DATETIME',
        'poll_failures':       'INT DEFAULT 0',
    }

    added = []
    with engine.begin() as conn:
        for col, definition in columns_to_add.items():
            if not column_exists(engine, 'snmp_devices', col):
                conn.execute(text(f"ALTER TABLE snmp_devices ADD {col} {definition}"))
                added.append(col)
                print(f"  ✓ Eklendi: snmp_devices.{col}")
            else:
                print(f"  — Zaten var: snmp_devices.{col}")

    print()
    if added:
        print(f"✓ {len(added)} sütun eklendi: {', '.join(added)}")
    else:
        print("✓ Tüm sütunlar zaten mevcut — migration gerekmiyor.")
    return True


if __name__ == "__main__":
    sys.exit(0 if run_migration() else 1)
