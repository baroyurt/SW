#!/usr/bin/env python3
"""
MERGED: Alarms Tablosu Ek Sütunlar
Birleştirilen dosyalar:
  - add_alarm_notification_columns.py  (notification_sent, last_notification_sent)
  - add_vlan_columns_to_alarms.py      (old_vlan_id, new_vlan_id)

Bu migration idempotent — defalarca çalıştırılabilir.
"""

import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_loader import Config


def column_exists(engine, table: str, column: str) -> bool:
    insp = inspect(engine)
    return any(c['name'] == column for c in insp.get_columns(table))


def run_migration():
    print("=" * 60)
    print("MERGED: Alarms Tablosu Ek Sütunlar Migration")
    print("=" * 60)

    config = Config()
    db_url = config.get_database_url()
    engine = create_engine(db_url, echo=False)

    with engine.connect() as conn:
        conn.execute(text("SELECT @@VERSION")).fetchone()
    print("✓ Veritabanı bağlantısı başarılı")

    columns_to_add = {
        # Bildirim takip sütunları
        'notification_sent':       'BIT NOT NULL DEFAULT 0',
        'last_notification_sent':  'DATETIME',
        # VLAN değişim sütunları
        'old_vlan_id':             'INT',
        'new_vlan_id':             'INT',
    }

    added = []
    with engine.begin() as conn:
        for col, definition in columns_to_add.items():
            if not column_exists(engine, 'alarms', col):
                conn.execute(text(f"ALTER TABLE alarms ADD {col} {definition}"))
                added.append(col)
                print(f"  ✓ Eklendi: alarms.{col}")
            else:
                print(f"  — Zaten var: alarms.{col}")

    print()
    if added:
        print(f"✓ {len(added)} sütun eklendi: {', '.join(added)}")
    else:
        print("✓ Tüm sütunlar zaten mevcut — migration gerekmiyor.")
    return True


if __name__ == "__main__":
    sys.exit(0 if run_migration() else 1)
