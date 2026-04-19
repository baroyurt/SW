-- ============================================================================
-- MERGED: Switch / Cihaz Tablosu Ek Sütunlar
-- Birleştirilen dosyalar:
--   - add_switches_core_virtual_columns.sql  (switches: is_virtual, is_core)
--   - add_snmp_hub_auto_source.sql           (mac_device_registry: source genişletme)
--   - add_cpu_1min_column.sql                (snmp_devices: cpu_1min)
--   - add_fan_temp_poe_columns.sql           (snmp_devices: fan/temp/poe sütunları)
-- Tümü idempotent — defalarca çalıştırılabilir.
-- ============================================================================

-- ── switches tablosu ─────────────────────────────────────────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='switches' AND COLUMN_NAME='is_virtual')
BEGIN
    ALTER TABLE switches ADD is_virtual BIT NOT NULL DEFAULT 0;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='switches' AND COLUMN_NAME='is_core')
BEGIN
    ALTER TABLE switches ADD is_core BIT NOT NULL DEFAULT 0;
END
GO

-- ── mac_device_registry: source sütununu genişlet ───────────────────────────

ALTER TABLE mac_device_registry ALTER COLUMN source VARCHAR(50);
GO

-- ── snmp_devices: cpu_1min ───────────────────────────────────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='cpu_1min')
BEGIN
    ALTER TABLE snmp_devices ADD cpu_1min FLOAT DEFAULT NULL;
END
GO

-- ── snmp_devices: fan / sıcaklık / PoE özet sütunları ───────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='fan_status')
BEGIN
    ALTER TABLE snmp_devices ADD fan_status VARCHAR(50) DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='temperature')
BEGIN
    ALTER TABLE snmp_devices ADD temperature FLOAT DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='poe_total_power')
BEGIN
    ALTER TABLE snmp_devices ADD poe_total_power FLOAT DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='poe_used_power')
BEGIN
    ALTER TABLE snmp_devices ADD poe_used_power FLOAT DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='snmp_devices' AND COLUMN_NAME='poe_remaining_power')
BEGIN
    ALTER TABLE snmp_devices ADD poe_remaining_power FLOAT DEFAULT NULL;
END
GO

SELECT 'SUCCESS: merged_switch_columns migration complete' AS status;
