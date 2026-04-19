-- ============================================================================
-- MERGED: Port & Port Data Columns
-- Birleştirilen dosyalar:
--   - add_ports_missing_columns.sql   (ports: device_name, note)
--   - add_port_operational_status.sql (ports: oper_status, last_status_update)
--   - add_port_reservation_columns.sql (ports: is_reserved, reserved_for)
--   - add_port_config_columns.sql     (port_status_data: port_type, port_speed, port_mtu)
--   - add_port_poe_columns.sql        (port_status_data: poe_detecting, poe_power_mw, poe_class)
--   - add_port_traffic_history.sql    (yeni tablo: port_traffic_history)
-- Tümü idempotent (IF NOT EXISTS korumalı) — defalarca çalıştırılabilir.
-- ============================================================================

-- ── ports tablosu ───────────────────────────────────────────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='device_name')
    ALTER TABLE dbo.ports ADD device_name VARCHAR(255) DEFAULT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='note')
    ALTER TABLE dbo.ports ADD note NVARCHAR(MAX) DEFAULT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='oper_status')
    ALTER TABLE ports ADD oper_status VARCHAR(20) DEFAULT 'unknown';
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='last_status_update')
    ALTER TABLE ports ADD last_status_update DATETIME DEFAULT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='is_reserved')
BEGIN
    ALTER TABLE ports ADD is_reserved BIT DEFAULT 0;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='reserved_for')
BEGIN
    ALTER TABLE ports ADD reserved_for VARCHAR(255) DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='ports' AND COLUMN_NAME='connection_info')
BEGIN
    ALTER TABLE ports ADD connection_info NVARCHAR(MAX) DEFAULT NULL;
END
GO

-- ── port_status_data tablosu ─────────────────────────────────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='port_status_data' AND COLUMN_NAME='port_type')
BEGIN
    ALTER TABLE port_status_data ADD port_type VARCHAR(100) DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='port_status_data' AND COLUMN_NAME='port_speed')
BEGIN
    ALTER TABLE port_status_data ADD port_speed BIGINT DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='port_status_data' AND COLUMN_NAME='port_mtu')
BEGIN
    ALTER TABLE port_status_data ADD port_mtu INT DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('port_status_data') AND name = 'poe_detecting')
    ALTER TABLE port_status_data ADD poe_detecting TINYINT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('port_status_data') AND name = 'poe_power_mw')
    ALTER TABLE port_status_data ADD poe_power_mw INT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('port_status_data') AND name = 'poe_class')
    ALTER TABLE port_status_data ADD poe_class INT NULL;
GO

-- ── port_traffic_history tablosu (yeni) ─────────────────────────────────────

IF OBJECT_ID('dbo.port_traffic_history','U') IS NULL BEGIN
CREATE TABLE port_traffic_history (
    id          BIGINT IDENTITY(1,1) PRIMARY KEY,
    device_id   INT      NOT NULL,
    port_number INT      NOT NULL,
    sample_time DATETIME NOT NULL,
    in_octets   BIGINT   DEFAULT 0,
    out_octets  BIGINT   DEFAULT 0,
    in_bps      BIGINT   DEFAULT NULL,
    out_bps     BIGINT   DEFAULT NULL,
    FOREIGN KEY (device_id) REFERENCES snmp_devices(id) ON DELETE CASCADE
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pth_device_port' AND object_id=OBJECT_ID('port_traffic_history'))
    CREATE INDEX idx_pth_device_port ON port_traffic_history(device_id, port_number);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pth_time' AND object_id=OBJECT_ID('port_traffic_history'))
    CREATE INDEX idx_pth_time ON port_traffic_history(sample_time);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pth_device_port_time' AND object_id=OBJECT_ID('port_traffic_history'))
    CREATE INDEX idx_pth_device_port_time ON port_traffic_history(device_id, port_number, sample_time);
GO

SELECT 'SUCCESS: merged_port_columns migration complete' AS status;
