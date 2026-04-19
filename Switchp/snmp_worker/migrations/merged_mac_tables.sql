-- ============================================================================
-- MERGED: MAC Takip ve Cihaz Kayıt Tabloları
-- Birleştirilen dosyalar:
--   - mac_device_import.sql              (mac_device_registry, mac_device_import_history)
--   - add_mac_tracking_tables.sql        (port_change_history, mac_address_tracking)
--   - add_acknowledged_port_mac_table.sql (acknowledged_port_mac + alarms ek sütunlar)
--   - fix_acknowledged_port_mac_schema.sql (device_name schema düzeltmesi)
-- Tümü idempotent — defalarca çalıştırılabilir.
-- ============================================================================

-- ── mac_device_registry ──────────────────────────────────────────────────────

IF OBJECT_ID('dbo.mac_device_registry','U') IS NULL BEGIN
CREATE TABLE mac_device_registry (
    id          INT IDENTITY(1,1) PRIMARY KEY,
    mac_address VARCHAR(17)  NOT NULL,
    ip_address  VARCHAR(45),
    device_name VARCHAR(255),
    user_name   VARCHAR(255),
    location    VARCHAR(255),
    department  VARCHAR(100),
    notes       NVARCHAR(MAX),
    source      VARCHAR(50)  DEFAULT 'manual',
    last_seen   DATETIME     NULL,
    created_at  DATETIME     DEFAULT GETDATE(),
    updated_at  DATETIME     DEFAULT GETDATE(),
    created_by  VARCHAR(100),
    updated_by  VARCHAR(100),
    CONSTRAINT uq_mac_device_registry UNIQUE (mac_address)
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_mac' AND object_id=OBJECT_ID('mac_device_registry'))
    CREATE INDEX idx_mac ON mac_device_registry(mac_address);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_ip' AND object_id=OBJECT_ID('mac_device_registry'))
    CREATE INDEX idx_ip ON mac_device_registry(ip_address);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_device_name' AND object_id=OBJECT_ID('mac_device_registry'))
    CREATE INDEX idx_device_name ON mac_device_registry(device_name);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_source' AND object_id=OBJECT_ID('mac_device_registry'))
    CREATE INDEX idx_source ON mac_device_registry(source);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_updated' AND object_id=OBJECT_ID('mac_device_registry'))
    CREATE INDEX idx_updated ON mac_device_registry(updated_at);
GO

-- ── mac_device_import_history ────────────────────────────────────────────────

IF OBJECT_ID('dbo.mac_device_import_history','U') IS NULL BEGIN
CREATE TABLE mac_device_import_history (
    id            INT IDENTITY(1,1) PRIMARY KEY,
    filename      VARCHAR(255),
    total_rows    INT,
    success_count INT,
    error_count   INT,
    imported_by   VARCHAR(100),
    import_date   DATETIME DEFAULT GETDATE(),
    errors        NVARCHAR(MAX)
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_date' AND object_id=OBJECT_ID('mac_device_import_history'))
    CREATE INDEX idx_date ON mac_device_import_history(import_date);
GO

-- ── port_change_history ──────────────────────────────────────────────────────

IF OBJECT_ID('dbo.port_change_history','U') IS NULL BEGIN
CREATE TABLE port_change_history (
  id               INT IDENTITY(1,1) NOT NULL,
  device_id        INT          NOT NULL,
  port_number      INT          NOT NULL,
  change_type      VARCHAR(50)  NOT NULL,
  change_timestamp DATETIME     NOT NULL DEFAULT GETDATE(),
  old_value        NVARCHAR(MAX) DEFAULT NULL,
  old_mac_address  VARCHAR(17)  DEFAULT NULL,
  old_vlan_id      INT          DEFAULT NULL,
  old_description  VARCHAR(255) DEFAULT NULL,
  new_value        NVARCHAR(MAX) DEFAULT NULL,
  new_mac_address  VARCHAR(17)  DEFAULT NULL,
  new_vlan_id      INT          DEFAULT NULL,
  new_description  VARCHAR(255) DEFAULT NULL,
  from_device_id   INT          DEFAULT NULL,
  from_port_number INT          DEFAULT NULL,
  to_device_id     INT          DEFAULT NULL,
  to_port_number   INT          DEFAULT NULL,
  change_details   NVARCHAR(MAX) DEFAULT NULL,
  alarm_created    BIT          DEFAULT 0,
  alarm_id         INT          DEFAULT NULL,
  PRIMARY KEY (id),
  CONSTRAINT fk_pch_device FOREIGN KEY (device_id) REFERENCES snmp_devices (id) ON DELETE CASCADE
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pch_device_port' AND object_id=OBJECT_ID('port_change_history'))
    CREATE INDEX idx_pch_device_port ON port_change_history(device_id, port_number);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pch_change_type' AND object_id=OBJECT_ID('port_change_history'))
    CREATE INDEX idx_pch_change_type ON port_change_history(change_type);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pch_timestamp' AND object_id=OBJECT_ID('port_change_history'))
    CREATE INDEX idx_pch_timestamp ON port_change_history(change_timestamp);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_pch_mac' AND object_id=OBJECT_ID('port_change_history'))
    CREATE INDEX idx_pch_mac ON port_change_history(old_mac_address, new_mac_address);
GO

-- ── mac_address_tracking ─────────────────────────────────────────────────────

IF OBJECT_ID('dbo.mac_address_tracking','U') IS NULL BEGIN
CREATE TABLE mac_address_tracking (
  id                   INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
  mac_address          VARCHAR(17)  NOT NULL,
  current_device_id    INT          DEFAULT NULL,
  current_port_number  INT          DEFAULT NULL,
  current_vlan_id      INT          DEFAULT NULL,
  device_name          VARCHAR(255) DEFAULT NULL,
  ip_address           VARCHAR(45)  DEFAULT NULL,
  device_type          VARCHAR(100) DEFAULT NULL,
  domain_user          VARCHAR(255) DEFAULT NULL,
  first_seen           DATETIME     DEFAULT GETDATE(),
  last_seen            DATETIME     DEFAULT GETDATE(),
  move_count           INT          DEFAULT 0,
  CONSTRAINT uq_mac_tracking UNIQUE (mac_address)
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_mat_mac' AND object_id=OBJECT_ID('mac_address_tracking'))
    CREATE INDEX idx_mat_mac ON mac_address_tracking(mac_address);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_mat_device' AND object_id=OBJECT_ID('mac_address_tracking'))
    CREATE INDEX idx_mat_device ON mac_address_tracking(current_device_id, current_port_number);
GO

-- ── acknowledged_port_mac ────────────────────────────────────────────────────

IF OBJECT_ID('dbo.acknowledged_port_mac','U') IS NULL BEGIN
CREATE TABLE acknowledged_port_mac (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    device_name     VARCHAR(100) NOT NULL,
    port_number     INT          NOT NULL,
    mac_address     VARCHAR(17)  NOT NULL,
    acknowledged_at DATETIME     NOT NULL DEFAULT GETDATE(),
    acknowledged_by VARCHAR(100) NOT NULL,
    note            NVARCHAR(MAX),
    created_at      DATETIME     NOT NULL DEFAULT GETDATE(),
    updated_at      DATETIME     NOT NULL DEFAULT GETDATE(),
    CONSTRAINT unique_whitelist UNIQUE (device_name, port_number, mac_address)
)
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_apm_device_port' AND object_id=OBJECT_ID('acknowledged_port_mac'))
    CREATE INDEX idx_apm_device_port ON acknowledged_port_mac(device_name, port_number);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_apm_mac' AND object_id=OBJECT_ID('acknowledged_port_mac'))
    CREATE INDEX idx_apm_mac ON acknowledged_port_mac(mac_address);
GO

-- ── acknowledged_port_mac schema düzeltmesi (eski kurulumlar için) ───────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='acknowledged_port_mac' AND COLUMN_NAME='device_name')
BEGIN
    ALTER TABLE acknowledged_port_mac ADD device_name VARCHAR(100) DEFAULT NULL;
    UPDATE acknowledged_port_mac SET device_name = 'UNKNOWN' WHERE device_name IS NULL;
    ALTER TABLE acknowledged_port_mac ALTER COLUMN device_name VARCHAR(100) NOT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='acknowledged_port_mac' AND COLUMN_NAME='note')
BEGIN
    ALTER TABLE acknowledged_port_mac ADD note NVARCHAR(MAX) DEFAULT NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='acknowledged_port_mac' AND COLUMN_NAME='updated_at')
BEGIN
    ALTER TABLE acknowledged_port_mac ADD updated_at DATETIME DEFAULT GETDATE();
END
GO

IF EXISTS (SELECT 1 FROM sys.indexes WHERE name='uq_ack_port_mac' AND object_id=OBJECT_ID('acknowledged_port_mac'))
    DROP INDEX uq_ack_port_mac ON acknowledged_port_mac;
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_ack_port_mac_device' AND object_id=OBJECT_ID('acknowledged_port_mac'))
    DROP INDEX idx_ack_port_mac_device ON acknowledged_port_mac;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='unique_whitelist' AND object_id=OBJECT_ID('acknowledged_port_mac'))
    ALTER TABLE acknowledged_port_mac ADD CONSTRAINT unique_whitelist UNIQUE (device_name, port_number, mac_address);
GO

-- ── alarms tablosu ek sütunlar (MAC takip için) ──────────────────────────────

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='alarms' AND COLUMN_NAME='from_port')
BEGIN ALTER TABLE alarms ADD from_port INT DEFAULT NULL END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='alarms' AND COLUMN_NAME='to_port')
BEGIN ALTER TABLE alarms ADD to_port INT DEFAULT NULL END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='alarms' AND COLUMN_NAME='alarm_fingerprint')
BEGIN ALTER TABLE alarms ADD alarm_fingerprint VARCHAR(255) DEFAULT NULL END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_alarm_fingerprint' AND object_id=OBJECT_ID('alarms'))
BEGIN CREATE INDEX idx_alarm_fingerprint ON alarms(alarm_fingerprint) END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_device_port_type_status' AND object_id=OBJECT_ID('alarms'))
BEGIN CREATE INDEX idx_device_port_type_status ON alarms(device_id, port_number, alarm_type, status) END
GO

SELECT 'SUCCESS: merged_mac_tables migration complete' AS status;
