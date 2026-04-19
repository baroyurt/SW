-- Migration: Create maintenance_windows table
-- Date: 2026-03-17

IF OBJECT_ID('dbo.maintenance_windows','U') IS NULL BEGIN
CREATE TABLE maintenance_windows (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    device_id       INT          DEFAULT NULL,
    device_name     VARCHAR(100) DEFAULT NULL,
    title           VARCHAR(255) NOT NULL,
    start_time      DATETIME     NOT NULL,
    end_time        DATETIME     NOT NULL,
    recurring       BIT          DEFAULT 0,
    recur_days      VARCHAR(20)  DEFAULT NULL,
    recur_start     TIME         DEFAULT NULL,
    recur_end       TIME         DEFAULT NULL,
    suppress_alarms BIT          DEFAULT 1,
    created_by      VARCHAR(100) DEFAULT NULL,
    created_at      DATETIME     DEFAULT GETDATE(),
    updated_at      DATETIME     DEFAULT GETDATE()
)
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_mw_device' AND object_id=OBJECT_ID('maintenance_windows'))
    CREATE INDEX idx_mw_device ON maintenance_windows(device_id);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_mw_times' AND object_id=OBJECT_ID('maintenance_windows'))
    CREATE INDEX idx_mw_times ON maintenance_windows(start_time, end_time);
