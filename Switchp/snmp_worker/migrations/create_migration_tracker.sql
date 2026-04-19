-- ============================================================================
-- Migration Tracker Table
-- ============================================================================
-- Bu tablo hangi migration'ların uygulandığını takip eder
-- Otomatik migration sistemi için gerekli
-- ============================================================================

-- Migration tracker tablosunu oluştur
IF OBJECT_ID('dbo.migration_history','U') IS NULL BEGIN
CREATE TABLE migration_history (
    id                 INT IDENTITY(1,1) PRIMARY KEY,
    migration_name     VARCHAR(255) NOT NULL,
    migration_type     VARCHAR(50)  NOT NULL,
    applied_at         DATETIME     DEFAULT GETDATE(),
    success            BIT          DEFAULT 1,
    error_message      NVARCHAR(MAX) NULL,
    execution_time_ms  INT          NULL,
    applied_by         VARCHAR(100) DEFAULT 'system',
    CONSTRAINT uq_migration_name UNIQUE (migration_name)
)
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_applied_at' AND object_id=OBJECT_ID('migration_history'))
    CREATE INDEX idx_applied_at ON migration_history(applied_at);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_migration_type' AND object_id=OBJECT_ID('migration_history'))
    CREATE INDEX idx_migration_type ON migration_history(migration_type);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_success' AND object_id=OBJECT_ID('migration_history'))
    CREATE INDEX idx_success ON migration_history(success);

-- Migration istatistikleri için view
IF OBJECT_ID('dbo.migration_stats','V') IS NOT NULL DROP VIEW migration_stats;
GO
CREATE VIEW migration_stats AS
SELECT
    migration_type,
    COUNT(*)                                              AS total_count,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END)         AS success_count,
    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)         AS failed_count,
    AVG(CAST(execution_time_ms AS FLOAT))                AS avg_execution_time_ms,
    MAX(applied_at)                                       AS last_applied
FROM migration_history
GROUP BY migration_type;
GO

-- Son migration'ları görmek için view
IF OBJECT_ID('dbo.recent_migrations','V') IS NOT NULL DROP VIEW recent_migrations;
GO
CREATE VIEW recent_migrations AS
SELECT TOP 50
    id,
    migration_name,
    migration_type,
    applied_at,
    success,
    execution_time_ms,
    CASE
        WHEN success = 1 THEN 'SUCCESS'
        ELSE 'FAILED'
    END AS status
FROM migration_history
ORDER BY applied_at DESC;
GO

-- Başarısız migration'ları görmek için view
IF OBJECT_ID('dbo.failed_migrations','V') IS NOT NULL DROP VIEW failed_migrations;
GO
CREATE VIEW failed_migrations AS
SELECT TOP (2147483647)
    id,
    migration_name,
    migration_type,
    applied_at,
    error_message,
    execution_time_ms
FROM migration_history
WHERE success = 0
ORDER BY applied_at DESC;
GO

-- ============================================================================
-- Mevcut migration'ları kaydet (eğer daha önce uygulandıysa)
-- ============================================================================

-- SQL Migrations
INSERT INTO migration_history (migration_name, migration_type, applied_by)
SELECT v.migration_name, v.migration_type, v.applied_by
FROM (VALUES
    ('create_alarm_severity_config.sql', 'SQL', 'initial_setup'),
    ('add_mac_tracking_tables.sql',      'SQL', 'initial_setup'),
    ('add_acknowledged_port_mac_table.sql', 'SQL', 'initial_setup'),
    ('create_switch_change_log_view.sql','SQL', 'initial_setup'),
    ('mac_device_import.sql',            'SQL', 'initial_setup'),
    ('fix_status_enum_uppercase.sql',    'SQL', 'initial_setup'),
    ('fix_alarms_status_enum_uppercase.sql', 'SQL', 'initial_setup'),
    ('enable_description_change_notifications.sql', 'SQL', 'initial_setup')
) AS v(migration_name, migration_type, applied_by)
WHERE NOT EXISTS (
    SELECT 1 FROM migration_history mh WHERE mh.migration_name = v.migration_name
);

-- Python Migrations
INSERT INTO migration_history (migration_name, migration_type, applied_by)
SELECT v.migration_name, v.migration_type, v.applied_by
FROM (VALUES
    ('create_tables.py',                  'PYTHON', 'initial_setup'),
    ('add_snmp_v3_columns.py',            'PYTHON', 'initial_setup'),
    ('add_system_info_columns.py',        'PYTHON', 'initial_setup'),
    ('add_engine_id.py',                  'PYTHON', 'initial_setup'),
    ('add_polling_data_columns.py',       'PYTHON', 'initial_setup'),
    ('add_port_config_columns.py',        'PYTHON', 'initial_setup'),
    ('add_alarm_notification_columns.py', 'PYTHON', 'initial_setup'),
    ('fix_status_enum_uppercase.py',      'PYTHON', 'initial_setup')
) AS v(migration_name, migration_type, applied_by)
WHERE NOT EXISTS (
    SELECT 1 FROM migration_history mh WHERE mh.migration_name = v.migration_name
);

-- ============================================================================
-- Kullanım Örnekleri
-- ============================================================================

-- Tüm migration'ları göster
-- SELECT * FROM migration_history ORDER BY applied_at DESC;

-- Migration istatistiklerini göster
-- SELECT * FROM migration_stats;

-- Son 10 migration'ı göster
-- SELECT TOP 10 * FROM recent_migrations;

-- Başarısız migration'ları göster
-- SELECT * FROM failed_migrations;

-- Belirli bir migration'ın uygulanıp uygulanmadığını kontrol et
-- SELECT CASE WHEN EXISTS(SELECT 1 FROM migration_history WHERE migration_name = 'create_alarm_severity_config.sql' AND success = 1) THEN 1 ELSE 0 END AS is_applied;

-- Migration ekle (yeni migration uygulandığında)
-- INSERT INTO migration_history (migration_name, migration_type, execution_time_ms)
-- VALUES ('new_migration.sql', 'SQL', 125);
