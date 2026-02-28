-- ============================================================================
-- Migration Tracker Table
-- ============================================================================
-- Bu tablo hangi migration'ların uygulandığını takip eder
-- Otomatik migration sistemi için gerekli
-- ============================================================================

-- Migration tracker tablosunu oluştur
CREATE TABLE IF NOT EXISTS migration_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL UNIQUE,
    migration_type ENUM('SQL', 'PYTHON', 'PHP') NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT NULL,
    execution_time_ms INT NULL,
    applied_by VARCHAR(100) DEFAULT 'system',
    INDEX idx_applied_at (applied_at),
    INDEX idx_migration_type (migration_type),
    INDEX idx_success (success)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks applied database migrations';

-- Migration istatistikleri için view
CREATE OR REPLACE VIEW migration_stats AS
SELECT 
    migration_type,
    COUNT(*) as total_count,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_count,
    AVG(execution_time_ms) as avg_execution_time_ms,
    MAX(applied_at) as last_applied
FROM migration_history
GROUP BY migration_type;

-- Son migration'ları görmek için view
CREATE OR REPLACE VIEW recent_migrations AS
SELECT 
    id,
    migration_name,
    migration_type,
    applied_at,
    success,
    execution_time_ms,
    CASE 
        WHEN success = 1 THEN 'SUCCESS'
        ELSE 'FAILED'
    END as status
FROM migration_history
ORDER BY applied_at DESC
LIMIT 50;

-- Başarısız migration'ları görmek için view
CREATE OR REPLACE VIEW failed_migrations AS
SELECT 
    id,
    migration_name,
    migration_type,
    applied_at,
    error_message,
    execution_time_ms
FROM migration_history
WHERE success = 0
ORDER BY applied_at DESC;

-- ============================================================================
-- Mevcut migration'ları kaydet (eğer daha önce uygulandıysa)
-- ============================================================================

-- Önemli: Bu INSERT IGNORE kullanır, yani zaten kayıtlı migration'lar tekrar eklenmez

-- SQL Migrations
INSERT IGNORE INTO migration_history (migration_name, migration_type, applied_by) VALUES
('create_alarm_severity_config.sql', 'SQL', 'initial_setup'),
('add_mac_tracking_tables.sql', 'SQL', 'initial_setup'),
('add_acknowledged_port_mac_table.sql', 'SQL', 'initial_setup'),
('create_switch_change_log_view.sql', 'SQL', 'initial_setup'),
('mac_device_import.sql', 'SQL', 'initial_setup'),
('fix_status_enum_uppercase.sql', 'SQL', 'initial_setup'),
('fix_alarms_status_enum_uppercase.sql', 'SQL', 'initial_setup'),
('enable_description_change_notifications.sql', 'SQL', 'initial_setup');

-- Python Migrations
INSERT IGNORE INTO migration_history (migration_name, migration_type, applied_by) VALUES
('create_tables.py', 'PYTHON', 'initial_setup'),
('add_snmp_v3_columns.py', 'PYTHON', 'initial_setup'),
('add_system_info_columns.py', 'PYTHON', 'initial_setup'),
('add_engine_id.py', 'PYTHON', 'initial_setup'),
('add_polling_data_columns.py', 'PYTHON', 'initial_setup'),
('add_port_config_columns.py', 'PYTHON', 'initial_setup'),
('add_alarm_notification_columns.py', 'PYTHON', 'initial_setup'),
('fix_status_enum_uppercase.py', 'PYTHON', 'initial_setup');

-- ============================================================================
-- Kullanım Örnekleri
-- ============================================================================

-- Tüm migration'ları göster
-- SELECT * FROM migration_history ORDER BY applied_at DESC;

-- Migration istatistiklerini göster
-- SELECT * FROM migration_stats;

-- Son 10 migration'ı göster
-- SELECT * FROM recent_migrations LIMIT 10;

-- Başarısız migration'ları göster
-- SELECT * FROM failed_migrations;

-- Belirli bir migration'ın uygulanıp uygulanmadığını kontrol et
-- SELECT EXISTS(SELECT 1 FROM migration_history WHERE migration_name = 'create_alarm_severity_config.sql' AND success = 1) as is_applied;

-- Migration ekle (yeni migration uygulandığında)
-- INSERT INTO migration_history (migration_name, migration_type, execution_time_ms) 
-- VALUES ('new_migration.sql', 'SQL', 125);
