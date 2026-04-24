-- Alarm Severity Configuration Table
-- Allows admin to configure severity levels and notification routing per alarm type

IF OBJECT_ID('dbo.alarm_severity_config','U') IS NULL BEGIN
CREATE TABLE alarm_severity_config (
    id               INT IDENTITY(1,1) PRIMARY KEY,
    alarm_type       VARCHAR(50)  NOT NULL,
    severity         VARCHAR(50)  NOT NULL DEFAULT 'MEDIUM',
    telegram_enabled BIT          DEFAULT 1,
    email_enabled    BIT          DEFAULT 1,
    description      VARCHAR(255),
    created_at       DATETIME     DEFAULT GETDATE(),
    updated_at       DATETIME     DEFAULT GETDATE(),
    CONSTRAINT uq_alarm_type UNIQUE (alarm_type)
)
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_alarm_type' AND object_id=OBJECT_ID('alarm_severity_config'))
    CREATE INDEX idx_alarm_type ON alarm_severity_config(alarm_type);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_severity' AND object_id=OBJECT_ID('alarm_severity_config'))
    CREATE INDEX idx_severity ON alarm_severity_config(severity);

-- Insert default alarm types with their default severities (UPDATE-then-INSERT pattern)
UPDATE alarm_severity_config SET severity='CRITICAL', telegram_enabled=1, email_enabled=1, description='Cihaz erişilemez durumda' WHERE alarm_type='device_unreachable';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('device_unreachable', 'CRITICAL', 1, 1, 'Cihaz erişilemez durumda');

UPDATE alarm_severity_config SET severity='CRITICAL', telegram_enabled=1, email_enabled=1, description='Birden fazla port çalışmıyor' WHERE alarm_type='multiple_ports_down';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('multiple_ports_down', 'CRITICAL', 1, 1, 'Birden fazla port çalışmıyor');

UPDATE alarm_severity_config SET severity='CRITICAL', telegram_enabled=1, email_enabled=1, description='Core uplink bağlantısı kesildi' WHERE alarm_type='core_link_down';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('core_link_down', 'CRITICAL', 1, 1, 'Core uplink bağlantısı kesildi');

UPDATE alarm_severity_config SET severity='HIGH', telegram_enabled=1, email_enabled=1, description='MAC adresi taşındı' WHERE alarm_type='mac_moved';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('mac_moved', 'HIGH', 1, 1, 'MAC adresi taşındı');

UPDATE alarm_severity_config SET severity='HIGH', telegram_enabled=1, email_enabled=1, description='Port düştü' WHERE alarm_type='port_down';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('port_down', 'HIGH', 1, 1, 'Port düştü');

UPDATE alarm_severity_config SET severity='MEDIUM', telegram_enabled=0, email_enabled=1, description='VLAN değişti' WHERE alarm_type='vlan_changed';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('vlan_changed', 'MEDIUM', 0, 1, 'VLAN değişti');

UPDATE alarm_severity_config SET severity='MEDIUM', telegram_enabled=0, email_enabled=1, description='Port aktif oldu' WHERE alarm_type='port_up';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('port_up', 'MEDIUM', 0, 1, 'Port aktif oldu');

UPDATE alarm_severity_config SET severity='LOW', telegram_enabled=0, email_enabled=0, description='Port açıklaması değişti' WHERE alarm_type='description_changed';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('description_changed', 'LOW', 0, 0, 'Port açıklaması değişti');

UPDATE alarm_severity_config SET severity='MEDIUM', telegram_enabled=0, email_enabled=1, description='Yeni MAC adresi tespit edildi' WHERE alarm_type='mac_added';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('mac_added', 'MEDIUM', 0, 1, 'Yeni MAC adresi tespit edildi');

UPDATE alarm_severity_config SET severity='HIGH', telegram_enabled=1, email_enabled=1, description='SNMP hatası' WHERE alarm_type='snmp_error';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('snmp_error', 'HIGH', 1, 1, 'SNMP hatası');

UPDATE alarm_severity_config SET severity='HIGH', telegram_enabled=1, email_enabled=1, description='Yüksek sıcaklık (>=70°C)' WHERE alarm_type='high_temperature';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('high_temperature', 'HIGH', 1, 1, 'Yüksek sıcaklık (>=70°C)');

UPDATE alarm_severity_config SET severity='CRITICAL', telegram_enabled=1, email_enabled=1, description='Fan arızası' WHERE alarm_type='fan_failure';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('fan_failure', 'CRITICAL', 1, 1, 'Fan arızası');

UPDATE alarm_severity_config SET severity='HIGH', telegram_enabled=1, email_enabled=1, description='Yüksek işlemci kullanımı (>=%30)' WHERE alarm_type='high_cpu';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('high_cpu', 'HIGH', 1, 1, 'Yüksek işlemci kullanımı (>=%30)');

-- PHP notification types (no telegram, email-only)
UPDATE alarm_severity_config SET severity='LOW', telegram_enabled=0, email_enabled=1, description='Excel export bildirimi' WHERE alarm_type='excel_export';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('excel_export', 'LOW', 0, 1, 'Excel export bildirimi');

UPDATE alarm_severity_config SET severity='LOW', telegram_enabled=0, email_enabled=1, description='MAC geçmiş silme bildirimi' WHERE alarm_type='mac_history_cleanup';
IF @@ROWCOUNT = 0 INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES ('mac_history_cleanup', 'LOW', 0, 1, 'MAC geçmiş silme bildirimi');
