-- Alarm Severity Configuration Table
-- Allows admin to configure severity levels and notification routing per alarm type

CREATE TABLE IF NOT EXISTS alarm_severity_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alarm_type VARCHAR(50) NOT NULL UNIQUE,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL DEFAULT 'MEDIUM',
    telegram_enabled BOOLEAN DEFAULT TRUE,
    email_enabled BOOLEAN DEFAULT TRUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alarm_type (alarm_type),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default alarm types with their default severities
INSERT INTO alarm_severity_config (alarm_type, severity, telegram_enabled, email_enabled, description) VALUES
('device_unreachable', 'CRITICAL', TRUE, TRUE, 'Cihaz erişilemez durumda'),
('multiple_ports_down', 'CRITICAL', TRUE, TRUE, 'Birden fazla port çalışmıyor'),
('mac_moved', 'HIGH', TRUE, TRUE, 'MAC adresi taşındı'),
('port_down', 'HIGH', TRUE, TRUE, 'Port düştü'),
('vlan_changed', 'MEDIUM', FALSE, TRUE, 'VLAN değişti'),
('port_up', 'MEDIUM', FALSE, TRUE, 'Port aktif oldu'),
('description_changed', 'LOW', FALSE, FALSE, 'Port açıklaması değişti'),
('mac_added', 'MEDIUM', FALSE, TRUE, 'Yeni MAC adresi tespit edildi'),
('snmp_error', 'HIGH', TRUE, TRUE, 'SNMP hatası')
ON DUPLICATE KEY UPDATE 
    severity = VALUES(severity),
    telegram_enabled = VALUES(telegram_enabled),
    email_enabled = VALUES(email_enabled),
    description = VALUES(description);
