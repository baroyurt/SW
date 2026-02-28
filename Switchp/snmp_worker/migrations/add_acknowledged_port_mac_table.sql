-- Migration: Add acknowledged_port_mac whitelist table
-- Purpose: Store permanently whitelisted MAC+Port combinations that should not trigger alarms
-- Date: 2026-02-15

-- Create acknowledged_port_mac table for whitelist
CREATE TABLE IF NOT EXISTS acknowledged_port_mac (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    port_number INT NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    acknowledged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_by VARCHAR(100) NOT NULL,
    note TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Unique constraint: one whitelist entry per device+port+mac combination
    UNIQUE KEY unique_whitelist (device_name, port_number, mac_address),
    
    -- Indexes for fast lookups
    INDEX idx_device_port (device_name, port_number),
    INDEX idx_mac (mac_address),
    INDEX idx_acknowledged_at (acknowledged_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add alarm fingerprint columns to alarms table for better uniqueness tracking
ALTER TABLE alarms 
ADD COLUMN IF NOT EXISTS from_port INT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS to_port INT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS alarm_fingerprint VARCHAR(255) DEFAULT NULL,
ADD INDEX IF NOT EXISTS idx_alarm_fingerprint (alarm_fingerprint);

-- Add counter column if it doesn't exist (for tracking repeat occurrences)
-- Note: occurrence_count already exists, but let's ensure it's there
ALTER TABLE alarms 
MODIFY COLUMN occurrence_count INT DEFAULT 1;

-- Create index on device + port + type + status for faster queries
ALTER TABLE alarms
ADD INDEX IF NOT EXISTS idx_device_port_type_status (device_id, port_number, alarm_type, status);

-- Migration complete
