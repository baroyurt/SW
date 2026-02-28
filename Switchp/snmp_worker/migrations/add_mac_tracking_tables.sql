-- ============================================================================
-- MAC Address Tracking & Change Detection System
-- Database Schema Enhancement
-- Date: 2026-02-13
-- ============================================================================

USE switchdb;

-- ============================================================================
-- Table: port_change_history
-- Purpose: Track all changes to ports (MAC, VLAN, description, etc.)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `port_change_history` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `device_id` INT(11) NOT NULL,
  `port_number` INT(11) NOT NULL,
  `change_type` ENUM('mac_added', 'mac_removed', 'mac_moved', 'vlan_changed', 'description_changed', 'status_changed') NOT NULL,
  `change_timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Old values
  `old_value` TEXT DEFAULT NULL,
  `old_mac_address` VARCHAR(17) DEFAULT NULL,
  `old_vlan_id` INT(11) DEFAULT NULL,
  `old_description` VARCHAR(255) DEFAULT NULL,
  
  -- New values
  `new_value` TEXT DEFAULT NULL,
  `new_mac_address` VARCHAR(17) DEFAULT NULL,
  `new_vlan_id` INT(11) DEFAULT NULL,
  `new_description` VARCHAR(255) DEFAULT NULL,
  
  -- Movement tracking (if MAC moved)
  `from_device_id` INT(11) DEFAULT NULL,
  `from_port_number` INT(11) DEFAULT NULL,
  `to_device_id` INT(11) DEFAULT NULL,
  `to_port_number` INT(11) DEFAULT NULL,
  
  -- Change metadata
  `change_details` TEXT DEFAULT NULL,
  `alarm_created` TINYINT(1) DEFAULT 0,
  `alarm_id` INT(11) DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_device_port` (`device_id`, `port_number`),
  KEY `idx_change_type` (`change_type`),
  KEY `idx_timestamp` (`change_timestamp`),
  KEY `idx_mac_address` (`old_mac_address`, `new_mac_address`),
  KEY `idx_alarm` (`alarm_id`),
  CONSTRAINT `fk_pch_device` FOREIGN KEY (`device_id`) REFERENCES `snmp_devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================================
-- Table: mac_address_tracking
-- Purpose: Track current location and history of each MAC address
-- ============================================================================
CREATE TABLE IF NOT EXISTS `mac_address_tracking` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `mac_address` VARCHAR(17) NOT NULL,
  
  -- Current location
  `current_device_id` INT(11) DEFAULT NULL,
  `current_port_number` INT(11) DEFAULT NULL,
  `current_vlan_id` INT(11) DEFAULT NULL,
  
  -- Device information (from domain/DHCP)
  `device_name` VARCHAR(255) DEFAULT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `device_type` VARCHAR(100) DEFAULT NULL,
  `domain_user` VARCHAR(255) DEFAULT NULL,
  
  -- Tracking metadata
  `first_seen` DATETIME NOT NULL,
  `last_seen` DATETIME NOT NULL,
  `last_moved` DATETIME DEFAULT NULL,
  `move_count` INT(11) DEFAULT 0,
  
  -- Previous location (for quick reference)
  `previous_device_id` INT(11) DEFAULT NULL,
  `previous_port_number` INT(11) DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_mac_address` (`mac_address`),
  KEY `idx_current_location` (`current_device_id`, `current_port_number`),
  KEY `idx_last_seen` (`last_seen`),
  CONSTRAINT `fk_mat_device` FOREIGN KEY (`current_device_id`) REFERENCES `snmp_devices` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================================
-- Table: port_snapshot
-- Purpose: Store periodic snapshots of port states for comparison
-- ============================================================================
CREATE TABLE IF NOT EXISTS `port_snapshot` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `device_id` INT(11) NOT NULL,
  `port_number` INT(11) NOT NULL,
  `snapshot_timestamp` DATETIME NOT NULL,
  
  -- Port configuration
  `port_name` VARCHAR(100) DEFAULT NULL,
  `port_alias` VARCHAR(255) DEFAULT NULL,
  `port_description` TEXT DEFAULT NULL,
  `admin_status` VARCHAR(20) DEFAULT NULL,
  `oper_status` VARCHAR(20) DEFAULT NULL,
  
  -- VLAN information
  `vlan_id` INT(11) DEFAULT NULL,
  `vlan_name` VARCHAR(100) DEFAULT NULL,
  
  -- MAC information
  `mac_address` VARCHAR(17) DEFAULT NULL,
  `mac_addresses` TEXT DEFAULT NULL,  -- JSON array of multiple MACs
  
  PRIMARY KEY (`id`),
  KEY `idx_device_port_time` (`device_id`, `port_number`, `snapshot_timestamp`),
  KEY `idx_timestamp` (`snapshot_timestamp`),
  CONSTRAINT `fk_ps_device` FOREIGN KEY (`device_id`) REFERENCES `snmp_devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================================
-- Enhance alarms table with acknowledgment type
-- ============================================================================
ALTER TABLE `alarms` 
ADD COLUMN IF NOT EXISTS `acknowledgment_type` ENUM('known_change', 'silenced', 'resolved') DEFAULT NULL,
ADD COLUMN IF NOT EXISTS `silence_until` DATETIME DEFAULT NULL,
ADD COLUMN IF NOT EXISTS `mac_address` VARCHAR(17) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS `old_value` TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS `new_value` TEXT DEFAULT NULL;

-- Add index for MAC address in alarms
ALTER TABLE `alarms` 
ADD KEY IF NOT EXISTS `idx_mac_address` (`mac_address`);

-- ============================================================================
-- Create view for current port status with change indicators
-- ============================================================================
CREATE OR REPLACE VIEW `v_port_current_status` AS
SELECT 
    sd.id AS device_id,
    sd.name AS device_name,
    sd.ip_address,
    psd.port_number,
    psd.port_name,
    psd.port_alias,
    psd.port_description,
    psd.admin_status,
    psd.oper_status,
    psd.vlan_id,
    psd.vlan_name,
    psd.mac_address,
    psd.mac_addresses,
    psd.poll_timestamp,
    mat.device_name AS mac_device_name,
    mat.ip_address AS mac_ip_address,
    (SELECT COUNT(*) FROM alarms a 
     WHERE a.device_id = sd.id 
     AND a.port_number = psd.port_number 
     AND a.status = 'active') AS active_alarm_count,
    (SELECT COUNT(*) FROM port_change_history pch
     WHERE pch.device_id = sd.id
     AND pch.port_number = psd.port_number
     AND pch.change_timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS changes_last_24h
FROM snmp_devices sd
INNER JOIN port_status_data psd ON sd.id = psd.device_id
LEFT JOIN mac_address_tracking mat ON psd.mac_address = mat.mac_address
WHERE psd.poll_timestamp = (
    SELECT MAX(poll_timestamp) 
    FROM port_status_data 
    WHERE device_id = sd.id AND port_number = psd.port_number
);

-- ============================================================================
-- Verification queries
-- ============================================================================
SELECT 'port_change_history table created' AS status;
SELECT 'mac_address_tracking table created' AS status;
SELECT 'port_snapshot table created' AS status;
SELECT 'alarms table enhanced' AS status;
SELECT 'v_port_current_status view created' AS status;

-- Show table structures
DESCRIBE port_change_history;
DESCRIBE mac_address_tracking;
DESCRIBE port_snapshot;
