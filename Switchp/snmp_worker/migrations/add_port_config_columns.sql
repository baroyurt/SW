-- ============================================================================
-- Add Port Configuration Columns Migration
-- Date: 2026-02-15
-- Purpose: Add missing columns to port_status_data table
-- ============================================================================
--
-- This migration adds columns that are required for SNMP worker to function:
-- - port_type: Port interface type (e.g., "ethernetCsmacd")
-- - port_speed: Port speed in bits per second
-- - port_mtu: Maximum Transmission Unit size
--
-- Without these columns, SNMP worker crashes with "Unknown column" errors.
-- ============================================================================

USE switchdb;

-- Add port_type column if it doesn't exist
SET @column_exists = (
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'switchdb' 
    AND TABLE_NAME = 'port_status_data' 
    AND COLUMN_NAME = 'port_type'
);

SET @sql = IF(@column_exists = 0,
    'ALTER TABLE port_status_data ADD COLUMN port_type VARCHAR(100) DEFAULT NULL COMMENT ''Port interface type (e.g., ethernetCsmacd)''',
    'SELECT ''Column port_type already exists'' AS status'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add port_speed column if it doesn't exist
SET @column_exists = (
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'switchdb' 
    AND TABLE_NAME = 'port_status_data' 
    AND COLUMN_NAME = 'port_speed'
);

SET @sql = IF(@column_exists = 0,
    'ALTER TABLE port_status_data ADD COLUMN port_speed BIGINT DEFAULT NULL COMMENT ''Port speed in bits per second''',
    'SELECT ''Column port_speed already exists'' AS status'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add port_mtu column if it doesn't exist
SET @column_exists = (
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'switchdb' 
    AND TABLE_NAME = 'port_status_data' 
    AND COLUMN_NAME = 'port_mtu'
);

SET @sql = IF(@column_exists = 0,
    'ALTER TABLE port_status_data ADD COLUMN port_mtu INTEGER DEFAULT NULL COMMENT ''Maximum Transmission Unit size''',
    'SELECT ''Column port_mtu already exists'' AS status'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Verify columns were added
SELECT 'SUCCESS: Port configuration columns migration complete' AS status;

SELECT 
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_DEFAULT,
    COLUMN_COMMENT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'switchdb'
AND TABLE_NAME = 'port_status_data'
AND COLUMN_NAME IN ('port_type', 'port_speed', 'port_mtu')
ORDER BY COLUMN_NAME;
